#!/usr/bin/env python3
"""
Tests du système complet.

Chaque test lance les vrais programmes (serveur_central, serveur_ftp,
client_ftp), dans un dossier temporaire, et vérifie une exigence du sujet.

Lancement : make test
"""
import hashlib
import hmac
import os
import pty
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import termios
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CENTRAL = str(ROOT / "serveur_central")
FTP = str(ROOT / "serveur_ftp")
CLIENT = str(ROOT / "client_ftp")

HOST = "127.0.0.1"
FAKE_USER = "robot"
FAKE_SALT = "$6$abcdefghijklmnop$"
FAKE_KEY = hashlib.sha256(b"cle du robot").digest()
FAKE_VERIFIER = hashlib.sha256(FAKE_KEY).hexdigest()
SANITIZER = re.compile(
    r"AddressSanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer|"
    r"LeakSanitizer|runtime error:"
)

EXEMPLE_SUJET = (
    "MP3.txt\n"
    "FAQ sur l’algorithme de compression utilisé dans le codage audio MPEG-2\n"
)


def wait_until(predicate, timeout=15, step=0.05):
    """Attend qu'une condition devienne vraie. Renvoie False si le délai expire."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return bool(predicate())


def make_proof(key, verifier, nonce):
    """preuve = clé XOR HMAC(vérificateur, défi) : calcul de référence en Python."""
    signature = hmac.new(bytes.fromhex(verifier), nonce.encode(), hashlib.sha256).digest()
    return bytes(a ^ b for a, b in zip(key, signature)).hex()


def local_network_ip():
    """Adresse de la machine sur le réseau local, ou None s'il n'y en a pas."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 9))
        ip = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return None if ip.startswith("127.") else ip


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rss_kb(pid):
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)]).strip())


class Process:
    """Un programme lancé, dont on collecte la sortie en continu."""

    def __init__(self, argv, stdin_text=None):
        self.argv = argv
        self.popen = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.output = bytearray()
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        if stdin_text is not None:
            self.popen.stdin.write(stdin_text.encode())
            self.popen.stdin.flush()
        self.popen.stdin.close()

    def _read(self):
        while True:
            chunk = self.popen.stdout.read1(65536)
            if not chunk:
                return
            with self.lock:
                self.output += chunk

    def text(self):
        with self.lock:
            return self.output.decode("utf-8", "replace")

    def wait_for(self, pattern, timeout=15):
        found = wait_until(lambda: re.search(pattern, self.text()), timeout)
        if not found:
            raise AssertionError(
                f"Texte « {pattern} » absent de la sortie :\n{self.text()}"
            )

    def count(self, pattern):
        return len(re.findall(pattern, self.text()))

    def alive(self):
        return self.popen.poll() is None

    def signal(self, sig):
        if self.alive():
            self.popen.send_signal(sig)

    def wait_exit(self, timeout=15):
        return self.popen.wait(timeout=timeout)

    def kill(self):
        if self.alive():
            self.popen.send_signal(signal.SIGCONT)
            self.popen.kill()
        self.popen.wait(timeout=15)
        self.reader.join(timeout=5)
        self.popen.stdout.close()


class Raw:
    """Connexion TCP brute, pour parler le protocole directement."""

    def __init__(self, port, timeout=10):
        self.sock = socket.create_connection((HOST, port), timeout=timeout)
        self.file = self.sock.makefile("rb")

    def send(self, text):
        self.sock.sendall(text.encode() if isinstance(text, str) else text)

    def recv(self):
        return self.file.readline().decode("utf-8", "replace").rstrip("\n")

    def recv_bytes(self):
        return self.file.read()

    def close(self):
        self.file.close()
        self.sock.close()


class Capture:
    """Relais TCP qui enregistre tout ce qui circule, comme un espion réseau."""

    def __init__(self, target_port):
        self.target_port = target_port
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((HOST, 0))
        self.server.listen(16)
        self.port = self.server.getsockname()[1]
        self.data = bytearray()
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _ = self.server.accept()
            except OSError:
                return
            upstream = socket.create_connection((HOST, self.target_port))
            for src, dst in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(src, dst), daemon=True).start()

    def _pump(self, src, dst):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                with self.lock:
                    self.data += chunk
                dst.sendall(chunk)
        except OSError:
            pass
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def captured(self):
        with self.lock:
            return bytes(self.data)

    def close(self):
        self.server.close()


class FakeCentral:
    """Faux serveur central : impose le sel choisi par le test."""

    def __init__(self, salt):
        self.salt = salt
        self.auth_received = threading.Event()
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((HOST, 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            connection, _ = self.server.accept()
            stream = connection.makefile("rb")
            stream.readline()
            connection.sendall(f"CHALLENGE\t{self.salt}\t{'0' * 32}\n".encode())
            if stream.readline().startswith(b"AUTH"):
                self.auth_received.set()
            connection.close()
        except OSError:
            pass

    def close(self):
        self.server.close()


class Base(unittest.TestCase):
    peer_timeout = 15

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="p2p_")).resolve()
        self.users_file = self.tmp / "utilisateurs.db"
        self.users_file.write_text(f"{FAKE_USER}:{FAKE_SALT}:{FAKE_VERIFIER}\n")
        self.processes = []
        self.sockets = []
        self.central_port = None
        self.central = None
        self.start_central()

    def tearDown(self):
        for s in self.sockets:
            s.close()
        for p in reversed(self.processes):
            p.kill()
        for p in self.processes:
            self.assertNotRegex(p.text(), SANITIZER)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def spawn(self, argv, stdin_text=None):
        p = Process([str(a) for a in argv], stdin_text)
        self.processes.append(p)
        return p

    def start_central(self, port=0):
        self.central = self.spawn(
            [CENTRAL, "-t", self.peer_timeout, "-f", self.users_file, port]
        )
        self.central.wait_for(r"port \d+")
        self.central_port = int(re.search(r"port (\d+)", self.central.text()).group(1))

    def make_share(self, name, files=None, desc=None):
        folder = self.tmp / name
        folder.mkdir(exist_ok=True)
        for rel, content in (files or {}).items():
            target = folder / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            data = content.encode() if isinstance(content, str) else content
            target.write_bytes(data)
        if desc is not None:
            (folder / "descriptions.txt").write_text(desc, encoding="utf-8")
        return folder

    def start_peer(self, name, files=None, desc=None, password="secret123",
                   create=True, central_port=None, wait=True, options=()):
        folder = self.make_share(name, files, desc)
        if create:
            script = f"2\n{name}\n{password}\n{password}\n"
        else:
            script = f"1\n{name}\n{password}\n"
        port = central_port or self.central_port
        p = self.spawn([FTP, *options, HOST, port, folder], script)
        if wait:
            p.wait_for("Liste envoyée au serveur central")
            p.transfer_port = int(re.search(r"port (\d+),", p.text()).group(1))
        return p

    def run_client(self, name, commands, timeout=60, central_port=None):
        folder = self.tmp / name
        folder.mkdir(exist_ok=True)
        port = central_port or self.central_port
        result = subprocess.run(
            [CLIENT, HOST, str(port), str(folder)],
            input=commands.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        text = result.stdout.decode("utf-8", "replace")
        self.assertNotRegex(text, SANITIZER)
        self.assertEqual(result.returncode, 0, text)
        return text

    def raw(self, port=None):
        connection = Raw(port or self.central_port)
        self.sockets.append(connection)
        return connection

    def raw_login(self):
        connection = self.raw()
        connection.send(f"LOGIN\t{FAKE_USER}\n")
        kind, salt, nonce = connection.recv().split("\t")
        self.assertEqual(kind, "CHALLENGE")
        connection.send(f"AUTH\t{make_proof(FAKE_KEY, FAKE_VERIFIER, nonce)}\n")
        self.assertTrue(connection.recv().startswith("OK"))
        return connection

    def raw_publish(self, connection, port, files, host=HOST):
        connection.send(f"PUBLISH\t{host}\t{port}\t{len(files)}\n")
        for path, size, mtime, desc in files:
            connection.send(f"FILE\t{path}\t{size}\t{mtime}\t{desc}\n")
        self.assertEqual(connection.recv(), "OK")

    def search(self, query, sort="pertinence", order="desc"):
        connection = Raw(self.central_port)
        try:
            connection.send(f"SEARCH\t{sort}\t{order}\t{query}\n")
            head = connection.recv().split("\t")
            self.assertEqual(head[0], "RESULTS", head)
            rows = []
            for _ in range(int(head[1])):
                f = connection.recv().split("\t")
                rows.append({
                    "user": f[1], "host": f[2], "ip": f[3], "port": int(f[4]),
                    "path": f[5], "size": int(f[6]), "mtime": int(f[7]),
                    "score": int(f[8]), "desc": f[9],
                })
            return rows
        finally:
            connection.close()

    def paths(self, query, **kwargs):
        return [r["path"] for r in self.search(query, **kwargs)]

    def assert_central_alive(self):
        self.assertTrue(self.central.alive())
        self.search("nimportequoi")


class TestAuthentification(Base):
    def test_inscription_puis_connexion(self):
        self.start_peer("alice", {"a.txt": "x"}, "a.txt\nun fichier\n")
        self.search("fichier")
        self.assertIn("alice:", self.users_file.read_text())
        self.central.wait_for("alice authentifié")

    def test_reconnexion_avec_compte_existant(self):
        peer = self.start_peer("alice", {"a.txt": "x"}, "a.txt\nun fichier\n")
        peer.signal(signal.SIGINT)
        self.assertEqual(peer.wait_exit(), 0)
        again = self.start_peer("alice", create=False)
        self.assertTrue(again.alive())
        self.assertEqual(self.paths("fichier"), ["a.txt"])

    def test_nom_deja_pris(self):
        self.start_peer("alice", {"a.txt": "x"})
        p = self.spawn(
            [FTP, HOST, self.central_port, self.make_share("alice2")],
            "2\nalice\nautre\nautre\n",
        )
        p.wait_for("existe déjà")
        self.assertEqual(self.users_file.read_text().count("alice:"), 1)

    def test_mauvais_mot_de_passe(self):
        peer = self.start_peer("alice", {"a.txt": "x"})
        peer.signal(signal.SIGINT)
        peer.wait_exit()
        p = self.start_peer("alice", password="mauvais", create=False, wait=False)
        p.wait_for("Échec de la connexion")
        self.assertEqual(self.search("a.txt"), [])

    def test_utilisateur_inconnu(self):
        p = self.start_peer("fantome", create=False, wait=False)
        p.wait_for("Échec de la connexion")

    def test_tous_les_caracteres_du_mot_de_passe_comptent(self):
        """Piège de DES : seuls les 8 premiers caractères seraient vérifiés."""
        peer = self.start_peer("alice", password="motdepasse1")
        peer.signal(signal.SIGINT)
        peer.wait_exit()
        p = self.start_peer("alice", password="motdepasse2", create=False, wait=False)
        p.wait_for("Échec de la connexion")

    def test_confirmation_differente(self):
        p = self.spawn(
            [FTP, HOST, self.central_port, self.make_share("alice")],
            "2\nalice\nun\ndeux\n",
        )
        p.wait_for("différents")
        self.assertNotIn("alice:", self.users_file.read_text())

    def test_mot_de_passe_jamais_en_clair(self):
        spy = Capture(self.central_port)
        self.addCleanup(spy.close)
        password = "SuperSecretXYZ"
        peer = self.start_peer("alice", {"a.txt": "x"}, password=password,
                               central_port=spy.port)
        data = spy.captured()
        self.assertIn(b"REGISTER", data)
        self.assertIn(b"AUTH", data)
        self.assertNotIn(password.encode(), data)
        peer.signal(signal.SIGINT)
        peer.wait_exit()

    def test_verificateur_absent_de_la_connexion(self):
        """À la connexion, ni le mot de passe ni le vérificateur ne circulent."""
        peer = self.start_peer("alice", {"a.txt": "x"})
        peer.signal(signal.SIGINT)
        peer.wait_exit()
        stored = self.users_file.read_text().splitlines()[-1].split(":")[2]

        spy = Capture(self.central_port)
        self.addCleanup(spy.close)
        self.start_peer("alice", create=False, central_port=spy.port)
        data = spy.captured()
        self.assertIn(b"CHALLENGE", data)
        self.assertNotIn(stored.encode(), data)
        self.assertNotIn(b"secret123", data)

    def test_reponse_capturee_inutilisable(self):
        """Rejeu : une réponse enregistrée ne doit pas rouvrir une session."""
        first = self.raw()
        first.send(f"LOGIN\t{FAKE_USER}\n")
        _, salt1, nonce1 = first.recv().split("\t")
        captured = make_proof(FAKE_KEY, FAKE_VERIFIER, nonce1)

        second = self.raw()
        second.send(f"LOGIN\t{FAKE_USER}\n")
        _, salt2, nonce2 = second.recv().split("\t")
        self.assertEqual(salt1, salt2)
        self.assertNotEqual(nonce1, nonce2)
        second.send(f"AUTH\t{captured}\n")
        self.assertTrue(second.recv().startswith("ERR"))

    def test_defi_a_usage_unique(self):
        c = self.raw()
        c.send(f"LOGIN\t{FAKE_USER}\n")
        c.recv()
        c.send("AUTH\t" + "0" * 64 + "\n")
        self.assertTrue(c.recv().startswith("ERR"))
        c.send("AUTH\t" + "0" * 64 + "\n")
        self.assertIn("LOGIN attendu", c.recv())

    def test_sel_transmis_sans_verificateur(self):
        c = self.raw()
        c.send(f"LOGIN\t{FAKE_USER}\n")
        line = c.recv()
        kind, salt, nonce = line.split("\t")
        self.assertEqual(kind, "CHALLENGE")
        self.assertEqual(salt, FAKE_SALT)
        self.assertEqual(len(nonce), 32)
        self.assertNotIn(FAKE_VERIFIER, line)

    def test_hmac_conforme_a_la_reference(self):
        """Python calcule la preuve : notre SHA-256 et notre HMAC doivent suivre."""
        self.raw_login()

    def forged_login(self, verifier, user=FAKE_USER):
        """Tente une connexion en ne connaissant que le vérificateur."""
        attempts = []
        nonce_proofs = [
            lambda nonce: make_proof(bytes.fromhex(verifier), verifier, nonce),
            lambda nonce: hmac.new(verifier.encode(), nonce.encode(), hashlib.sha256).hexdigest(),
        ]
        for forge in nonce_proofs:
            c = self.raw()
            c.send(f"LOGIN\t{user}\n")
            _, _, nonce = c.recv().split("\t")
            c.send(f"AUTH\t{forge(nonce)}\n")
            attempts.append(c.recv())
        return attempts

    def test_fichier_des_comptes_vole_inutilisable(self):
        """Comme sous UNIX : le fichier volé ne suffit pas pour se connecter."""
        stolen = self.users_file.read_text().strip().split(":")[2]
        for reply in self.forged_login(stolen):
            self.assertTrue(reply.startswith("ERR"), reply)

    def test_inscription_espionnee_inutilisable(self):
        spy = Capture(self.central_port)
        self.addCleanup(spy.close)
        peer = self.start_peer("alice", {"a.txt": "x"}, central_port=spy.port)
        text = spy.captured().decode("utf-8", "replace")
        line = next(l for l in text.splitlines() if l.startswith("REGISTER"))
        _, user, _, verifier = line.split("\t")
        peer.signal(signal.SIGINT)
        peer.wait_exit()
        for reply in self.forged_login(verifier, user):
            self.assertTrue(reply.startswith("ERR"), reply)

    def test_sel_impose_par_un_faux_central_refuse(self):
        for index, salt in enumerate((
            "ab", "$1$abcdefgh$", "_J9..rasm",
            "$6$rounds=999999999$abcdefghijklmnop$", "$6$abcdefghijklmnop$x",
        )):
            fake = FakeCentral(salt)
            self.addCleanup(fake.close)
            p = self.spawn([FTP, HOST, fake.port, self.make_share(f"s{index}")],
                           "1\nalice\nmdp\n")
            self.assertEqual(p.wait_exit(timeout=10), 1, salt)
            self.assertIn("réponse invalide", p.text(), salt)
            self.assertFalse(fake.auth_received.is_set(), salt)

    def test_nom_de_32_caracteres_accepte(self):
        name = "a" * 32
        self.start_peer(name, {"a.txt": "x"})
        self.assertIn(f"{name}:", self.users_file.read_text())

    def test_nom_de_33_caracteres_refuse(self):
        p = self.start_peer("a" * 33, {"a.txt": "x"}, wait=False)
        p.wait_for("Nom invalide")

    def test_fichier_des_comptes_sans_fin_de_ligne(self):
        self.users_file.write_text(self.users_file.read_text().rstrip("\n"))
        self.start_peer("alice", {"a.txt": "x"})
        lines = self.users_file.read_text().splitlines()
        self.assertEqual([l.split(":")[0] for l in lines], [FAKE_USER, "alice"])
        self.central.kill()
        self.start_central()
        self.raw_login()

    def test_fichier_des_comptes_comme_unix(self):
        self.users_file.unlink()   # le central doit le créer lui-même
        self.start_peer("alice", {"a.txt": "x"})
        line = self.users_file.read_text().splitlines()[-1]
        name, salt, verifier = line.split(":")
        self.assertEqual(name, "alice")
        self.assertTrue(salt.startswith(("$6$", "_")), salt)
        self.assertRegex(verifier, r"^[0-9a-f]{64}$")
        self.assertNotIn("secret123", line)
        self.assertEqual(self.users_file.stat().st_mode & 0o777, 0o600)

    def test_comptes_conserves_au_redemarrage(self):
        peer = self.start_peer("alice", {"a.txt": "x"})
        peer.signal(signal.SIGINT)
        peer.wait_exit()
        self.central.kill()
        self.start_central()
        self.start_peer("alice", create=False)
        self.assertEqual(self.paths("a.txt"), ["a.txt"])

    def test_meme_utilisateur_deux_fois_refuse(self):
        self.start_peer("alice", {"a.txt": "x"})
        p = self.start_peer("alice", create=False, wait=False)
        p.wait_for("déjà connecté")

    def test_nom_invalide_refuse_par_le_central(self):
        c = self.raw()
        c.send(f"REGISTER\tmauvais:nom\t{FAKE_SALT}\t{FAKE_VERIFIER}\n")
        self.assertTrue(c.recv().startswith("ERR"))
        for salt, verifier in (
            ("pasunsel", FAKE_VERIFIER), ("ab", FAKE_VERIFIER),
            ("$6$rounds=999999999$abcdefghijklmnop$", FAKE_VERIFIER),
            (FAKE_SALT, "pasunverificateur"), (FAKE_SALT, "G" * 64),
        ):
            c.send(f"REGISTER\tcorrect\t{salt}\t{verifier}\n")
            self.assertTrue(c.recv().startswith("ERR"), salt)
        self.assertNotIn("correct", self.users_file.read_text())


class TestAffichageMotDePasse(Base):
    def spawn_on_pty(self, script_folder):
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [FTP, HOST, str(self.central_port), str(script_folder)],
            stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
        )
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        return process, master, slave

    def read_until(self, master, text, timeout=10):
        buffer = b""
        deadline = time.time() + timeout
        os.set_blocking(master, False)
        while time.time() < deadline:
            try:
                buffer += os.read(master, 65536)
            except BlockingIOError:
                time.sleep(0.02)
            if text.encode() in buffer:
                return buffer
        raise AssertionError(f"« {text} » absent : {buffer!r}")

    def test_mot_de_passe_non_affiche(self):
        process, master, slave = self.spawn_on_pty(self.make_share("alice", {"a": "x"}))
        self.read_until(master, "Choix :")
        os.write(master, b"2\n")
        self.read_until(master, "utilisateur :")
        os.write(master, b"alice\n")
        self.read_until(master, "Mot de passe :")
        wait_until(lambda: not termios.tcgetattr(slave)[3] & termios.ECHO, 5)
        self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
        os.write(master, b"VisiblePasDuTout\n")
        seen = self.read_until(master, "Confirmer")
        os.write(master, b"VisiblePasDuTout\n")
        seen += self.read_until(master, "Connecté en tant que")
        self.assertNotIn(b"VisiblePasDuTout", seen)
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO)

    def test_ctrl_c_retablit_le_terminal(self):
        process, master, slave = self.spawn_on_pty(self.make_share("bob", {"a": "x"}))
        self.read_until(master, "Choix :")
        os.write(master, b"1\n")
        self.read_until(master, "utilisateur :")
        os.write(master, b"bob\n")
        self.read_until(master, "Mot de passe :")
        wait_until(lambda: not termios.tcgetattr(slave)[3] & termios.ECHO, 5)
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO)


class TestPublication(Base):
    def test_hote_noms_et_descriptions_envoyes(self):
        peer = self.start_peer("alice", {"MP3.txt": "contenu"}, EXEMPLE_SUJET)
        rows = self.search("compression")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["user"], "alice")
        self.assertEqual(row["path"], "MP3.txt")
        self.assertEqual(row["host"], socket.gethostname())
        self.assertEqual(row["port"], peer.transfer_port)
        self.assertEqual(row["size"], len("contenu"))
        self.assertIn("MPEG-2", row["desc"])

    def test_format_du_sujet_sans_ligne_vide(self):
        self.start_peer(
            "alice", {"a.txt": "1", "b.txt": "2"},
            "a.txt\npremier texte\nb.txt\nsecond texte\n",
        )
        self.assertEqual(self.paths("premier"), ["a.txt"])
        self.assertEqual(self.paths("second"), ["b.txt"])

    def test_fins_de_ligne_windows_et_bom(self):
        folder = self.make_share("alice", {"a.txt": "1", "b.txt": "2"})
        (folder / "descriptions.txt").write_bytes(
            b"\xef\xbb\xbfa.txt\r\npremier texte\r\n\r\nb.txt\r\nsecond texte\r\n"
        )
        self.start_peer("alice")
        rows = self.search("premier")
        self.assertEqual([r["path"] for r in rows], ["a.txt"])
        self.assertEqual(rows[0]["desc"], "premier texte")

    def test_fichier_sans_description_partage(self):
        self.start_peer("alice", {"a.txt": "1", "seul.txt": "2"}, "a.txt\ntexte\n")
        rows = self.search("seul")
        self.assertEqual([r["path"] for r in rows], ["seul.txt"])
        self.assertEqual(rows[0]["desc"], "")

    def test_sans_fichier_descriptions(self):
        peer = self.start_peer("alice", {"a.txt": "1"})
        self.assertIn("introuvable", peer.text())
        self.assertEqual(self.paths("a.txt"), ["a.txt"])

    def test_description_sans_fichier_ignoree(self):
        peer = self.start_peer("alice", {"a.txt": "1"}, "absent.txt\nfantome\n")
        self.assertEqual(self.search("fantome"), [])
        self.assertIn("absent du partage", peer.text())

    def test_sous_repertoires(self):
        self.start_peer(
            "alice", {"docs/cours/reseaux.txt": "tcp"},
            "docs/cours/reseaux.txt\ncours sur les sockets\n",
        )
        self.assertEqual(self.paths("sockets"), ["docs/cours/reseaux.txt"])

    def test_fichiers_speciaux_non_partages(self):
        self.start_peer("alice", {".cache": "x", "a.txt": "1", "sub/.cache2": "x"},
                        "a.txt\ntexte\n")
        self.assertEqual(self.search("cache"), [])
        self.assertEqual(self.search("descriptions"), [])
        self.assertEqual(self.search("serveur_ftp"), [])

    def test_lien_symbolique_ignore(self):
        secret = self.tmp / "secret.txt"
        secret.write_text("confidentiel")
        folder = self.make_share("alice", {"a.txt": "1"})
        os.symlink(secret, folder / "lien.txt")
        self.start_peer("alice")
        self.assertEqual(self.search("lien"), [])

    def test_description_tres_longue_tronquee_proprement(self):
        self.start_peer("alice", {"a.txt": "1"}, "a.txt\n" + "é" * 5000 + " fin\n")
        rows = self.search("a.txt")
        self.assertEqual(len(rows), 1)
        self.assertLess(len(rows[0]["desc"].encode()), 1024)
        rows[0]["desc"].encode().decode("utf-8")
        self.assertNotIn("�", rows[0]["desc"])

    def test_nom_de_fichier_avec_espace_et_accent(self):
        self.start_peer("alice", {"été à la plage.txt": "x"},
                        "été à la plage.txt\nsouvenirs\n")
        self.assertEqual(self.paths("souvenirs"), ["été à la plage.txt"])

    def test_fichier_descriptions_ignore_quelle_que_soit_la_casse(self):
        self.start_peer("alice", {"a.txt": "1", "DESCRIPTIONS.TXT": "a.txt\ntexte\n"})
        self.assertEqual(self.search("DESCRIPTIONS"), [])

    def test_nom_avec_espace_final_garde_sa_description(self):
        self.start_peer("alice", {"note ": "1"}, "note \nbelle description\n")
        self.assertEqual(self.paths("belle"), ["note "])

    def test_espaces_en_trop_dans_le_fichier_de_description(self):
        self.start_peer("alice", {"a.txt": "1"}, "  a.txt   \ntexte decale\n")
        self.assertEqual(self.paths("decale"), ["a.txt"])

    def test_nom_annonce_personnalise(self):
        self.start_peer("alice", {"a.txt": "1"}, "a.txt\ntexte\n",
                        options=["-H", "machine.exemple"])
        self.assertEqual(self.search("texte")[0]["host"], "machine.exemple")


class TestRecherche(Base):
    def setUp(self):
        super().setUp()
        self.start_peer("alice", {"MP3.txt": "contenu"}, EXEMPLE_SUJET)

    def test_mot_entier(self):
        self.assertEqual(self.paths("compression"), ["MP3.txt"])

    def test_sous_chaine(self):
        self.assertEqual(self.paths("compress"), ["MP3.txt"])
        self.assertEqual(self.paths("gorith"), ["MP3.txt"])

    def test_majuscules_ignorees(self):
        self.assertEqual(self.paths("COMPRESSION"), ["MP3.txt"])

    def test_accents_ignores(self):
        self.assertEqual(self.paths("utilise"), ["MP3.txt"])
        self.assertEqual(self.paths("utilisé"), ["MP3.txt"])
        self.assertEqual(self.paths("UTILISÉ"), ["MP3.txt"])

    def test_recherche_sur_le_nom_du_fichier(self):
        self.assertEqual(self.paths("mp3"), ["MP3.txt"])

    def test_plusieurs_mots_tous_requis(self):
        self.assertEqual(self.paths("audio mpeg"), ["MP3.txt"])
        self.assertEqual(self.paths("audio absent"), [])

    def test_aucun_resultat(self):
        self.assertEqual(self.paths("inexistant"), [])

    def test_mot_cle_vide_refuse(self):
        c = self.raw()
        c.send("SEARCH\tpertinence\tdesc\t   \n")
        self.assertTrue(c.recv().startswith("ERR"))

    def test_mot_entier_mieux_classe(self):
        self.start_peer("bob", {"p1.txt": "x", "p2.txt": "x"},
                        "p1.txt\nle partage de fichiers\np2.txt\nun art ancien\n")
        self.assertEqual(self.paths("art"), ["p2.txt", "p1.txt"])

    def test_apostrophe_typographique_separe_les_mots(self):
        self.assertEqual(self.search("algorithme")[0]["score"], 2)

    def test_trop_de_mots_cles_refuse(self):
        c = self.raw()
        c.send("SEARCH\tpertinence\tdesc\t" + " ".join(["audio"] * 17) + "\n")
        self.assertIn("trop de mots-clés", c.recv())

    def test_seize_mots_cles_acceptes(self):
        self.assertEqual(self.paths(" ".join(["audio"] * 16)), ["MP3.txt"])

    def test_critere_de_tri_inconnu(self):
        c = self.raw()
        c.send("SEARCH\tcouleur\tdesc\tx\n")
        self.assertTrue(c.recv().startswith("ERR"))


class TestTri(Base):
    def setUp(self):
        super().setUp()
        folder = self.make_share(
            "alice", {"c.txt": "a" * 300, "a.txt": "a" * 100, "B.txt": "a" * 200},
            "c.txt\ndonnees mot\na.txt\ndonnees mot mot mot\nB.txt\ndonnees mot mot\n",
        )
        os.utime(folder / "c.txt", (1_600_000_000, 1_600_000_000))
        os.utime(folder / "a.txt", (1_700_000_000, 1_700_000_000))
        os.utime(folder / "B.txt", (1_500_000_000, 1_500_000_000))
        self.start_peer("alice", options=["-H", "zzz.exemple"])

    def test_serveur_tri_par_nom(self):
        self.assertEqual(self.paths("donnees", sort="nom", order="asc"),
                         ["a.txt", "B.txt", "c.txt"])
        self.assertEqual(self.paths("donnees", sort="nom", order="desc"),
                         ["c.txt", "B.txt", "a.txt"])

    def test_serveur_tri_par_taille(self):
        self.assertEqual(self.paths("donnees", sort="taille", order="asc"),
                         ["a.txt", "B.txt", "c.txt"])
        self.assertEqual(self.paths("donnees", sort="taille", order="desc"),
                         ["c.txt", "B.txt", "a.txt"])

    def test_serveur_tri_par_date(self):
        self.assertEqual(self.paths("donnees", sort="date", order="asc"),
                         ["B.txt", "c.txt", "a.txt"])

    def test_serveur_tri_par_pertinence(self):
        self.assertEqual(self.paths("mot", sort="pertinence", order="desc"),
                         ["a.txt", "B.txt", "c.txt"])

    def test_serveur_tri_par_hote(self):
        self.start_peer("bob", {"z.txt": "x"}, "z.txt\ndonnees\n",
                        options=["-H", "aaa.exemple"])
        rows = self.search("donnees", sort="hote", order="asc")
        self.assertEqual(rows[0]["host"], "aaa.exemple")
        self.assertEqual(rows[-1]["host"], "zzz.exemple")

    def order_in(self, output):
        return re.findall(r"^\s+\d+\. (\S+)$", output, re.M)

    def test_client_retrie_les_resultats(self):
        out = self.run_client("bob", "chercher donnees\ntrier taille desc\nquitter\n")
        blocks = out.split("tri : ")
        self.assertEqual(self.order_in(blocks[2]), ["c.txt", "B.txt", "a.txt"])

    def test_client_chaque_critere(self):
        expected = {
            "trier nom asc": ["a.txt", "B.txt", "c.txt"],
            "trier taille asc": ["a.txt", "B.txt", "c.txt"],
            "trier date desc": ["a.txt", "c.txt", "B.txt"],
            "trier pertinence": ["a.txt", "B.txt", "c.txt"],
        }
        for command, order in expected.items():
            out = self.run_client("bob", f"chercher donnees mot\n{command}\nquitter\n")
            self.assertEqual(self.order_in(out.split("tri : ")[2]), order, command)

    def test_tri_choisi_envoye_au_serveur(self):
        out = self.run_client(
            "bob", "chercher donnees\ntrier taille asc\nchercher donnees\nquitter\n"
        )
        self.assertIn("tri : taille (croissant)", out.split("tri : pertinence")[1])
        self.assertEqual(self.order_in(out.split("tri : ")[3]), ["a.txt", "B.txt", "c.txt"])

    def test_commande_trier_invalide(self):
        out = self.run_client("bob", "trier couleur\nquitter\n")
        self.assertIn("Usage : trier", out)


class TestTelechargement(Base):
    def download(self, source_files, wanted, desc=""):
        self.start_peer("alice", source_files, desc)
        self.start_peer("bob")
        out = self.run_client("bob", f"chercher {wanted}\ntelecharger 1\nquitter\n")
        self.assertIn("Téléchargé", out)
        return out

    def test_fichier_texte(self):
        self.download({"note.txt": "bonjour"}, "note")
        self.assertEqual((self.tmp / "bob/note.txt").read_text(), "bonjour")

    def test_fichier_binaire(self):
        data = os.urandom(5 * 1024 * 1024)
        self.download({"image.bin": data}, "image")
        self.assertEqual((self.tmp / "bob/image.bin").read_bytes(), data)

    def test_fichier_vide(self):
        self.download({"vide.txt": b""}, "vide")
        self.assertEqual((self.tmp / "bob/vide.txt").stat().st_size, 0)

    def test_gros_fichier(self):
        source = self.make_share("alice")
        with open(source / "gros.bin", "wb") as f:
            for _ in range(128):
                f.write(os.urandom(1 << 20))
        self.download({}, "gros")
        self.assertEqual(sha256_of(source / "gros.bin"), sha256_of(self.tmp / "bob/gros.bin"))

    def test_nom_avec_espaces_et_accents(self):
        self.download({"été à la plage.txt": "soleil"}, "plage")
        self.assertEqual((self.tmp / "bob/été à la plage.txt").read_text(), "soleil")

    def test_fichier_de_sous_repertoire_arrive_a_la_racine(self):
        self.download({"a/b/profond.txt": "x"}, "profond")
        self.assertTrue((self.tmp / "bob/profond.txt").exists())

    def test_aucun_fichier_temporaire_restant(self):
        self.download({"note.txt": "bonjour"}, "note")
        leftovers = [p.name for p in (self.tmp / "bob").iterdir() if p.name.endswith(".part")]
        self.assertEqual(leftovers, [])

    def test_mot_cle_demande_si_absent(self):
        self.start_peer("alice", {"note.txt": "x"}, "note.txt\ndu texte\n")
        out = self.run_client("bob", "chercher\ndu texte\nquitter\n")
        self.assertIn("Mot-clé :", out)
        self.assertIn("note.txt", out)

    def test_commandes_courtes(self):
        self.start_peer("alice", {"note.txt": "x"}, "note.txt\ndu texte\n")
        out = self.run_client("bob", "c texte\nl\nt nom\nd 1\nh\nq\n")
        self.assertIn("Téléchargé", out)

    def test_numero_invalide(self):
        self.start_peer("alice", {"note.txt": "x"}, "note.txt\ndu texte\n")
        out = self.run_client(
            "bob", "chercher texte\ntelecharger 9\ntelecharger abc\ntelecharger 0\nquitter\n"
        )
        self.assertEqual(out.count("Numéro invalide"), 3)

    def test_sans_recherche_prealable(self):
        out = self.run_client("bob", "telecharger 1\nquitter\n")
        self.assertIn("lancez d'abord une recherche", out)

    def test_commande_inconnue(self):
        out = self.run_client("bob", "envoyer fichier\nquitter\n")
        self.assertIn("Commande inconnue", out)

    def test_fichier_existant_jamais_ecrase(self):
        self.start_peer("alice", {"note.txt": "distant"}, "note.txt\ndu texte\n")
        self.make_share("bob", {"note.txt": "local"})
        out = self.run_client("bob", "chercher texte\ntelecharger 1\n\nquitter\n")
        self.assertIn("Téléchargement annulé", out)
        self.assertEqual((self.tmp / "bob/note.txt").read_text(), "local")

    def test_nouveau_nom_si_le_fichier_existe(self):
        self.start_peer("alice", {"note.txt": "distant"}, "note.txt\ndu texte\n")
        self.make_share("bob", {"note.txt": "local"})
        out = self.run_client("bob", "chercher texte\ntelecharger 1\ncopie.txt\nquitter\n")
        self.assertIn("Téléchargé : copie.txt", out)
        self.assertEqual((self.tmp / "bob/note.txt").read_text(), "local")
        self.assertEqual((self.tmp / "bob/copie.txt").read_text(), "distant")
        self.assertIn("copie.txt\ndu texte\n", (self.tmp / "bob/descriptions.txt").read_text())

    def test_nouveau_nom_dangereux_refuse(self):
        self.start_peer("alice", {"note.txt": "distant"}, "note.txt\ndu texte\n")
        self.make_share("bob", {"note.txt": "local"})
        out = self.run_client(
            "bob",
            "chercher texte\ntelecharger 1\n../evil.txt\n.cache\ndescriptions.txt\n\nquitter\n",
        )
        self.assertEqual(out.count("Nom invalide"), 3)
        self.assertFalse((self.tmp / "evil.txt").exists())

    def part_files(self, name):
        return [p.name for p in (self.tmp / name).iterdir() if p.name.endswith(".part")]

    def paused_peer(self, start, rest):
        """Pair factice : envoie start, attend le feu vert, puis envoie rest."""
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, 0))
        server.listen(4)
        self.addCleanup(server.close)
        release = threading.Event()

        def run():
            try:
                connection, _ = server.accept()
                connection.recv(4096)
                connection.sendall(start)
                release.wait(30)
                connection.sendall(rest)
                connection.close()
            except OSError:
                pass

        threading.Thread(target=run, daemon=True).start()
        return server.getsockname()[1], release

    def test_fichier_cree_pendant_le_transfert_jamais_ecrase(self):
        port, release = self.paused_peer(b"OK\t4\nAB", b"CD")
        robot = self.raw_login()
        self.raw_publish(robot, port, [("note.txt", 4, 1, "texte lent")])
        folder = self.make_share("bob")
        client = self.spawn([CLIENT, HOST, self.central_port, folder],
                            "chercher lent\ntelecharger 1\nnouveau.txt\nquitter\n")
        self.assertTrue(wait_until(lambda: self.part_files("bob"), 10))
        (folder / "note.txt").write_text("local")
        release.set()
        self.assertEqual(client.wait_exit(), 0)
        self.assertIn("existe déjà", client.text())
        self.assertEqual((folder / "note.txt").read_text(), "local")
        self.assertEqual((folder / "nouveau.txt").read_text(), "ABCD")
        descriptions = (folder / "descriptions.txt").read_text()
        self.assertIn("nouveau.txt\ntexte lent\n", descriptions)
        self.assertNotIn("note.txt", descriptions)

    def test_ctrl_c_pendant_le_telechargement_ne_laisse_rien(self):
        port, release = self.paused_peer(b"OK\t1000\nAB", b"")
        robot = self.raw_login()
        self.raw_publish(robot, port, [("note.txt", 1000, 1, "texte lent")])
        folder = self.make_share("bob")
        client = self.spawn([CLIENT, HOST, self.central_port, folder],
                            "chercher lent\ntelecharger 1\nquitter\n")
        self.assertTrue(wait_until(lambda: self.part_files("bob"), 10))
        client.signal(signal.SIGINT)
        client.wait_exit()
        release.set()
        self.assertEqual(self.part_files("bob"), [])

    def test_nom_trop_long_refuse_avant_le_transfert(self):
        port = self.fake_peer(b"OK\t1\nx")
        robot = self.raw_login()
        self.raw_publish(robot, port, [("a" * 300 + ".txt", 1, 1, "nom immense")])
        out = self.run_client("bob", "chercher immense\ntelecharger 1\nquitter\n")
        self.assertIn("inutilisable", out)
        self.assertNotIn("Téléchargé", out)
        self.assertEqual(list((self.tmp / "bob").iterdir()), [])

    def test_message_du_pair_sans_code_de_controle(self):
        port = self.fake_peer(b"ERR\t\x1b[2Jpiege\xc2\x9b31m\n")
        robot = self.raw_login()
        self.raw_publish(robot, port, [("x.bin", 10, 1, "fichier hostile")])
        out = self.run_client("bob", "chercher hostile\ntelecharger 1\nquitter\n")
        self.assertIn("Le pair refuse", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\u009b", out)

    def test_adresse_vue_par_le_central_essayee_d_abord(self):
        lan_ip = local_network_ip()
        if lan_ip is None:
            self.skipTest("pas d'adresse réseau")
        with socket.socket() as s:
            s.bind((HOST, 0))
            port = s.getsockname()[1]
        self.fake_peer(b"OK\t4\nVRAI", host=HOST, port=port)
        self.fake_peer(b"ERR\tmauvais pair\n", host=lan_ip, port=port)
        robot = self.raw_login()
        self.raw_publish(robot, port, [("vrai.bin", 4, 1, "le bon pair")], host=lan_ip)
        out = self.run_client("bob", "chercher pair\ntelecharger 1\nquitter\n")
        self.assertIn("Téléchargé", out)
        self.assertEqual((self.tmp / "bob/vrai.bin").read_text(), "VRAI")

    def fake_peer(self, reply, host=HOST, port=0):
        """Pair factice : renvoie exactement reply à toute demande."""
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(4)
        self.addCleanup(server.close)

        def run():
            try:
                while True:
                    c, _ = server.accept()
                    c.recv(4096)
                    c.sendall(reply)
                    c.close()
            except OSError:
                pass

        threading.Thread(target=run, daemon=True).start()
        return server.getsockname()[1]

    def test_transfert_incomplet_rejete(self):
        port = self.fake_peer(b"OK\t1000\n0123456789")
        robot = self.raw_login()
        self.raw_publish(robot, port, [("coupe.bin", 1000, 1, "fichier coupe")])
        out = self.run_client("bob", "chercher coupe\ntelecharger 1\nquitter\n")
        self.assertIn("Transfert interrompu", out)
        names = [p.name for p in (self.tmp / "bob").iterdir()]
        self.assertEqual(names, [])

    def test_reponse_invalide_du_pair(self):
        port = self.fake_peer(b"BONJOUR\n")
        robot = self.raw_login()
        self.raw_publish(robot, port, [("x.bin", 10, 1, "fichier bizarre")])
        out = self.run_client("bob", "chercher bizarre\ntelecharger 1\nquitter\n")
        self.assertIn("Réponse invalide du pair", out)

    def test_nom_distant_dangereux_refuse(self):
        port = self.fake_peer(b"OK\t1\nx")
        robot = self.raw_login()
        for name in ("descriptions.txt", "DESCRIPTIONS.TXT"):
            self.raw_publish(robot, port, [(name, 1, 1, "piege")])
            out = self.run_client("bob", "chercher piege\ntelecharger 1\nquitter\n")
            self.assertIn("refusé", out)
            self.assertEqual(list((self.tmp / "bob").iterdir()), [])

    def test_nom_hote_introuvable_repli_sur_ip(self):
        self.start_peer("alice", {"note.txt": "x"}, "note.txt\ndu texte\n",
                        options=["-H", "hote-inconnu.invalid"])
        out = self.run_client("bob", "chercher texte\ntelecharger 1\nquitter\n")
        self.assertIn("Téléchargé", out)

    def test_pair_parti_entre_recherche_et_telechargement(self):
        robot = self.raw_login()
        self.raw_publish(robot, 1, [("x.bin", 10, 1, "ancien fichier")])   # port 1 : personne
        out = self.run_client("bob", "chercher ancien\ntelecharger 1\nquitter\n")
        self.assertIn("Pair injoignable", out)

    def test_pas_de_commande_upload(self):
        peer = self.start_peer("alice", {"a.txt": "x"})
        for command in ("PUT\tmalware.txt\n", "STOR\tmalware.txt\n", "UPLOAD\tx\n"):
            c = self.raw(peer.transfer_port)
            c.send(command)
            self.assertTrue(c.recv().startswith("ERR"))
        self.assertFalse((self.tmp / "alice/malware.txt").exists())


class TestMiseAJourApresTelechargement(Base):
    def test_le_fichier_telecharge_est_republie(self):
        self.start_peer("alice", {"note.txt": "contenu"}, "note.txt\ndu texte rare\n")
        bob = self.start_peer("bob")
        self.assertEqual([r["user"] for r in self.search("rare")], ["alice"])

        out = self.run_client("bob", "chercher rare\ntelecharger 1\nquitter\n")
        self.assertIn("Fichier ajouté au partage", out)

        self.assertTrue(wait_until(lambda: len(self.search("rare")) == 2, 5))
        self.assertEqual(sorted(r["user"] for r in self.search("rare")), ["alice", "bob"])
        self.assertIn("note.txt\ndu texte rare\n", (self.tmp / "bob/descriptions.txt").read_text())
        self.assertGreaterEqual(bob.count("Liste envoyée"), 2)

    def test_mise_a_jour_immediate(self):
        """Le client prévient le serveur local : pas d'attente du signal de vie."""
        self.start_peer("alice", {"note.txt": "contenu"}, "note.txt\ndu texte rare\n")
        self.start_peer("bob")
        self.run_client("bob", "chercher rare\ntelecharger 1\nquitter\n")
        self.assertTrue(wait_until(lambda: len(self.search("rare")) == 2, 1.5))

    def test_un_troisieme_pair_telecharge_chez_le_second(self):
        self.start_peer("alice", {"note.txt": "contenu"}, "note.txt\ndu texte rare\n")
        self.start_peer("bob")
        self.run_client("bob", "chercher rare\ntelecharger 1\nquitter\n")
        self.assertTrue(wait_until(lambda: len(self.search("rare")) == 2, 5))

        rows = self.search("rare", sort="nom", order="asc")
        index = [r["user"] for r in rows].index("bob") + 1
        out = self.run_client(
            "carol", f"trier nom asc\nchercher rare\ntelecharger {index}\nquitter\n"
        )
        self.assertIn("depuis bob", out)
        self.assertEqual((self.tmp / "carol/note.txt").read_text(), "contenu")

    def test_description_ajoutee_a_un_fichier_sans_fin_de_ligne(self):
        self.start_peer("alice", {"note.txt": "x"}, "note.txt\ndu texte rare\n")
        self.make_share("bob", {"mien.txt": "y"})
        (self.tmp / "bob/descriptions.txt").write_bytes(b"mien.txt\nma description")
        self.start_peer("bob")
        self.run_client("bob", "chercher rare\ntelecharger 1\nquitter\n")
        self.assertTrue(wait_until(lambda: len(self.search("rare")) == 2, 5))
        self.assertEqual(self.search("ma description")[0]["path"], "mien.txt")

    def test_description_ajoutee_apres_un_nom_seul(self):
        self.start_peer("alice", {"note.txt": "x"}, "note.txt\ndu texte rare\n")
        self.make_share("bob", {"mien.txt": "y"})
        (self.tmp / "bob/descriptions.txt").write_bytes(b"mien.txt\n")
        self.start_peer("bob")
        self.run_client("bob", "chercher rare\ntelecharger 1\nquitter\n")
        self.assertTrue(wait_until(lambda: len(self.search("rare")) == 2, 5))
        rows = [r for r in self.search("note.txt") if r["user"] == "bob"]
        self.assertEqual(rows[0]["desc"], "du texte rare")

    def test_sans_serveur_local_publie_au_prochain_lancement(self):
        self.start_peer("alice", {"note.txt": "x"}, "note.txt\ndu texte rare\n")
        out = self.run_client("bob", "chercher rare\ntelecharger 1\nquitter\n")
        self.assertIn("Serveur local non démarré", out)
        self.assertEqual(len(self.search("rare")), 1)
        self.start_peer("bob")
        self.assertEqual(len(self.search("rare")), 2)


class TestDepartDesPairs(Base):
    peer_timeout = 3

    def setUp(self):
        super().setUp()
        self.peer = self.start_peer("alice", {"note.txt": "x"}, "note.txt\ndu texte rare\n")
        self.assertEqual(len(self.search("rare")), 1)

    def gone(self, timeout=10):
        return wait_until(lambda: self.search("rare") == [], timeout)

    def test_depart_annonce(self):
        self.peer.signal(signal.SIGINT)
        self.assertEqual(self.peer.wait_exit(), 0)
        self.assertEqual(self.search("rare"), [])
        self.central.wait_for("départ annoncé")
        self.assertFalse((self.tmp / "alice/.serveur_ftp.port").exists())

    def test_sigterm_annonce_aussi_le_depart(self):
        self.peer.signal(signal.SIGTERM)
        self.assertEqual(self.peer.wait_exit(), 0)
        self.central.wait_for("départ annoncé")

    def test_processus_tue(self):
        self.peer.signal(signal.SIGKILL)
        self.assertTrue(self.gone(5))
        self.central.wait_for("connexion fermée")

    def test_silence_detecte_par_le_signal_de_vie(self):
        start = time.time()
        self.peer.signal(signal.SIGSTOP)
        self.assertTrue(self.gone(10))
        self.assertGreaterEqual(time.time() - start, 1.5)
        self.central.wait_for("plus de signal de vie")

    def test_signal_de_vie_garde_le_pair_en_ligne(self):
        time.sleep(self.peer_timeout * 2.5)
        self.assertEqual(len(self.search("rare")), 1)
        self.assertEqual(self.central.count("retiré"), 0)

    def test_retour_apres_silence(self):
        self.peer.signal(signal.SIGSTOP)
        self.assertTrue(self.gone(10))
        self.peer.signal(signal.SIGCONT)
        self.peer.wait_for("Reconnecté", 20)
        self.assertTrue(wait_until(lambda: len(self.search("rare")) == 1, 10))

    def test_serveur_central_redemarre(self):
        port = self.central_port
        self.central.kill()
        self.start_central(port)
        self.peer.wait_for("Reconnecté", 20)
        self.assertTrue(wait_until(lambda: len(self.search("rare")) == 1, 10))

    def test_manque_de_descripteurs_garde_la_liste(self):
        """Une panne passagère ne doit pas vider la liste publiée."""
        folder = self.make_share("bob", {"rare2.txt": "x"}, "rare2.txt\ndu texte precieux\n")
        peer = self.spawn(
            ["/bin/sh", "-c", f'ulimit -n 40; exec "{FTP}" {HOST} {self.central_port} "{folder}"'],
            "2\nbob\nmdp\nmdp\n",
        )
        peer.wait_for("Liste envoyée")
        port = int(re.search(r"port (\d+),", peer.text()).group(1))
        held = [socket.create_connection((HOST, port), timeout=5) for _ in range(80)]
        self.addCleanup(lambda: [s.close() for s in held])
        time.sleep(self.peer_timeout)    # plusieurs relectures du répertoire
        self.assertEqual(self.paths("precieux"), ["rare2.txt"])
        self.assertEqual(peer.count("Liste envoyée"), 1)

    def test_ajout_manuel_detecte(self):
        folder = self.tmp / "alice"
        (folder / "nouveau.txt").write_text("y")
        with open(folder / "descriptions.txt", "a", encoding="utf-8") as f:
            f.write("\nnouveau.txt\narrive plus tard\n")
        self.assertTrue(wait_until(lambda: self.paths("arrive") == ["nouveau.txt"], 6))

    def test_suppression_manuelle_detectee(self):
        (self.tmp / "alice/note.txt").unlink()
        self.assertTrue(self.gone(6))


class TestConcurrence(Base):
    def test_authentifications_simultanees(self):
        count = 24
        peers = []
        for i in range(count):
            peers.append(self.start_peer(
                f"user{i}", {f"f{i}.txt": "x"}, f"f{i}.txt\ncommun\n", wait=False))
        for p in peers:
            p.wait_for("Liste envoyée au serveur central", 40)
        self.assertEqual(len(self.search("commun")), count)

    def test_connexion_lente_ne_bloque_pas_les_autres(self):
        idle = self.raw()
        idle.send(f"LOGIN\t{FAKE_USER}\n")
        self.start_peer("alice", {"a.txt": "x"}, "a.txt\nmot\n")
        self.assertEqual(self.paths("mot"), ["a.txt"])

    def test_recherches_simultanees(self):
        self.start_peer("alice", {f"f{i}.txt": "x" for i in range(50)},
                        "".join(f"f{i}.txt\ncommun\n" for i in range(50)))
        errors = []

        def worker():
            try:
                for _ in range(20):
                    self.assertEqual(len(self.search("commun")), 50)
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_recherches_pendant_les_publications(self):
        robot = self.raw_login()
        stop = threading.Event()
        errors = []

        def searcher():
            try:
                while not stop.is_set():
                    self.assertIn(len(self.search("commun")), (0, 3, 5))
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        threads = [threading.Thread(target=searcher) for _ in range(8)]
        for t in threads:
            t.start()
        for i in range(150):
            n = 3 if i % 2 else 5
            self.raw_publish(robot, 2000, [(f"f{j}.txt", 1, 1, "commun") for j in range(n)])
        stop.set()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_telechargements_simultanes(self):
        data = os.urandom(20 * 1024 * 1024)
        self.start_peer("alice", {"film.bin": data}, "film.bin\nun long film\n")
        expected = hashlib.sha256(data).hexdigest()
        results = {}

        def worker(name):
            out = self.run_client(name, "chercher film\ntelecharger 1\nquitter\n", timeout=120)
            results[name] = (out, sha256_of(self.tmp / name / "film.bin"))

        names = [f"c{i}" for i in range(8)]
        threads = [threading.Thread(target=worker, args=(n,)) for n in names]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), sorted(names))
        for out, digest in results.values():
            self.assertIn("Téléchargé", out)
            self.assertEqual(digest, expected)


class TestRobustesse(Base):
    def test_commande_inconnue(self):
        c = self.raw()
        c.send("BONJOUR\n")
        self.assertTrue(c.recv().startswith("ERR"))
        self.assert_central_alive()

    def test_donnees_aleatoires(self):
        for _ in range(30):
            c = Raw(self.central_port)
            try:
                c.send(os.urandom(4096))
            except OSError:
                pass
            c.close()
        self.assert_central_alive()

    def test_ligne_trop_longue(self):
        c = self.raw()
        try:
            c.send("X" * 200000)
            self.assertEqual(c.recv(), "")   # connexion fermée par le central
        except ConnectionError:
            pass                             # fermeture brutale : aussi valable
        self.assert_central_alive()

    def test_octet_nul(self):
        c = self.raw()
        c.send(b"SEARCH\x00\tnom\n")
        self.assertEqual(c.recv(), "")
        self.assert_central_alive()

    def test_commandes_sans_authentification(self):
        c = self.raw()
        c.send("PUBLISH\thote\t1234\t0\n")
        self.assertTrue(c.recv().startswith("ERR"))
        for command in ("HEARTBEAT\n", "LOGOUT\n"):
            c = self.raw()
            c.send(command)
            self.assertTrue(c.recv().startswith("ERR"))
        c = self.raw()
        c.send("AUTH\tabc\n")
        self.assertTrue(c.recv().startswith("ERR"))
        self.assert_central_alive()

    def test_annonces_invalides(self):
        lines = [
            "PUBLISH\thote\t0\t0\n",
            "PUBLISH\thote\t70000\t0\n",
            "PUBLISH\thote\t1234\t-1\n",
            "PUBLISH\thote\t1234\t999999\n",
            "PUBLISH\t\t1234\t0\n",
            "PUBLISH\thote\tabc\t0\n",
        ]
        for line in lines:
            c = self.raw_login()
            c.send(line)
            self.assertTrue(c.recv().startswith("ERR"), line)
            self.assertTrue(wait_until(lambda: self.central.count("retiré") >= 1, 5))
            c.close()
            self.sockets.remove(c)
            self.wait_session_gone()
        self.assert_central_alive()

    def wait_session_gone(self):
        def free():
            c = Raw(self.central_port)
            try:
                c.send(f"LOGIN\t{FAKE_USER}\n")
                _, _, nonce = c.recv().split("\t")
                c.send(f"AUTH\t{make_proof(FAKE_KEY, FAKE_VERIFIER, nonce)}\n")
                ok = c.recv().startswith("OK")
                if ok:
                    c.send("LOGOUT\n")
                    c.recv()
                return ok
            finally:
                c.close()

        self.assertTrue(wait_until(free, 5))

    def test_lignes_de_fichier_invalides(self):
        bad = [
            "FILE\t../secret\t1\t1\tx\n",
            "FILE\t/etc/passwd\t1\t1\tx\n",
            "FILE\ta/../b\t1\t1\tx\n",
            "FILE\t.cache\t1\t1\tx\n",
            "FILE\ta\t-5\t1\tx\n",
            "FILE\ta\tabc\t1\tx\n",
            "FILE\ta\t1\t1\n",
            "AUTRE\ta\t1\t1\tx\n",
            "FILE\t\t1\t1\tx\n",
            "FILE\ta\t1\t1\t" + "d" * 2000 + "\n",
        ]
        for line in bad:
            c = self.raw_login()
            c.send(f"PUBLISH\thote\t1234\t2\nFILE\tbon.txt\t1\t1\tmarqueur\n")
            c.send(line)
            self.assertTrue(c.recv().startswith("ERR"), line)
            c.close()
            self.sockets.remove(c)
            self.wait_session_gone()
            self.assertEqual(self.search("marqueur"), [], line)
        self.assert_central_alive()

    def test_annonce_interrompue(self):
        c = self.raw_login()
        c.send("PUBLISH\thote\t1234\t5\nFILE\ta.txt\t1\t1\tmarqueur\n")
        c.close()
        self.sockets.remove(c)
        self.wait_session_gone()
        self.assertEqual(self.search("marqueur"), [])
        self.assert_central_alive()

    def test_liste_republiee_remplace_l_ancienne(self):
        c = self.raw_login()
        self.raw_publish(c, 1234, [("ancien.txt", 1, 1, "motun")])
        self.raw_publish(c, 1234, [("nouveau.txt", 1, 1, "motdeux")])
        self.assertEqual(self.search("motun"), [])
        self.assertEqual(self.paths("motdeux"), ["nouveau.txt"])

    def test_codes_de_controle_neutralises(self):
        c = self.raw_login()
        self.raw_publish(c, 1234, [("a.txt", 1, 1, "mot\x1b[31mrouge\x07")])
        rows = self.search("rouge")
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\x1b", rows[0]["desc"])
        self.assertNotIn("\x07", rows[0]["desc"])

    def test_caracteres_de_controle_c1_neutralises(self):
        c = self.raw_login()
        self.raw_publish(c, 1234, [("a.txt", 1, 1, "mot\u009b31mrouge")])
        rows = self.search("rouge")
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\u009b", rows[0]["desc"])

    def test_limite_du_nombre_de_resultats(self):
        c = self.raw_login()
        files = [(f"f{i}.txt", 1, 1, "commun") for i in range(1500)]
        self.raw_publish(c, 1234, files)
        self.assertEqual(len(self.search("commun")), 1000)
        out = self.run_client("bob", "chercher commun\nquitter\n")
        self.assertIn("1000 résultats affichés sur 1500", out)

    def test_memoire_stable(self):
        if b"__asan_init" in Path(CENTRAL).read_bytes():
            self.skipTest("ASan garde exprès la mémoire libérée : mesure impossible")
        c = self.raw_login()
        files = [(f"fichier_{i}.txt", 1, 1, "un texte commun " * 8) for i in range(200)]

        def cycle(n):
            for _ in range(n):
                self.raw_publish(c, 1234, files)
                self.search("commun")
                s = Raw(self.central_port)
                s.send(f"REGISTER\tx:y\t{FAKE_SALT}\t{FAKE_VERIFIER}\n")
                s.recv()
                s.close()

        cycle(150)
        before = rss_kb(self.central.popen.pid)
        cycle(1200)
        growth = rss_kb(self.central.popen.pid) - before
        self.assertLess(growth, 12000, f"La mémoire a grandi de {growth} Ko")


class TestSecuriteTransfert(Base):
    def setUp(self):
        super().setUp()
        (self.tmp / "secret.txt").write_text("confidentiel")
        self.peer = self.start_peer(
            "alice", {"a.txt": "partage", ".cache": "cache", "sub/b.txt": "b"},
            "a.txt\ntexte\n",
        )

    def get(self, path):
        c = self.raw(self.peer.transfer_port)
        c.send(f"GET\t{path}\n")
        return c.recv()

    def test_demande_valide(self):
        self.assertEqual(self.get("a.txt"), "OK\t7")
        self.assertEqual(self.get("sub/b.txt"), "OK\t1")

    def test_chemins_interdits(self):
        for path in (
            "../secret.txt", "/etc/passwd", "../../../../etc/passwd",
            "sub/../../secret.txt", "./a.txt", "sub//b.txt", "descriptions.txt",
            ".cache", ".serveur_ftp.port", "..", ".", "", "sub", "absent.txt",
        ):
            self.assertTrue(self.get(path).startswith("ERR"), path)

    def test_contenu_exact(self):
        c = self.raw(self.peer.transfer_port)
        c.send("GET\ta.txt\n")
        self.assertEqual(c.recv(), "OK\t7")
        self.assertEqual(c.recv_bytes(), b"partage")

    def test_fichier_supprime_apres_annonce(self):
        (self.tmp / "alice/a.txt").unlink()
        self.assertTrue(self.get("a.txt").startswith("ERR"))

    def test_rescan_refuse_hors_machine_locale(self):
        ip = local_network_ip()
        if ip is None:
            self.skipTest("pas d'adresse réseau")
        with socket.create_connection((ip, self.peer.transfer_port), timeout=5) as s:
            s.sendall(b"RESCAN\n")
            self.assertTrue(s.makefile().readline().startswith("ERR"))

    def test_rescan_local_accepte(self):
        c = self.raw(self.peer.transfer_port)
        c.send("RESCAN\n")
        self.assertEqual(c.recv(), "OK")

    def test_donnees_aleatoires(self):
        for _ in range(30):
            c = Raw(self.peer.transfer_port)
            try:
                c.send(os.urandom(9000))
            except OSError:
                pass
            c.close()
        self.assertEqual(self.get("a.txt"), "OK\t7")
        self.assertTrue(self.peer.alive())

    def test_client_coupe_pendant_le_transfert(self):
        (self.tmp / "alice/gros.bin").write_bytes(os.urandom(30 * 1024 * 1024))
        c = self.raw(self.peer.transfer_port)
        c.send("RESCAN\n")
        c.recv()
        self.assertTrue(wait_until(lambda: self.get("gros.bin").startswith("OK"), 5))
        for _ in range(5):
            s = socket.create_connection((HOST, self.peer.transfer_port))
            s.sendall(b"GET\tgros.bin\n")
            s.recv(1000)
            s.close()
        self.assertEqual(self.get("a.txt"), "OK\t7")
        self.assertTrue(self.peer.alive())


class TestSortieBloquee(Base):
    """Un terminal en pause ou un tube non lu ne doit rien figer."""

    def flood_central(self, port):
        """Produit bien plus de journal que la capacité d'un tube."""
        query = "x" * 900
        for _ in range(700):
            c = Raw(port)
            c.send(f"SEARCH\tpertinence\tdesc\t{query}\n")
            self.assertTrue(c.recv().startswith("RESULTS"))
            c.close()

    def check_central(self, port):
        """La connexion écrit au journal avant de répondre : le test le prouve."""
        c = Raw(port, timeout=5)
        c.send(f"LOGIN\t{FAKE_USER}\n")
        _, _, nonce = c.recv().split("\t")
        c.send(f"AUTH\t{make_proof(FAKE_KEY, FAKE_VERIFIER, nonce)}\n")
        self.assertTrue(c.recv().startswith("OK"))
        c.close()

    def test_central_avec_tube_non_lu(self):
        p = subprocess.Popen(
            [CENTRAL, "-f", str(self.users_file), "0"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        port = int(re.search(rb"port (\d+)", p.stdout.readline()).group(1))
        self.flood_central(port)
        self.check_central(port)

    def test_central_avec_terminal_en_pause(self):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        p = subprocess.Popen(
            [CENTRAL, "-f", str(self.users_file), "0"],
            stdin=subprocess.DEVNULL, stdout=slave, stderr=slave, start_new_session=True,
        )
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        banner = b""
        while b"compte" not in banner:
            banner += os.read(master, 4096)
        port = int(re.search(rb"port (\d+)", banner).group(1))
        termios.tcflow(slave, termios.TCOOFF)    # équivaut à Ctrl-S
        self.flood_central(port)
        self.check_central(port)

    def test_serveur_ftp_avec_tube_non_lu(self):
        folder = self.make_share("alice", {"n" * 200 + ".txt": "x"})
        p = subprocess.Popen(
            [FTP, HOST, str(self.central_port), str(folder)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        p.stdin.write(b"2\nalice\nmdp\nmdp\n")
        p.stdin.close()
        output = b""
        while b"Connect\xc3\xa9 en tant que" not in output or b"Liste envoy" not in output:
            output += p.stdout.readline()
        port = int(re.search(rb"port (\d+),", output).group(1))
        for _ in range(1500):
            c = Raw(port)
            c.send("GET\t" + "n" * 200 + ".txt\n")
            self.assertEqual(c.recv(), "OK\t1")
            c.close()


class TestLigneDeCommande(Base):
    def run_bad(self, argv):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        return result.returncode, (result.stdout + result.stderr).decode("utf-8", "replace")

    def test_arguments_invalides(self):
        for argv in (
            [CENTRAL],
            [CENTRAL, "abc"],
            [CENTRAL, "99999"],
            [CENTRAL, "-t", "1", "5000"],
            [FTP],
            [FTP, HOST, "abc", "."],
            [FTP, HOST, "0", "."],
            [CLIENT],
            [CLIENT, HOST, "abc", "."],
        ):
            code, out = self.run_bad(argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("Usage", out, argv)

    def test_repertoire_absent(self):
        code, _ = self.run_bad([FTP, HOST, "1234", str(self.tmp / "absent")])
        self.assertEqual(code, 1)
        code, _ = self.run_bad([CLIENT, HOST, "1234", str(self.tmp / "absent")])
        self.assertEqual(code, 1)

    def test_port_deja_utilise(self):
        code, out = self.run_bad([CENTRAL, "-f", str(self.users_file), str(self.central_port)])
        self.assertEqual(code, 1)
        self.assertIn("Écoute impossible", out)

    def test_serveur_central_absent(self):
        with socket.socket() as s:
            s.bind((HOST, 0))
            free_port = s.getsockname()[1]
        out = self.run_client("bob", "chercher x\nquitter\n", central_port=free_port)
        self.assertIn("injoignable", out)

    def test_serveur_ftp_sans_central(self):
        with socket.socket() as s:
            s.bind((HOST, 0))
            free_port = s.getsockname()[1]
        p = self.spawn([FTP, HOST, free_port, self.make_share("alice")], "1\nalice\nmdp\n")
        p.wait_for("injoignable")

    def test_fin_de_saisie(self):
        p = self.spawn([FTP, HOST, self.central_port, self.make_share("alice")], "")
        self.assertEqual(p.wait_exit(), 1)
        self.assertIn("Fin de la saisie", p.text())

    def test_choix_invalide_redemande(self):
        p = self.spawn(
            [FTP, HOST, self.central_port, self.make_share("alice", {"a": "x"})],
            "9\nabc\n2\nalice\npw\npw\n",
        )
        p.wait_for("Choix invalide")
        p.wait_for("Connecté en tant que alice")

    def test_port_local_choisi(self):
        with socket.socket() as s:
            s.bind((HOST, 0))
            port = s.getsockname()[1]
        peer = self.start_peer("alice", {"a.txt": "x"}, options=["-p", port])
        self.assertEqual(peer.transfer_port, port)

    def test_mot_de_passe_trop_long(self):
        long_password = "x" * 500
        p = self.spawn(
            [FTP, HOST, self.central_port, self.make_share("alice", {"a": "x"})],
            f"1\nalice\n{long_password}\n",
        )
        p.wait_for("Mot de passe invalide")


if __name__ == "__main__":
    unittest.main(verbosity=2)
