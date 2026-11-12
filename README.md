# Système de partage de fichiers en P2P

Projet réseaux, module Programmation IP. Langage : C. Transport : TCP. Concurrence : threads POSIX.

Le serveur central ne stocke aucun fichier. Il sait seulement **qui possède quoi**. Les fichiers passent directement d'un utilisateur à l'autre.

```
                  +----------------------------------+
                  |         serveur_central          |
                  | comptes, pairs en ligne, fichiers|
                  +----------------------------------+
    authentification,  ^                      ^  recherche
    liste des fichiers,|                      |  par mot-clé
    signal de vie      |                      |
              +--------+------+      +--------+------+
              | serveur_ftp   |      | client_ftp    |
              | (site Alice)  |<-----| (site Bob)    |
              +---------------+      +---------------+
                     téléchargement direct du fichier
```

| Programme | Rôle |
|---|---|
| `serveur_central` | Inscrit et authentifie les utilisateurs. Garde la liste des pairs en ligne. Répond aux recherches. |
| `serveur_ftp` | Tourne sur chaque site. Annonce les fichiers au central et les envoie aux autres clients. |
| `client_ftp` | Tourne sur chaque site. Cherche, trie et télécharge. Il ne peut pas envoyer de fichier. |

## Compiler

```sh
make
```

Il faut un compilateur C et `make`. Sur Debian ou Ubuntu : `sudo apt install build-essential`.

## Essayer en quatre terminaux

```sh
make demo                                    # prépare demo/ et remet les comptes à zéro

./serveur_central 7777                       # terminal 1
./serveur_ftp localhost 7777 demo/alice      # terminal 2 : choisir 2, créer le compte alice
./serveur_ftp localhost 7777 demo/bob        # terminal 3 : choisir 2, créer le compte bob
./client_ftp  localhost 7777 demo/bob        # terminal 4
```

Dans le client :

```
client> chercher compression
client> trier taille desc
client> telecharger 1
client> quitter
```

Le fichier arrive dans `demo/bob/`. Le serveur central sait aussitôt que Bob le possède aussi : relancez la recherche pour voir la nouvelle source.

Ctrl-C dans un `serveur_ftp` annonce le départ. Ses fichiers disparaissent alors des recherches.

### Options

```
serveur_central [-t délai_de_vie_en_s] [-f fichier_utilisateurs] <port>
serveur_ftp [-p port_local] [-H nom_annoncé] <hôte_central> <port_central> <répertoire_partagé>
client_ftp <hôte_central> <port_central> <répertoire_partagé>
```

Par défaut, un pair est déclaré parti après 15 s de silence. `serveur_ftp` choisit un port libre, sauf avec `-p`.

Sur plusieurs machines, donnez aux programmes l'adresse réseau du serveur central, pas `localhost`. Si les autres machines ne peuvent pas joindre un pair par son adresse, annoncez un nom ou une adresse joignable avec `-H`.

## Décrire les fichiers partagés

Le répertoire partagé contient un fichier `descriptions.txt`. Le nom du fichier est sur une ligne et sa description sur la ligne suivante :

```
MP3.txt
FAQ sur l'algorithme de compression utilisé dans le codage audio MPEG-2

cours/sockets.txt
Cours d'introduction à la programmation réseau
```

- Les lignes vides entre deux fichiers sont facultatives.
- Un fichier en sous-répertoire s'écrit avec son chemin relatif.
- La taille et la date sont lues directement sur le disque.
- Un fichier sans description reste partagé et se trouve par son nom.
- Les fichiers cachés et les liens symboliques ne sont jamais partagés.

## Ce que le sujet demande, et où c'est fait

| Exigence | Réalisation | Tests (`tests/test_systeme.py`) |
|---|---|---|
| Inscription des nouveaux utilisateurs | `cmd_register` | `TestAuthentification` |
| Authentification par `crypt()`, jamais de mot de passe en clair | `auth.c`, `central_login` | `test_mot_de_passe_jamais_en_clair` (espion réseau) |
| Liste des utilisateurs et mots de passe cryptés | `utilisateurs.db`, format `nom:sel:vérificateur` | `test_fichier_des_comptes_comme_unix` |
| Envoi du hostname, des noms et des descriptions | `central_publish` | `TestPublication` |
| Sous-répertoires (amélioration) | `scan_directory` | `test_sous_repertoires` |
| Hôte et port du central passés aux programmes | ligne de commande | `TestLigneDeCommande` |
| Recherche par mot-clé | `cmd_search` | `TestRecherche` |
| Sous-chaîne de caractères (amélioration) | `count_hits` | `test_sous_chaine` |
| Téléchargement direct entre pairs | `do_download`, `serve_file` | `TestTelechargement` |
| Pas d'upload | aucune commande d'envoi | `test_pas_de_commande_upload` |
| Tri côté serveur et côté client | `results_sort` dans `cmd_search` et `do_sort` | `TestTri` |
| Déconnexion annoncée | `LOGOUT`, `cmd_logout` | `test_depart_annonce` |
| Signal de vie périodique (amélioration) | `HEARTBEAT`, délai de réception | `test_silence_detecte_par_le_signal_de_vie` |
| Plusieurs authentifications en même temps | un thread par connexion | `TestConcurrence` |
| Fichier téléchargé ajouté au partage et mise à jour du central | `add_description`, `notify_local_server`, `RESCAN` | `TestMiseAJourApresTelechargement` |

## Comment fonctionne l'authentification

Le mot de passe ne quitte jamais la machine de l'utilisateur.

Le principe est celui de SCRAM (RFC 5802), construit sur `crypt()` :

```
empreinte    = crypt(mot_de_passe, sel)
clé          = HMAC-SHA-256(empreinte, "Client Key")
vérificateur = SHA-256(clé)
```

1. **Inscription.** `serveur_ftp` tire un sel au hasard et envoie le sel et le vérificateur. Le central les stocke dans `utilisateurs.db`.
2. **Connexion.** Le central envoie le sel du compte et un défi aléatoire à usage unique. `serveur_ftp` recalcule la clé et répond `preuve = clé XOR HMAC(vérificateur, défi)`.
3. **Vérification.** Le central recalcule `HMAC(vérificateur, défi)`. Le même XOR lui redonne la clé. Il vérifie que `SHA-256(clé)` est bien le vérificateur.

Ce que cela garantit :

- Ni le mot de passe ni l'empreinte ne circulent.
- Une preuve capturée ne peut pas être rejouée : le défi suivant sera différent.
- Comme sous UNIX, voler le fichier des comptes ne suffit pas pour se connecter : il ne contient pas la clé.

`crypt()` utilise SHA-512 s'il existe (Linux), sinon DES étendu (macOS). Le programme vérifie le résultat, car macOS ignore SHA-512 sans le signaler. Il retomberait alors sur DES classique, qui ne lit que 8 caractères du mot de passe.

## Départ d'un pair

Le central retire un pair de trois façons :

| Situation | Détection |
|---|---|
| Ctrl-C | le pair envoie `LOGOUT` |
| Programme arrêté brutalement | le système ferme la connexion TCP |
| Machine figée ou réseau coupé | plus aucun message pendant le délai de vie |

Le pair envoie un signal de vie trois fois par délai de vie. Si la session est perdue, `serveur_ftp` se reconnecte seul et publie de nouveau sa liste.

## Protocole

Tous les messages sont des lignes de texte. Les champs sont séparés par une tabulation.

**`serveur_ftp` vers le central.** L'inscription utilise une connexion courte. La session (`LOGIN` et la suite) reste ouverte.

| Requête | Réponse |
|---|---|
| `REGISTER nom sel vérificateur` | `OK` ou `ERR message` |
| `LOGIN nom` | `CHALLENGE sel défi` ou `ERR message` |
| `AUTH preuve` | `OK intervalle_signal_de_vie` ou `ERR message` |
| `PUBLISH hôte port n`, puis `n` lignes `FILE chemin taille date description` | `OK` ou `ERR message` |
| `HEARTBEAT` | `OK` |
| `LOGOUT` | `OK` |

**`client_ftp` vers le central**, une connexion par recherche :

| Requête | Réponse |
|---|---|
| `SEARCH tri ordre mots-clés` | `RESULTS n total`, puis `n` lignes `R utilisateur hôte ip port chemin taille date score description` |

`tri` vaut `pertinence`, `nom`, `taille`, `date` ou `hote`. `ordre` vaut `asc` ou `desc`. Une recherche accepte 16 mots-clés et envoie 1 000 résultats au plus ; `total` indique combien de fichiers correspondent.

`ip` est l'adresse du pair vue par le central. Le client l'essaie d'abord, puis le nom d'hôte.

**`client_ftp` vers `serveur_ftp`**, une connexion par demande :

| Requête | Réponse |
|---|---|
| `GET chemin` | `OK taille`, puis les octets du fichier, ou `ERR message` |
| `RESCAN` (machine locale seulement) | `OK` |

## Tests

```sh
make test                                 # lance tous les tests
make clean all SAN=address,undefined      # erreurs de mémoire ; relancer ensuite make test
make clean all SAN=thread                 # erreurs de concurrence ; relancer ensuite make test
```

Les tests exigent Python 3 et lancent les vrais programmes. Ils couvrent aussi les cas difficiles : tentatives d'accès hors du partage (`../../etc/passwd`), données invalides sur le réseau, transferts coupés, 24 connexions simultanées.

## Avant de rendre le projet

```sh
make distclean
```

Cette commande retire les programmes compilés, le dossier `demo/` et les comptes de test.

## Limites connues

- Seuls les mots de passe sont protégés. Les recherches et les fichiers circulent sans chiffrement.
- Un espion qui capture une connexion ne peut pas la rejouer, mais il peut essayer de deviner un mot de passe faible hors ligne.
- Un espion qui possède le vérificateur (fichier des comptes ou inscription capturée) **et** une connexion capturée peut retrouver la clé. Le chiffrement du canal (TLS) supprimerait ce risque.
- Un compte créé sous Linux (SHA-512) ne s'ouvre pas depuis macOS, dont `crypt()` ne connaît pas cet algorithme. Le programme l'indique clairement. Il suffit de créer un autre compte.
- Il n'y a pas de protection contre le déni de service : un grand nombre de connexions lentes peut empêcher de nouveaux utilisateurs d'entrer tant que l'attaque dure.
- Il est possible de savoir si un nom d'utilisateur existe : l'inscription le révèle.
- Le client se fie à la taille donnée par le pair au moment du transfert, car celle annoncée au central peut être ancienne. Un pair malveillant peut donc envoyer un fichier plus gros que prévu.
- Le système utilise IPv4 seulement.
