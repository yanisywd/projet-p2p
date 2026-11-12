/*
 * serveur_ftp.c - Serveur de transfert exécuté sur chaque site utilisateur.
 *
 * Au lancement, il demande le nom et le mot de passe de l'utilisateur et
 * s'authentifie auprès du serveur central. Ensuite :
 *   - un thread garde la session avec le central : il envoie l'hôte, le nom
 *     et la description des fichiers, puis un signal de vie régulier ;
 *   - un thread accepte les demandes de fichiers, chacune servie par son
 *     propre thread. Le protocole ne permet que le téléchargement.
 *
 * Ctrl-C prévient le serveur central avant de quitter.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"
#include "common.h"

#define CONNECT_TIMEOUT   5
#define CENTRAL_TIMEOUT   10
#define TRANSFER_TIMEOUT  30
#define RETRY_DELAY       3
#define MAX_DEPTH         32
#define MAX_PASSWORD      128
#define CHUNK_SIZE        65536

typedef struct {
    char path[MAX_PATH_LEN];
    char desc[MAX_DESC];
    long long size;
    long long mtime;
} SharedFile;

typedef struct {
    SharedFile *items;
    size_t count;
    size_t cap;
} FileList;

static const char *g_central_host;
static int  g_central_port;
static char g_hostname[MAX_HOST];
static int  g_listen_fd;
static int  g_local_port;

/* Seule l'empreinte reste en mémoire pour se reconnecter, jamais le mot de passe. */
static char g_user[MAX_USER + 1];
static char g_hash[MAX_HASH];

static Conn g_central;
static int  g_beat_interval = 5;

/* g_lock protège les trois variables suivantes. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_wake = PTHREAD_COND_INITIALIZER;
static FileList g_files;
static int g_rescan_wanted;
static int g_stop;

/* ------------------------------------------------------------------ */
/* Liste des fichiers partagés                                        */
/* ------------------------------------------------------------------ */

static int list_add(FileList *list, const char *path, const struct stat *st)
{
    if (list->count == list->cap) {
        size_t cap = list->cap ? list->cap * 2 : 32;
        SharedFile *items = realloc(list->items, cap * sizeof *items);
        if (items == NULL)
            return -1;
        list->items = items;
        list->cap = cap;
    }
    SharedFile *f = &list->items[list->count++];
    snprintf(f->path, sizeof f->path, "%s", path);
    f->desc[0] = '\0';
    f->size = (long long)st->st_size;
    f->mtime = (long long)st->st_mtime;
    return 0;
}

static int has_control_char(const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7f)
            return 1;
    }
    return 0;
}

/* Manque passager de ressources : le disque n'a peut-être pas changé. */
static int is_temporary_error(int error)
{
    return error == EMFILE || error == ENFILE || error == ENOMEM;
}

/*
 * Parcourt le répertoire et ses sous-répertoires.
 * Ne garde que les fichiers ordinaires lisibles : pas de fichiers cachés,
 * ni de liens symboliques, qui pourraient pointer hors du partage.
 * Renvoie -1 en cas d'échec passager : la liste construite est alors fausse.
 */
static int scan_directory(const char *dir, FileList *list, int depth, int warn)
{
    DIR *d = opendir(dir[0] ? dir : ".");
    if (d == NULL) {
        if (is_temporary_error(errno))
            return -1;
        if (warn)
            printf("Attention : répertoire illisible : %s\n", dir[0] ? dir : ".");
        return 0;
    }

    int status = 0;
    struct dirent *entry;
    while (status == 0 && (entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        if (name[0] == '.' || (dir[0] == '\0' && strcasecmp(name, DESC_FILE) == 0))
            continue;

        char path[MAX_PATH_LEN];
        int n = dir[0] ? snprintf(path, sizeof path, "%s/%s", dir, name)
                       : snprintf(path, sizeof path, "%s", name);
        if (n < 0 || (size_t)n >= sizeof path || has_control_char(path)) {
            if (warn)
                printf("Attention : nom de fichier ignoré dans « %s »\n", dir);
            continue;
        }

        struct stat st;
        if (lstat(path, &st) < 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            if (depth < MAX_DEPTH)
                status = scan_directory(path, list, depth + 1, warn);
        } else if (S_ISREG(st.st_mode) && access(path, R_OK) == 0) {
            if (list->count >= MAX_FILES) {
                if (warn)
                    printf("Attention : limite de %d fichiers atteinte\n", MAX_FILES);
                break;
            }
            status = list_add(list, path, &st);
        }
    }
    closedir(d);
    return status;
}

static int compare_files(const void *a, const void *b)
{
    return strcmp(((const SharedFile *)a)->path, ((const SharedFile *)b)->path);
}

static int compare_key_file(const void *key, const void *file)
{
    return strcmp(key, ((const SharedFile *)file)->path);
}

/* La liste doit être triée par chemin. */
static SharedFile *list_find(const FileList *list, const char *path)
{
    if (list->count == 0)
        return NULL;
    return bsearch(path, list->items, list->count, sizeof *list->items,
                   compare_key_file);
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
    return s;
}

/* Le nom exact d'abord, puis sans les espaces en trop autour. */
static SharedFile *find_described(const FileList *list, char *name)
{
    SharedFile *file = list_find(list, name);
    return file != NULL ? file : list_find(list, trim(name));
}

/*
 * Lit descriptions.txt : le nom du fichier sur une ligne, sa description
 * sur la ligne suivante. Les lignes vides entre deux fichiers sont ignorées.
 * Renvoie -1 en cas d'échec passager.
 */
static int apply_descriptions(FileList *list, int warn)
{
    FILE *f = fopen(DESC_FILE, "r");
    if (f == NULL) {
        if (is_temporary_error(errno))
            return -1;
        if (warn)
            printf("Attention : %s introuvable, fichiers partagés sans description\n",
                   DESC_FILE);
        return 0;
    }

    char *line = NULL;
    size_t line_cap = 0;
    char name[MAX_PATH_LEN] = "";
    int have_name = 0;
    int first_line = 1;

    while (getline(&line, &line_cap, f) >= 0) {
        char *text = line;
        if (first_line && strncmp(text, "\xEF\xBB\xBF", 3) == 0)
            text += 3;                    /* marque BOM ajoutée par Windows */
        first_line = 0;
        text[strcspn(text, "\r\n")] = '\0';

        if (!have_name) {
            snprintf(name, sizeof name, "%s", text);
            have_name = *trim(text) != '\0';
            continue;
        }

        have_name = 0;
        SharedFile *file = find_described(list, name);
        if (file == NULL) {
            if (warn)
                printf("Attention : « %s » est décrit mais absent du partage\n", name);
            continue;
        }
        text = trim(text);
        text_clean(text);
        text_truncate(text, MAX_DESC - 1);
        snprintf(file->desc, sizeof file->desc, "%s", text);
    }
    free(line);
    fclose(f);
    return 0;
}

static int lists_equal(const FileList *a, const FileList *b)
{
    if (a->count != b->count)
        return 0;
    for (size_t i = 0; i < a->count; i++) {
        const SharedFile *x = &a->items[i];
        const SharedFile *y = &b->items[i];
        if (x->size != y->size || x->mtime != y->mtime ||
            strcmp(x->path, y->path) != 0 || strcmp(x->desc, y->desc) != 0)
            return 0;
    }
    return 1;
}

/*
 * Relit le répertoire. Renvoie 1 si la liste a changé.
 * Après un échec passager, l'ancienne liste reste valable : on la garde.
 */
static int rescan(int warn)
{
    FileList fresh = { NULL, 0, 0 };

    if (scan_directory("", &fresh, 0, warn) < 0) {
        free(fresh.items);
        return 0;
    }
    if (fresh.count > 0)
        qsort(fresh.items, fresh.count, sizeof *fresh.items, compare_files);
    if (apply_descriptions(&fresh, warn) < 0) {
        free(fresh.items);
        return 0;
    }

    int changed = !lists_equal(&fresh, &g_files);

    pthread_mutex_lock(&g_lock);
    SharedFile *old = g_files.items;
    g_files = fresh;
    pthread_mutex_unlock(&g_lock);
    free(old);
    return changed;
}

static void request_rescan(void)
{
    pthread_mutex_lock(&g_lock);
    g_rescan_wanted = 1;
    pthread_cond_broadcast(&g_wake);
    pthread_mutex_unlock(&g_lock);
}

/* ------------------------------------------------------------------ */
/* Dialogue avec le serveur central                                   */
/* ------------------------------------------------------------------ */

static int central_open(void)
{
    int fd = tcp_connect(g_central_host, g_central_port, CONNECT_TIMEOUT);
    if (fd < 0)
        return -1;
    sock_configure(fd, CENTRAL_TIMEOUT);
    conn_init(&g_central, fd);
    return 0;
}

/* Attend "OK" ou "OK <valeur>". Renvoie 0 si la réponse est OK. */
static int expect_ok(char *err, size_t err_size, int *value)
{
    char line[MAX_LINE];
    char *f[2];

    if (conn_read_line(&g_central, line, sizeof line) != NET_OK) {
        snprintf(err, err_size, "le serveur central ne répond pas");
        return -1;
    }
    int n = split_fields(line, f, 2);
    if (strcmp(f[0], "OK") == 0) {
        long long v;
        if (value != NULL && n == 2 && parse_long(f[1], 1, 86400, &v))
            *value = (int)v;
        return 0;
    }
    snprintf(err, err_size, "%s",
             (n == 2 && strcmp(f[0], "ERR") == 0) ? f[1] : "réponse invalide");
    text_clean(err);
    return -1;
}

/* Le mot de passe ne sert qu'à calculer l'empreinte, sur cette machine. */
static int central_register(const char *user, const char *password,
                            char *err, size_t err_size)
{
    char salt[AUTH_SALT_SIZE];
    char hash[MAX_HASH];
    char verifier[AUTH_HEX_LEN + 1];

    if (auth_new_salt(salt, sizeof salt) < 0 ||
        auth_hash(password, salt, hash, sizeof hash) < 0) {
        snprintf(err, err_size, "crypt() ne fonctionne pas sur cette machine");
        return -1;
    }
    auth_verifier(hash, verifier);
    auth_wipe(hash, sizeof hash);

    if (central_open() < 0) {
        snprintf(err, err_size, "serveur central injoignable");
        return -1;
    }
    int status = -1;
    if (send_line(g_central.fd, "REGISTER\t%s\t%s\t%s\n", user, salt, verifier) < 0)
        snprintf(err, err_size, "le serveur central ne répond pas");
    else
        status = expect_ok(err, err_size, NULL);
    close(g_central.fd);
    return status;
}

/*
 * Authentification par défi sur la connexion ouverte.
 * password vaut NULL lors d'une reconnexion : g_hash est déjà connu.
 */
static int central_login(const char *password, char *err, size_t err_size)
{
    char line[MAX_LINE];
    char *f[3];

    if (send_line(g_central.fd, "LOGIN\t%s\n", g_user) < 0 ||
        conn_read_line(&g_central, line, sizeof line) != NET_OK) {
        snprintf(err, err_size, "le serveur central ne répond pas");
        return -1;
    }

    int n = split_fields(line, f, 3);
    if (n == 2 && strcmp(f[0], "ERR") == 0) {
        snprintf(err, err_size, "%s", f[1]);
        text_clean(err);
        return -1;
    }
    if (n != 3 || strcmp(f[0], "CHALLENGE") != 0 || !auth_valid_salt(f[1])) {
        snprintf(err, err_size, "réponse invalide du serveur central");
        return -1;
    }

    if (password != NULL && auth_hash(password, f[1], g_hash, sizeof g_hash) < 0) {
        snprintf(err, err_size,
                 "ce compte utilise un algorithme absent de cette machine");
        return -1;
    }

    char proof[AUTH_HEX_LEN + 1];
    auth_proof(g_hash, f[2], proof);
    if (send_line(g_central.fd, "AUTH\t%s\n", proof) < 0) {
        snprintf(err, err_size, "le serveur central ne répond pas");
        return -1;
    }
    return expect_ok(err, err_size, &g_beat_interval);
}

/* Envoie l'hôte, le port et la liste complète des fichiers. */
static int central_publish(void)
{
    char err[256];

    if (send_line(g_central.fd, "PUBLISH\t%s\t%d\t%zu\n",
                  g_hostname, g_local_port, g_files.count) < 0)
        return -1;
    for (size_t i = 0; i < g_files.count; i++) {
        const SharedFile *f = &g_files.items[i];
        if (send_line(g_central.fd, "FILE\t%s\t%lld\t%lld\t%s\n",
                      f->path, f->size, f->mtime, f->desc) < 0)
            return -1;
    }
    if (expect_ok(err, sizeof err, NULL) < 0) {
        log_line("Annonce refusée : %s", err);
        return -1;
    }
    log_line("Liste envoyée au serveur central : %zu fichier(s)", g_files.count);
    return 0;
}

static int central_simple(const char *command)
{
    char err[256];

    if (send_line(g_central.fd, "%s\n", command) < 0)
        return -1;
    return expect_ok(err, sizeof err, NULL);
}

/* Garde la session ouverte jusqu'à l'arrêt demandé ou une panne réseau. */
static void run_session(void)
{
    rescan(0);
    if (central_publish() < 0)
        return;

    time_t next_beat = time(NULL) + g_beat_interval;
    for (;;) {
        pthread_mutex_lock(&g_lock);
        while (!g_stop && !g_rescan_wanted && time(NULL) < next_beat) {
            struct timespec deadline = { .tv_sec = next_beat, .tv_nsec = 0 };
            pthread_cond_timedwait(&g_wake, &g_lock, &deadline);
        }
        int stop = g_stop;
        g_rescan_wanted = 0;
        pthread_mutex_unlock(&g_lock);

        if (stop) {
            central_simple("LOGOUT");
            return;
        }
        if (rescan(0) && central_publish() < 0)
            return;
        if (time(NULL) >= next_beat) {
            if (central_simple("HEARTBEAT") < 0)
                return;
            next_beat = time(NULL) + g_beat_interval;
        }
    }
}

/* Attend quelques secondes. Renvoie 1 si l'arrêt est demandé. */
static int wait_or_stop(int seconds)
{
    struct timespec deadline = { .tv_sec = time(NULL) + seconds, .tv_nsec = 0 };

    pthread_mutex_lock(&g_lock);
    while (!g_stop) {
        if (pthread_cond_timedwait(&g_wake, &g_lock, &deadline) == ETIMEDOUT)
            break;
    }
    int stop = g_stop;
    pthread_mutex_unlock(&g_lock);
    return stop;
}

static void *session_thread(void *arg)
{
    (void)arg;

    run_session();
    close(g_central.fd);

    while (!wait_or_stop(RETRY_DELAY)) {
        char err[256];
        if (central_open() < 0)
            continue;
        if (central_login(NULL, err, sizeof err) == 0) {
            log_line("Reconnecté au serveur central");
            run_session();
        }
        close(g_central.fd);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Transferts de fichiers                                             */
/* ------------------------------------------------------------------ */

static int is_shared(const char *path)
{
    pthread_mutex_lock(&g_lock);
    int found = list_find(&g_files, path) != NULL;
    pthread_mutex_unlock(&g_lock);
    return found;
}

/*
 * Seuls les fichiers de la liste partagée sont servis. Cette règle bloque
 * à elle seule "../../etc/passwd" et l'accès aux fichiers cachés.
 */
static void serve_file(int fd, const char *path)
{
    if (!is_shared(path)) {
        send_line(fd, "ERR\tfichier non partagé\n");
        return;
    }

    int file = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat st;
    if (file < 0 || fstat(file, &st) < 0 || !S_ISREG(st.st_mode)) {
        send_line(fd, "ERR\tfichier illisible\n");
        if (file >= 0)
            close(file);
        return;
    }

    char ip[MAX_IP] = "?";
    sock_peer_ip(fd, ip);
    log_line("Envoi de « %s » à %s", path, ip);

    if (send_line(fd, "OK\t%lld\n", (long long)st.st_size) == 0) {
        char buf[CHUNK_SIZE];
        long long left = (long long)st.st_size;
        while (left > 0) {
            size_t want = left < CHUNK_SIZE ? (size_t)left : CHUNK_SIZE;
            ssize_t n = read(file, buf, want);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0 || send_all(fd, buf, (size_t)n) < 0)
                break;
            left -= n;
        }
    }
    close(file);
}

/* RESCAN : le client local signale un nouveau fichier téléchargé. */
static void handle_rescan(int fd)
{
    char ip[MAX_IP] = "";

    if (sock_peer_ip(fd, ip) < 0 || !ip_is_loopback(ip)) {
        send_line(fd, "ERR\tcommande réservée au client local\n");
        return;
    }
    request_rescan();
    send_line(fd, "OK\n");
}

static void *transfer_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    Conn conn;
    char line[MAX_LINE];
    char *f[2];

    conn_init(&conn, fd);
    if (conn_read_line(&conn, line, sizeof line) == NET_OK) {
        int n = split_fields(line, f, 2);
        if (n == 2 && strcmp(f[0], "GET") == 0)
            serve_file(fd, f[1]);
        else if (n == 1 && strcmp(f[0], "RESCAN") == 0)
            handle_rescan(fd);
        else
            send_line(fd, "ERR\tcommande inconnue\n");
    }
    close(fd);
    return NULL;
}

static void *accept_thread(void *arg)
{
    (void)arg;

    for (;;) {
        int fd = accept(g_listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno != EINTR)
                usleep(100000);
            continue;
        }
        sock_configure(fd, TRANSFER_TIMEOUT);

        pthread_t thread;
        if (pthread_create(&thread, NULL, transfer_thread, (void *)(intptr_t)fd) != 0)
            close(fd);
        else
            pthread_detach(thread);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Saisie de l'identité                                               */
/* ------------------------------------------------------------------ */

static struct termios g_saved_term;
static volatile sig_atomic_t g_term_changed;

/* Ctrl-C pendant la saisie du mot de passe : rétablit l'affichage du terminal. */
static void restore_term_and_quit(int sig)
{
    if (g_term_changed)
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_term);
    signal(sig, SIG_DFL);
    raise(sig);
}

/* Renvoie 1 si une ligne est lue, 0 en fin d'entrée, -1 si elle est trop longue. */
static int read_input(char *buf, size_t size)
{
    if (fgets(buf, (int)size, stdin) == NULL)
        return 0;

    size_t n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n') {
        buf[--n] = '\0';
        if (n > 0 && buf[n - 1] == '\r')
            buf[--n] = '\0';
        return 1;
    }
    if (n + 1 == size) {
        int c;
        while ((c = getchar()) != EOF && c != '\n')
            ;
        return -1;
    }
    return 1;
}

static int prompt_input(const char *label, char *buf, size_t size)
{
    printf("%s", label);
    fflush(stdout);
    return read_input(buf, size);
}

/* Lit un mot de passe sans l'afficher à l'écran. */
static int prompt_password(const char *label, char *buf, size_t size)
{
    int tty = isatty(STDIN_FILENO);

    printf("%s", label);
    fflush(stdout);

    if (tty) {
        struct termios silent;
        tcgetattr(STDIN_FILENO, &g_saved_term);
        silent = g_saved_term;
        silent.c_lflag &= (tcflag_t)~ECHO;
        g_term_changed = 1;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent);
    }

    int r = read_input(buf, size);

    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_term);
        g_term_changed = 0;
        printf("\n");
    }
    return r;
}

/* Demande l'identité jusqu'à une connexion réussie. Renvoie -1 en fin d'entrée. */
static int interactive_login(void)
{
    char choice[16], user[MAX_USER + 1];    /* +1 : place pour la fin de ligne */
    char password[MAX_PASSWORD], confirm[MAX_PASSWORD];
    char err[256];
    int r;

    for (;;) {
        printf("\n1) Se connecter\n2) Créer un compte\n");
        r = prompt_input("Choix : ", choice, sizeof choice);
        if (r == 0)
            return -1;
        if (r < 0 || (strcmp(choice, "1") != 0 && strcmp(choice, "2") != 0)) {
            printf("Choix invalide.\n");
            continue;
        }
        int creating = choice[0] == '2';

        r = prompt_input("Nom d'utilisateur : ", user, sizeof user);
        if (r == 0)
            return -1;
        if (r < 0 || !valid_username(user)) {
            printf("Nom invalide : 1 à %d caractères parmi lettres, chiffres, "
                   "'_', '-' et '.'.\n", MAX_USER - 1);
            continue;
        }

        r = prompt_password("Mot de passe : ", password, sizeof password);
        if (r == 0)
            return -1;
        if (r < 0 || password[0] == '\0') {
            printf("Mot de passe invalide : 1 à %d caractères.\n", MAX_PASSWORD - 2);
            continue;
        }

        if (creating) {
            r = prompt_password("Confirmer le mot de passe : ", confirm, sizeof confirm);
            if (r == 0) {
                auth_wipe(password, sizeof password);
                return -1;
            }
            int same = r > 0 && strcmp(password, confirm) == 0;
            auth_wipe(confirm, sizeof confirm);
            if (!same) {
                auth_wipe(password, sizeof password);
                printf("Les deux mots de passe sont différents.\n");
                continue;
            }
            if (central_register(user, password, err, sizeof err) < 0) {
                auth_wipe(password, sizeof password);
                printf("Échec de l'inscription : %s\n", err);
                continue;
            }
            printf("Compte créé.\n");
        }

        snprintf(g_user, sizeof g_user, "%s", user);
        if (central_open() < 0) {
            auth_wipe(password, sizeof password);
            printf("Serveur central injoignable (%s:%d).\n",
                   g_central_host, g_central_port);
            continue;
        }

        r = central_login(password, err, sizeof err);
        auth_wipe(password, sizeof password);
        if (r == 0)
            return 0;

        close(g_central.fd);
        printf("Échec de la connexion : %s\n", err);
    }
}

/* ------------------------------------------------------------------ */
/* Programme principal                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage : %s [-p port_local] [-H nom_annoncé] "
            "<hôte_central> <port_central> <répertoire_partagé>\n", program);
    exit(2);
}

static void write_port_file(void)
{
    FILE *f = fopen(PORT_FILE, "w");
    if (f == NULL) {
        log_line("Attention : impossible d'écrire %s", PORT_FILE);
        return;
    }
    fprintf(f, "%d\n", g_local_port);
    fclose(f);
}

int main(int argc, char **argv)
{
    long long value;
    int local_port = 0;
    const char *announced = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "p:H:")) != -1) {
        switch (opt) {
        case 'p':
            if (!parse_long(optarg, 0, 65535, &value))
                usage(argv[0]);
            local_port = (int)value;
            break;
        case 'H':
            announced = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }
    if (argc - optind != 3 || !parse_long(argv[optind + 1], 1, 65535, &value))
        usage(argv[0]);
    g_central_host = argv[optind];
    g_central_port = (int)value;

    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, restore_term_and_quit);
    signal(SIGTERM, restore_term_and_quit);
    signal(SIGHUP, restore_term_and_quit);

    if (chdir(argv[optind + 2]) < 0) {
        perror(argv[optind + 2]);
        return 1;
    }

    if (announced != NULL) {
        snprintf(g_hostname, sizeof g_hostname, "%s", announced);
    } else if (gethostname(g_hostname, sizeof g_hostname - 1) < 0) {
        g_hostname[0] = '\0';
    }
    g_hostname[sizeof g_hostname - 1] = '\0';
    if (!valid_hostname(g_hostname)) {
        if (announced != NULL) {
            fprintf(stderr, "Nom d'hôte invalide : %s\n", announced);
            return 2;
        }
        snprintf(g_hostname, sizeof g_hostname, "localhost");
    }

    g_listen_fd = tcp_listen(local_port);
    if (g_listen_fd < 0) {
        perror("Écoute impossible");
        return 1;
    }
    g_local_port = tcp_local_port(g_listen_fd);

    rescan(1);
    printf("Serveur de transfert : hôte %s, port %d, %zu fichier(s) à partager\n",
           g_hostname, g_local_port, g_files.count);

    if (interactive_login() < 0) {
        printf("\nFin de la saisie.\n");
        return 1;
    }

    /* À partir d'ici, seul sigwait() traite Ctrl-C : le départ reste propre. */
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &signals, NULL);

    write_port_file();

    pthread_t accepter, session;
    if (pthread_create(&accepter, NULL, accept_thread, NULL) != 0 ||
        pthread_create(&session, NULL, session_thread, NULL) != 0) {
        fprintf(stderr, "Impossible de créer les threads\n");
        unlink(PORT_FILE);
        return 1;
    }
    pthread_detach(accepter);

    log_line("Connecté en tant que %s. Ctrl-C pour se déconnecter.", g_user);

    int sig;
    sigwait(&signals, &sig);

    log_line("\nDéconnexion...");
    pthread_mutex_lock(&g_lock);
    g_stop = 1;
    pthread_cond_broadcast(&g_wake);
    pthread_mutex_unlock(&g_lock);
    pthread_join(session, NULL);

    unlink(PORT_FILE);
    log_line("Déconnecté.");
    return 0;
}
