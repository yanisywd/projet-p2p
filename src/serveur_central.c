/*
 * serveur_central.c - Serveur centralisé du système P2P.
 *
 * Rôles :
 *   - inscrire et authentifier les utilisateurs ;
 *   - garder la liste des pairs connectés et de leurs fichiers ;
 *   - répondre aux recherches par mots-clés.
 *
 * Concurrence : un thread par connexion TCP. Un seul mutex protège les
 * utilisateurs et les sessions.
 *
 * Départ d'un pair : le pair est retiré dès qu'il annonce son départ (LOGOUT),
 * que sa connexion se ferme, ou qu'il n'envoie plus rien pendant le délai
 * de vie (signal de vie absent : la réception expire).
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "auth.h"
#include "common.h"

#define DEFAULT_PEER_TIMEOUT 15
#define MIN_PEER_TIMEOUT     3
#define DEFAULT_USERS_FILE   "utilisateurs.db"
#define MAX_TERMS            16
#define USER_LINE_SIZE       (MAX_USER + AUTH_SALT_SIZE + AUTH_HEX_LEN + 8)
#define BAD_LOGIN            "nom d'utilisateur ou mot de passe incorrect"

/* Le central ne connaît ni le mot de passe ni la clé qui en dérive. */
typedef struct {
    char name[MAX_USER];
    char salt[AUTH_SALT_SIZE];
    char verifier[AUTH_HEX_LEN + 1];
} User;

typedef struct {
    char *path;
    char *desc;
    char *folded_path;   /* sans majuscules ni accents, pour la recherche */
    char *folded_desc;
    long long size;
    long long mtime;
} FileEntry;

/* Un pair authentifié et ses fichiers. */
typedef struct Session {
    struct Session *next;
    char user[MAX_USER];
    char host[MAX_HOST];
    char ip[MAX_IP];
    int  port;
    FileEntry *files;
    size_t file_count;
} Session;

/* État d'une connexion TCP. */
typedef struct {
    Conn conn;
    char ip[MAX_IP];              /* adresse du correspondant */
    char local_ip[MAX_IP];        /* notre adresse sur cette connexion */
    char pending_user[MAX_USER];  /* utilisateur en cours de connexion */
    char nonce[NONCE_HEX_LEN + 1];
    int  challenged;              /* un défi attend sa réponse */
    Session *session;
} Client;

enum { CMD_KEEP, CMD_CLOSE, CMD_LOGOUT };

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static User    *g_users;
static size_t   g_user_count;
static size_t   g_user_cap;
static Session *g_sessions;

static const char *g_users_path = DEFAULT_USERS_FILE;
static int g_peer_timeout = DEFAULT_PEER_TIMEOUT;

/* ------------------------------------------------------------------ */
/* Utilisateurs                                                       */
/* ------------------------------------------------------------------ */

/* Appelant : verrou pris. */
static User *find_user(const char *name)
{
    for (size_t i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].name, name) == 0)
            return &g_users[i];
    }
    return NULL;
}

/* Appelant : verrou pris. */
static int add_user(const char *name, const char *salt, const char *verifier)
{
    if (g_user_count == g_user_cap) {
        size_t cap = g_user_cap ? g_user_cap * 2 : 16;
        User *users = realloc(g_users, cap * sizeof *users);
        if (users == NULL)
            return -1;
        g_users = users;
        g_user_cap = cap;
    }
    User *u = &g_users[g_user_count++];
    snprintf(u->name, sizeof u->name, "%s", name);
    snprintf(u->salt, sizeof u->salt, "%s", salt);
    snprintf(u->verifier, sizeof u->verifier, "%s", verifier);
    return 0;
}

/* Comme /etc/passwd, une ligne par compte : "nom:sel:vérificateur". */
static void load_users(void)
{
    FILE *f = fopen(g_users_path, "r");
    if (f == NULL) {
        if (errno == ENOENT)
            return;
        perror(g_users_path);
        exit(1);
    }

    char line[USER_LINE_SIZE];
    int number = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        number++;
        line[strcspn(line, "\r\n")] = '\0';

        char *salt = strchr(line, ':');
        char *verifier = salt ? strchr(salt + 1, ':') : NULL;
        if (verifier != NULL) {
            *salt++ = '\0';
            *verifier++ = '\0';
        }
        if (verifier == NULL || !valid_username(line) || !auth_valid_salt(salt) ||
            !auth_valid_key(verifier) || find_user(line) != NULL) {
            fprintf(stderr, "%s:%d : ligne ignorée\n", g_users_path, number);
            continue;
        }
        if (add_user(line, salt, verifier) < 0) {
            fprintf(stderr, "Mémoire insuffisante\n");
            exit(1);
        }
    }
    fclose(f);
}

static int save_user(const char *name, const char *salt, const char *verifier)
{
    int fd = open(g_users_path, O_RDWR | O_APPEND | O_CREAT, 0600);
    if (fd < 0)
        return -1;

    /* Un fichier retouché à la main peut ne pas finir par une fin de ligne. */
    char last = '\n';
    off_t size = lseek(fd, 0, SEEK_END);
    if (size > 0 && pread(fd, &last, 1, size - 1) != 1)
        size = -1;

    int status = -1;
    if (size >= 0) {
        char line[USER_LINE_SIZE];
        int len = snprintf(line, sizeof line, "%s%s:%s:%s\n",
                           last == '\n' ? "" : "\n", name, salt, verifier);
        if (write(fd, line, (size_t)len) == len)
            status = 0;
        else if (ftruncate(fd, size) < 0)    /* ne pas laisser une demi-ligne */
            log_line("%s : réparation impossible", g_users_path);
    }
    if (close(fd) < 0)
        status = -1;
    return status;
}

/* ------------------------------------------------------------------ */
/* Sessions                                                           */
/* ------------------------------------------------------------------ */

static void free_entries(FileEntry *files, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        free(files[i].path);
        free(files[i].desc);
        free(files[i].folded_path);
        free(files[i].folded_desc);
    }
    free(files);
}

/* Appelant : verrou pris. */
static Session *session_of(const char *user)
{
    for (Session *s = g_sessions; s != NULL; s = s->next) {
        if (strcmp(s->user, user) == 0)
            return s;
    }
    return NULL;
}

/* Après cet appel, plus aucune recherche ne voit les fichiers du pair. */
static void session_remove(Session *session)
{
    pthread_mutex_lock(&g_lock);
    for (Session **p = &g_sessions; *p != NULL; p = &(*p)->next) {
        if (*p == session) {
            *p = session->next;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);

    free_entries(session->files, session->file_count);
    free(session);
}

/* ------------------------------------------------------------------ */
/* Recherche                                                          */
/* ------------------------------------------------------------------ */

/*
 * Met un texte UTF-8 en minuscules et sans accents : "Été" devient "ete".
 * Le travail se fait sur place, car le texte ne s'allonge jamais.
 */
static void fold_text(char *text)
{
    /* U+00C0 à U+00FF. '*' : caractère gardé tel quel. */
    static const char latin1[] =
        "aaaaaaaceeeeiiiidnooooo*ouuuuy*s"
        "aaaaaaaceeeeiiiidnooooo*ouuuuy*y";

    unsigned char *in = (unsigned char *)text;
    unsigned char *out = in;

    while (*in) {
        if (in[0] == 0xC3 && in[1] >= 0x80 && in[1] <= 0xBF) {
            unsigned char c = in[1];
            char plain = latin1[c - 0x80];
            if (c == 0x86 || c == 0xA6) {          /* Æ æ */
                *out++ = 'a';
                *out++ = 'e';
            } else if (c == 0x9F) {                /* ß */
                *out++ = 's';
                *out++ = 's';
            } else if (plain != '*') {
                *out++ = (unsigned char)plain;
            } else {
                *out++ = in[0];
                *out++ = in[1];
            }
            in += 2;
        } else if (in[0] == 0xC5 && (in[1] == 0x92 || in[1] == 0x93)) {  /* Œ œ */
            *out++ = 'o';
            *out++ = 'e';
            in += 2;
        } else if ((in[0] == 0xCC && in[1] >= 0x80 && in[1] <= 0xBF) ||
                   (in[0] == 0xCD && in[1] >= 0x80 && in[1] <= 0xAF)) {
            in += 2;                               /* accent combinant seul */
        } else {
            *out++ = (unsigned char)tolower(*in);
            in++;
        }
    }
    *out = '\0';
}

/* Le texte est déjà sans accents : les autres octets sont de la ponctuation. */
static int is_word_char(char c)
{
    return isalnum((unsigned char)c);
}

/* Un mot entier vaut 2 points, une simple sous-chaîne vaut 1 point. */
static int count_hits(const char *text, const char *term)
{
    size_t len = strlen(term);
    int points = 0;

    for (const char *p = strstr(text, term); p != NULL; p = strstr(p + len, term)) {
        int starts = p == text || !is_word_char(p[-1]);
        int ends = !is_word_char(p[len]);
        points += (starts && ends) ? 2 : 1;
    }
    return points;
}

/* Tous les mots doivent être présents. Un résultat sur le nom compte triple. */
static int match_score(const FileEntry *file, char **terms, int term_count)
{
    int total = 0;

    for (int i = 0; i < term_count; i++) {
        int points = 3 * count_hits(file->folded_path, terms[i]) +
                     count_hits(file->folded_desc, terms[i]);
        if (points == 0)
            return 0;
        total += points;
    }
    return total;
}

static int result_append(Result **results, size_t *count, size_t *cap,
                         const Session *s, const char *ip,
                         const FileEntry *file, int score)
{
    if (*count == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 32;
        Result *grown = realloc(*results, new_cap * sizeof *grown);
        if (grown == NULL)
            return -1;
        *results = grown;
        *cap = new_cap;
    }

    Result r;
    memset(&r, 0, sizeof r);
    snprintf(r.user, sizeof r.user, "%s", s->user);
    snprintf(r.host, sizeof r.host, "%s", s->host);
    snprintf(r.ip, sizeof r.ip, "%s", ip);
    r.port = s->port;
    r.path = strdup(file->path);
    r.desc = strdup(file->desc);
    r.size = file->size;
    r.mtime = file->mtime;
    r.score = score;
    if (r.path == NULL || r.desc == NULL) {
        free(r.path);
        free(r.desc);
        return -1;
    }
    (*results)[(*count)++] = r;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Commandes                                                          */
/* ------------------------------------------------------------------ */

static int reply_err(Client *c, const char *message)
{
    return send_line(c->conn.fd, "ERR\t%s\n", message) < 0 ? CMD_CLOSE : CMD_KEEP;
}

static int reply_ok(Client *c)
{
    return send_line(c->conn.fd, "OK\n") < 0 ? CMD_CLOSE : CMD_KEEP;
}

/* REGISTER <nom> <sel> <vérificateur> */
static int cmd_register(Client *c, char **f)
{
    if (!valid_username(f[1]))
        return reply_err(c, "nom d'utilisateur invalide");
    if (!auth_valid_salt(f[2]) || !auth_valid_key(f[3]))
        return reply_err(c, "données d'inscription invalides");

    const char *error = NULL;
    pthread_mutex_lock(&g_lock);
    if (find_user(f[1]) != NULL)
        error = "ce nom d'utilisateur existe déjà";
    else if (save_user(f[1], f[2], f[3]) < 0 || add_user(f[1], f[2], f[3]) < 0)
        error = "enregistrement impossible sur le serveur";
    pthread_mutex_unlock(&g_lock);

    if (error != NULL)
        return reply_err(c, error);
    log_line("[compte] nouvel utilisateur : %s", f[1]);
    return reply_ok(c);
}

/* LOGIN <nom> : répond par le sel du compte et un défi neuf. */
static int cmd_login(Client *c, char **f)
{
    char salt[AUTH_SALT_SIZE] = "";

    if (c->session != NULL)
        return reply_err(c, "session déjà ouverte");

    if (valid_username(f[1])) {
        pthread_mutex_lock(&g_lock);
        User *u = find_user(f[1]);
        if (u != NULL)
            snprintf(salt, sizeof salt, "%s", u->salt);
        pthread_mutex_unlock(&g_lock);
    }
    if (salt[0] == '\0') {
        sleep(1);
        return reply_err(c, BAD_LOGIN);
    }

    if (auth_new_nonce(c->nonce) < 0)
        return reply_err(c, "erreur interne");

    snprintf(c->pending_user, sizeof c->pending_user, "%s", f[1]);
    c->challenged = 1;
    return send_line(c->conn.fd, "CHALLENGE\t%s\t%s\n", salt, c->nonce) < 0
               ? CMD_CLOSE : CMD_KEEP;
}

/* AUTH <preuve> : vérifie la preuve avec le vérificateur du compte. */
static int cmd_auth(Client *c, char **f)
{
    char verifier[AUTH_HEX_LEN + 1] = "";

    if (!c->challenged || c->session != NULL)
        return reply_err(c, "LOGIN attendu avant AUTH");
    c->challenged = 0;    /* un défi ne sert qu'une seule fois */

    pthread_mutex_lock(&g_lock);
    User *u = find_user(c->pending_user);
    if (u != NULL)
        snprintf(verifier, sizeof verifier, "%s", u->verifier);
    pthread_mutex_unlock(&g_lock);

    if (verifier[0] == '\0' || !auth_check(verifier, c->nonce, f[1])) {
        sleep(1);         /* ralentit les essais de mots de passe */
        log_line("[compte] échec de connexion : %s (%s)", c->pending_user, c->ip);
        return reply_err(c, BAD_LOGIN);
    }

    Session *s = calloc(1, sizeof *s);
    if (s == NULL)
        return reply_err(c, "erreur interne");
    snprintf(s->user, sizeof s->user, "%s", c->pending_user);
    snprintf(s->ip, sizeof s->ip, "%s", c->ip);

    pthread_mutex_lock(&g_lock);
    int already_online = session_of(s->user) != NULL;
    if (!already_online) {
        s->next = g_sessions;
        g_sessions = s;
    }
    pthread_mutex_unlock(&g_lock);

    if (already_online) {
        free(s);
        return reply_err(c, "cet utilisateur est déjà connecté");
    }

    c->session = s;
    log_line("[pair] %s authentifié depuis %s", s->user, s->ip);

    int beat = g_peer_timeout / 3;
    return send_line(c->conn.fd, "OK\t%d\n", beat) < 0 ? CMD_CLOSE : CMD_KEEP;
}

/* Lit une ligne "FILE <chemin> <taille> <date> <description>". */
static int read_file_entry(Client *c, FileEntry *entry)
{
    char line[MAX_LINE];
    char *f[5];
    long long size, mtime;

    if (conn_read_line(&c->conn, line, sizeof line) != NET_OK)
        return -1;
    if (split_fields(line, f, 5) != 5 || strcmp(f[0], "FILE") != 0)
        return -1;
    if (!safe_relative_path(f[1]) || strlen(f[1]) >= MAX_PATH_LEN ||
        strlen(f[4]) >= MAX_DESC)
        return -1;
    if (!parse_long(f[2], 0, LLONG_MAX, &size) ||
        !parse_long(f[3], LLONG_MIN, LLONG_MAX, &mtime))
        return -1;

    text_clean(f[1]);
    text_clean(f[4]);
    entry->size = size;
    entry->mtime = mtime;
    entry->path = strdup(f[1]);
    entry->desc = strdup(f[4]);
    entry->folded_path = strdup(f[1]);
    entry->folded_desc = strdup(f[4]);
    if (!entry->path || !entry->desc || !entry->folded_path || !entry->folded_desc)
        return -1;
    fold_text(entry->folded_path);
    fold_text(entry->folded_desc);
    return 0;
}

/* PUBLISH <hôte> <port> <nombre>, suivi de <nombre> lignes FILE. */
static int cmd_publish(Client *c, char **f)
{
    long long port, count;
    char host[MAX_HOST];

    if (c->session == NULL) {
        reply_err(c, "authentification requise");
        return CMD_CLOSE;
    }
    if (!valid_hostname(f[1]) || !parse_long(f[2], 1, 65535, &port) ||
        !parse_long(f[3], 0, MAX_FILES, &count)) {
        reply_err(c, "annonce invalide");
        return CMD_CLOSE;
    }
    snprintf(host, sizeof host, "%s", f[1]);

    /* calloc : les pointeurs non remplis restent nuls pour free_entries(). */
    FileEntry *files = calloc(count > 0 ? (size_t)count : 1, sizeof *files);
    if (files == NULL) {
        reply_err(c, "erreur interne");
        return CMD_CLOSE;
    }
    for (long long i = 0; i < count; i++) {
        if (read_file_entry(c, &files[i]) < 0) {
            free_entries(files, (size_t)count);
            reply_err(c, "description de fichier invalide");
            return CMD_CLOSE;
        }
    }

    /* La nouvelle liste remplace l'ancienne d'un seul coup. */
    Session *s = c->session;
    pthread_mutex_lock(&g_lock);
    FileEntry *old = s->files;
    size_t old_count = s->file_count;
    s->files = files;
    s->file_count = (size_t)count;
    snprintf(s->host, sizeof s->host, "%s", host);
    s->port = (int)port;
    pthread_mutex_unlock(&g_lock);
    free_entries(old, old_count);

    log_line("[pair] %s partage %lld fichier(s) depuis %s:%lld",
             s->user, count, host, port);
    return reply_ok(c);
}

static int cmd_heartbeat(Client *c)
{
    if (c->session == NULL) {
        reply_err(c, "authentification requise");
        return CMD_CLOSE;
    }
    return reply_ok(c);
}

static int cmd_logout(Client *c)
{
    if (c->session == NULL) {
        reply_err(c, "authentification requise");
        return CMD_CLOSE;
    }
    log_line("[pair] %s parti (départ annoncé)", c->session->user);
    session_remove(c->session);
    c->session = NULL;
    reply_ok(c);
    return CMD_LOGOUT;
}

/* SEARCH <critère de tri> <asc|desc> <mots-clés> */
static int cmd_search(Client *c, char **f)
{
    SortKey key;
    int descending;

    if (!sort_key_parse(f[1], &key))
        return reply_err(c, "critère de tri inconnu");
    if (strcmp(f[2], "asc") == 0)
        descending = 0;
    else if (strcmp(f[2], "desc") == 0)
        descending = 1;
    else
        return reply_err(c, "ordre de tri inconnu");

    text_clean(f[3]);
    char query[MAX_LINE];
    snprintf(query, sizeof query, "%s", f[3]);
    fold_text(query);

    char *terms[MAX_TERMS];
    int term_count = 0;
    char *save = NULL;
    for (char *t = strtok_r(query, " ", &save); t != NULL;
         t = strtok_r(NULL, " ", &save)) {
        if (term_count == MAX_TERMS)
            return reply_err(c, "trop de mots-clés (16 au maximum)");
        terms[term_count++] = t;
    }
    if (term_count == 0)
        return reply_err(c, "mot-clé vide");

    Result *results = NULL;
    size_t count = 0, cap = 0;
    int failed = 0;

    pthread_mutex_lock(&g_lock);
    for (Session *s = g_sessions; s != NULL && !failed; s = s->next) {
        /* Un pair local au central est joignable à l'adresse du central. */
        const char *ip = ip_is_loopback(s->ip) ? c->local_ip : s->ip;
        for (size_t i = 0; i < s->file_count && !failed; i++) {
            int score = match_score(&s->files[i], terms, term_count);
            if (score > 0 &&
                result_append(&results, &count, &cap, s, ip, &s->files[i], score) < 0)
                failed = 1;
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (failed) {
        results_free(results, count);
        return reply_err(c, "erreur interne");
    }

    results_sort(results, count, key, descending);
    size_t sent = count < MAX_RESULTS ? count : MAX_RESULTS;

    int status = send_line(c->conn.fd, "RESULTS\t%zu\t%zu\n", sent, count);
    for (size_t i = 0; i < sent && status == 0; i++) {
        const Result *r = &results[i];
        status = send_line(c->conn.fd, "R\t%s\t%s\t%s\t%d\t%s\t%lld\t%lld\t%d\t%s\n",
                           r->user, r->host, r->ip, r->port, r->path,
                           r->size, r->mtime, r->score, r->desc);
    }
    results_free(results, count);

    log_line("[recherche] « %s » : %zu résultat(s)", f[3], count);
    return status == 0 ? CMD_KEEP : CMD_CLOSE;
}

static int dispatch(Client *c, char *line)
{
    char *f[4];
    int n = split_fields(line, f, 4);

    if (n == 4 && strcmp(f[0], "REGISTER") == 0)
        return cmd_register(c, f);
    if (n == 2 && strcmp(f[0], "LOGIN") == 0)
        return cmd_login(c, f);
    if (n == 2 && strcmp(f[0], "AUTH") == 0)
        return cmd_auth(c, f);
    if (n == 4 && strcmp(f[0], "PUBLISH") == 0)
        return cmd_publish(c, f);
    if (n == 1 && strcmp(f[0], "HEARTBEAT") == 0)
        return cmd_heartbeat(c);
    if (n == 1 && strcmp(f[0], "LOGOUT") == 0)
        return cmd_logout(c);
    if (n == 4 && strcmp(f[0], "SEARCH") == 0)
        return cmd_search(c, f);
    return reply_err(c, "commande inconnue");
}

/* ------------------------------------------------------------------ */
/* Connexions                                                         */
/* ------------------------------------------------------------------ */

static void *client_thread(void *arg)
{
    Client *c = arg;
    char line[MAX_LINE];
    const char *reason = NULL;

    while (reason == NULL) {
        int r = conn_read_line(&c->conn, line, sizeof line);
        if (r == NET_TIMEOUT)
            reason = "plus de signal de vie";
        else if (r == NET_EOF)
            reason = "connexion fermée";
        else if (r != NET_OK)
            reason = "erreur réseau ou ligne invalide";
        else {
            int action = dispatch(c, line);
            if (action == CMD_LOGOUT)
                reason = "départ annoncé";
            else if (action == CMD_CLOSE)
                reason = "erreur de protocole";
        }
    }

    if (c->session != NULL) {
        log_line("[pair] %s retiré (%s)", c->session->user, reason);
        session_remove(c->session);
    }
    close(c->conn.fd);
    free(c);
    return NULL;
}

static void start_client(int fd)
{
    Client *c = calloc(1, sizeof *c);
    if (c == NULL) {
        close(fd);
        return;
    }
    conn_init(&c->conn, fd);
    sock_configure(fd, g_peer_timeout);
    if (sock_peer_ip(fd, c->ip) < 0 || sock_local_ip(fd, c->local_ip) < 0) {
        close(fd);
        free(c);
        return;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, client_thread, c) != 0) {
        close(fd);
        free(c);
        return;
    }
    pthread_detach(thread);
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage : %s [-t délai_de_vie_en_s] [-f fichier_utilisateurs] <port>\n",
            program);
    exit(2);
}

int main(int argc, char **argv)
{
    int opt;
    long long value;

    while ((opt = getopt(argc, argv, "t:f:")) != -1) {
        switch (opt) {
        case 't':
            if (!parse_long(optarg, MIN_PEER_TIMEOUT, 86400, &value))
                usage(argv[0]);
            g_peer_timeout = (int)value;
            break;
        case 'f':
            g_users_path = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }
    if (argc - optind != 1 || !parse_long(argv[optind], 0, 65535, &value))
        usage(argv[0]);

    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    load_users();

    int listen_fd = tcp_listen((int)value);
    if (listen_fd < 0) {
        perror("Écoute impossible");
        return 1;
    }
    log_line("Serveur central en écoute sur le port %d "
             "(%zu compte(s), délai de vie des pairs : %d s)",
             tcp_local_port(listen_fd), g_user_count, g_peer_timeout);

    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd >= 0) {
            start_client(fd);
        } else if (errno != EINTR) {
            log_line("accept : %s", strerror(errno));
            usleep(100000);
        }
    }
}
