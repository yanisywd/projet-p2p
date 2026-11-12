/*
 * client_ftp.c - Client de transfert exécuté sur chaque site utilisateur.
 *
 * Il demande un mot-clé, interroge le serveur central, trie et affiche les
 * résultats, puis télécharge le fichier choisi chez le pair qui le possède.
 * Le protocole ne contient aucune commande d'envoi : pas d'upload possible.
 *
 * Un fichier téléchargé rejoint le répertoire partagé et sa description.
 * Le client prévient ensuite le serveur de transfert local, qui met à jour
 * la liste du serveur central.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define CONNECT_TIMEOUT   5
#define NETWORK_TIMEOUT   30
#define CHUNK_SIZE        65536
#define MAX_COMMAND       1024

static const char *g_central_host;
static int g_central_port;

static Result *g_results;
static size_t  g_result_count;
static size_t  g_result_total;        /* résultats trouvés, même non reçus */
static SortKey g_sort_key = SORT_SCORE;
static int     g_sort_descending = 1;

/* Fichier en cours de réception, supprimé si l'utilisateur interrompt. */
static char g_tmp_path[64];
static volatile sig_atomic_t g_tmp_in_use;

static void remove_tmp_and_quit(int sig)
{
    if (g_tmp_in_use)
        unlink(g_tmp_path);
    signal(sig, SIG_DFL);
    raise(sig);
}

/* ------------------------------------------------------------------ */
/* Saisie et affichage                                                */
/* ------------------------------------------------------------------ */

/* Renvoie 1 si une ligne est lue, 0 en fin d'entrée. */
static int read_command(const char *prompt, char *buf, size_t size)
{
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)size, stdin) == NULL)
        return 0;

    size_t n = strcspn(buf, "\r\n");
    if (buf[n] == '\0' && n + 1 == size) {     /* ligne plus longue que buf */
        int c;
        while ((c = getchar()) != EOF && c != '\n')
            ;
    }
    buf[n] = '\0';
    return 1;
}

static void format_size(long long size, char *out, size_t out_size)
{
    static const char *const units[] = { "Ko", "Mo", "Go", "To" };

    if (size < 1024) {
        snprintf(out, out_size, "%lld o", size);
        return;
    }
    double value = (double)size / 1024;
    int unit = 0;
    while (value >= 1024 && unit < 3) {
        value /= 1024;
        unit++;
    }
    snprintf(out, out_size, "%.1f %s", value, units[unit]);
}

static void format_date(long long mtime, char *out, size_t out_size)
{
    time_t t = (time_t)mtime;
    struct tm tm;

    if (localtime_r(&t, &tm) == NULL ||
        strftime(out, out_size, "%Y-%m-%d %H:%M", &tm) == 0)
        snprintf(out, out_size, "date inconnue");
}

static void show_results(void)
{
    if (g_result_count == 0) {
        printf("Aucun résultat.\n");
        return;
    }
    if (g_result_total > g_result_count)
        printf("%zu résultats affichés sur %zu", g_result_count, g_result_total);
    else
        printf("%zu résultat(s)", g_result_count);
    printf(", tri : %s (%s)\n", sort_key_name(g_sort_key),
           g_sort_descending ? "décroissant" : "croissant");

    for (size_t i = 0; i < g_result_count; i++) {
        const Result *r = &g_results[i];
        char size[32], date[32];
        format_size(r->size, size, sizeof size);
        format_date(r->mtime, date, sizeof date);
        printf("%4zu. %s\n", i + 1, r->path);
        printf("      %s | %s | %s sur %s:%d | pertinence %d\n",
               size, date, r->user, r->host, r->port, r->score);
        if (r->desc[0] != '\0')
            printf("      %s\n", r->desc);
    }
}

/* ------------------------------------------------------------------ */
/* Recherche                                                          */
/* ------------------------------------------------------------------ */

static void clear_results(void)
{
    results_free(g_results, g_result_count);
    g_results = NULL;
    g_result_count = 0;
    g_result_total = 0;
}

/* Décode une ligne "R ..." envoyée par le serveur central. */
static int parse_result(char *line, Result *r)
{
    char *f[10];
    long long port, size, mtime, score;

    if (split_fields(line, f, 10) != 10 || strcmp(f[0], "R") != 0)
        return -1;
    if (!parse_long(f[4], 1, 65535, &port) ||
        !parse_long(f[6], 0, LLONG_MAX, &size) ||
        !parse_long(f[7], LLONG_MIN, LLONG_MAX, &mtime) ||
        !parse_long(f[8], 0, INT_MAX, &score) ||
        !safe_relative_path(f[5]) ||
        strlen(f[1]) >= MAX_USER || strlen(f[2]) >= MAX_HOST || strlen(f[3]) >= MAX_IP)
        return -1;

    /* Le texte vient du réseau : aucun code de contrôle à l'écran. */
    text_clean(f[1]);
    text_clean(f[2]);
    text_clean(f[3]);
    text_clean(f[5]);
    text_clean(f[9]);

    memset(r, 0, sizeof *r);
    snprintf(r->user, sizeof r->user, "%s", f[1]);
    snprintf(r->host, sizeof r->host, "%s", f[2]);
    snprintf(r->ip, sizeof r->ip, "%s", f[3]);
    r->port = (int)port;
    r->size = size;
    r->mtime = mtime;
    r->score = (int)score;
    r->path = strdup(f[5]);
    r->desc = strdup(f[9]);
    if (r->path == NULL || r->desc == NULL) {
        free(r->path);
        free(r->desc);
        return -1;
    }
    return 0;
}

static void do_search(const char *keyword)
{
    char query[MAX_COMMAND];
    char line[MAX_LINE];
    char *f[3];
    long long received, total;

    snprintf(query, sizeof query, "%s", keyword);
    text_clean(query);

    int fd = tcp_connect(g_central_host, g_central_port, CONNECT_TIMEOUT);
    if (fd < 0) {
        printf("Serveur central injoignable (%s:%d).\n",
               g_central_host, g_central_port);
        return;
    }
    sock_configure(fd, NETWORK_TIMEOUT);

    Conn conn;
    conn_init(&conn, fd);

    if (send_line(fd, "SEARCH\t%s\t%s\t%s\n", sort_key_name(g_sort_key),
                  g_sort_descending ? "desc" : "asc", query) < 0 ||
        conn_read_line(&conn, line, sizeof line) != NET_OK) {
        printf("Le serveur central ne répond pas.\n");
        close(fd);
        return;
    }

    int n = split_fields(line, f, 3);
    if (n == 2 && strcmp(f[0], "ERR") == 0) {
        text_clean(f[1]);
        printf("Recherche refusée : %s\n", f[1]);
        close(fd);
        return;
    }
    if (n != 3 || strcmp(f[0], "RESULTS") != 0 ||
        !parse_long(f[1], 0, MAX_RESULTS, &received) ||
        !parse_long(f[2], received, LLONG_MAX, &total)) {
        printf("Réponse invalide du serveur central.\n");
        close(fd);
        return;
    }

    Result *results = calloc(received > 0 ? (size_t)received : 1, sizeof *results);
    if (results == NULL) {
        printf("Mémoire insuffisante.\n");
        close(fd);
        return;
    }

    size_t count = 0;
    for (; count < (size_t)received; count++) {
        if (conn_read_line(&conn, line, sizeof line) != NET_OK ||
            parse_result(line, &results[count]) < 0) {
            printf("Réponse incomplète du serveur central.\n");
            results_free(results, count);
            close(fd);
            return;
        }
    }
    close(fd);

    clear_results();
    g_results = results;
    g_result_count = count;
    g_result_total = (size_t)total;
    show_results();
}

/* Trie côté client les résultats déjà reçus, sans interroger le serveur. */
static void do_sort(char *args)
{
    char *save = NULL;
    char *name = strtok_r(args, " ", &save);
    char *order = strtok_r(NULL, " ", &save);
    SortKey key;
    int descending;

    if (name != NULL && strcmp(name, "hôte") == 0)
        name = "hote";
    if (name == NULL || !sort_key_parse(name, &key) ||
        strtok_r(NULL, " ", &save) != NULL) {
        printf("Usage : trier <pertinence|nom|taille|date|hote> [asc|desc]\n");
        return;
    }
    if (order == NULL)
        descending = key == SORT_SCORE;
    else if (strcmp(order, "asc") == 0)
        descending = 0;
    else if (strcmp(order, "desc") == 0)
        descending = 1;
    else {
        printf("Usage : trier <pertinence|nom|taille|date|hote> [asc|desc]\n");
        return;
    }

    g_sort_key = key;
    g_sort_descending = descending;
    results_sort(g_results, g_result_count, key, descending);
    show_results();
}

/* ------------------------------------------------------------------ */
/* Téléchargement                                                     */
/* ------------------------------------------------------------------ */

/* Un nom local : pas de chemin, pas de fichier caché ni réservé. */
static int valid_local_name(const char *name)
{
    return name[0] != '\0' && name[0] != '.' && strchr(name, '/') == NULL &&
           strcasecmp(name, DESC_FILE) != 0 && strlen(name) < MAX_PATH_LEN;
}

static int write_all(int fd, const char *data, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Le fichier temporaire est caché : il ne sera jamais partagé incomplet. */
static int receive_file(Conn *conn, long long size, const char *tmp_path)
{
    unlink(tmp_path);
    int out = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (out < 0) {
        perror("Création du fichier");
        return -1;
    }

    char buf[CHUNK_SIZE];
    long long left = size;
    while (left > 0) {
        size_t want = left < CHUNK_SIZE ? (size_t)left : CHUNK_SIZE;
        ssize_t n = conn_read_some(conn, buf, want);
        if (n <= 0) {
            printf("Transfert interrompu : %lld octet(s) manquant(s).\n", left);
            close(out);
            unlink(tmp_path);
            return -1;
        }
        if (write_all(out, buf, (size_t)n) < 0) {
            perror("Écriture du fichier");
            close(out);
            unlink(tmp_path);
            return -1;
        }
        left -= n;
    }
    if (close(out) < 0) {
        perror("Écriture du fichier");
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

/*
 * Ajoute un bloc à descriptions.txt. La ligne vide de tête sépare le bloc du
 * précédent, même si le fichier se termine par un nom sans description.
 */
static int add_description(const char *name, const char *desc)
{
    int fd = open(DESC_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return -1;

    const char *prefix = "";
    off_t end = lseek(fd, 0, SEEK_END);
    if (end > 0) {
        char last = '\n';
        if (pread(fd, &last, 1, end - 1) != 1)
            last = '\n';
        prefix = last == '\n' ? "\n" : "\n\n";
    }

    char block[MAX_PATH_LEN + MAX_DESC + 8];
    int len = snprintf(block, sizeof block, "%s%s\n%s\n", prefix, name, desc);
    int status = (len > 0 && (size_t)len < sizeof block &&
                  write_all(fd, block, (size_t)len) == 0) ? 0 : -1;
    if (close(fd) < 0)
        status = -1;
    return status;
}

/* Demande au serveur local de relire son répertoire. Renvoie 0 si c'est fait. */
static int notify_local_server(void)
{
    char text[32] = "";
    long long port;

    FILE *f = fopen(PORT_FILE, "r");
    if (f == NULL)
        return -1;
    char *got = fgets(text, sizeof text, f);
    fclose(f);
    if (got == NULL)
        return -1;
    text[strcspn(text, "\r\n")] = '\0';
    if (!parse_long(text, 1, 65535, &port))
        return -1;

    int fd = tcp_connect("127.0.0.1", (int)port, CONNECT_TIMEOUT);
    if (fd < 0)
        return -1;
    sock_configure(fd, CONNECT_TIMEOUT);

    Conn conn;
    char line[64];
    conn_init(&conn, fd);
    int status = (send_line(fd, "RESCAN\n") == 0 &&
                  conn_read_line(&conn, line, sizeof line) == NET_OK &&
                  strcmp(line, "OK") == 0) ? 0 : -1;
    close(fd);
    return status;
}

/*
 * L'adresse vue par le serveur central d'abord : ce même nom d'hôte peut
 * désigner une autre machine de notre côté du réseau. Le nom sert de repli.
 */
static int connect_peer(const Result *r)
{
    int fd = tcp_connect(r->ip, r->port, CONNECT_TIMEOUT);
    if (fd < 0 && strcmp(r->host, r->ip) != 0)
        fd = tcp_connect(r->host, r->port, CONNECT_TIMEOUT);
    return fd;
}

/* Demande un nom libre si le fichier existe. Renvoie 0, ou -1 si annulé. */
static int choose_local_name(char *name, size_t size)
{
    struct stat st;

    while (lstat(name, &st) == 0) {
        char prompt[MAX_PATH_LEN + 64];
        char answer[MAX_PATH_LEN];

        snprintf(prompt, sizeof prompt,
                 "« %s » existe déjà. Nouveau nom (vide pour annuler) : ", name);
        if (!read_command(prompt, answer, sizeof answer) || answer[0] == '\0')
            return -1;
        if (!valid_local_name(answer)) {
            printf("Nom invalide.\n");
            continue;
        }
        snprintf(name, size, "%s", answer);
    }
    if (errno != ENOENT) {
        perror("Nom de fichier inutilisable");
        return -1;
    }
    return 0;
}

/*
 * Donne au fichier reçu son nom définitif, sans jamais écraser un fichier :
 * link() échoue si le nom a été pris pendant le transfert, rename() non.
 */
static int install_file(const char *tmp_path, const char *name)
{
    if (link(tmp_path, name) == 0) {
        unlink(tmp_path);
        return 0;
    }
    if (errno == EEXIST)
        return -1;

    /* Disque sans liens physiques (clé USB par exemple). */
    struct stat st;
    if (lstat(name, &st) == 0) {
        errno = EEXIST;
        return -1;
    }
    return rename(tmp_path, name);
}

static void do_download(const char *arg)
{
    long long number;

    if (g_result_count == 0) {
        printf("Aucun résultat : lancez d'abord une recherche.\n");
        return;
    }
    if (!parse_long(arg, 1, (long long)g_result_count, &number)) {
        printf("Numéro invalide : choisissez entre 1 et %zu.\n", g_result_count);
        return;
    }
    const Result *r = &g_results[number - 1];

    /* Le fichier arrive à la racine du partage, sans le chemin distant. */
    const char *slash = strrchr(r->path, '/');
    char name[MAX_PATH_LEN];
    snprintf(name, sizeof name, "%s", slash ? slash + 1 : r->path);
    if (!valid_local_name(name)) {
        printf("Ce nom de fichier est refusé : %s\n", name);
        return;
    }
    if (choose_local_name(name, sizeof name) < 0) {
        printf("Téléchargement annulé.\n");
        return;
    }

    int fd = connect_peer(r);
    if (fd < 0) {
        printf("Pair injoignable (%s:%d). Il s'est peut-être déconnecté.\n",
               r->host, r->port);
        return;
    }
    sock_configure(fd, NETWORK_TIMEOUT);

    Conn conn;
    char line[MAX_LINE];
    char *f[2];
    long long size;

    conn_init(&conn, fd);
    if (send_line(fd, "GET\t%s\n", r->path) < 0 ||
        conn_read_line(&conn, line, sizeof line) != NET_OK) {
        printf("Le pair ne répond pas.\n");
        close(fd);
        return;
    }

    int n = split_fields(line, f, 2);
    if (n == 2 && strcmp(f[0], "ERR") == 0) {
        text_clean(f[1]);
        printf("Le pair refuse : %s\n", f[1]);
        close(fd);
        return;
    }
    if (n != 2 || strcmp(f[0], "OK") != 0 ||
        !parse_long(f[1], 0, LLONG_MAX, &size)) {
        printf("Réponse invalide du pair.\n");
        close(fd);
        return;
    }

    g_tmp_in_use = 1;
    int received = receive_file(&conn, size, g_tmp_path);
    close(fd);
    if (received < 0) {
        g_tmp_in_use = 0;
        return;
    }

    /* Le nom a pu être pris pendant le transfert : on en redemande un. */
    while (install_file(g_tmp_path, name) < 0) {
        int failed_on_other_error = errno != EEXIST;
        if (failed_on_other_error)
            perror("Enregistrement du fichier");
        if (failed_on_other_error || choose_local_name(name, sizeof name) < 0) {
            unlink(g_tmp_path);
            g_tmp_in_use = 0;
            printf("Téléchargement annulé.\n");
            return;
        }
    }
    g_tmp_in_use = 0;

    if (add_description(name, r->desc) < 0)
        printf("Attention : description non enregistrée dans %s\n", DESC_FILE);

    char text[32];
    format_size(size, text, sizeof text);
    printf("Téléchargé : %s (%s) depuis %s\n", name, text, r->user);

    if (notify_local_server() == 0)
        printf("Fichier ajouté au partage : le serveur local va prévenir le serveur central.\n");
    else
        printf("Serveur local non démarré : le fichier sera annoncé à son prochain lancement.\n");
}

/* ------------------------------------------------------------------ */
/* Programme principal                                                */
/* ------------------------------------------------------------------ */

static void show_help(void)
{
    printf("Commandes :\n"
           "  chercher [mot-clé]           cherche un fichier (c)\n"
           "  trier <critère> [asc|desc]   critère : pertinence, nom, taille, date, hote (t)\n"
           "  telecharger <numéro>         télécharge un résultat (d)\n"
           "  liste                        réaffiche les résultats (l)\n"
           "  aide                         affiche cette aide (h)\n"
           "  quitter                      ferme le client (q)\n");
}

/* Sépare le premier mot de la ligne. Renvoie le reste de la ligne. */
static char *split_command(char *line)
{
    char *p = line + strspn(line, " \t");
    memmove(line, p, strlen(p) + 1);

    char *rest = line + strcspn(line, " \t");
    if (*rest != '\0') {
        *rest++ = '\0';
        rest += strspn(rest, " \t");
    }
    return rest;
}

int main(int argc, char **argv)
{
    long long port;

    if (argc != 4 || !parse_long(argv[2], 1, 65535, &port)) {
        fprintf(stderr, "Usage : %s <hôte_central> <port_central> <répertoire_partagé>\n",
                argv[0]);
        return 2;
    }
    g_central_host = argv[1];
    g_central_port = (int)port;

    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    snprintf(g_tmp_path, sizeof g_tmp_path, ".telechargement.%ld.part", (long)getpid());
    signal(SIGINT, remove_tmp_and_quit);
    signal(SIGTERM, remove_tmp_and_quit);
    signal(SIGHUP, remove_tmp_and_quit);

    if (chdir(argv[3]) < 0) {
        perror(argv[3]);
        return 1;
    }

    show_help();

    char line[MAX_COMMAND];
    while (read_command("\nclient> ", line, sizeof line)) {
        char *args = split_command(line);

        if (line[0] == '\0') {
            continue;
        } else if (!strcmp(line, "chercher") || !strcmp(line, "rechercher") ||
                   !strcmp(line, "c")) {
            char keyword[MAX_COMMAND];
            if (args[0] != '\0') {
                snprintf(keyword, sizeof keyword, "%s", args);
            } else if (!read_command("Mot-clé : ", keyword, sizeof keyword)) {
                break;
            }
            do_search(keyword);
        } else if (!strcmp(line, "trier") || !strcmp(line, "t")) {
            do_sort(args);
        } else if (!strcmp(line, "telecharger") || !strcmp(line, "télécharger") ||
                   !strcmp(line, "d")) {
            do_download(args);
        } else if (!strcmp(line, "liste") || !strcmp(line, "l")) {
            show_results();
        } else if (!strcmp(line, "aide") || !strcmp(line, "h")) {
            show_help();
        } else if (!strcmp(line, "quitter") || !strcmp(line, "q")) {
            break;
        } else {
            printf("Commande inconnue. Tapez « aide ».\n");
        }
    }

    clear_results();
    return 0;
}
