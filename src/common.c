/*
 * common.c - Outils réseau et texte partagés par les trois programmes.
 */
#include "common.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Sockets                                                            */
/* ------------------------------------------------------------------ */

/* Ouvre une socket d'écoute TCP. Le port 0 laisse le système choisir. */
int tcp_listen(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 ||
        listen(fd, SOMAXCONN) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int tcp_local_port(int fd)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;
    if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0)
        return -1;
    return ntohs(addr.sin_port);
}

/* connect() avec délai : un hôte éteint ne doit pas bloquer le programme. */
static int connect_with_timeout(int fd, const struct sockaddr *addr,
                                socklen_t len, int timeout_s)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    if (connect(fd, addr, len) < 0) {
        if (errno != EINPROGRESS)
            return -1;

        struct pollfd p = { .fd = fd, .events = POLLOUT, .revents = 0 };
        int r;
        do {
            r = poll(&p, 1, timeout_s * 1000);
        } while (r < 0 && errno == EINTR);

        if (r <= 0)
            return -1;

        int err = 0;
        socklen_t err_len = sizeof err;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err != 0)
            return -1;
    }
    return fcntl(fd, F_SETFL, flags);
}

/* Résout le nom d'hôte et se connecte. Renvoie la socket ou -1. */
int tcp_connect(const char *host, int port, int timeout_s)
{
    struct addrinfo hints, *list, *ai;
    char service[16];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(service, sizeof service, "%d", port);

    if (getaddrinfo(host, service, &hints, &list) != 0)
        return -1;

    int fd = -1;
    for (ai = list; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, timeout_s) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(list);
    return fd;
}

/* Délais d'envoi et de réception, et envoi immédiat des petits messages. */
void sock_configure(int fd, int timeout_s)
{
    struct timeval tv;
    int one = 1;

    tv.tv_sec = timeout_s;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

static int addr_to_text(const struct sockaddr_in *addr, char ip[MAX_IP])
{
    return inet_ntop(AF_INET, &addr->sin_addr, ip, MAX_IP) ? 0 : -1;
}

/* Adresse IP de l'autre extrémité de la connexion. */
int sock_peer_ip(int fd, char ip[MAX_IP])
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;
    if (getpeername(fd, (struct sockaddr *)&addr, &len) < 0)
        return -1;
    return addr_to_text(&addr, ip);
}

/* Adresse IP locale utilisée par cette connexion. */
int sock_local_ip(int fd, char ip[MAX_IP])
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;
    if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0)
        return -1;
    return addr_to_text(&addr, ip);
}

int ip_is_loopback(const char *ip)
{
    return strncmp(ip, "127.", 4) == 0;
}

/* ------------------------------------------------------------------ */
/* Lecture et envoi                                                   */
/* ------------------------------------------------------------------ */

void conn_init(Conn *c, int fd)
{
    c->fd = fd;
    c->start = 0;
    c->end = 0;
}

/* Remplit le tampon vide. Renvoie un code NET_*. */
static int conn_fill(Conn *c)
{
    for (;;) {
        ssize_t n = recv(c->fd, c->buf, sizeof c->buf, 0);
        if (n > 0) {
            c->start = 0;
            c->end = (size_t)n;
            return NET_OK;
        }
        if (n == 0)
            return NET_EOF;
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return NET_TIMEOUT;
        return NET_ERROR;
    }
}

/*
 * Lit une ligne terminée par '\n' et enlève la fin de ligne.
 * Une ligne trop longue ou contenant un octet nul est une erreur.
 */
int conn_read_line(Conn *c, char *line, size_t size)
{
    size_t len = 0;

    for (;;) {
        while (c->start < c->end) {
            char ch = c->buf[c->start++];
            if (ch == '\n') {
                if (len > 0 && line[len - 1] == '\r')
                    len--;
                line[len] = '\0';
                return NET_OK;
            }
            if (ch == '\0' || len + 1 >= size)
                return NET_ERROR;
            line[len++] = ch;
        }
        int r = conn_fill(c);
        if (r != NET_OK)
            return r;
    }
}

/*
 * Lit au plus max octets. Consomme d'abord ce que le tampon contient déjà.
 * Renvoie le nombre d'octets lus, ou un code NET_* (0 ou négatif).
 */
ssize_t conn_read_some(Conn *c, void *out, size_t max)
{
    if (c->start == c->end) {
        int r = conn_fill(c);
        if (r != NET_OK)
            return r;
    }
    size_t n = c->end - c->start;
    if (n > max)
        n = max;
    memcpy(out, c->buf + c->start, n);
    c->start += n;
    return (ssize_t)n;
}

int send_all(int fd, const void *data, size_t len)
{
    const char *p = data;

    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int send_line(int fd, const char *fmt, ...)
{
    char buf[MAX_LINE];
    va_list ap;

    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= sizeof buf)
        return -1;
    return send_all(fd, buf, (size_t)n);
}

/*
 * Écrit une ligne de journal, ou l'abandonne si la sortie est bloquée
 * (terminal en pause, tube que personne ne lit). Sinon, un printf() bloqué
 * figerait les threads qui servent le réseau. La ligne reste plus courte
 * que PIPE_BUF (512 octets au minimum) : l'écriture ne bloque donc pas.
 */
void log_line(const char *fmt, ...)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;

    text_truncate(buf, sizeof buf - 2);
    size_t len = strlen(buf);
    buf[len++] = '\n';

    struct pollfd out = { .fd = STDOUT_FILENO, .events = POLLOUT, .revents = 0 };
    pthread_mutex_lock(&lock);
    if (poll(&out, 1, 0) == 1 && (out.revents & POLLOUT)) {
        ssize_t ignored = write(STDOUT_FILENO, buf, len);
        (void)ignored;
    }
    pthread_mutex_unlock(&lock);
}

/* ------------------------------------------------------------------ */
/* Texte et validation                                                */
/* ------------------------------------------------------------------ */

/*
 * Découpe une ligne sur les tabulations.
 * Renvoie le nombre de champs, ou max + 1 s'il y en a trop.
 */
int split_fields(char *line, char **fields, int max)
{
    int n = 0;
    char *p = line;

    while (n < max) {
        fields[n++] = p;
        char *tab = strchr(p, '\t');
        if (tab == NULL)
            return n;
        *tab = '\0';
        p = tab + 1;
    }
    return max + 1;
}

/* Convertit un entier décimal et vérifie ses bornes. Renvoie 1 si valide. */
int parse_long(const char *s, long long min, long long max, long long *out)
{
    char *end;

    if (*s == '\0')
        return 0;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || *end != '\0' || v < min || v > max)
        return 0;
    *out = v;
    return 1;
}

/*
 * Remplace les caractères de contrôle : tabulation, séquences de terminal,
 * et aussi U+0080 à U+009F, qui s'écrivent C2 80 à C2 9F en UTF-8.
 */
void text_clean(char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7f) {
            *s = ' ';
        } else if (c == 0xC2 && (unsigned char)s[1] >= 0x80 &&
                   (unsigned char)s[1] <= 0x9F) {
            *s = ' ';
            *++s = ' ';
        }
    }
}

/* Raccourcit un texte sans couper un caractère UTF-8 en deux. */
void text_truncate(char *s, size_t max_len)
{
    if (strlen(s) <= max_len)
        return;
    while (max_len > 0 && ((unsigned char)s[max_len] & 0xC0) == 0x80)
        max_len--;
    s[max_len] = '\0';
}

int valid_username(const char *s)
{
    size_t n = strlen(s);

    if (n == 0 || n >= MAX_USER)
        return 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (!isalnum(c) && c != '_' && c != '-' && c != '.')
            return 0;
    }
    return 1;
}

int valid_hostname(const char *s)
{
    size_t n = strlen(s);

    if (n == 0 || n >= MAX_HOST)
        return 0;
    for (; *s; s++) {
        if (!isgraph((unsigned char)*s))
            return 0;
    }
    return 1;
}

/* Chemin relatif sans "..", sans composant caché et sans composant vide. */
int safe_relative_path(const char *path)
{
    const char *p = path;

    if (*p == '\0' || *p == '/')
        return 0;
    for (;;) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if (len == 0 || p[0] == '.')
            return 0;
        if (slash == NULL)
            return 1;
        p = slash + 1;
    }
}

/* Octets aléatoires pour les sels et les défis d'authentification. */
int random_bytes(void *buf, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    unsigned char *p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0) {
            close(fd);
            return -1;
        }
        p += r;
        n -= (size_t)r;
    }
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tri des résultats                                                  */
/* ------------------------------------------------------------------ */

static const char *const sort_names[] = {
    [SORT_SCORE] = "pertinence",
    [SORT_NAME]  = "nom",
    [SORT_SIZE]  = "taille",
    [SORT_DATE]  = "date",
    [SORT_HOST]  = "hote",
};

const char *sort_key_name(SortKey key)
{
    return sort_names[key];
}

int sort_key_parse(const char *name, SortKey *key)
{
    for (size_t i = 0; i < sizeof sort_names / sizeof sort_names[0]; i++) {
        if (strcmp(name, sort_names[i]) == 0) {
            *key = (SortKey)i;
            return 1;
        }
    }
    return 0;
}

/* qsort() ne transmet pas de contexte : chaque thread garde le sien. */
static _Thread_local SortKey current_key;
static _Thread_local int current_descending;

static int compare_numbers(long long a, long long b)
{
    return (a > b) - (a < b);
}

static int compare_results(const void *pa, const void *pb)
{
    const Result *a = pa;
    const Result *b = pb;
    int c = 0;

    switch (current_key) {
    case SORT_SCORE: c = compare_numbers(a->score, b->score); break;
    case SORT_NAME:  c = strcasecmp(a->path, b->path); break;
    case SORT_SIZE:  c = compare_numbers(a->size, b->size); break;
    case SORT_DATE:  c = compare_numbers(a->mtime, b->mtime); break;
    case SORT_HOST:
        c = strcasecmp(a->host, b->host);
        if (c == 0)
            c = compare_numbers(a->port, b->port);
        break;
    }
    if (current_descending)
        c = -c;
    if (c != 0)
        return c;

    /* À égalité, l'ordre reste stable : chemin, puis utilisateur. */
    c = strcmp(a->path, b->path);
    return c != 0 ? c : strcmp(a->user, b->user);
}

void results_sort(Result *results, size_t count, SortKey key, int descending)
{
    if (count < 2)
        return;
    current_key = key;
    current_descending = descending;
    qsort(results, count, sizeof *results, compare_results);
}

void results_free(Result *results, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        free(results[i].path);
        free(results[i].desc);
    }
    free(results);
}
