/*
 * common.h - Définitions partagées par les trois programmes :
 * limites du protocole, outils réseau, résultats de recherche.
 */
#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <sys/types.h>

/* Limites du protocole (les tailles comptent le '\0' final). */
#define MAX_LINE     4096   /* une ligne de protocole */
#define MAX_USER     33     /* nom d'utilisateur */
#define MAX_HASH     128    /* empreinte crypt() */
#define MAX_HOST     256    /* nom d'hôte */
#define MAX_IP       16     /* adresse IPv4 en texte */
#define MAX_PATH_LEN 1024   /* chemin relatif d'un fichier partagé */
#define MAX_DESC     1024   /* description d'un fichier */
#define MAX_FILES    10000  /* fichiers annoncés par un même pair */
#define MAX_RESULTS  1000   /* résultats renvoyés par une recherche */

/* Fichiers spéciaux du répertoire partagé. Ils ne sont jamais partagés. */
#define DESC_FILE "descriptions.txt"
#define PORT_FILE ".serveur_ftp.port"

/* Codes de retour des lectures réseau. */
enum { NET_OK = 1, NET_EOF = 0, NET_ERROR = -1, NET_TIMEOUT = -2 };

/* Connexion TCP avec un tampon de lecture. */
typedef struct {
    int    fd;
    size_t start;     /* première donnée non lue dans buf */
    size_t end;       /* fin des données présentes dans buf */
    char   buf[8192];
} Conn;

/* Sockets IPv4 */
int  tcp_listen(int port);
int  tcp_local_port(int fd);
int  tcp_connect(const char *host, int port, int timeout_s);
void sock_configure(int fd, int timeout_s);
int  sock_peer_ip(int fd, char ip[MAX_IP]);
int  sock_local_ip(int fd, char ip[MAX_IP]);
int  ip_is_loopback(const char *ip);

/* Lecture et envoi */
void    conn_init(Conn *c, int fd);
int     conn_read_line(Conn *c, char *line, size_t size);
ssize_t conn_read_some(Conn *c, void *out, size_t max);
int     send_all(int fd, const void *data, size_t len);
int     send_line(int fd, const char *fmt, ...)
            __attribute__((format(printf, 2, 3)));

/* Journal des serveurs : n'attend jamais la sortie standard. */
void    log_line(const char *fmt, ...)
            __attribute__((format(printf, 1, 2)));

/* Texte et validation */
int  split_fields(char *line, char **fields, int max);
int  parse_long(const char *s, long long min, long long max, long long *out);
void text_clean(char *s);
void text_truncate(char *s, size_t max_len);
int  valid_username(const char *s);
int  valid_hostname(const char *s);
int  safe_relative_path(const char *path);
int  random_bytes(void *buf, size_t n);

/* Résultats de recherche : triés par le serveur central et par le client. */
typedef enum { SORT_SCORE, SORT_NAME, SORT_SIZE, SORT_DATE, SORT_HOST } SortKey;

typedef struct {
    char user[MAX_USER];
    char host[MAX_HOST];   /* nom d'hôte annoncé par le pair */
    char ip[MAX_IP];       /* adresse IP vue par le serveur central */
    int  port;             /* port du serveur de transfert du pair */
    char *path;
    char *desc;
    long long size;
    long long mtime;
    int  score;
} Result;

const char *sort_key_name(SortKey key);
int  sort_key_parse(const char *name, SortKey *key);
void results_sort(Result *results, size_t count, SortKey key, int descending);
void results_free(Result *results, size_t count);

#endif
