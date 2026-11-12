/*
 * auth.c - Empreintes crypt() et preuve d'identité (voir auth.h).
 */
#include "auth.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <crypt.h>
#endif

#include "common.h"
#include "sha256.h"

#define SALT_CHARS \
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#define SHA512_SALT_LEN 16

/* DES étendu : "_", puis 786 433 tours en base 64 (environ 80 ms). */
#define EXT_DES_PREFIX   "_/..1"
#define EXT_DES_SALT_LEN 4

static int random_salt(char *out, size_t n)
{
    unsigned char bytes[32];

    if (n > sizeof bytes || random_bytes(bytes, n) < 0)
        return -1;
    for (size_t i = 0; i < n; i++)
        out[i] = SALT_CHARS[bytes[i] & 63];
    out[n] = '\0';
    return 0;
}

/*
 * Calcule crypt(password, salt).
 *
 * Le résultat doit commencer par le sel demandé. Ce contrôle est essentiel :
 * sur macOS, crypt() ne connaît pas "$6$" et utilise DES en silence, ce qui
 * ne garde que les 8 premiers caractères du mot de passe.
 */
int auth_hash(const char *password, const char *salt, char *hash, size_t size)
{
    const char *result = crypt(password, salt);

    if (result == NULL || strncmp(result, salt, strlen(salt)) != 0)
        return -1;

    size_t len = strlen(result);
    if (len >= size)
        return -1;
    memcpy(hash, result, len + 1);
    return 0;
}

/*
 * Crée un sel : SHA-512 s'il est disponible (Linux), sinon DES étendu (macOS).
 * Ces deux algorithmes utilisent tous les caractères du mot de passe.
 */
int auth_new_salt(char *salt, size_t size)
{
    char random[SHA512_SALT_LEN + 1];
    char probe[MAX_HASH];

    if (random_salt(random, SHA512_SALT_LEN) < 0)
        return -1;
    snprintf(salt, size, "$6$%s$", random);
    if (auth_hash("test", salt, probe, sizeof probe) == 0)
        return 0;

    if (random_salt(random, EXT_DES_SALT_LEN) < 0)
        return -1;
    snprintf(salt, size, EXT_DES_PREFIX "%s", random);
    if (auth_hash("test", salt, probe, sizeof probe) == 0)
        return 0;

    return -1;
}

/*
 * N'accepte que les deux formes créées par auth_new_salt(). Le sel vient du
 * réseau : un serveur malveillant ne peut donc pas imposer DES classique, ni
 * un nombre de tours démesuré qui bloquerait la connexion.
 */
int auth_valid_salt(const char *salt)
{
    size_t len = strlen(salt);

    if (len == 3 + SHA512_SALT_LEN + 1 && strncmp(salt, "$6$", 3) == 0 &&
        salt[len - 1] == '$')
        return strspn(salt + 3, SALT_CHARS) == SHA512_SALT_LEN;

    if (len == strlen(EXT_DES_PREFIX) + EXT_DES_SALT_LEN &&
        strncmp(salt, EXT_DES_PREFIX, strlen(EXT_DES_PREFIX)) == 0)
        return strspn(salt + strlen(EXT_DES_PREFIX), SALT_CHARS) == EXT_DES_SALT_LEN;

    return 0;
}

static void to_hex(const uint8_t *bytes, size_t n, char *hex)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < n; i++) {
        hex[i * 2]     = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 15];
    }
    hex[n * 2] = '\0';
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

/* Décode exactement n octets. Renvoie 1 si le texte est valide. */
static int from_hex(const char *hex, uint8_t *bytes, size_t n)
{
    if (strlen(hex) != n * 2)
        return 0;
    for (size_t i = 0; i < n; i++) {
        int high = hex_digit(hex[i * 2]);
        int low = hex_digit(hex[i * 2 + 1]);
        if (high < 0 || low < 0)
            return 0;
        bytes[i] = (uint8_t)(high << 4 | low);
    }
    return 1;
}

int auth_valid_key(const char *hex)
{
    uint8_t bytes[SHA256_DIGEST_LEN];

    return from_hex(hex, bytes, sizeof bytes);
}

static void client_key(const char *hash, uint8_t key[SHA256_DIGEST_LEN])
{
    static const char label[] = "Client Key";

    hmac_sha256(hash, strlen(hash), label, sizeof label - 1, key);
}

void auth_verifier(const char *hash, char verifier[AUTH_HEX_LEN + 1])
{
    uint8_t key[SHA256_DIGEST_LEN], stored[SHA256_DIGEST_LEN];

    client_key(hash, key);
    sha256(key, sizeof key, stored);
    to_hex(stored, sizeof stored, verifier);
    auth_wipe(key, sizeof key);
}

int auth_new_nonce(char nonce[NONCE_HEX_LEN + 1])
{
    uint8_t bytes[NONCE_HEX_LEN / 2];

    if (random_bytes(bytes, sizeof bytes) < 0)
        return -1;
    to_hex(bytes, sizeof bytes, nonce);
    return 0;
}

/* Calcule key XOR HMAC(stored, nonce). Le XOR sert dans les deux sens. */
static void mask_with_signature(const uint8_t stored[SHA256_DIGEST_LEN],
                                const char *nonce,
                                const uint8_t in[SHA256_DIGEST_LEN],
                                uint8_t out[SHA256_DIGEST_LEN])
{
    uint8_t signature[SHA256_DIGEST_LEN];

    hmac_sha256(stored, SHA256_DIGEST_LEN, nonce, strlen(nonce), signature);
    for (int i = 0; i < SHA256_DIGEST_LEN; i++)
        out[i] = in[i] ^ signature[i];
}

void auth_proof(const char *hash, const char *nonce, char proof[AUTH_HEX_LEN + 1])
{
    uint8_t key[SHA256_DIGEST_LEN], stored[SHA256_DIGEST_LEN];
    uint8_t masked[SHA256_DIGEST_LEN];

    client_key(hash, key);
    sha256(key, sizeof key, stored);
    mask_with_signature(stored, nonce, key, masked);
    to_hex(masked, sizeof masked, proof);
    auth_wipe(key, sizeof key);
}

/* Renvoie 1 si la preuve est bonne. La comparaison se fait en temps constant. */
int auth_check(const char *verifier, const char *nonce, const char *proof)
{
    uint8_t stored[SHA256_DIGEST_LEN], given[SHA256_DIGEST_LEN];
    uint8_t key[SHA256_DIGEST_LEN], computed[SHA256_DIGEST_LEN];

    if (!from_hex(verifier, stored, sizeof stored) ||
        !from_hex(proof, given, sizeof given))
        return 0;

    mask_with_signature(stored, nonce, given, key);
    sha256(key, sizeof key, computed);
    auth_wipe(key, sizeof key);

    unsigned char diff = 0;
    for (int i = 0; i < SHA256_DIGEST_LEN; i++)
        diff |= computed[i] ^ stored[i];
    return diff == 0;
}

/* Efface un secret. "volatile" empêche le compilateur de supprimer l'écriture. */
void auth_wipe(void *p, size_t n)
{
    volatile unsigned char *v = p;

    while (n-- > 0)
        *v++ = 0;
}
