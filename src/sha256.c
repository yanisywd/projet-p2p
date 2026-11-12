/*
 * sha256.c - SHA-256 (FIPS 180-4) et HMAC-SHA-256 (RFC 2104).
 */
#include "sha256.h"

#include <string.h>

#define BLOCK_LEN 64
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

typedef struct {
    uint32_t state[8];
    uint64_t total;            /* octets reçus */
    uint8_t  block[BLOCK_LEN];
    size_t   used;             /* octets présents dans block */
} Sha256;

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_init(Sha256 *s)
{
    static const uint32_t initial[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    memcpy(s->state, initial, sizeof initial);
    s->total = 0;
    s->used = 0;
}

static void sha256_block(Sha256 *s, const uint8_t *p)
{
    uint32_t w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
               (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = s->state[0], b = s->state[1], c = s->state[2], d = s->state[3];
    uint32_t e = s->state[4], f = s->state[5], g = s->state[6], h = s->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t big1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + big1 + ch + K[i] + w[i];
        uint32_t big0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = big0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    s->state[0] += a;
    s->state[1] += b;
    s->state[2] += c;
    s->state[3] += d;
    s->state[4] += e;
    s->state[5] += f;
    s->state[6] += g;
    s->state[7] += h;
}

static void sha256_update(Sha256 *s, const void *data, size_t len)
{
    const uint8_t *p = data;

    s->total += len;
    while (len > 0) {
        size_t n = BLOCK_LEN - s->used;
        if (n > len)
            n = len;
        memcpy(s->block + s->used, p, n);
        s->used += n;
        p += n;
        len -= n;
        if (s->used == BLOCK_LEN) {
            sha256_block(s, s->block);
            s->used = 0;
        }
    }
}

static void sha256_final(Sha256 *s, uint8_t out[SHA256_DIGEST_LEN])
{
    uint64_t bits = s->total * 8;
    uint8_t pad = 0x80;
    uint8_t zero = 0;
    uint8_t length[8];

    sha256_update(s, &pad, 1);
    while (s->used != BLOCK_LEN - 8)
        sha256_update(s, &zero, 1);

    for (int i = 0; i < 8; i++)
        length[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(s, length, 8);

    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(s->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(s->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(s->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(s->state[i]);
    }
}

void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN])
{
    Sha256 s;

    sha256_init(&s);
    sha256_update(&s, data, len);
    sha256_final(&s, out);
}

void hmac_sha256(const void *key, size_t key_len,
                 const void *msg, size_t msg_len,
                 uint8_t out[SHA256_DIGEST_LEN])
{
    uint8_t k[BLOCK_LEN] = { 0 };
    uint8_t inner_pad[BLOCK_LEN], outer_pad[BLOCK_LEN];
    uint8_t inner[SHA256_DIGEST_LEN];
    Sha256 s;

    if (key_len > BLOCK_LEN) {
        sha256_init(&s);
        sha256_update(&s, key, key_len);
        sha256_final(&s, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < BLOCK_LEN; i++) {
        inner_pad[i] = k[i] ^ 0x36;
        outer_pad[i] = k[i] ^ 0x5c;
    }

    sha256_init(&s);
    sha256_update(&s, inner_pad, BLOCK_LEN);
    sha256_update(&s, msg, msg_len);
    sha256_final(&s, inner);

    sha256_init(&s);
    sha256_update(&s, outer_pad, BLOCK_LEN);
    sha256_update(&s, inner, SHA256_DIGEST_LEN);
    sha256_final(&s, out);
}
