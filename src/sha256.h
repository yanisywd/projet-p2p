/*
 * sha256.h - SHA-256 (FIPS 180-4) et HMAC-SHA-256 (RFC 2104).
 */
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32

void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

void hmac_sha256(const void *key, size_t key_len,
                 const void *msg, size_t msg_len,
                 uint8_t out[SHA256_DIGEST_LEN]);

#endif
