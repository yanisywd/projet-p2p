/*
 * auth.h - Authentification sans mot de passe en clair sur le réseau.
 *
 * Le principe est celui de SCRAM (RFC 5802), construit sur crypt() :
 *
 *   empreinte    = crypt(mot_de_passe, sel)
 *   clé          = HMAC(empreinte, "Client Key")
 *   vérificateur = SHA-256(clé)
 *
 * Inscription : le client envoie le sel et le vérificateur.
 * Connexion   : le central envoie le sel et un défi aléatoire.
 *               Le client répond preuve = clé XOR HMAC(vérificateur, défi).
 *               Le central retrouve la clé avec le même XOR et vérifie que
 *               SHA-256(clé) redonne le vérificateur.
 *
 * Le mot de passe et l'empreinte ne quittent jamais la machine de
 * l'utilisateur. Comme sous UNIX, voler le fichier des comptes ne suffit pas
 * pour se connecter : il ne contient pas la clé.
 */
#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#define AUTH_SALT_SIZE 32   /* taille d'un sel, '\0' compris */
#define NONCE_HEX_LEN  32
#define AUTH_HEX_LEN   64   /* vérificateur et preuve, en hexadécimal */

int  auth_new_salt(char *salt, size_t size);
int  auth_valid_salt(const char *salt);
int  auth_hash(const char *password, const char *salt, char *hash, size_t size);
void auth_verifier(const char *hash, char verifier[AUTH_HEX_LEN + 1]);
int  auth_valid_key(const char *hex);
int  auth_new_nonce(char nonce[NONCE_HEX_LEN + 1]);
void auth_proof(const char *hash, const char *nonce, char proof[AUTH_HEX_LEN + 1]);
int  auth_check(const char *verifier, const char *nonce, const char *proof);
void auth_wipe(void *p, size_t n);

#endif
