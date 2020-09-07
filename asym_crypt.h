#ifndef _ASYM_CRYPT_H
#define _ASYM_CRYPT_H

#include <stdio.h>
#define RSAKEYLEN 1024

/* Generate private/public 2048 bits RSA key pairs */
int gen_key(char **pkey, char **skey, size_t *plen, size_t *slen);

/* Encrypt plaintext with public key RSA algorithm */
int asym_encrypt(char *pkey, const char *plaintext, size_t plaintext_len, char **out_buff, size_t *out_len);

/* Decrypt ciphertext with secret key RSA algorithm */
int asym_decrypt(char *skey, const char *in_buff, size_t in_len, char **plaintext, size_t *plaintext_len);

#endif //ASYM_CRYPT_H
