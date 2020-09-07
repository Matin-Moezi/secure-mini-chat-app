/******************************* Symmetric Cryptography Library *********************************/
/******************************* Using Libgcrypt library ****************************************/
/******************************* AES-256 Algorithm & HMAC **********************************************/
/******************************* Network Security Course Project ********************************/
/******************************* Matin Moezi #9512058 *******************************************/
/******************************* Spring 2020 ****************************************************/

/******************************* Header File ****************************************************/

#ifndef SYMM_CRYPT_H
#define SYMM_CRYPT_H

#include <gcrypt.h>

#define NEED_LIBGCRYPT_VERSION "1.8.1"

#define AES256_KEY_LEN 32	    							// AES-256 key length 32 (bytes)
#define AES256_BLOCK_LEN 16     							// AES-256 data block length 16 (bytes)
#define KDF_SALT_LEN 128									// Key derivation salt length
#define KDF_ITERATIONS 100   								// Key derivation iterations
#define KDF_KEY_LEN AES256_KEY_LEN + AES256_BLOCK_LEN 		// Key derivation output length


/* Print libgcrypt error string and error source */
void print_err(const char *, gcry_error_t);

/* Initialization libgcrypt */
int init_crypt();

/* Initialization cipher context by cipher algorith and cipher mode */
/* AES-256 cipher with 32 bytes key and counter cipher mode */
int init_cipher(gcry_cipher_hd_t *cipher_hd, const unsigned char *aes_key, const unsigned char *ctr_key);

/* Encrypt plain-text */
int encrypt_text(const char *passphrase, const char *plaintext, size_t in_len, char **out_buffer, size_t *out_len);

/* Decrypt cipher-text */
int decrypt_text(const char *passphrase, const char *in_buffer, size_t in_len, char **plaintext);

/* Generate random key */
void generate_random(char *buffer, size_t buffer_len);

#endif  /* SYMM_CRYPT_H */