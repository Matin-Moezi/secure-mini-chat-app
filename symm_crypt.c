/******************************* Symmetric Cryptography Library *********************************/
/******************************* Using Libgcrypt library ****************************************/
/******************************* AES-256 Algorithm & HMAC **********************************************/
/******************************* Network Security Course Project ********************************/
/******************************* Matin Moezi #9512058 *******************************************/
/******************************* Spring 2020 ****************************************************/

/******************************* Source code ****************************************************/

#include <stdio.h>
#include <string.h>

#include "symm_crypt.h"

/* Print libgcrypt error string and error source */
void print_err(const char *desc, gcry_error_t error)
{
    fprintf(stderr, "%s: %s: %s\n", desc, gcry_strsource(error), gcry_strerror(error));
}

/* Initialization libgcrypt */
int init_crypt()
{
    char *ver = NEED_LIBGCRYPT_VERSION;

    /* Check libgcrypt version */
    if (!gcry_check_version(ver))
    {
        fprintf(stderr, "libgcrypt is too old (need %s, have %s)\n",
                NEED_LIBGCRYPT_VERSION, gcry_check_version(NULL));
        return -1;
    }

    /* Disable secure memory.  */
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

    /* Tell Libgcrypt that initialization has completed. */
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    return 0;
}

/* Initialization cipher context by cipher algorithm and cipher mode */
/* AES-256 cipher with 32 bytes key and counter cipher mode */
int init_cipher(gcry_cipher_hd_t *cipher_hd, const unsigned char *aes_key, const unsigned char *ctr_key)
{
    if (init_crypt() != 0)
        exit(EXIT_FAILURE);
    gcry_error_t ctx_err;

    /* Create cipher */
    ctx_err = gcry_cipher_open(cipher_hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
    if (ctx_err != 0)
    {
        print_err("init_cipher", ctx_err);
        return -1;
    }

    /* Set counter variable for CTR cipher mode */
    ctx_err = gcry_cipher_setctr(*cipher_hd, ctr_key, AES256_BLOCK_LEN);
    if (ctx_err != 0)
    {
        print_err("set_ctr_var", ctx_err);
        return -1;
    }

    /* Set key */
    ctx_err = gcry_cipher_setkey(*cipher_hd, aes_key, AES256_KEY_LEN);
    if (ctx_err != 0)
    {
        print_err("set_aes_key", ctx_err);
        return -1;
    }
    return 0;
}

/* Encrypt plain-text */
int encrypt_text(const char *passphrase, const char *plaintext, size_t in_len, char **out_buffer, size_t *out_len)
{

    /* Define variables */
    gcry_error_t ctx_err;
    gcry_mac_hd_t mac_hd;
    gcry_cipher_hd_t cipher_hd;

    unsigned char kdf_key[KDF_KEY_LEN], aes_key[AES256_KEY_LEN], ctr_key[AES256_BLOCK_LEN], kdf_salt[KDF_SALT_LEN];

    unsigned char *ciphertext, *data, *hmac;

    size_t blocks, data_len, hmac_len;

    /* Generate salt key */
    gcry_create_nonce(kdf_salt, KDF_SALT_LEN);

    /* Derive 64 byte kdf key: SHA-256 hash algo with 128 salt key */
    ctx_err = gcry_kdf_derive(passphrase, strlen(passphrase), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, kdf_salt, KDF_SALT_LEN,
                              KDF_ITERATIONS, KDF_KEY_LEN, kdf_key);
    if (ctx_err != 0)
    {
        print_err("encrypt_key derivation", ctx_err);
        return -1;
    }

    /* Copy the first 32 bytes of kdf key to aes key */
    memcpy(aes_key, kdf_key, AES256_KEY_LEN);

    /* Copy 16 bytes of kdf key to counter variable */
    memcpy(ctr_key, &(kdf_key[AES256_KEY_LEN]), AES256_BLOCK_LEN);

    /* Initialization Cipher Context */
    if (init_cipher(&cipher_hd, aes_key, ctr_key) != 0)
        return -1;


    /* Create ciphertext space and copy plaintext to it for in place encryption */
    blocks = in_len % AES256_BLOCK_LEN == 0 ? in_len / AES256_BLOCK_LEN : in_len / AES256_BLOCK_LEN + 1;
    ciphertext = malloc(blocks * AES256_BLOCK_LEN);
    memcpy(ciphertext, plaintext, blocks * AES256_BLOCK_LEN);

    /* Encrypt plaintext in place into ciphertext */
    ctx_err = gcry_cipher_encrypt(cipher_hd, ciphertext, blocks * AES256_BLOCK_LEN, NULL, 0);
    if (ctx_err != 0)
    {
        print_err("encryption", ctx_err);
        gcry_cipher_close(cipher_hd);
        free(ciphertext);
        return -1;
    }

    /* Initialization MAC Context */
    ctx_err = gcry_mac_open(&mac_hd, GCRY_MAC_HMAC_SHA256, 0, NULL);
    if (ctx_err != 0)
    {
        print_err("encrypt_init_mac", ctx_err);
        gcry_cipher_close(cipher_hd);
        return -1;
    }

    /* Set HMAC key */
    ctx_err = gcry_mac_setkey(mac_hd, aes_key, AES256_KEY_LEN);
    if (ctx_err != 0)
    {
        print_err("encrypt_set_mac_key", ctx_err);
        gcry_cipher_close(cipher_hd);
        gcry_mac_close(mac_hd);
        return -1;
    }

    /* Packed data: kdf_salt + ciphertext + hmac */
    hmac_len = gcry_mac_get_algo_keylen(GCRY_MAC_HMAC_SHA256);
    data_len = KDF_SALT_LEN + blocks * AES256_BLOCK_LEN + hmac_len;
    data = malloc(data_len);
    memcpy(data, kdf_salt, KDF_SALT_LEN);
    memcpy(&(data[KDF_SALT_LEN]), ciphertext, blocks * AES256_BLOCK_LEN);

    /* Write data to MAC algo */
    ctx_err = gcry_mac_write(mac_hd, data, data_len - hmac_len);
    if (ctx_err != 0)
    {
        print_err("encrypt_hmac_write", ctx_err);
        gcry_cipher_close(cipher_hd);
        gcry_mac_close(mac_hd);
        free(data);
        free(ciphertext);
        return -1;
    }

    /* Finalize HMAC and save to hmac buffer */
    hmac = malloc(hmac_len);
    ctx_err = gcry_mac_read(mac_hd, hmac, &hmac_len);
    if (ctx_err != 0)
    {
        print_err("encrypt_hmac_read", ctx_err);
        gcry_cipher_close(cipher_hd);
        gcry_mac_close(mac_hd);
        free(data);
        free(ciphertext);
        free(hmac);
        return -1;
    }

    /* Add hmac to data */
    memcpy(&(data[KDF_SALT_LEN + blocks * AES256_BLOCK_LEN]), hmac, hmac_len);

    /* Write data to output buffer */
    *(out_buffer) = malloc(data_len);
    memcpy(*out_buffer, data, data_len);
    *out_len = data_len;

    /* Release resources */
    gcry_cipher_close(cipher_hd);
    gcry_mac_close(mac_hd);
    free(data);
    free(ciphertext);
    free(hmac);

    return 0;
}

/* Decrypt cipher-text */
int decrypt_text(const char *passphrase, const char *in_buffer, const size_t in_len, char **plaintext)
{
    gcry_error_t ctx_err;
    gcry_cipher_hd_t cipher_hd;
    gcry_mac_hd_t mac_hd;
    unsigned char kdf_salt[KDF_SALT_LEN], kdf_key[KDF_KEY_LEN], aes_key[AES256_KEY_LEN], ctr_key[AES256_BLOCK_LEN],
            *hmac, *ciphertext;
    size_t hmac_len, ciphertext_len;

    /* Extract kdf_salt from encrypted data */
    memcpy(kdf_salt, in_buffer, KDF_SALT_LEN);

    /* Key derivation */
    ctx_err = gcry_kdf_derive(passphrase, strlen(passphrase), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, kdf_salt, KDF_SALT_LEN,
                              KDF_ITERATIONS, KDF_KEY_LEN, kdf_key);
    if (ctx_err != 0)
    {
        print_err("decrypt_kdf_derive", ctx_err);
        return -1;
    }

    /* Copy the first 32 bytes of kdf_key to aes_key */
    memcpy(aes_key, kdf_key, AES256_KEY_LEN);

    /* Copy the next 16 bytes of kdf_key to ctr_key */
    memcpy(ctr_key, &(kdf_key[AES256_KEY_LEN]), AES256_BLOCK_LEN);

    hmac_len = gcry_mac_get_algo_keylen(GCRY_MAC_HMAC_SHA256);
    ciphertext_len = in_len - hmac_len - KDF_SALT_LEN;

    hmac = malloc(hmac_len);
    ciphertext = malloc(ciphertext_len);

    /* Extract ciphertext and hmac from encrypted data */
    memcpy(ciphertext, &(in_buffer[KDF_SALT_LEN]), ciphertext_len);
    memcpy(hmac, &(in_buffer[KDF_SALT_LEN + ciphertext_len]), hmac_len);

    /* Verify message with hmac */
    /* Initializing HMAC */
    ctx_err = gcry_mac_open(&mac_hd, GCRY_MAC_HMAC_SHA256, 0, NULL);
    if (ctx_err != 0)
    {
        print_err("decrypt_init_hmac", ctx_err);
        free(ciphertext);
        free(hmac);
        return -1;
    }

    /* Set hmac key */
    ctx_err = gcry_mac_setkey(mac_hd, aes_key, AES256_KEY_LEN);
    if (ctx_err != 0)
    {
        print_err("decrypt_init_hmac", ctx_err);
        gcry_mac_close(mac_hd);
        free(ciphertext);
        free(hmac);
        return -1;
    }

    /* Write hmac data */
    ctx_err = gcry_mac_write(mac_hd, in_buffer, in_len);
    if (ctx_err != 0)
    {
        print_err("decrypt_init_hmac", ctx_err);
        gcry_mac_close(mac_hd);
        free(ciphertext);
        free(hmac);
        return -1;
    }

    /* Verify */
    ctx_err = gcry_mac_verify(mac_hd, hmac, hmac_len);
    if (ctx_err == GPG_ERR_CHECKSUM)
    {
        printf("HMAC Verification failed.\n");
        gcry_mac_close(mac_hd);
        free(ciphertext);
        free(hmac);
        return -1;
    }

    /* Initializing Cipher Context */
    if (init_cipher(&cipher_hd, aes_key, ctr_key) != 0)
    {
        print_err("decrypt_init_cipher", ctx_err);
        gcry_mac_close(mac_hd);
        free(ciphertext);
        free(hmac);
        return -1;
    }

    /* Decryption */
    ctx_err = gcry_cipher_decrypt(cipher_hd, ciphertext, ciphertext_len, NULL, 0);
    if (ctx_err != 0)
    {
        print_err("decryption", ctx_err);
        gcry_cipher_close(cipher_hd);
        gcry_mac_close(mac_hd);
        free(ciphertext);
        free(hmac);
        return -1;
    }

    /* Copy plaintext to output buffer */
    *plaintext = malloc(ciphertext_len);
    memcpy(*plaintext, ciphertext, ciphertext_len);

    /* Release resources */
    gcry_cipher_close(cipher_hd);
    gcry_mac_close(mac_hd);
    free(ciphertext);
    free(hmac);

    return 0;
}

/* Generate random key */
void generate_random(char *buffer, size_t buffer_len)
{
    gcry_create_nonce(buffer, buffer_len);
}