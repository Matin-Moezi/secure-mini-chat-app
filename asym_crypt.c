#include "asym_crypt.h"
#include "symm_crypt.h"

#include <gcrypt.h>


/* Generate private/public 2048 bits RSA key pairs */
int gen_key(char **pkey, char **skey, size_t *plen, size_t *slen)
{
    char pub_tmp[RSAKEYLEN], priv_tmp[RSAKEYLEN];
    gcry_error_t error;
    gcry_sexp_t key_params, key_pairs, pub_key, priv_key;
    if ((error = gcry_sexp_build(&key_params, NULL, "(genkey (rsa (nbits 3:512)(rsa-use-e 1:3)))")) == 0)
        if ((error = gcry_pk_genkey(&key_pairs, key_params)) == 0)
            if ((pub_key = gcry_sexp_find_token(key_pairs, "public-key", 0)) != NULL &&
                ((priv_key = gcry_sexp_find_token(key_pairs, "private-key", 0)) != NULL))
                if ((*plen = gcry_sexp_sprint(pub_key, GCRYSEXP_FMT_CANON, pub_tmp, RSAKEYLEN)) != 0 &&
                    ((*slen = gcry_sexp_sprint(priv_key, GCRYSEXP_FMT_CANON, priv_tmp, RSAKEYLEN)) != 0))
                {
                    *pkey = malloc(*plen);
                    memcpy(*pkey, pub_tmp, *plen);
                    *skey = malloc(*slen);
                    memcpy(*skey, priv_tmp, *slen);
                    return 0;
                }
    print_err("generate_keypairs", error);
    return -1;
}

/* Encrypt plaintext with public key RSA algorithm */
int asym_encrypt(char *pkey, const char *plaintext, size_t plaintext_len, char **out_buff, size_t *out_len)
{
    gcry_error_t error;
    gcry_sexp_t pub_key, data, ciphertext, enc_val;
    if ((error = gcry_sexp_new(&pub_key, pkey, gcry_sexp_canon_len(pkey, RSAKEYLEN, NULL, NULL), 0)) == 0)
        if ((error = gcry_sexp_build(&data, NULL, "(data (flags raw)(value %b))", plaintext_len, plaintext)) == 0)
            if ((error = gcry_pk_encrypt(&enc_val, data, pub_key)) == 0)
                if ((ciphertext = gcry_sexp_find_token(enc_val, "a", 0)) != NULL)
                    if ((*out_buff = gcry_sexp_nth_data(ciphertext, 1, out_len)) != NULL)
                        return 0;
    print_err("rsa_encrypt", error);
    return -1;
}

/* Decrypt ciphertext with secret key RSA algorithm */
int asym_decrypt(char *skey, const char *in_buff, size_t in_len, char **plaintext, size_t *plaintext_len)
{
    gcry_error_t error;
    gcry_sexp_t priv_key, plain, ciphertext;

    if ((error = gcry_sexp_new(&priv_key, skey, gcry_sexp_canon_len(skey, RSAKEYLEN, NULL, NULL), 0)) == 0)
        if ((error = gcry_sexp_build(&ciphertext, NULL, "(enc-val (rsa (a %b)))", in_len, in_buff)) == 0)
            if ((error = gcry_pk_decrypt(&plain, ciphertext, priv_key)) == 0)
                if ((*plaintext = gcry_sexp_nth_data(plain, 0, plaintext_len)) != NULL)
                    return 0;
    print_err("rsa_decrypt", error);
    return -1;
}
