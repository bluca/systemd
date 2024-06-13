/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "iovec-util.h"
#include "macro.h"
#include "sha256.h"

typedef enum KeySourceType {
        OPENSSL_KEY_SOURCE_FILE,
        OPENSSL_KEY_SOURCE_ENGINE,
        OPENSSL_KEY_SOURCE_PROVIDER,
        _OPENSSL_KEY_SOURCE_MAX,
        _OPENSSL_KEY_SOURCE_INVALID = -EINVAL,
} KeySourceType;

int parse_openssl_key_source_argument(const char *argument, char **private_key_source, KeySourceType *private_key_source_type);

#define X509_FINGERPRINT_SIZE SHA256_DIGEST_SIZE

#if HAVE_OPENSSL
#  include <openssl/bio.h>
#  include <openssl/bn.h>
#  include <openssl/crypto.h>
#  include <openssl/err.h>
#  include <openssl/evp.h>
#  include <openssl/opensslv.h>
#  include <openssl/pkcs7.h>
#  include <openssl/ssl.h>
#  include <openssl/x509v3.h>
#  ifndef OPENSSL_VERSION_MAJOR
/* OPENSSL_VERSION_MAJOR macro was added in OpenSSL 3. Thus, if it doesn't exist,  we must be before OpenSSL 3. */
#    define OPENSSL_VERSION_MAJOR 1
#  endif
#  if OPENSSL_VERSION_MAJOR >= 3
#    include <openssl/core_names.h>
#    include <openssl/kdf.h>
#    include <openssl/param_build.h>
#    include <openssl/provider.h>
#    include <openssl/store.h>
#  endif

#include "dlfcn-util.h"

DLSYM_PROTOTYPE(CRYPTO_free);
DLSYM_PROTOTYPE(X509_NAME_free);
DLSYM_PROTOTYPE(EVP_PKEY_CTX_free);
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_free);
DLSYM_PROTOTYPE(EC_POINT_free);
DLSYM_PROTOTYPE(EC_GROUP_free);
DLSYM_PROTOTYPE(BN_free);
DLSYM_PROTOTYPE(BN_CTX_free);
DLSYM_PROTOTYPE(ECDSA_SIG_free);
DLSYM_PROTOTYPE(PKCS7_free);
DLSYM_PROTOTYPE(SSL_free);
DLSYM_PROTOTYPE(BIO_free);
DLSYM_PROTOTYPE(EVP_MD_CTX_free);
DLSYM_PROTOTYPE(ASN1_OCTET_STRING_free);
DLSYM_PROTOTYPE(OPENSSL_sk_pop_free);
// DLSYM_PROTOTYPE(ossl_check_X509_sk_type);
// DLSYM_PROTOTYPE(ossl_check_X509_freefunc_type);
DLSYM_PROTOTYPE(X509_free);
DLSYM_PROTOTYPE(EVP_PKEY_free);
DLSYM_PROTOTYPE(BIO_new_mem_buf);
DLSYM_PROTOTYPE(BN_bn2nativepad);
DLSYM_PROTOTYPE(BN_CTX_new);
DLSYM_PROTOTYPE(BN_new);
DLSYM_PROTOTYPE(BN_num_bits);
DLSYM_PROTOTYPE(d2i_ASN1_OCTET_STRING);
DLSYM_PROTOTYPE(d2i_ECPKParameters);
DLSYM_PROTOTYPE(d2i_PKCS7);
DLSYM_PROTOTYPE(d2i_PUBKEY);
DLSYM_PROTOTYPE(d2i_X509);
DLSYM_PROTOTYPE(EC_GROUP_get0_generator);
DLSYM_PROTOTYPE(EC_GROUP_get0_order);
DLSYM_PROTOTYPE(EC_GROUP_get_curve);
DLSYM_PROTOTYPE(EC_GROUP_get_curve_name);
DLSYM_PROTOTYPE(EC_GROUP_get_field_type);
DLSYM_PROTOTYPE(EC_POINT_new);
DLSYM_PROTOTYPE(EC_POINT_oct2point);
DLSYM_PROTOTYPE(EC_POINT_point2oct);
DLSYM_PROTOTYPE(ERR_error_string);
DLSYM_PROTOTYPE(ERR_get_error);
DLSYM_PROTOTYPE(EVP_aes_256_gcm);
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_ctrl);
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_get_block_size);
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_new);
DLSYM_PROTOTYPE(EVP_CIPHER_get_block_size);
DLSYM_PROTOTYPE(EVP_CIPHER_get_iv_length);
DLSYM_PROTOTYPE(EVP_CIPHER_get_key_length);
DLSYM_PROTOTYPE(EVP_DecryptFinal_ex);
DLSYM_PROTOTYPE(EVP_DecryptInit_ex);
DLSYM_PROTOTYPE(EVP_DecryptUpdate);
DLSYM_PROTOTYPE(EVP_Digest);
DLSYM_PROTOTYPE(EVP_DigestFinal_ex);
DLSYM_PROTOTYPE(EVP_DigestInit_ex);
DLSYM_PROTOTYPE(EVP_DigestUpdate);
DLSYM_PROTOTYPE(EVP_EncryptFinal_ex);
DLSYM_PROTOTYPE(EVP_EncryptInit_ex);
DLSYM_PROTOTYPE(EVP_EncryptUpdate);
DLSYM_PROTOTYPE(EVP_get_digestbyname);
DLSYM_PROTOTYPE(EVP_MD_CTX_get0_md);
DLSYM_PROTOTYPE(EVP_MD_CTX_new);
DLSYM_PROTOTYPE(EVP_MD_get0_name);
DLSYM_PROTOTYPE(EVP_MD_get_size);
DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_from_name);
DLSYM_PROTOTYPE(EVP_PKEY_fromdata);
DLSYM_PROTOTYPE(EVP_PKEY_fromdata_init);
DLSYM_PROTOTYPE(EVP_PKEY_get_base_id);
DLSYM_PROTOTYPE(EVP_PKEY_get_bits);
DLSYM_PROTOTYPE(EVP_PKEY_get_id);
DLSYM_PROTOTYPE(EVP_sha256);
DLSYM_PROTOTYPE(HMAC);
DLSYM_PROTOTYPE(OPENSSL_sk_new_null);
DLSYM_PROTOTYPE(OPENSSL_sk_push);
DLSYM_PROTOTYPE(OSSL_EC_curve_nid2name);
DLSYM_PROTOTYPE(OSSL_PARAM_construct_BN);
DLSYM_PROTOTYPE(OSSL_PARAM_construct_end);
DLSYM_PROTOTYPE(OSSL_PARAM_construct_octet_string);
DLSYM_PROTOTYPE(OSSL_PARAM_construct_utf8_string);
DLSYM_PROTOTYPE(PEM_read_X509);
DLSYM_PROTOTYPE(PKCS7_verify);
DLSYM_PROTOTYPE(X509_get_pubkey);
DLSYM_PROTOTYPE(X509_get_subject_name);
DLSYM_PROTOTYPE(X509_NAME_oneline);

# define sym_OPENSSL_free(addr) \
        sym_CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)
#define sym_sk_X509_pop_free(sk, freefunc) sym_OPENSSL_sk_pop_free(ossl_check_X509_sk_type(sk),ossl_check_X509_freefunc_type(freefunc))

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO(void*, sym_OPENSSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509_NAME*, sym_X509_NAME_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY_CTX*, sym_EVP_PKEY_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_CIPHER_CTX*, sym_EVP_CIPHER_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_POINT*, sym_EC_POINT_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_GROUP*, sym_EC_GROUP_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIGNUM*, sym_BN_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BN_CTX*, sym_BN_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ECDSA_SIG*, sym_ECDSA_SIG_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(PKCS7*, sym_PKCS7_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SSL*, sym_SSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIO*, sym_BIO_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MD_CTX*, sym_EVP_MD_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ASN1_OCTET_STRING*, sym_ASN1_OCTET_STRING_free, NULL);

#if OPENSSL_VERSION_MAJOR >= 3
DLSYM_PROTOTYPE(EVP_CIPHER_free);
DLSYM_PROTOTYPE(EVP_KDF_free);
DLSYM_PROTOTYPE(EVP_KDF_CTX_free);
DLSYM_PROTOTYPE(EVP_MAC_free);
DLSYM_PROTOTYPE(EVP_MAC_CTX_free);
DLSYM_PROTOTYPE(EVP_MD_free);
DLSYM_PROTOTYPE(OSSL_PARAM_free);
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_free);
DLSYM_PROTOTYPE(OSSL_STORE_close);
DLSYM_PROTOTYPE(OSSL_STORE_INFO_free);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_CIPHER*, sym_EVP_CIPHER_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_KDF*, sym_EVP_KDF_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_KDF_CTX*, sym_EVP_KDF_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MAC*, sym_EVP_MAC_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MAC_CTX*, sym_EVP_MAC_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MD*, sym_EVP_MD_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OSSL_PARAM*, sym_OSSL_PARAM_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OSSL_PARAM_BLD*, sym_OSSL_PARAM_BLD_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OSSL_STORE_CTX*, sym_OSSL_STORE_close, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OSSL_STORE_INFO*, sym_OSSL_STORE_INFO_free, NULL);

#  pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wdeprecated-declarations"
DLSYM_PROTOTYPE(EC_KEY_free);
DLSYM_PROTOTYPE(RSA_free);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_KEY*, sym_EC_KEY_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(RSA*, sym_RSA_free, NULL);
#  pragma GCC diagnostic pop
#else
DLSYM_PROTOTYPE(EC_KEY_free);
DLSYM_PROTOTYPE(HMAC_CTX_free);
DLSYM_PROTOTYPE(RSA_free);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_KEY*, sym_EC_KEY_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(HMAC_CTX*, sym_HMAC_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(RSA*, sym_RSA_free, NULL);
#endif

static inline void sk_X509_free_allp(STACK_OF(X509) **sk) {
        if (!sk || !*sk)
                return;

        sym_sk_X509_pop_free(*sk, sym_X509_free);
}

int openssl_pkey_from_pem(const void *pem, size_t pem_size, EVP_PKEY **ret);

int openssl_digest_size(const char *digest_alg, size_t *ret_digest_size);

int openssl_digest_many(const char *digest_alg, const struct iovec data[], size_t n_data, void **ret_digest, size_t *ret_digest_size);

static inline int openssl_digest(const char *digest_alg, const void *buf, size_t len, void **ret_digest, size_t *ret_digest_size) {
        return openssl_digest_many(digest_alg, &IOVEC_MAKE((void*) buf, len), 1, ret_digest, ret_digest_size);
}

int openssl_hmac_many(const char *digest_alg, const void *key, size_t key_size, const struct iovec data[], size_t n_data, void **ret_digest, size_t *ret_digest_size);

static inline int openssl_hmac(const char *digest_alg, const void *key, size_t key_size, const void *buf, size_t len, void **ret_digest, size_t *ret_digest_size) {
        return openssl_hmac_many(digest_alg, key, key_size, &IOVEC_MAKE((void*) buf, len), 1, ret_digest, ret_digest_size);
}

int openssl_cipher_many(const char *alg, size_t bits, const char *mode, const void *key, size_t key_size, const void *iv, size_t iv_size, const struct iovec data[], size_t n_data, void **ret, size_t *ret_size);

static inline int openssl_cipher(const char *alg, size_t bits, const char *mode, const void *key, size_t key_size, const void *iv, size_t iv_size, const void *buf, size_t len, void **ret, size_t *ret_size) {
        return openssl_cipher_many(alg, bits, mode, key, key_size, iv, iv_size, &IOVEC_MAKE((void*) buf, len), 1, ret, ret_size);
}

int kdf_ss_derive(const char *digest, const void *key, size_t key_size, const void *salt, size_t salt_size, const void *info, size_t info_size, size_t derive_size, void **ret);

int kdf_kb_hmac_derive(const char *mode, const char *digest, const void *key, size_t key_size, const void *salt, size_t salt_size, const void *info, size_t info_size, const void *seed, size_t seed_size, size_t derive_size, void **ret);

int rsa_encrypt_bytes(EVP_PKEY *pkey, const void *decrypted_key, size_t decrypted_key_size, void **ret_encrypt_key, size_t *ret_encrypt_key_size);

int rsa_oaep_encrypt_bytes(const EVP_PKEY *pkey, const char *digest_alg, const char *label, const void *decrypted_key, size_t decrypted_key_size, void **ret_encrypt_key, size_t *ret_encrypt_key_size);

int rsa_pkey_to_suitable_key_size(EVP_PKEY *pkey, size_t *ret_suitable_key_size);

int rsa_pkey_new(size_t bits, EVP_PKEY **ret);

int rsa_pkey_from_n_e(const void *n, size_t n_size, const void *e, size_t e_size, EVP_PKEY **ret);

int rsa_pkey_to_n_e(const EVP_PKEY *pkey, void **ret_n, size_t *ret_n_size, void **ret_e, size_t *ret_e_size);

int ecc_pkey_from_curve_x_y(int curve_id, const void *x, size_t x_size, const void *y, size_t y_size, EVP_PKEY **ret);

int ecc_pkey_to_curve_x_y(const EVP_PKEY *pkey, int *ret_curve_id, void **ret_x, size_t *ret_x_size, void **ret_y, size_t *ret_y_size);

int ecc_pkey_new(int curve_id, EVP_PKEY **ret);

int ecc_ecdh(const EVP_PKEY *private_pkey, const EVP_PKEY *peer_pkey, void **ret_shared_secret, size_t *ret_shared_secret_size);

int pkey_generate_volume_keys(EVP_PKEY *pkey, void **ret_decrypted_key, size_t *ret_decrypted_key_size, void **ret_saved_key, size_t *ret_saved_key_size);

int pubkey_fingerprint(EVP_PKEY *pk, const EVP_MD *md, void **ret, size_t *ret_size);

int digest_and_sign(const EVP_MD *md, EVP_PKEY *privkey, const void *data, size_t size, void **ret, size_t *ret_size);

int openssl_load_key_from_token(KeySourceType private_key_source_type, const char *private_key_source, const char *private_key, EVP_PKEY **ret);

#else

typedef struct X509 X509;
typedef struct EVP_PKEY EVP_PKEY;

static inline void *sym_X509_free(X509 *p) {
        assert(p == NULL);
        return NULL;
}

static inline void *sym_EVP_PKEY_free(EVP_PKEY *p) {
        assert(p == NULL);
        return NULL;
}

static inline int openssl_load_key_from_token(
                KeySourceType private_key_source_type,
                const char *private_key_source,
                const char *private_key,
                EVP_PKEY **ret) {

        return -EOPNOTSUPP;
}

#endif

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509*, sym_X509_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY*, sym_EVP_PKEY_free, NULL);

int x509_fingerprint(X509 *cert, uint8_t buffer[static X509_FINGERPRINT_SIZE]);

#if PREFER_OPENSSL
/* The openssl definition */
typedef const EVP_MD* hash_md_t;
typedef const EVP_MD* hash_algorithm_t;
typedef int elliptic_curve_t;
typedef EVP_MD_CTX* hash_context_t;
#  define OPENSSL_OR_GCRYPT(a, b) (a)

#elif HAVE_GCRYPT

#  include <gcrypt.h>

/* The gcrypt definition */
typedef int hash_md_t;
typedef const char* hash_algorithm_t;
typedef const char* elliptic_curve_t;
typedef gcry_md_hd_t hash_context_t;
#  define OPENSSL_OR_GCRYPT(a, b) (b)
#endif

#if PREFER_OPENSSL
int string_hashsum(const char *s, size_t len, const char *md_algorithm, char **ret);

static inline int string_hashsum_sha224(const char *s, size_t len, char **ret) {
        return string_hashsum(s, len, "SHA224", ret);
}

static inline int string_hashsum_sha256(const char *s, size_t len, char **ret) {
        return string_hashsum(s, len, "SHA256", ret);
}
#endif
