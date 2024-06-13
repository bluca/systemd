/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "openssl-util.h"
#include "random-util.h"
#include "string-util.h"

#if HAVE_OPENSSL
#  include <openssl/rsa.h>
#  include <openssl/ec.h>

DLSYM_FUNCTION(CRYPTO_free);
DLSYM_FUNCTION(X509_NAME_free);
DLSYM_FUNCTION(EVP_PKEY_CTX_free);
DLSYM_FUNCTION(EVP_CIPHER_CTX_free);
DLSYM_FUNCTION(EC_POINT_free);
DLSYM_FUNCTION(EC_GROUP_free);
DLSYM_FUNCTION(BN_free);
DLSYM_FUNCTION(BN_CTX_free);
DLSYM_FUNCTION(ECDSA_SIG_free);
DLSYM_FUNCTION(PKCS7_free);
DLSYM_FUNCTION(SSL_free);
DLSYM_FUNCTION(BIO_free);
DLSYM_FUNCTION(EVP_MD_CTX_free);
DLSYM_FUNCTION(ASN1_OCTET_STRING_free);
DLSYM_FUNCTION(OPENSSL_sk_pop_free);
// DLSYM_FUNCTION(ossl_check_X509_sk_type);
// DLSYM_FUNCTION(ossl_check_X509_freefunc_type);
DLSYM_FUNCTION(X509_free);
DLSYM_FUNCTION(EVP_PKEY_free);
#if OPENSSL_VERSION_MAJOR >= 3
DLSYM_FUNCTION(EVP_CIPHER_free);
DLSYM_FUNCTION(EVP_KDF_free);
DLSYM_FUNCTION(EVP_KDF_CTX_free);
DLSYM_FUNCTION(EVP_MAC_free);
DLSYM_FUNCTION(EVP_MAC_CTX_free);
DLSYM_FUNCTION(EVP_MD_free);
DLSYM_FUNCTION(OSSL_PARAM_free);
DLSYM_FUNCTION(OSSL_PARAM_BLD_free);
DLSYM_FUNCTION(OSSL_STORE_close);
DLSYM_FUNCTION(OSSL_STORE_INFO_free);
#  pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wdeprecated-declarations"
DLSYM_FUNCTION(EC_KEY_free);
DLSYM_FUNCTION(RSA_free);
#  pragma GCC diagnostic pop
#else
DLSYM_FUNCTION(EC_KEY_free);
DLSYM_FUNCTION(sym_HMAC_CTX_free);
DLSYM_FUNCTION(RSA_free);
#endif

DLSYM_FUNCTION(BIO_new_mem_buf);
DLSYM_FUNCTION(BN_bin2bn);
DLSYM_FUNCTION(BN_bn2bin);
DLSYM_FUNCTION(BN_bn2nativepad);
DLSYM_FUNCTION(BN_CTX_new);
DLSYM_FUNCTION(BN_new);
DLSYM_FUNCTION(BN_num_bits);
DLSYM_FUNCTION(d2i_ASN1_OCTET_STRING);
DLSYM_FUNCTION(d2i_ECPKParameters);
DLSYM_FUNCTION(d2i_PKCS7);
DLSYM_FUNCTION(d2i_PUBKEY);
DLSYM_FUNCTION(d2i_X509);
DLSYM_FUNCTION(EC_GROUP_get0_generator);
DLSYM_FUNCTION(EC_GROUP_get0_order);
DLSYM_FUNCTION(EC_GROUP_get_curve);
DLSYM_FUNCTION(EC_GROUP_get_curve_name);
DLSYM_FUNCTION(EC_GROUP_get_field_type);
DLSYM_FUNCTION(EC_GROUP_new_by_curve_name);
DLSYM_FUNCTION(EC_POINT_new);
DLSYM_FUNCTION(EC_POINT_oct2point);
DLSYM_FUNCTION(EC_POINT_point2buf);
DLSYM_FUNCTION(EC_POINT_point2oct);
DLSYM_FUNCTION(EC_POINT_set_affine_coordinates);
DLSYM_FUNCTION(ERR_error_string);
DLSYM_FUNCTION(ERR_error_string_n);
DLSYM_FUNCTION(ERR_get_error);
DLSYM_FUNCTION(EVP_aes_256_gcm);
DLSYM_FUNCTION(EVP_CIPHER_CTX_ctrl);
DLSYM_FUNCTION(EVP_CIPHER_CTX_get_block_size);
DLSYM_FUNCTION(EVP_CIPHER_CTX_new);
DLSYM_FUNCTION(EVP_CIPHER_fetch);
DLSYM_FUNCTION(EVP_CIPHER_get_block_size);
DLSYM_FUNCTION(EVP_CIPHER_get_iv_length);
DLSYM_FUNCTION(EVP_CIPHER_get_key_length);
DLSYM_FUNCTION(EVP_DecryptFinal_ex);
DLSYM_FUNCTION(EVP_DecryptInit_ex);
DLSYM_FUNCTION(EVP_DecryptUpdate);
DLSYM_FUNCTION(EVP_Digest);
DLSYM_FUNCTION(EVP_DigestFinal_ex);
DLSYM_FUNCTION(EVP_DigestInit_ex);
DLSYM_FUNCTION(EVP_DigestSign);
DLSYM_FUNCTION(EVP_DigestSignInit);
DLSYM_FUNCTION(EVP_DigestUpdate);
DLSYM_FUNCTION(EVP_EncryptFinal_ex);
DLSYM_FUNCTION(EVP_EncryptInit);
DLSYM_FUNCTION(EVP_EncryptInit_ex);
DLSYM_FUNCTION(EVP_EncryptUpdate);
DLSYM_FUNCTION(EVP_get_digestbyname);
DLSYM_FUNCTION(EVP_KDF_CTX_new);
DLSYM_FUNCTION(EVP_KDF_derive);
DLSYM_FUNCTION(EVP_KDF_fetch);
DLSYM_FUNCTION(EVP_MAC_CTX_get_mac_size);
DLSYM_FUNCTION(EVP_MAC_CTX_new);
DLSYM_FUNCTION(EVP_MAC_fetch);
DLSYM_FUNCTION(EVP_MAC_final);
DLSYM_FUNCTION(EVP_MAC_init);
DLSYM_FUNCTION(EVP_MAC_update);
DLSYM_FUNCTION(EVP_MD_CTX_get0_md);
DLSYM_FUNCTION(EVP_MD_CTX_new);
DLSYM_FUNCTION(EVP_MD_fetch);
DLSYM_FUNCTION(EVP_MD_get0_name);
DLSYM_FUNCTION(EVP_MD_get_size);
DLSYM_FUNCTION(EVP_PKEY_CTX_new);
DLSYM_FUNCTION(EVP_PKEY_CTX_new_from_name);
DLSYM_FUNCTION(EVP_PKEY_CTX_new_id);
DLSYM_FUNCTION(EVP_PKEY_CTX_set0_rsa_oaep_label);
DLSYM_FUNCTION(EVP_PKEY_CTX_set_ec_paramgen_curve_nid);
DLSYM_FUNCTION(EVP_PKEY_CTX_set_rsa_keygen_bits);
DLSYM_FUNCTION(EVP_PKEY_CTX_set_rsa_oaep_md);
DLSYM_FUNCTION(EVP_PKEY_CTX_set_rsa_padding);
DLSYM_FUNCTION(EVP_PKEY_derive);
DLSYM_FUNCTION(EVP_PKEY_derive_init);
DLSYM_FUNCTION(EVP_PKEY_derive_set_peer);
DLSYM_FUNCTION(EVP_PKEY_encrypt);
DLSYM_FUNCTION(EVP_PKEY_encrypt_init);
DLSYM_FUNCTION(EVP_PKEY_fromdata);
DLSYM_FUNCTION(EVP_PKEY_fromdata_init);
DLSYM_FUNCTION(EVP_PKEY_get1_encoded_public_key);
DLSYM_FUNCTION(EVP_PKEY_get_base_id);
DLSYM_FUNCTION(EVP_PKEY_get_bits);
DLSYM_FUNCTION(EVP_PKEY_get_bn_param);
DLSYM_FUNCTION(EVP_PKEY_get_group_name);
DLSYM_FUNCTION(EVP_PKEY_get_id);
DLSYM_FUNCTION(EVP_PKEY_get_utf8_string_param);
DLSYM_FUNCTION(EVP_PKEY_keygen);
DLSYM_FUNCTION(EVP_PKEY_keygen_init);
DLSYM_FUNCTION(EVP_sha256);
DLSYM_FUNCTION(HMAC);
DLSYM_FUNCTION(i2d_PublicKey);
DLSYM_FUNCTION(i2d_X509);
DLSYM_FUNCTION(OBJ_nid2sn);
DLSYM_FUNCTION(OBJ_sn2nid);
DLSYM_FUNCTION(OPENSSL_sk_new_null);
DLSYM_FUNCTION(OPENSSL_sk_push);
DLSYM_FUNCTION(OSSL_EC_curve_nid2name);
DLSYM_FUNCTION(OSSL_PARAM_BLD_new);
DLSYM_FUNCTION(OSSL_PARAM_BLD_push_octet_string);
DLSYM_FUNCTION(OSSL_PARAM_BLD_push_utf8_string);
DLSYM_FUNCTION(OSSL_PARAM_BLD_to_param);
DLSYM_FUNCTION(OSSL_PARAM_construct_BN);
DLSYM_FUNCTION(OSSL_PARAM_construct_end);
DLSYM_FUNCTION(OSSL_PARAM_construct_octet_string);
DLSYM_FUNCTION(OSSL_PARAM_construct_utf8_string);
DLSYM_FUNCTION(OSSL_PROVIDER_try_load);
DLSYM_FUNCTION(OSSL_STORE_INFO_get1_PKEY);
DLSYM_FUNCTION(OSSL_STORE_load);
DLSYM_FUNCTION(OSSL_STORE_open);
DLSYM_FUNCTION(PEM_read_PUBKEY);
DLSYM_FUNCTION(PEM_read_X509);
DLSYM_FUNCTION(PKCS7_verify);
DLSYM_FUNCTION(X509_get_pubkey);
DLSYM_FUNCTION(X509_get_subject_name);
DLSYM_FUNCTION(X509_NAME_oneline);

#  if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
#    include <openssl/engine.h>
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_FUNCTION(ENGINE_by_id);
DLSYM_FUNCTION(ENGINE_free);
DLSYM_FUNCTION(ENGINE_init);
DLSYM_FUNCTION(ENGINE_load_private_key);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ENGINE*, sym_ENGINE_free, NULL);
REENABLE_WARNING;
#  endif

/* For each error in the OpenSSL thread error queue, log the provided message and the OpenSSL error
 * string. If there are no errors in the OpenSSL thread queue, this logs the message with "No OpenSSL
 * errors." This logs at level debug. Returns -EIO (or -ENOMEM). */
#define log_openssl_errors(fmt, ...) _log_openssl_errors(UNIQ, fmt, ##__VA_ARGS__)
#define _log_openssl_errors(u, fmt, ...)                                \
        ({                                                              \
                size_t UNIQ_T(MAX, u) = 512 /* arbitrary, but openssl doc states it must be >= 256 */; \
                _cleanup_free_ char *UNIQ_T(BUF, u) = malloc(UNIQ_T(MAX, u)); \
                !UNIQ_T(BUF, u)                                         \
                        ? log_oom_debug()                               \
                        : __log_openssl_errors(u, UNIQ_T(BUF, u), UNIQ_T(MAX, u), fmt, ##__VA_ARGS__) \
                        ?: log_debug_errno(SYNTHETIC_ERRNO(EIO), fmt ": No OpenSSL errors.", ##__VA_ARGS__); \
        })
#define __log_openssl_errors(u, buf, max, fmt, ...)                     \
        ({                                                              \
                int UNIQ_T(R, u) = 0;                                   \
                for (;;) {                                              \
                        unsigned long UNIQ_T(E, u) = sym_ERR_get_error();   \
                        if (UNIQ_T(E, u) == 0)                          \
                                break;                                  \
                        sym_ERR_error_string_n(UNIQ_T(E, u), buf, max);     \
                        UNIQ_T(R, u) = log_debug_errno(SYNTHETIC_ERRNO(EIO), fmt ": %s", ##__VA_ARGS__, buf); \
                }                                                       \
                UNIQ_T(R, u);                                           \
        })

static void *crypto_dl = NULL;
static void *ssl_dl = NULL;

static int dlopen_openssl(void) {
        int r;

        ELF_NOTE_DLOPEN("openssl",
                        "Support for openssl",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libcrypto.so.3",
                        "libssl.so.3");

/* Needed for EC_KEY_free() and RSA_free(), gcc dislikes #pragma in the middle of a function call. */
#  pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        r = dlopen_many_sym_or_warn(
                        &crypto_dl,
                        "libcrypto.so.3", LOG_DEBUG,
                        DLSYM_ARG(CRYPTO_free),
                        DLSYM_ARG(X509_NAME_free),
                        DLSYM_ARG(EVP_PKEY_CTX_free),
                        DLSYM_ARG(EVP_CIPHER_CTX_free),
                        DLSYM_ARG(EC_POINT_free),
                        DLSYM_ARG(EC_GROUP_free),
                        DLSYM_ARG(BN_free),
                        DLSYM_ARG(BN_CTX_free),
                        DLSYM_ARG(ECDSA_SIG_free),
                        DLSYM_ARG(PKCS7_free),
                        DLSYM_ARG(BIO_free),
                        DLSYM_ARG(EVP_MD_CTX_free),
                        DLSYM_ARG(ASN1_OCTET_STRING_free),
                        DLSYM_ARG(OPENSSL_sk_pop_free),
                        DLSYM_ARG(X509_free),
                        DLSYM_ARG(EVP_PKEY_free),
#  if OPENSSL_VERSION_MAJOR >= 3
                        DLSYM_ARG(EVP_CIPHER_free),
                        DLSYM_ARG(EVP_KDF_free),
                        DLSYM_ARG(EVP_KDF_CTX_free),
                        DLSYM_ARG(EVP_MAC_free),
                        DLSYM_ARG(EVP_MAC_CTX_free),
                        DLSYM_ARG(EVP_MD_free),
                        DLSYM_ARG(OSSL_PARAM_free),
                        DLSYM_ARG(OSSL_PARAM_BLD_free),
                        DLSYM_ARG(OSSL_STORE_close),
                        DLSYM_ARG(OSSL_STORE_INFO_free),
                        DLSYM_ARG(EC_KEY_free),
                        DLSYM_ARG(RSA_free),
#  else
                        DLSYM_ARG(sym_HMAC_CTX_free),
#  endif
                        DLSYM_ARG(BIO_new_mem_buf),
                        DLSYM_ARG(BN_bin2bn),
                        DLSYM_ARG(BN_bn2bin),
                        DLSYM_ARG(BN_bn2nativepad),
                        DLSYM_ARG(BN_CTX_new),
                        DLSYM_ARG(BN_new),
                        DLSYM_ARG(BN_num_bits),
                        DLSYM_ARG(d2i_ASN1_OCTET_STRING),
                        DLSYM_ARG(d2i_ECPKParameters),
                        DLSYM_ARG(d2i_PKCS7),
                        DLSYM_ARG(d2i_PUBKEY),
                        DLSYM_ARG(d2i_X509),
                        DLSYM_ARG(EC_GROUP_get0_generator),
                        DLSYM_ARG(EC_GROUP_get0_order),
                        DLSYM_ARG(EC_GROUP_get_curve),
                        DLSYM_ARG(EC_GROUP_get_curve_name),
                        DLSYM_ARG(EC_GROUP_get_field_type),
                        DLSYM_ARG(EC_GROUP_new_by_curve_name),
                        DLSYM_ARG(EC_POINT_new),
                        DLSYM_ARG(EC_POINT_oct2point),
                        DLSYM_ARG(EC_POINT_point2buf),
                        DLSYM_ARG(EC_POINT_point2oct),
                        DLSYM_ARG(EC_POINT_set_affine_coordinates),
#  if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
                        DLSYM_ARG(ENGINE_by_id),
                        DLSYM_ARG(ENGINE_free),
                        DLSYM_ARG(ENGINE_init),
                        DLSYM_ARG(ENGINE_load_private_key),
#  endif
                        DLSYM_ARG(ERR_error_string),
                        DLSYM_ARG(ERR_error_string_n),
                        DLSYM_ARG(ERR_get_error),
                        DLSYM_ARG(EVP_aes_256_gcm),
                        DLSYM_ARG(EVP_CIPHER_CTX_ctrl),
                        DLSYM_ARG(EVP_CIPHER_CTX_get_block_size),
                        DLSYM_ARG(EVP_CIPHER_CTX_new),
                        DLSYM_ARG(EVP_CIPHER_fetch),
                        DLSYM_ARG(EVP_CIPHER_get_block_size),
                        DLSYM_ARG(EVP_CIPHER_get_iv_length),
                        DLSYM_ARG(EVP_CIPHER_get_key_length),
                        DLSYM_ARG(EVP_DecryptFinal_ex),
                        DLSYM_ARG(EVP_DecryptInit_ex),
                        DLSYM_ARG(EVP_DecryptUpdate),
                        DLSYM_ARG(EVP_Digest),
                        DLSYM_ARG(EVP_DigestFinal_ex),
                        DLSYM_ARG(EVP_DigestInit_ex),
                        DLSYM_ARG(EVP_DigestSign),
                        DLSYM_ARG(EVP_DigestSignInit),
                        DLSYM_ARG(EVP_DigestUpdate),
                        DLSYM_ARG(EVP_EncryptFinal_ex),
                        DLSYM_ARG(EVP_EncryptInit),
                        DLSYM_ARG(EVP_EncryptInit_ex),
                        DLSYM_ARG(EVP_EncryptUpdate),
                        DLSYM_ARG(EVP_get_digestbyname),
                        DLSYM_ARG(EVP_KDF_CTX_new),
                        DLSYM_ARG(EVP_KDF_derive),
                        DLSYM_ARG(EVP_KDF_fetch),
                        DLSYM_ARG(EVP_MAC_CTX_get_mac_size),
                        DLSYM_ARG(EVP_MAC_CTX_new),
                        DLSYM_ARG(EVP_MAC_fetch),
                        DLSYM_ARG(EVP_MAC_final),
                        DLSYM_ARG(EVP_MAC_init),
                        DLSYM_ARG(EVP_MAC_update),
                        DLSYM_ARG(EVP_MD_CTX_get0_md),
                        DLSYM_ARG(EVP_MD_CTX_new),
                        DLSYM_ARG(EVP_MD_fetch),
                        DLSYM_ARG(EVP_MD_get0_name),
                        DLSYM_ARG(EVP_MD_get_size),
                        DLSYM_ARG(EVP_PKEY_CTX_new),
                        DLSYM_ARG(EVP_PKEY_CTX_new_from_name),
                        DLSYM_ARG(EVP_PKEY_CTX_new_id),
                        DLSYM_ARG(EVP_PKEY_CTX_set0_rsa_oaep_label),
                        DLSYM_ARG(EVP_PKEY_CTX_set_ec_paramgen_curve_nid),
                        DLSYM_ARG(EVP_PKEY_CTX_set_rsa_keygen_bits),
                        DLSYM_ARG(EVP_PKEY_CTX_set_rsa_oaep_md),
                        DLSYM_ARG(EVP_PKEY_CTX_set_rsa_padding),
                        DLSYM_ARG(EVP_PKEY_derive),
                        DLSYM_ARG(EVP_PKEY_derive_init),
                        DLSYM_ARG(EVP_PKEY_derive_set_peer),
                        DLSYM_ARG(EVP_PKEY_encrypt),
                        DLSYM_ARG(EVP_PKEY_encrypt_init),
                        DLSYM_ARG(EVP_PKEY_fromdata),
                        DLSYM_ARG(EVP_PKEY_fromdata_init),
                        DLSYM_ARG(EVP_PKEY_get1_encoded_public_key),
                        DLSYM_ARG(EVP_PKEY_get_base_id),
                        DLSYM_ARG(EVP_PKEY_get_bits),
                        DLSYM_ARG(EVP_PKEY_get_bn_param),
                        DLSYM_ARG(EVP_PKEY_get_group_name),
                        DLSYM_ARG(EVP_PKEY_get_id),
                        DLSYM_ARG(EVP_PKEY_get_utf8_string_param),
                        DLSYM_ARG(EVP_PKEY_keygen),
                        DLSYM_ARG(EVP_PKEY_keygen_init),
                        DLSYM_ARG(EVP_sha256),
                        DLSYM_ARG(HMAC),
                        DLSYM_ARG(i2d_PublicKey),
                        DLSYM_ARG(i2d_X509),
                        DLSYM_ARG(OBJ_nid2sn),
                        DLSYM_ARG(OBJ_sn2nid),
                        DLSYM_ARG(OPENSSL_sk_new_null),
                        DLSYM_ARG(OPENSSL_sk_push),
                        DLSYM_ARG(OSSL_EC_curve_nid2name),
                        DLSYM_ARG(OSSL_PARAM_BLD_new),
                        DLSYM_ARG(OSSL_PARAM_BLD_push_octet_string),
                        DLSYM_ARG(OSSL_PARAM_BLD_push_utf8_string),
                        DLSYM_ARG(OSSL_PARAM_BLD_to_param),
                        DLSYM_ARG(OSSL_PARAM_construct_BN),
                        DLSYM_ARG(OSSL_PARAM_construct_end),
                        DLSYM_ARG(OSSL_PARAM_construct_octet_string),
                        DLSYM_ARG(OSSL_PARAM_construct_utf8_string),
                        DLSYM_ARG(OSSL_PROVIDER_try_load),
                        DLSYM_ARG(OSSL_STORE_INFO_get1_PKEY),
                        DLSYM_ARG(OSSL_STORE_load),
                        DLSYM_ARG(OSSL_STORE_open),
                        DLSYM_ARG(PEM_read_PUBKEY),
                        DLSYM_ARG(PEM_read_X509),
                        DLSYM_ARG(PKCS7_verify),
                        DLSYM_ARG(X509_get_pubkey),
                        DLSYM_ARG(X509_get_subject_name),
                        DLSYM_ARG(X509_NAME_oneline));
#  pragma GCC diagnostic pop
        if (r < 0)
                return r;

        return dlopen_many_sym_or_warn(
                        &ssl_dl,
                        "libssl.so.3", LOG_DEBUG,
                        // DLSYM_ARG(ossl_check_X509_sk_type),
                        // DLSYM_ARG(ossl_check_X509_freefunc_type),
                        DLSYM_ARG(SSL_free));
}

int openssl_pkey_from_pem(const void *pem, size_t pem_size, EVP_PKEY **ret) {
        int r;

        assert(pem);
        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        _cleanup_fclose_ FILE *f = NULL;
        f = fmemopen((void*) pem, pem_size, "r");
        if (!f)
                return log_oom_debug();

        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *pkey = sym_PEM_read_PUBKEY(f, NULL, NULL, NULL);
        if (!pkey)
                return log_openssl_errors("Failed to parse PEM");

        *ret = TAKE_PTR(pkey);

        return 0;
}

/* Returns the number of bytes generated by the specified digest algorithm. This can be used only for
 * fixed-size algorithms, e.g. md5, sha1, sha256, etc. Do not use this for variable-sized digest algorithms,
 * e.g. shake128. Returns 0 on success, -EOPNOTSUPP if the algorithm is not supported, or < 0 for any other
 * error. */
int openssl_digest_size(const char *digest_alg, size_t *ret_digest_size) {
        int r;

        assert(digest_alg);
        assert(ret_digest_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(sym_EVP_MD_freep) EVP_MD *md = sym_EVP_MD_fetch(NULL, digest_alg, NULL);
#else
        const EVP_MD *md = sym_EVP_get_digestbyname(digest_alg);
#endif
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Digest algorithm '%s' not supported.", digest_alg);

        size_t digest_size;
#if OPENSSL_VERSION_MAJOR >= 3
        digest_size = sym_EVP_MD_get_size(md);
#else
        digest_size = EVP_MD_size(md);
#endif
        if (digest_size == 0)
                return log_openssl_errors("Failed to get Digest size");

        *ret_digest_size = digest_size;

        return 0;
}

/* Calculate the digest hash value for the provided data, using the specified digest algorithm. Returns 0 on
 * success, -EOPNOTSUPP if the digest algorithm is not supported, or < 0 for any other error. */
int openssl_digest_many(
                const char *digest_alg,
                const struct iovec data[],
                size_t n_data,
                void **ret_digest,
                size_t *ret_digest_size) {

        int r;

        assert(digest_alg);
        assert(data || n_data == 0);
        assert(ret_digest);
        /* ret_digest_size is optional, as caller may already know the digest size */

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(sym_EVP_MD_freep) EVP_MD *md = sym_EVP_MD_fetch(NULL, digest_alg, NULL);
#else
        const EVP_MD *md = sym_EVP_get_digestbyname(digest_alg);
#endif
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Digest algorithm '%s' not supported.", digest_alg);

        _cleanup_(sym_EVP_MD_CTX_freep) EVP_MD_CTX *ctx = sym_EVP_MD_CTX_new();
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_MD_CTX");

        if (!sym_EVP_DigestInit_ex(ctx, md, NULL))
                return log_openssl_errors("Failed to initialize EVP_MD_CTX");

        for (size_t i = 0; i < n_data; i++)
                if (!sym_EVP_DigestUpdate(ctx, data[i].iov_base, data[i].iov_len))
                        return log_openssl_errors("Failed to update Digest");

        size_t digest_size;
        r = openssl_digest_size(digest_alg, &digest_size);
        if (r < 0)
                return r;

        _cleanup_free_ void *buf = malloc(digest_size);
        if (!buf)
                return log_oom_debug();

        unsigned int size;
        if (!sym_EVP_DigestFinal_ex(ctx, buf, &size))
                return log_openssl_errors("Failed to finalize Digest");

        assert(size == digest_size);

        *ret_digest = TAKE_PTR(buf);
        if (ret_digest_size)
                *ret_digest_size = size;

        return 0;
}

/* Calculate the sym_HMAC digest hash value for the provided data, using the provided key and specified digest
 * algorithm. Returns 0 on success, -EOPNOTSUPP if the digest algorithm is not supported, or < 0 for any
 * other error. */
int openssl_hmac_many(
                const char *digest_alg,
                const void *key,
                size_t key_size,
                const struct iovec data[],
                size_t n_data,
                void **ret_digest,
                size_t *ret_digest_size) {

        int r;

        assert(digest_alg);
        assert(key);
        assert(data || n_data == 0);
        assert(ret_digest);
        /* ret_digest_size is optional, as caller may already know the digest size */

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(sym_EVP_MD_freep) EVP_MD *md = sym_EVP_MD_fetch(NULL, digest_alg, NULL);
#else
        const EVP_MD *md = sym_EVP_get_digestbyname(digest_alg);
#endif
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Digest algorithm '%s' not supported.", digest_alg);

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(sym_EVP_MAC_freep) EVP_MAC *mac = sym_EVP_MAC_fetch(NULL, "sym_HMAC", NULL);
        if (!mac)
                return log_openssl_errors("Failed to create new EVP_MAC");

        _cleanup_(sym_EVP_MAC_CTX_freep) EVP_MAC_CTX *ctx = sym_EVP_MAC_CTX_new(mac);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_MAC_CTX");

        _cleanup_(sym_OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_MAC_PARAM_DIGEST, (char*) digest_alg, 0))
                return log_openssl_errors("Failed to set sym_HMAC OSSL_MAC_PARAM_DIGEST");

        _cleanup_(sym_OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build sym_HMAC OSSL_PARAM");

        if (!sym_EVP_MAC_init(ctx, key, key_size, params))
                return log_openssl_errors("Failed to initialize EVP_MAC_CTX");
#else
        _cleanup_(sym_HMAC_CTX_freep) sym_HMAC_CTX *ctx = sym_HMAC_CTX_new();
        if (!ctx)
                return log_openssl_errors("Failed to create new sym_HMAC_CTX");

        if (!sym_HMAC_Init_ex(ctx, key, key_size, md, NULL))
                return log_openssl_errors("Failed to initialize sym_HMAC_CTX");
#endif

        for (size_t i = 0; i < n_data; i++)
#if OPENSSL_VERSION_MAJOR >= 3
                if (!sym_EVP_MAC_update(ctx, data[i].iov_base, data[i].iov_len))
#else
                if (!sym_HMAC_Update(ctx, data[i].iov_base, data[i].iov_len))
#endif
                        return log_openssl_errors("Failed to update sym_HMAC");

        size_t digest_size;
#if OPENSSL_VERSION_MAJOR >= 3
        digest_size = sym_EVP_MAC_CTX_get_mac_size(ctx);
#else
        digest_size = sym_HMAC_size(ctx);
#endif
        if (digest_size == 0)
                return log_openssl_errors("Failed to get sym_HMAC digest size");

        _cleanup_free_ void *buf = malloc(digest_size);
        if (!buf)
                return log_oom_debug();

#if OPENSSL_VERSION_MAJOR >= 3
        size_t size;
        if (!sym_EVP_MAC_final(ctx, buf, &size, digest_size))
#else
        unsigned int size;
        if (!sym_HMAC_Final(ctx, buf, &size))
#endif
                return log_openssl_errors("Failed to finalize sym_HMAC");

        assert(size == digest_size);

        *ret_digest = TAKE_PTR(buf);
        if (ret_digest_size)
                *ret_digest_size = size;

        return 0;
}

/* Symmetric Cipher encryption using the alg-bits-mode cipher, e.g. AES-128-CFB. The key is required and must
 * be at least the minimum required key length for the cipher. The IV is optional but, if provided, it must
 * be at least the minimum iv length for the cipher. If no IV is provided and the cipher requires one, a
 * buffer of zeroes is used. Returns 0 on success, -EOPNOTSUPP if the cipher algorithm is not supported, or <
 * 0 on any other error. */
int openssl_cipher_many(
                const char *alg,
                size_t bits,
                const char *mode,
                const void *key,
                size_t key_size,
                const void *iv,
                size_t iv_size,
                const struct iovec data[],
                size_t n_data,
                void **ret,
                size_t *ret_size) {

        int r;

        assert(alg);
        assert(bits > 0);
        assert(mode);
        assert(key);
        assert(iv || iv_size == 0);
        assert(data || n_data == 0);
        assert(ret);
        assert(ret_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        _cleanup_free_ char *cipher_alg = NULL;
        if (asprintf(&cipher_alg, "%s-%zu-%s", alg, bits, mode) < 0)
                return log_oom_debug();

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(sym_EVP_CIPHER_freep) EVP_CIPHER *cipher = sym_EVP_CIPHER_fetch(NULL, cipher_alg, NULL);
#else
        const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_alg);
#endif
        if (!cipher)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Cipher algorithm '%s' not supported.", cipher_alg);

        _cleanup_(sym_EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *ctx = sym_EVP_CIPHER_CTX_new();
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_CIPHER_CTX");

        /* Verify enough key data was provided. */
        int cipher_key_length = sym_EVP_CIPHER_get_key_length(cipher);
        assert(cipher_key_length >= 0);
        if ((size_t) cipher_key_length > key_size)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not enough key bytes provided, require %d", cipher_key_length);

        /* Verify enough IV data was provided or, if no IV was provided, use a zeroed buffer for IV data. */
        int cipher_iv_length = sym_EVP_CIPHER_get_iv_length(cipher);
        assert(cipher_iv_length >= 0);
        _cleanup_free_ void *zero_iv = NULL;
        if (iv_size == 0) {
                zero_iv = malloc0(cipher_iv_length);
                if (!zero_iv)
                        return log_oom_debug();

                iv = zero_iv;
                iv_size = (size_t) cipher_iv_length;
        }
        if ((size_t) cipher_iv_length > iv_size)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not enough IV bytes provided, require %d", cipher_iv_length);

        if (!sym_EVP_EncryptInit(ctx, cipher, key, iv))
                return log_openssl_errors("Failed to initialize EVP_CIPHER_CTX.");

        int cipher_block_size = sym_EVP_CIPHER_CTX_block_size(ctx);
        assert(cipher_block_size > 0);

        _cleanup_free_ uint8_t *buf = NULL;
        size_t size = 0;

        for (size_t i = 0; i < n_data; i++) {
                /* Cipher may produce (up to) input length + cipher block size of output. */
                if (!GREEDY_REALLOC(buf, size + data[i].iov_len + cipher_block_size))
                        return log_oom_debug();

                int update_size;
                if (!sym_EVP_EncryptUpdate(ctx, &buf[size], &update_size, data[i].iov_base, data[i].iov_len))
                        return log_openssl_errors("Failed to update Cipher.");

                size += update_size;
        }

        if (!GREEDY_REALLOC(buf, size + cipher_block_size))
                return log_oom_debug();

        int final_size;
        if (!sym_EVP_EncryptFinal_ex(ctx, &buf[size], &final_size))
                return log_openssl_errors("Failed to finalize Cipher.");

        *ret = TAKE_PTR(buf);
        *ret_size = size + final_size;

        return 0;
}

/* Perform Single-Step (aka "Concat") KDF. Currently, this only supports using the digest for the auxiliary
 * function. The derive_size parameter specifies how many bytes are derived.
 *
 * For more details see: https://www.openssl.org/docs/manmaster/man7/EVP_KDF-SS.html */
int kdf_ss_derive(
                const char *digest,
                const void *key,
                size_t key_size,
                const void *salt,
                size_t salt_size,
                const void *info,
                size_t info_size,
                size_t derive_size,
                void **ret) {

#if OPENSSL_VERSION_MAJOR >= 3
        int r;

        assert(digest);
        assert(key);
        assert(derive_size > 0);
        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        _cleanup_(sym_EVP_KDF_freep) EVP_KDF *kdf = sym_EVP_KDF_fetch(NULL, "SSKDF", NULL);
        if (!kdf)
                return log_openssl_errors("Failed to create new EVP_KDF");

        _cleanup_(sym_EVP_KDF_CTX_freep) EVP_KDF_CTX *ctx = sym_EVP_KDF_CTX_new(kdf);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_KDF_CTX");

        _cleanup_(sym_OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        _cleanup_free_ void *buf = malloc(derive_size);
        if (!buf)
                return log_oom_debug();

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_DIGEST, (char*) digest, 0))
                return log_openssl_errors("Failed to add KDF-SS OSSL_KDF_PARAM_DIGEST");

        if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_KEY, (char*) key, key_size))
                return log_openssl_errors("Failed to add KDF-SS OSSL_KDF_PARAM_KEY");

        if (salt)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT, (char*) salt, salt_size))
                        return log_openssl_errors("Failed to add KDF-SS OSSL_KDF_PARAM_SALT");

        if (info)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_INFO, (char*) info, info_size))
                        return log_openssl_errors("Failed to add KDF-SS OSSL_KDF_PARAM_INFO");

        _cleanup_(sym_OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build KDF-SS OSSL_PARAM");

        if (sym_EVP_KDF_derive(ctx, buf, derive_size, params) <= 0)
                return log_openssl_errors("OpenSSL KDF-SS derive failed");

        *ret = TAKE_PTR(buf);

        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "KDF-SS requires OpenSSL >= 3.");
#endif
}

/* Perform Key-Based sym_HMAC KDF. The mode must be "COUNTER" or "FEEDBACK". The parameter naming is from the
 * OpenSSL api, and maps to SP800-108 naming as "...key, salt, info, and seed correspond to KI, Label,
 * Context, and IV (respectively)...". The derive_size parameter specifies how many bytes are derived.
 *
 * For more details see: https://www.openssl.org/docs/manmaster/man7/EVP_KDF-KB.html */
int kdf_kb_hmac_derive(
                const char *mode,
                const char *digest,
                const void *key,
                size_t key_size,
                const void *salt,
                size_t salt_size,
                const void *info,
                size_t info_size,
                const void *seed,
                size_t seed_size,
                size_t derive_size,
                void **ret) {

#if OPENSSL_VERSION_MAJOR >= 3
        int r;

        assert(mode);
        assert(strcaseeq(mode, "COUNTER") || strcaseeq(mode, "FEEDBACK"));
        assert(digest);
        assert(key || key_size == 0);
        assert(salt || salt_size == 0);
        assert(info || info_size == 0);
        assert(seed || seed_size == 0);
        assert(derive_size > 0);
        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        _cleanup_(sym_EVP_KDF_freep) EVP_KDF *kdf = sym_EVP_KDF_fetch(NULL, "KBKDF", NULL);
        if (!kdf)
                return log_openssl_errors("Failed to create new EVP_KDF");

        _cleanup_(sym_EVP_KDF_CTX_freep) EVP_KDF_CTX *ctx = sym_EVP_KDF_CTX_new(kdf);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_KDF_CTX");

        _cleanup_(sym_OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_MAC, (char*) "sym_HMAC", 0))
                return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_MAC");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_MODE, (char*) mode, 0))
                return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_MODE");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_DIGEST, (char*) digest, 0))
                return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_DIGEST");

        if (key)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_KEY, (char*) key, key_size))
                        return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_KEY");

        if (salt)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT, (char*) salt, salt_size))
                        return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_SALT");

        if (info)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_INFO, (char*) info, info_size))
                        return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_INFO");

        if (seed)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SEED, (char*) seed, seed_size))
                        return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_SEED");

        _cleanup_(sym_OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build KDF-KB OSSL_PARAM");

        _cleanup_free_ void *buf = malloc(derive_size);
        if (!buf)
                return log_oom_debug();

        if (sym_EVP_KDF_derive(ctx, buf, derive_size, params) <= 0)
                return log_openssl_errors("OpenSSL KDF-KB derive failed");

        *ret = TAKE_PTR(buf);

        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "KDF-KB requires OpenSSL >= 3.");
#endif
}

int rsa_encrypt_bytes(
                EVP_PKEY *pkey,
                const void *decrypted_key,
                size_t decrypted_key_size,
                void **ret_encrypt_key,
                size_t *ret_encrypt_key_size) {

        _cleanup_(sym_EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = NULL;
        _cleanup_free_ void *b = NULL;
        size_t l;
        int r;

        r = dlopen_openssl();
        if (r < 0)
                return r;

        ctx = sym_EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to allocate public key context");

        if (sym_EVP_PKEY_encrypt_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize public key context");

        if (sym_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
                return log_openssl_errors("Failed to configure PKCS#1 padding");

        if (sym_EVP_PKEY_encrypt(ctx, NULL, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to determine encrypted key size");

        b = malloc(l);
        if (!b)
                return -ENOMEM;

        if (sym_EVP_PKEY_encrypt(ctx, b, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to determine encrypted key size");

        *ret_encrypt_key = TAKE_PTR(b);
        *ret_encrypt_key_size = l;
        return 0;
}

/* Encrypt the key data using RSA-OAEP with the provided label and specified digest algorithm. Returns 0 on
 * success, -EOPNOTSUPP if the digest algorithm is not supported, or < 0 for any other error. */
int rsa_oaep_encrypt_bytes(
                const EVP_PKEY *pkey,
                const char *digest_alg,
                const char *label,
                const void *decrypted_key,
                size_t decrypted_key_size,
                void **ret_encrypt_key,
                size_t *ret_encrypt_key_size) {

        int r;

        assert(pkey);
        assert(digest_alg);
        assert(label);
        assert(decrypted_key);
        assert(decrypted_key_size > 0);
        assert(ret_encrypt_key);
        assert(ret_encrypt_key_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(sym_EVP_MD_freep) EVP_MD *md = sym_EVP_MD_fetch(NULL, digest_alg, NULL);
#else
        const EVP_MD *md = sym_EVP_get_digestbyname(digest_alg);
#endif
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Digest algorithm '%s' not supported.", digest_alg);

        _cleanup_(sym_EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new((EVP_PKEY*) pkey, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_encrypt_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (sym_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
                return log_openssl_errors("Failed to configure RSA-OAEP padding");

        if (sym_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
                return log_openssl_errors("Failed to configure RSA-OAEP MD");

        _cleanup_free_ char *duplabel = strdup(label);
        if (!duplabel)
                return log_oom_debug();

        if (sym_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, duplabel, strlen(duplabel) + 1) <= 0)
                return log_openssl_errors("Failed to configure RSA-OAEP label");
        /* ctx owns this now, don't free */
        TAKE_PTR(duplabel);

        size_t size = 0;
        if (sym_EVP_PKEY_encrypt(ctx, NULL, &size, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to determine RSA-OAEP encrypted key size");

        _cleanup_free_ void *buf = malloc(size);
        if (!buf)
                return log_oom_debug();

        if (sym_EVP_PKEY_encrypt(ctx, buf, &size, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to RSA-OAEP encrypt");

        *ret_encrypt_key = TAKE_PTR(buf);
        *ret_encrypt_key_size = size;

        return 0;
}

int rsa_pkey_to_suitable_key_size(
                EVP_PKEY *pkey,
                size_t *ret_suitable_key_size) {

        size_t suitable_key_size;
        int bits, r;

        assert(pkey);
        assert(ret_suitable_key_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        /* Analyzes the specified public key and that it is RSA. If so, will return a suitable size for a
         * disk encryption key to encrypt with RSA for use in PKCS#11 security token schemes. */

        if (sym_EVP_PKEY_get_base_id(pkey) != EVP_PKEY_RSA)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "X.509 certificate does not refer to RSA key.");

        bits = EVP_PKEY_bits(pkey);
        log_debug("Bits in RSA key: %i", bits);

        /* We use PKCS#1 padding for the RSA cleartext, hence let's leave some extra space for it, hence only
         * generate a random key half the size of the RSA length */
        suitable_key_size = bits / 8 / 2;

        if (suitable_key_size < 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Uh, RSA key size too short?");

        *ret_suitable_key_size = suitable_key_size;
        return 0;
}

/* Generate RSA public key from provided "n" and "e" values. Numbers "n" and "e" must be provided here
 * in big-endian format, e.g. wrap it with htobe32() for uint32_t. */
int rsa_pkey_from_n_e(const void *n, size_t n_size, const void *e, size_t e_size, EVP_PKEY **ret) {
        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        int r;

        assert(n);
        assert(n_size != 0);
        assert(e);
        assert(e_size != 0);
        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(sym_EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_fromdata_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        OSSL_PARAM params[3];

#if __BYTE_ORDER == __BIG_ENDIAN
        params[0] = sym_OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, (void*)n, n_size);
        params[1] = sym_OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, (void*)e, e_size);
#else
        _cleanup_free_ void *native_n = memdup_reverse(n, n_size);
        if (!native_n)
                return log_oom_debug();

        _cleanup_free_ void *native_e = memdup_reverse(e, e_size);
        if (!native_e)
                return log_oom_debug();

        params[0] = sym_OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, native_n, n_size);
        params[1] = sym_OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, native_e, e_size);
#endif
        params[2] = sym_OSSL_PARAM_construct_end();

        if (sym_EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
                return log_openssl_errors("Failed to create RSA EVP_PKEY");
#else
        _cleanup_(sym_BN_freep) BIGNUM *bn_n = sym_BN_bin2bn(n, n_size, NULL);
        if (!bn_n)
                return log_openssl_errors("Failed to create BIGNUM for RSA n");

        _cleanup_(sym_BN_freep) BIGNUM *bn_e = sym_BN_bin2bn(e, e_size, NULL);
        if (!bn_e)
                return log_openssl_errors("Failed to create BIGNUM for RSA e");

        _cleanup_(sym_RSA_freep) RSA *rsa_key = RSA_new();
        if (!rsa_key)
                return log_openssl_errors("Failed to create new RSA");

        if (!RSA_set0_key(rsa_key, bn_n, bn_e, NULL))
                return log_openssl_errors("Failed to set RSA n/e");
        /* rsa_key owns these now, don't free */
        TAKE_PTR(bn_n);
        TAKE_PTR(bn_e);

        pkey = EVP_PKEY_new();
        if (!pkey)
                return log_openssl_errors("Failed to create new EVP_PKEY");

        if (!EVP_PKEY_assign_RSA(pkey, rsa_key))
                return log_openssl_errors("Failed to assign RSA key");
        /* pkey owns this now, don't free */
        TAKE_PTR(rsa_key);
#endif

        *ret = TAKE_PTR(pkey);

        return 0;
}

/* Get the "n" and "e" values from the pkey. The values are returned in "bin" format, i.e. sym_BN_bn2bin(). */
int rsa_pkey_to_n_e(
                const EVP_PKEY *pkey,
                void **ret_n,
                size_t *ret_n_size,
                void **ret_e,
                size_t *ret_e_size) {

        int r;

        assert(pkey);
        assert(ret_n);
        assert(ret_n_size);
        assert(ret_e);
        assert(ret_e_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(sym_BN_freep) BIGNUM *bn_n = NULL;
        if (!sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n))
                return log_openssl_errors("Failed to get RSA n");

        _cleanup_(sym_BN_freep) BIGNUM *bn_e = NULL;
        if (!sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e))
                return log_openssl_errors("Failed to get RSA e");
#else
        const RSA *rsa = EVP_PKEY_get0_RSA((EVP_PKEY*) pkey);
        if (!rsa)
                return log_openssl_errors("Failed to get RSA key from public key");

        const BIGNUM *bn_n = RSA_get0_n(rsa);
        if (!bn_n)
                return log_openssl_errors("Failed to get RSA n");

        const BIGNUM *bn_e = RSA_get0_e(rsa);
        if (!bn_e)
                return log_openssl_errors("Failed to get RSA e");
#endif

        size_t n_size = BN_num_bytes(bn_n), e_size = BN_num_bytes(bn_e);
        _cleanup_free_ void *n = malloc(n_size), *e = malloc(e_size);
        if (!n || !e)
                return log_oom_debug();

        assert(sym_BN_bn2bin(bn_n, n) == (int) n_size);
        assert(sym_BN_bn2bin(bn_e, e) == (int) e_size);

        *ret_n = TAKE_PTR(n);
        *ret_n_size = n_size;
        *ret_e = TAKE_PTR(e);
        *ret_e_size = e_size;

        return 0;
}

/* Generate a new RSA key with the specified number of bits. */
int rsa_pkey_new(size_t bits, EVP_PKEY **ret) {
        int r;

        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        _cleanup_(sym_EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_keygen_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (sym_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int) bits) <= 0)
                return log_openssl_errors("Failed to set RSA bits to %zu", bits);

        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (sym_EVP_PKEY_keygen(ctx, &pkey) <= 0)
                return log_openssl_errors("Failed to generate ECC key");

        *ret = TAKE_PTR(pkey);

        return 0;
}

/* Generate ECC public key from provided curve ID and x/y points. */
int ecc_pkey_from_curve_x_y(
                int curve_id,
                const void *x,
                size_t x_size,
                const void *y,
                size_t y_size,
                EVP_PKEY **ret) {

        int r;

        assert(x);
        assert(y);
        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        _cleanup_(sym_EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        _cleanup_(sym_BN_freep) BIGNUM *bn_x = sym_BN_bin2bn(x, x_size, NULL);
        if (!bn_x)
                return log_openssl_errors("Failed to create BIGNUM x");

        _cleanup_(sym_BN_freep) BIGNUM *bn_y = sym_BN_bin2bn(y, y_size, NULL);
        if (!bn_y)
                return log_openssl_errors("Failed to create BIGNUM y");

        _cleanup_(sym_EC_GROUP_freep) EC_GROUP *group = sym_EC_GROUP_new_by_curve_name(curve_id);
        if (!group)
                return log_openssl_errors("ECC curve id %d not supported", curve_id);

        _cleanup_(sym_EC_POINT_freep) EC_POINT *point = sym_EC_POINT_new(group);
        if (!point)
                return log_openssl_errors("Failed to create new EC_POINT");

        if (!sym_EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, NULL))
                return log_openssl_errors("Failed to set ECC coordinates");

#if OPENSSL_VERSION_MAJOR >= 3
        if (sym_EVP_PKEY_fromdata_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        _cleanup_(sym_OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, (char*) sym_OSSL_EC_curve_nid2name(curve_id), 0))
                return log_openssl_errors("Failed to add ECC OSSL_PKEY_PARAM_GROUP_NAME");

        _cleanup_(sym_OPENSSL_freep) void *pbuf = NULL;
        size_t pbuf_len = 0;
        pbuf_len = sym_EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED, (unsigned char**) &pbuf, NULL);
        if (pbuf_len == 0)
                return log_openssl_errors("Failed to convert ECC point to buffer");

        if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbuf, pbuf_len))
                return log_openssl_errors("Failed to add ECC OSSL_PKEY_PARAM_PUB_KEY");

        _cleanup_(sym_OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build ECC OSSL_PARAM");

        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (sym_EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
                return log_openssl_errors("Failed to create ECC EVP_PKEY");
#else
        _cleanup_(sym_EC_KEY_freep) EC_KEY *eckey = EC_KEY_new();
        if (!eckey)
                return log_openssl_errors("Failed to create new EC_KEY");

        if (!EC_KEY_set_group(eckey, group))
                return log_openssl_errors("Failed to set ECC group");

        if (!EC_KEY_set_public_key(eckey, point))
                return log_openssl_errors("Failed to set ECC point");

        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *pkey = EVP_PKEY_new();
        if (!pkey)
                return log_openssl_errors("Failed to create new EVP_PKEY");

        if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
                return log_openssl_errors("Failed to assign ECC key");
        /* pkey owns this now, don't free */
        TAKE_PTR(eckey);
#endif

    *ret = TAKE_PTR(pkey);

    return 0;
}

int ecc_pkey_to_curve_x_y(
                const EVP_PKEY *pkey,
                int *ret_curve_id,
                void **ret_x,
                size_t *ret_x_size,
                void **ret_y,
                size_t *ret_y_size) {

        _cleanup_(sym_BN_freep) BIGNUM *bn_x = NULL, *bn_y = NULL;
        int curve_id, r;

        assert(pkey);

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        size_t name_size;
        if (!sym_EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &name_size))
                return log_openssl_errors("Failed to get ECC group name size");

        _cleanup_free_ char *name = new(char, name_size + 1);
        if (!name)
                return log_oom_debug();

        if (!sym_EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, name, name_size + 1, NULL))
                return log_openssl_errors("Failed to get ECC group name");

        curve_id = sym_OBJ_sn2nid(name);
        if (curve_id == NID_undef)
                return log_openssl_errors("Failed to get ECC curve id");

        if (!sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bn_x))
                return log_openssl_errors("Failed to get ECC point x");

        if (!sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &bn_y))
                return log_openssl_errors("Failed to get ECC point y");
#else
        const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY((EVP_PKEY*) pkey);
        if (!eckey)
                return log_openssl_errors("Failed to get EC_KEY");

        const EC_GROUP *group = EC_KEY_get0_group(eckey);
        if (!group)
                return log_openssl_errors("Failed to get EC_GROUP");

        curve_id = sym_EC_GROUP_get_curve_name(group);
        if (curve_id == NID_undef)
                return log_openssl_errors("Failed to get ECC curve id");

        const EC_POINT *point = EC_KEY_get0_public_key(eckey);
        if (!point)
                return log_openssl_errors("Failed to get EC_POINT");

        bn_x = sym_BN_new();
        bn_y = sym_BN_new();
        if (!bn_x || !bn_y)
                return log_openssl_errors("Failed to create new BIGNUM");

        if (!EC_POINT_get_affine_coordinates(group, point, bn_x, bn_y, NULL))
                return log_openssl_errors("Failed to get ECC x/y.");
#endif

        size_t x_size = BN_num_bytes(bn_x), y_size = BN_num_bytes(bn_y);
        _cleanup_free_ void *x = malloc(x_size), *y = malloc(y_size);
        if (!x || !y)
                return log_oom_debug();

        assert(sym_BN_bn2bin(bn_x, x) == (int) x_size);
        assert(sym_BN_bn2bin(bn_y, y) == (int) y_size);

        if (ret_curve_id)
                *ret_curve_id = curve_id;
        if (ret_x)
                *ret_x = TAKE_PTR(x);
        if (ret_x_size)
                *ret_x_size = x_size;
        if (ret_y)
                *ret_y = TAKE_PTR(y);
        if (ret_y_size)
                *ret_y_size = y_size;

        return 0;
}

/* Generate a new ECC key for the specified ECC curve id. */
int ecc_pkey_new(int curve_id, EVP_PKEY **ret) {
        int r;

        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        _cleanup_(sym_EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_keygen_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (sym_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_id) <= 0)
                return log_openssl_errors("Failed to set ECC curve %d", curve_id);

        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (sym_EVP_PKEY_keygen(ctx, &pkey) <= 0)
                return log_openssl_errors("Failed to generate ECC key");

        *ret = TAKE_PTR(pkey);

        return 0;
}

/* Perform ECDH to derive an ECC shared secret between the provided private key and public peer key. For two
 * keys, this will result in the same shared secret in either direction; ECDH using Alice's private key and
 * Bob's public (peer) key will result in the same shared secret as ECDH using Bob's private key and Alice's
 * public (peer) key. On success, this returns 0 and provides the shared secret; otherwise this returns an
 * error. */
int ecc_ecdh(const EVP_PKEY *private_pkey,
             const EVP_PKEY *peer_pkey,
             void **ret_shared_secret,
             size_t *ret_shared_secret_size) {

        int r;

        assert(private_pkey);
        assert(peer_pkey);
        assert(ret_shared_secret);
        assert(ret_shared_secret_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        _cleanup_(sym_EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new((EVP_PKEY*) private_pkey, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_derive_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (sym_EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY*) peer_pkey) <= 0)
                return log_openssl_errors("Failed to set ECC derive peer");

        size_t shared_secret_size;
        if (sym_EVP_PKEY_derive(ctx, NULL, &shared_secret_size) <= 0)
                return log_openssl_errors("Failed to get ECC shared secret size");

        _cleanup_(erase_and_freep) void *shared_secret = malloc(shared_secret_size);
        if (!shared_secret)
                return log_oom_debug();

        if (sym_EVP_PKEY_derive(ctx, (unsigned char*) shared_secret, &shared_secret_size) <= 0)
                return log_openssl_errors("Failed to derive ECC shared secret");

        *ret_shared_secret = TAKE_PTR(shared_secret);
        *ret_shared_secret_size = shared_secret_size;

        return 0;
}

int pubkey_fingerprint(EVP_PKEY *pk, const EVP_MD *md, void **ret, size_t *ret_size) {
        _cleanup_(sym_EVP_MD_CTX_freep) EVP_MD_CTX* m = NULL;
        _cleanup_free_ void *d = NULL, *h = NULL;
        int sz, lsz, msz, r;
        unsigned umsz;
        unsigned char *dd;

        /* Calculates a message digest of the DER encoded public key */

        assert(pk);
        assert(md);
        assert(ret);
        assert(ret_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        sz = sym_i2d_PublicKey(pk, NULL);
        if (sz < 0)
                return log_openssl_errors("Unable to convert public key to DER format");

        dd = d = malloc(sz);
        if (!d)
                return log_oom_debug();

        lsz = sym_i2d_PublicKey(pk, &dd);
        if (lsz < 0)
                return log_openssl_errors("Unable to convert public key to DER format");

        m = sym_EVP_MD_CTX_new();
        if (!m)
                return log_openssl_errors("Failed to create new EVP_MD_CTX");

        if (sym_EVP_DigestInit_ex(m, md, NULL) != 1)
                return log_openssl_errors("Failed to initialize %s context", EVP_MD_name(md));

        if (sym_EVP_DigestUpdate(m, d, lsz) != 1)
                return log_openssl_errors("Failed to run %s context", EVP_MD_name(md));

        msz = EVP_MD_size(md);
        assert(msz > 0);

        h = malloc(msz);
        if (!h)
                return log_oom_debug();

        umsz = msz;
        if (sym_EVP_DigestFinal_ex(m, h, &umsz) != 1)
                return log_openssl_errors("Failed to finalize hash context");

        assert(umsz == (unsigned) msz);

        *ret = TAKE_PTR(h);
        *ret_size = msz;

        return 0;
}

int digest_and_sign(
                const EVP_MD *md,
                EVP_PKEY *privkey,
                const void *data, size_t size,
                void **ret, size_t *ret_size) {

        int r;

        assert(privkey);
        assert(ret);
        assert(ret_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        if (size == 0)
                data = ""; /* make sure to pass a valid pointer to OpenSSL */
        else {
                assert(data);

                if (size == SIZE_MAX) /* If SIZE_MAX input is a string whose size we determine automatically */
                        size = strlen(data);
        }

        _cleanup_(sym_EVP_MD_CTX_freep) EVP_MD_CTX* mdctx = sym_EVP_MD_CTX_new();
        if (!mdctx)
                return log_openssl_errors("Failed to create new EVP_MD_CTX");

        if (sym_EVP_DigestSignInit(mdctx, NULL, md, NULL, privkey) != 1)
                return log_openssl_errors("Failed to initialize signature context");

        /* Determine signature size */
        size_t ss;
        if (sym_EVP_DigestSign(mdctx, NULL, &ss, data, size) != 1)
                return log_openssl_errors("Failed to determine size of signature");

        _cleanup_free_ void *sig = malloc(ss);
        if (!sig)
                return log_oom_debug();

        if (sym_EVP_DigestSign(mdctx, sig, &ss, data, size) != 1)
                return log_openssl_errors("Failed to sign data");

        *ret = TAKE_PTR(sig);
        *ret_size = ss;
        return 0;
}

#  if PREFER_OPENSSL
int string_hashsum(
                const char *s,
                size_t len,
                const char *md_algorithm,
                char **ret) {

        _cleanup_free_ void *hash = NULL;
        size_t hash_size;
        _cleanup_free_ char *enc = NULL;
        int r;

        assert(s || len == 0);
        assert(md_algorithm);
        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        r = openssl_digest(md_algorithm, s, len, &hash, &hash_size);
        if (r < 0)
                return r;

        enc = hexmem(hash, hash_size);
        if (!enc)
                return -ENOMEM;

        *ret = TAKE_PTR(enc);
        return 0;
}
#  endif

static int ecc_pkey_generate_volume_keys(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_saved_key,
                size_t *ret_saved_key_size) {

        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *pkey_new = NULL;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_free_ unsigned char *saved_key = NULL;
        size_t decrypted_key_size, saved_key_size;
        int nid = NID_undef;
        int r;

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_free_ char *curve_name = NULL;
        size_t len = 0;

        if (sym_EVP_PKEY_get_group_name(pkey, NULL, 0, &len) != 1 || len == 0)
                return log_openssl_errors("Failed to determine PKEY group name length");

        len++;
        curve_name = new(char, len);
        if (!curve_name)
                return log_oom_debug();

        if (sym_EVP_PKEY_get_group_name(pkey, curve_name, len, &len) != 1)
                return log_openssl_errors("Failed to get PKEY group name");

        nid = sym_OBJ_sn2nid(curve_name);
#else
        EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
        if (!ec_key)
                return log_openssl_errors("PKEY doesn't have EC_KEY associated");

        if (EC_KEY_check_key(ec_key) != 1)
                return log_openssl_errors("EC_KEY associated with PKEY is not valid");

        nid = sym_EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
#endif

        r = ecc_pkey_new(nid, &pkey_new);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate a new EC keypair: %m");

        r = ecc_ecdh(pkey_new, pkey, &decrypted_key, &decrypted_key_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to derive shared secret: %m");

#if OPENSSL_VERSION_MAJOR >= 3
        /* sym_EVP_PKEY_get1_encoded_public_key() always returns uncompressed format of EC points.
           See https://github.com/openssl/openssl/discussions/22835 */
        saved_key_size = sym_EVP_PKEY_get1_encoded_public_key(pkey_new, &saved_key);
        if (saved_key_size == 0)
                return log_openssl_errors("Failed to convert the generated public key to SEC1 format");
#else
        EC_KEY *ec_key_new = EVP_PKEY_get0_EC_KEY(pkey_new);
        if (!ec_key_new)
                return log_openssl_errors("The generated key doesn't have associated EC_KEY");

        if (EC_KEY_check_key(ec_key_new) != 1)
                return log_openssl_errors("EC_KEY associated with the generated key is not valid");

        saved_key_size = sym_EC_POINT_point2oct(EC_KEY_get0_group(ec_key_new),
                                            EC_KEY_get0_public_key(ec_key_new),
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            NULL, 0, NULL);
        if (saved_key_size == 0)
                return log_openssl_errors("Failed to determine size of the generated public key");

        saved_key = malloc(saved_key_size);
        if (!saved_key)
                return log_oom_debug();

        saved_key_size = sym_EC_POINT_point2oct(EC_KEY_get0_group(ec_key_new),
                                            EC_KEY_get0_public_key(ec_key_new),
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            saved_key, saved_key_size, NULL);
        if (saved_key_size == 0)
                return log_openssl_errors("Failed to convert the generated public key to SEC1 format");
#endif

        *ret_decrypted_key = TAKE_PTR(decrypted_key);
        *ret_decrypted_key_size = decrypted_key_size;
        *ret_saved_key = TAKE_PTR(saved_key);
        *ret_saved_key_size = saved_key_size;
        return 0;
}

static int rsa_pkey_generate_volume_keys(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_saved_key,
                size_t *ret_saved_key_size) {

        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_free_ void *saved_key = NULL;
        size_t decrypted_key_size, saved_key_size;
        int r;

        r = dlopen_openssl();
        if (r < 0)
                return r;

        r = rsa_pkey_to_suitable_key_size(pkey, &decrypted_key_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine RSA public key size.");

        log_debug("Generating %zu bytes random key.", decrypted_key_size);

        decrypted_key = malloc(decrypted_key_size);
        if (!decrypted_key)
                return log_oom_debug();

        r = crypto_random_bytes(decrypted_key, decrypted_key_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate random key: %m");

        r = rsa_encrypt_bytes(pkey, decrypted_key, decrypted_key_size, &saved_key, &saved_key_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to encrypt random key: %m");

        *ret_decrypted_key = TAKE_PTR(decrypted_key);
        *ret_decrypted_key_size = decrypted_key_size;
        *ret_saved_key = TAKE_PTR(saved_key);
        *ret_saved_key_size = saved_key_size;
        return 0;
}

int pkey_generate_volume_keys(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_saved_key,
                size_t *ret_saved_key_size) {

        int r;

        assert(pkey);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);
        assert(ret_saved_key);
        assert(ret_saved_key_size);

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        int type = sym_EVP_PKEY_get_base_id(pkey);
#else
        int type = sym_EVP_PKEY_get_base_id(pkey);
#endif
        switch (type) {

        case EVP_PKEY_RSA:
                return rsa_pkey_generate_volume_keys(pkey, ret_decrypted_key, ret_decrypted_key_size, ret_saved_key, ret_saved_key_size);

        case EVP_PKEY_EC:
                return ecc_pkey_generate_volume_keys(pkey, ret_decrypted_key, ret_decrypted_key_size, ret_saved_key, ret_saved_key_size);

        case NID_undef:
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine a type of public key.");

        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported public key type: %s", sym_OBJ_nid2sn(type));
        }
}

static int load_key_from_provider(const char *provider, const char *private_key_uri, EVP_PKEY **ret) {
        int r;

        assert(provider);
        assert(private_key_uri);
        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if OPENSSL_VERSION_MAJOR >= 3
        /* Load the provider so that this can work without any custom written configuration in /etc/.
         * Also load the 'default' as that seems to be the recommendation. */
        if (!sym_OSSL_PROVIDER_try_load(/* ctx= */ NULL, provider, /* retain_fallbacks= */ true))
                return log_openssl_errors("Failed to load OpenSSL provider '%s'", provider);
        if (!sym_OSSL_PROVIDER_try_load(/* ctx= */ NULL, "default", /* retain_fallbacks= */ true))
                return log_openssl_errors("Failed to load OpenSSL provider 'default'");

        _cleanup_(sym_OSSL_STORE_closep) OSSL_STORE_CTX *store = sym_OSSL_STORE_open(
                        private_key_uri,
                        /* ui_method= */ NULL,
                        /* ui_data= */ NULL,
                        /* post_process= */ NULL,
                        /* post_process_data= */ NULL);
        if (!store)
                return log_openssl_errors("Failed to open OpenSSL store via '%s'", private_key_uri);

        _cleanup_(sym_OSSL_STORE_INFO_freep) OSSL_STORE_INFO *info = sym_OSSL_STORE_load(store);
        if (!info)
                return log_openssl_errors("Failed to load OpenSSL store via '%s'", private_key_uri);

        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *private_key = sym_OSSL_STORE_INFO_get1_PKEY(info);
        if (!private_key)
                return log_openssl_errors("Failed to load private key via '%s'", private_key_uri);

        *ret = TAKE_PTR(private_key);

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

static int load_key_from_engine(const char *engine, const char *private_key_uri, EVP_PKEY **ret) {
        int r;

        assert(engine);
        assert(private_key_uri);
        assert(ret);

        r = dlopen_openssl();
        if (r < 0)
                return r;

#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
        DISABLE_WARNING_DEPRECATED_DECLARATIONS;
        _cleanup_(sym_ENGINE_freep) ENGINE *e = sym_ENGINE_by_id(engine);
        if (!e)
                return log_openssl_errors("Failed to load signing engine '%s'", engine);

        if (sym_ENGINE_init(e) == 0)
                return log_openssl_errors("Failed to initialize signing engine '%s'", engine);

        _cleanup_(sym_EVP_PKEY_freep) EVP_PKEY *private_key = sym_ENGINE_load_private_key(
                        e,
                        private_key_uri,
                        /* ui_method= */ NULL,
                        /* callback_data= */ NULL);
        if (!private_key)
                return log_openssl_errors("Failed to load private key from '%s'", private_key_uri);
        REENABLE_WARNING;

        *ret = TAKE_PTR(private_key);

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int openssl_load_key_from_token(
                KeySourceType private_key_source_type,
                const char *private_key_source,
                const char *private_key,
                EVP_PKEY **ret) {

        int r;

        assert(IN_SET(private_key_source_type, OPENSSL_KEY_SOURCE_ENGINE, OPENSSL_KEY_SOURCE_PROVIDER));
        assert(private_key_source);
        assert(private_key);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        switch (private_key_source_type) {

        case OPENSSL_KEY_SOURCE_ENGINE:
                return load_key_from_engine(private_key_source, private_key, ret);
        case OPENSSL_KEY_SOURCE_PROVIDER:
                return load_key_from_provider(private_key_source, private_key, ret);
        default:
                assert_not_reached();
        }
}
#endif

int x509_fingerprint(X509 *cert, uint8_t buffer[static SHA256_DIGEST_SIZE]) {
#if HAVE_OPENSSL
        _cleanup_free_ uint8_t *der = NULL;
        int dersz, r;

        assert(cert);

        r = dlopen_openssl();
        if (r < 0)
                return r;

        dersz = sym_i2d_X509(cert, &der);
        if (dersz < 0)
                return log_openssl_errors("Unable to convert PEM certificate to DER format");

        sha256_direct(der, dersz, buffer);
        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot calculate X509 fingerprint.");
#endif
}

int parse_openssl_key_source_argument(
                const char *argument,
                char **private_key_source,
                KeySourceType *private_key_source_type) {

        KeySourceType type;
        const char *e = NULL;
        int r;

        assert(argument);
        assert(private_key_source);
        assert(private_key_source_type);

        if (streq(argument, "file"))
                type = OPENSSL_KEY_SOURCE_FILE;
        else if ((e = startswith(argument, "engine:")))
                type = OPENSSL_KEY_SOURCE_ENGINE;
        else if ((e = startswith(argument, "provider:")))
                type = OPENSSL_KEY_SOURCE_PROVIDER;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid private key source '%s'", argument);

        r = free_and_strdup_warn(private_key_source, e);
        if (r < 0)
                return r;

        *private_key_source_type = type;

        return 0;
}
