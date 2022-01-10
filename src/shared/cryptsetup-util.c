/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/sed-opal.h>
#include <sys/ioctl.h>

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "dlfcn-util.h"
#include "fd-util.h"
#include "log.h"
#include "parse-util.h"
#include "string-table.h"

#if HAVE_LIBCRYPTSETUP
static void *cryptsetup_dl = NULL;

int (*sym_crypt_activate_by_passphrase)(struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size, uint32_t flags);
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
int (*sym_crypt_activate_by_signed_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, const char *signature, size_t signature_size, uint32_t flags);
#endif
int (*sym_crypt_activate_by_volume_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, uint32_t flags);
int (*sym_crypt_deactivate_by_name)(struct crypt_device *cd, const char *name, uint32_t flags);
int (*sym_crypt_format)(struct crypt_device *cd, const char *type, const char *cipher, const char *cipher_mode, const char *uuid, const char *volume_key, size_t volume_key_size, void *params);
void (*sym_crypt_free)(struct crypt_device *cd);
const char *(*sym_crypt_get_cipher)(struct crypt_device *cd);
const char *(*sym_crypt_get_cipher_mode)(struct crypt_device *cd);
uint64_t (*sym_crypt_get_data_offset)(struct crypt_device *cd);
const char *(*sym_crypt_get_device_name)(struct crypt_device *cd);
const char *(*sym_crypt_get_dir)(void);
const char *(*sym_crypt_get_type)(struct crypt_device *cd);
const char *(*sym_crypt_get_uuid)(struct crypt_device *cd);
int (*sym_crypt_get_verity_info)(struct crypt_device *cd, struct crypt_params_verity *vp);
int (*sym_crypt_get_volume_key_size)(struct crypt_device *cd);
int (*sym_crypt_init)(struct crypt_device **cd, const char *device);
int (*sym_crypt_init_by_name)(struct crypt_device **cd, const char *name);
int (*sym_crypt_keyslot_add_by_volume_key)(struct crypt_device *cd, int keyslot, const char *volume_key, size_t volume_key_size, const char *passphrase, size_t passphrase_size);
int (*sym_crypt_keyslot_destroy)(struct crypt_device *cd, int keyslot);
int (*sym_crypt_keyslot_max)(const char *type);
int (*sym_crypt_load)(struct crypt_device *cd, const char *requested_type, void *params);
int (*sym_crypt_resize)(struct crypt_device *cd, const char *name, uint64_t new_size);
int (*sym_crypt_resume_by_passphrase)(struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size);
int (*sym_crypt_set_data_device)(struct crypt_device *cd, const char *device);
void (*sym_crypt_set_debug_level)(int level);
void (*sym_crypt_set_log_callback)(struct crypt_device *cd, void (*log)(int level, const char *msg, void *usrptr), void *usrptr);
#if HAVE_CRYPT_SET_METADATA_SIZE
int (*sym_crypt_set_metadata_size)(struct crypt_device *cd, uint64_t metadata_size, uint64_t keyslots_size);
#endif
int (*sym_crypt_set_pbkdf_type)(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf);
int (*sym_crypt_suspend)(struct crypt_device *cd, const char *name);
int (*sym_crypt_token_json_get)(struct crypt_device *cd, int token, const char **json);
int (*sym_crypt_token_json_set)(struct crypt_device *cd, int token, const char *json);
#if HAVE_CRYPT_TOKEN_MAX
int (*sym_crypt_token_max)(const char *type);
#endif
crypt_token_info (*sym_crypt_token_status)(struct crypt_device *cd, int token, const char **type);
int (*sym_crypt_volume_key_get)(struct crypt_device *cd, int keyslot, char *volume_key, size_t *volume_key_size, const char *passphrase, size_t passphrase_size);

static void cryptsetup_log_glue(int level, const char *msg, void *usrptr) {

        switch (level) {
        case CRYPT_LOG_NORMAL:
                level = LOG_NOTICE;
                break;
        case CRYPT_LOG_ERROR:
                level = LOG_ERR;
                break;
        case CRYPT_LOG_VERBOSE:
                level = LOG_INFO;
                break;
        case CRYPT_LOG_DEBUG:
                level = LOG_DEBUG;
                break;
        default:
                log_error("Unknown libcryptsetup log level: %d", level);
                level = LOG_ERR;
        }

        log_full(level, "%s", msg);
}

void cryptsetup_enable_logging(struct crypt_device *cd) {
        /* It's OK to call this with a NULL parameter, in which case libcryptsetup will set the default log
         * function.
         *
         * Note that this is also called from dlopen_cryptsetup(), which we call here too. Sounds like an
         * endless loop, but isn't because we break it via the check for 'cryptsetup_dl' early in
         * dlopen_cryptsetup(). */

        if (dlopen_cryptsetup() < 0)
                return; /* If this fails, let's gracefully ignore the issue, this is just debug logging after
                         * all, and if this failed we already generated a debug log message that should help
                         * to track things down. */

        sym_crypt_set_log_callback(cd, cryptsetup_log_glue, NULL);
        sym_crypt_set_debug_level(DEBUG_LOGGING ? CRYPT_DEBUG_ALL : CRYPT_DEBUG_NONE);
}

int cryptsetup_set_minimal_pbkdf(struct crypt_device *cd) {

        /* With CRYPT_PBKDF_NO_BENCHMARK flag set .time_ms member is ignored
         * while .iterations must be set at least to recommended minimum value. */

        static const struct crypt_pbkdf_type minimal_pbkdf = {
                .hash = "sha512",
                .type = CRYPT_KDF_PBKDF2,
                .iterations = 1000, /* recommended minimum count for pbkdf2
                                     * according to NIST SP 800-132, ch. 5.2 */
                .flags = CRYPT_PBKDF_NO_BENCHMARK
        };

        int r;

        /* Sets a minimal PKBDF in case we already have a high entropy key. */

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = sym_crypt_set_pbkdf_type(cd, &minimal_pbkdf);
        if (r < 0)
                return r;

        return 0;
}

int cryptsetup_get_token_as_json(
                struct crypt_device *cd,
                int idx,
                const char *verify_type,
                JsonVariant **ret) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        const char *text;
        int r;

        assert(cd);

        /* Extracts and parses the LUKS2 JSON token data from a LUKS2 device. Optionally verifies the type of
         * the token. Returns:
         *
         *      -EINVAL → token index out of range or "type" field missing
         *      -ENOENT → token doesn't exist
         * -EMEDIUMTYPE → "verify_type" specified and doesn't match token's type
         */

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = sym_crypt_token_json_get(cd, idx, &text);
        if (r < 0)
                return r;

        r = json_parse(text, 0, &v, NULL, NULL);
        if (r < 0)
                return r;

        if (verify_type) {
                JsonVariant *w;

                w = json_variant_by_key(v, "type");
                if (!w)
                        return -EINVAL;

                if (!streq_ptr(json_variant_string(w), verify_type))
                        return -EMEDIUMTYPE;
        }

        if (ret)
                *ret = TAKE_PTR(v);

        return 0;
}

int cryptsetup_add_token_json(struct crypt_device *cd, JsonVariant *v) {
        _cleanup_free_ char *text = NULL;
        int r;

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = json_variant_format(v, 0, &text);
        if (r < 0)
                return log_debug_errno(r, "Failed to format token data for LUKS: %m");

        log_debug("Adding token text <%s>", text);

        r = sym_crypt_token_json_set(cd, CRYPT_ANY_TOKEN, text);
        if (r < 0)
                return log_debug_errno(r, "Failed to write token data to LUKS: %m");

        return 0;
}
#endif

int dlopen_cryptsetup(void) {
#if HAVE_LIBCRYPTSETUP
        int r;

        r = dlopen_many_sym_or_warn(
                        &cryptsetup_dl, "libcryptsetup.so.12", LOG_DEBUG,
                        DLSYM_ARG(crypt_activate_by_passphrase),
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                        DLSYM_ARG(crypt_activate_by_signed_key),
#endif
                        DLSYM_ARG(crypt_activate_by_volume_key),
                        DLSYM_ARG(crypt_deactivate_by_name),
                        DLSYM_ARG(crypt_format),
                        DLSYM_ARG(crypt_free),
                        DLSYM_ARG(crypt_get_cipher),
                        DLSYM_ARG(crypt_get_cipher_mode),
                        DLSYM_ARG(crypt_get_data_offset),
                        DLSYM_ARG(crypt_get_device_name),
                        DLSYM_ARG(crypt_get_dir),
                        DLSYM_ARG(crypt_get_type),
                        DLSYM_ARG(crypt_get_uuid),
                        DLSYM_ARG(crypt_get_verity_info),
                        DLSYM_ARG(crypt_get_volume_key_size),
                        DLSYM_ARG(crypt_init),
                        DLSYM_ARG(crypt_init_by_name),
                        DLSYM_ARG(crypt_keyslot_add_by_volume_key),
                        DLSYM_ARG(crypt_keyslot_destroy),
                        DLSYM_ARG(crypt_keyslot_max),
                        DLSYM_ARG(crypt_load),
                        DLSYM_ARG(crypt_resize),
                        DLSYM_ARG(crypt_resume_by_passphrase),
                        DLSYM_ARG(crypt_set_data_device),
                        DLSYM_ARG(crypt_set_debug_level),
                        DLSYM_ARG(crypt_set_log_callback),
#if HAVE_CRYPT_SET_METADATA_SIZE
                        DLSYM_ARG(crypt_set_metadata_size),
#endif
                        DLSYM_ARG(crypt_set_pbkdf_type),
                        DLSYM_ARG(crypt_suspend),
                        DLSYM_ARG(crypt_token_json_get),
                        DLSYM_ARG(crypt_token_json_set),
#if HAVE_CRYPT_TOKEN_MAX
                        DLSYM_ARG(crypt_token_max),
#endif
                        DLSYM_ARG(crypt_token_status),
                        DLSYM_ARG(crypt_volume_key_get));
        if (r <= 0)
                return r;

        /* Redirect the default logging calls of libcryptsetup to our own logging infra. (Note that
         * libcryptsetup also maintains per-"struct crypt_device" log functions, which we'll also set
         * whenever allocating a "struct crypt_device" context. Why set both? To be defensive: maybe some
         * other code loaded into this process also changes the global log functions of libcryptsetup, who
         * knows? And if so, we still want our own objects to log via our own infra, at the very least.) */
        cryptsetup_enable_logging(NULL);
        return 1;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "cryptsetup support is not compiled in.");
#endif
}

int cryptsetup_get_keyslot_from_token(JsonVariant *v) {
        int keyslot, r;
        JsonVariant *w;

        /* Parses the "keyslots" field of a LUKS2 token object. The field can be an array, but here we assume
         * that it contains a single element only, since that's the only way we ever generate it
         * ourselves. */

        w = json_variant_by_key(v, "keyslots");
        if (!w)
                return -ENOENT;
        if (!json_variant_is_array(w) || json_variant_elements(w) != 1)
                return -EMEDIUMTYPE;

        w = json_variant_by_index(w, 0);
        if (!w)
                return -ENOENT;
        if (!json_variant_is_string(w))
                return -EMEDIUMTYPE;

        r = safe_atoi(json_variant_string(w), &keyslot);
        if (r < 0)
                return r;
        if (keyslot < 0)
                return -EINVAL;

        return keyslot;
}

#if HAVE_LIBCRYPTSETUP
/* Error codes are defined in the specification:
 * TCG_Storage_Architecture_Core_Spec_v2.01_r1.00
 * Section 5.1.5: Method Status Codes
 * Names and values from table 166 */
typedef enum OpalStatus {
        OPAL_STATUS_SUCCESS,
        OPAL_STATUS_NOT_AUTHORIZED,
        OPAL_STATUS_OBSOLETE0, /* Undefined but possible retun values are just called 'obsolete' */
        OPAL_STATUS_SP_BUSY,
        OPAL_STATUS_SP_FAILED,
        OPAL_STATUS_SP_DISABLED,
        OPAL_STATUS_SP_FROZEN,
        OPAL_STATUS_NO_SESSIONS_AVAILABLE,
        OPAL_STATUS_UNIQUENESS_CONFLICT,
        OPAL_STATUS_INSUFFICIENT_SPACE,
        OPAL_STATUS_INSUFFICIENT_ROWS,
        OPAL_STATUS_INVALID_PARAMETER,
        OPAL_STATUS_OBSOLETE1,
        OPAL_STATUS_OBSOLETE2,
        OPAL_STATUS_TPER_MALFUNCTION,
        OPAL_STATUS_TRANSACTION_FAILURE,
        OPAL_STATUS_RESPONSE_OVERFLOW,
        OPAL_STATUS_AUTHORITY_LOCKED_OUT,
        OPAL_STATUS_FAIL = 0x3F,
        _OPAL_STATUS_MAX,
        _OPAL_STATUS_INVALID = -EINVAL,
} OpalStatus;

static const char* const opal_status_table[_OPAL_STATUS_MAX] = {
        [OPAL_STATUS_SUCCESS]               = "success",
        [OPAL_STATUS_NOT_AUTHORIZED]        = "not authorized",
        [OPAL_STATUS_OBSOLETE0]             = "obsolete",
        [OPAL_STATUS_SP_BUSY]               = "SP busy",
        [OPAL_STATUS_SP_FAILED]             = "SP failed",
        [OPAL_STATUS_SP_DISABLED]           = "SP disabled",
        [OPAL_STATUS_SP_FROZEN]             = "SP frozen",
        [OPAL_STATUS_NO_SESSIONS_AVAILABLE] = "no sessions available",
        [OPAL_STATUS_UNIQUENESS_CONFLICT]   = "uniqueness conflict",
        [OPAL_STATUS_INSUFFICIENT_SPACE]    = "insufficient space",
        [OPAL_STATUS_INSUFFICIENT_ROWS]     = "insufficient rows",
        [OPAL_STATUS_INVALID_PARAMETER]     = "invalid parameter",
        [OPAL_STATUS_OBSOLETE1]             = "obsolete",
        [OPAL_STATUS_OBSOLETE2]             = "obsolete",
        [OPAL_STATUS_TPER_MALFUNCTION]      = "TPer malfunction",
        [OPAL_STATUS_TRANSACTION_FAILURE]   = "transaction failure",
        [OPAL_STATUS_RESPONSE_OVERFLOW]     = "response overflow",
        [OPAL_STATUS_AUTHORITY_LOCKED_OUT]  = "authority locked out",
        [OPAL_STATUS_FAIL]                  = "unknown failure",
};

const char *opal_status_to_string(int t) _const_;
DEFINE_STRING_TABLE_LOOKUP_TO_STRING(opal_status, OpalStatus);

/* The LUKS volume key is configured as the OPAL locking range passphrase, use it to lock/unlock the range. */
int opal_lock_unlock(
                struct crypt_device *cd,
                int fd,
                bool lock,
                bool pass_volume_key,
                int opal_segment,
                int keyslot,
                const char *passphrase,
                size_t passphrase_length) {

        if (opal_segment == -1)
                return 0; /* Nothing to do. */

        assert(cd);
        assert(passphrase || passphrase_length == 0);

        struct opal_lock_unlock unlock = {
                .l_state = lock ? OPAL_LK : OPAL_RW,
                .session = {
                        .who = OPAL_ADMIN1,
                        .opal_key = {
                                .lr = opal_segment,
                        },
                },
        };
        _cleanup_(erase_and_freep) char *volume_key = NULL;
        _cleanup_close_ int crypt_fd = -1;
        const char *device_name;
        size_t volume_key_size;
        int r;

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        volume_key_size = sym_crypt_get_volume_key_size(cd);
        if (volume_key_size > OPAL_KEY_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid volume key size: %zu > %d", volume_key_size, OPAL_KEY_MAX);

        if (volume_key_size > 0 && !pass_volume_key) {
                volume_key = malloc(volume_key_size);
                if (!volume_key)
                        return log_oom();

                r = sym_crypt_volume_key_get(cd, keyslot, volume_key, &volume_key_size, passphrase, passphrase_length);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get volume key: %m");

                unlock.session.opal_key.key_len = volume_key_size;
                memcpy(unlock.session.opal_key.key, volume_key, volume_key_size);
        } else if (volume_key_size > 0) {
                if (passphrase_length > OPAL_KEY_MAX)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid passphrase length: %zu > %d", passphrase_length, OPAL_KEY_MAX);

                unlock.session.opal_key.key_len = passphrase_length;
                memcpy(unlock.session.opal_key.key, passphrase, passphrase_length);
        }

        device_name = sym_crypt_get_device_name(cd);
        if (!device_name)
                return log_debug_errno(errno, "Failed to get device name: %m");

        if (fd < 0) {
                crypt_fd = open(device_name, O_RDWR);
                if (crypt_fd < 0)
                        return log_debug_errno(errno, "Failed to open device '%s': %m", device_name);
                fd = crypt_fd;
        }

        r = ioctl(fd, IOC_OPAL_LOCK_UNLOCK, &unlock);
        if (r < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OPAL not supported on this kernel version, refusing.");
        if (r == OPAL_STATUS_NOT_AUTHORIZED) /* We'll try again with a different key. */
                return log_debug_errno(SYNTHETIC_ERRNO(EPERM), "Failed to %slock OPAL device '%s': %m", lock ? "" : "un", device_name);
        if (r != OPAL_STATUS_SUCCESS) /* This will be propagated, log the useful string immediately. */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to %slock OPAL device '%s': %s", lock ? "" : "un", device_name, opal_status_to_string(r));

        if (lock)
                return 0;

        /* If we are unlocking, also tell the kernel to automatically unlock when resuming
         * from suspend, otherwise the drive will be locked and everything will go up in flames */
        r = ioctl(fd, IOC_OPAL_SAVE, &unlock);
        if (r != OPAL_STATUS_SUCCESS) /* This will be propagated, log the useful string immediately. */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to prepare OPAL device '%s' for sleep resume: %s", device_name, opal_status_to_string(r));

        return 0;
}
#endif
