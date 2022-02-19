/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/blkpg.h>
#include <linux/fs.h>
#include <linux/sed-opal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "dlfcn-util.h"
#include "fd-util.h"
#include "log.h"
#include "parse-util.h"
#include "sha256.h"
#include "string-table.h"

#if HAVE_LIBCRYPTSETUP
static void *cryptsetup_dl = NULL;

int (*sym_crypt_activate_by_passphrase)(struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size, uint32_t flags);
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
int (*sym_crypt_activate_by_signed_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, const char *signature, size_t signature_size, uint32_t flags);
#endif
int (*sym_crypt_activate_by_volume_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, uint32_t flags);
int (*sym_crypt_deactivate_by_name)(struct crypt_device *cd, const char *name, uint32_t flags);
int (*sym_crypt_dump_json)(struct crypt_device *cd, const char **json, uint32_t flags);
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
int (*sym_crypt_get_metadata_size)(struct crypt_device *cd, uint64_t *, uint64_t *);

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
                        DLSYM_ARG(crypt_dump_json),
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
                        DLSYM_ARG(crypt_volume_key_get),
                        DLSYM_ARG(crypt_get_metadata_size));
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
        uint64_t device_size, metadata_size, keyslots_size, offset, length;
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

        if (ioctl(fd, BLKGETSIZE64, &device_size) != 0)
                return log_debug_errno(errno, "Failed to get block device size of %s: %m", device_name);

        r = sym_crypt_get_metadata_size(cd, &metadata_size, &keyslots_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to get LUKS2 metadata size: %m");
        length = device_size - metadata_size - keyslots_size;
        offset = sym_crypt_get_data_offset(cd);

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

        struct blkpg_partition part = {
                .start = offset,
                .length = length,
                .pno = 1 + opal_segment,
        };
        struct blkpg_ioctl_arg arg = {
                .op = lock ? BLKPG_DEL_PARTITION : BLKPG_ADD_PARTITION,
                .data = &part,
                .datalen = sizeof(part),
        };

        _cleanup_close_ int new_fd = open("/dev/sdd", O_RDWR);
        if (new_fd < 0)
                return log_debug_errno(errno, "Failed to open device '%s': %m", "/dev/sdd");

        r = ioctl(new_fd, BLKPG, &arg);
        if (r < 0)
                return log_debug_errno(errno, "Failed to add partition to block device '%s': %m", "/dev/sdd");

        return 0;
}

int opal_psid_wipe(const char *psid, const char *device) {
        _cleanup_close_ int fd = -1;
        struct opal_key reset = {
                .lr = 0,
        };
        int r;

        assert(psid);
        assert(device);

        reset.key_len = strlen(psid);
        memcpy(reset.key, psid, reset.key_len);

        fd = open(device, O_RDWR);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open device '%s': %m", device);

        r = ioctl(fd, IOC_OPAL_PSID_REVERT_TPR, &reset);
        if (r < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OPAL not supported on this kernel version, refusing.");
        if (r == OPAL_STATUS_NOT_AUTHORIZED) /* We'll try again with a different key. */
                return log_debug_errno(SYNTHETIC_ERRNO(EPERM), "Failed to reset OPAL device '%s', incorrect PSID?", device);
        if (r != OPAL_STATUS_SUCCESS) /* This will be propagated, log the useful string immediately. */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to reset OPAL device '%s' with PSID: %s", device, opal_status_to_string(r));

        return 0;
}

int opal_setup_range(
                struct crypt_device *cd,
                int fd,
                uint64_t device_size,
                int opal_segment,
                const void *volume_key,
                size_t volume_key_size) {

        if (opal_segment == -1)
                return 0; /* Nothing to do. */

        assert(cd);
        assert(fd >= 0);
        assert(device_size > 0);
        assert(volume_key || volume_key_size == 0);

        struct opal_user_lr_setup setup = {
                .RLE = 1,
                .WLE = 1,
                .session = {
                        .who = OPAL_ADMIN1,
                        .opal_key = {
                                .lr = opal_segment,
                                .key_len = volume_key_size,
                        },
                },
        };
        uint64_t metadata_size, keyslots_size;
        const char *device_name;
        int r;

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        device_name = sym_crypt_get_device_name(cd);
        if (!device_name)
                return log_debug_errno(errno, "Failed to get device name: %m");

        r = sym_crypt_get_metadata_size(cd, &metadata_size, &keyslots_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to get LUKS2 metadata size: %m");
        setup.range_length = device_size - metadata_size - keyslots_size;
        setup.range_start = sym_crypt_get_data_offset(cd);

        memcpy(setup.session.opal_key.key, volume_key, volume_key_size);

        struct opal_lr_act activate = {
                .key = setup.session.opal_key,
                .num_lrs = 1,
        };

        r = ioctl(fd, IOC_OPAL_TAKE_OWNERSHIP, &setup.session.opal_key);
        if (r < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OPAL not supported on this kernel version, refusing.");
        if (r == OPAL_STATUS_NOT_AUTHORIZED) /* We'll try again with a different key. */
                return log_debug_errno(SYNTHETIC_ERRNO(EPERM), "Failed to take ownership of OPAL device '%s': %m", device_name);
        if (r != OPAL_STATUS_SUCCESS) /* This will be propagated, log the useful string immediately. */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to take ownership of OPAL device '%s': %s", device_name, opal_status_to_string(r));

        r = ioctl(fd, IOC_OPAL_ACTIVATE_LSP, &activate);
        if (r != OPAL_STATUS_SUCCESS) /* This will be propagated, log the useful string immediately. */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to activate OPAL device '%s': %s", device_name, opal_status_to_string(r));

        r = ioctl(fd, IOC_OPAL_LR_SETUP, &setup);
        if (r != OPAL_STATUS_SUCCESS) /* This will be propagated, log the useful string immediately. */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to setup locking range of length %llu at offset %llu on OPAL device '%s': %s",
                                       setup.range_length, setup.range_start, device_name, opal_status_to_string(r));

        return 0;
}

/* Definitions from https://gitlab.com/cryptsetup/LUKS2-docs/-/blob/master/luks2_doc_wip.pdf
 * The LUKS2 header is composed of a binary header (fixed in size at 4096 bytes) and
 * a variable JSON area, with duplication for redundancy.
 * The JSON area is variable but in fixed increments, so the actual storage area is
 * increased or decreased only when it goes above/below a certain threshold (e.g. the
 * first one is 16KB). In this helper function we strictly shrink the JSON, so we do
 * not change the disk allocation, but simply adjust the padding. */
#define LUKS2_MAGIC_ONE "LUKS\xba\xbe"
#define LUKS2_MAGIC_TWO "SKUL\xba\xbe"
#define LUKS2_MAGIC_SIZE 6
#define LUKS2_UUID_SIZE 40
#define LUKS2_LABEL_SIZE 48
#define LUKS2_SALT_SIZE 64
#define LUKS2_CHECKSUM_ALGORITHM_SIZE 32
#define LUKS2_CHECKSUM_SIZE 64

struct luks2_binary_header {
        char magic_string[LUKS2_MAGIC_SIZE];
        uint16_t luks_version;
        uint64_t header_size;
        uint64_t seqid;
        char label[LUKS2_LABEL_SIZE];
        char checksum_algorithm[LUKS2_CHECKSUM_ALGORITHM_SIZE];
        uint8_t salt[LUKS2_SALT_SIZE];
        char uuid[LUKS2_UUID_SIZE];
        char subsystem[LUKS2_LABEL_SIZE];
        uint64_t header_offset;
        char padding_before[184];
        uint8_t checksum[LUKS2_CHECKSUM_SIZE];
        char padding_after[7*512];
} __attribute__ ((packed));

static int write_header(int fd, const char *json, off_t *offset) {
        size_t header_size, json_area_size = 0;
        struct luks2_binary_header *header;
        char *luks_meta_raw = NULL;
        int r;

        assert(fd >= 0);
        assert(!isempty(json));
        assert(offset);

        header = mmap(NULL, sizeof(struct luks2_binary_header), PROT_READ | PROT_WRITE, MAP_SHARED, fd, *offset);
        if (header == MAP_FAILED)
                return log_debug_errno(errno, "Failed to read LUKS2 binary header: %m");

        /* Sanity checks */
        if (memcmp(header->magic_string, *offset == 0 ? LUKS2_MAGIC_ONE : LUKS2_MAGIC_TWO, LUKS2_MAGIC_SIZE) != 0) {
                r = log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "LUKS2 binary header magic string is invalid.");
                goto cleanup;
        }

        if (be16toh(header->luks_version) != 2) {
                r = log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "LUKS2 binary header version is invalid.");
                goto cleanup;
        }

        header_size = be64toh(header->header_size);
        json_area_size = header_size - sizeof(struct luks2_binary_header);

        luks_meta_raw = mmap(NULL, json_area_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, *offset + sizeof(struct luks2_binary_header));
        if (luks_meta_raw == MAP_FAILED) {
                r = log_debug_errno(errno, "Failed to read LUKS2 json area: %m");
                goto cleanup;
        }

        if (!streq(header->checksum_algorithm, "sha256")) {
                r = log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unsupported checksum algorithm: %s", header->checksum_algorithm);
                goto cleanup;
        }

        /* The checksum is calculated on the full header, with the checksum zeroed. */
        memset(header->checksum, 0, LUKS2_CHECKSUM_SIZE);

        memset(luks_meta_raw, 0, json_area_size - strlen(json));
        memcpy(luks_meta_raw, json, strlen(json));

        /* As per specification, the sequence number is incremented on any on-disk change. */
        uint64_t seqid = be64toh(header->seqid);
        header->seqid = htobe64(++seqid);

        /* Finally, update the checksum. We only support sha256 for now. */
        struct sha256_ctx hash;
        sha256_init_ctx(&hash);
        sha256_process_bytes(header, sizeof(struct luks2_binary_header), &hash);
        sha256_process_bytes(luks_meta_raw, json_area_size, &hash);
        sha256_finish_ctx(&hash, header->checksum);

        *offset = header_size;
        r = 0;

cleanup:
        if (munmap(header, sizeof(struct luks2_binary_header)) < 0)
                return log_debug_errno(errno, "Failed to munmap LUKS2 binary header: %m");

        if (munmap(luks_meta_raw, json_area_size) < 0)
                return log_debug_errno(errno, "Failed to munmap LUKS2 json area: %m");

        return r;
}

/* Overwrite the LUKS2 header on disk, changing the dm-crypt segment to dm-linear. */
int cryptsetup_make_linear(struct crypt_device *cd) {
        _cleanup_(json_variant_unrefp) JsonVariant *luks_meta = NULL;
        const char *device_name, *json;
        _cleanup_close_ int fd = -1;
        int r;

        assert(cd);

        /* The LUKS JSON defines how to map a section with a 'segment' object that
         * can be 'crypt' (will use the dm-crypt kernel driver) or 'linear' (will
         * use the dm-linear kernel driver).
         * We replace the 'crypt' segment with a 'linear' one, as OPAL does the
         * encryption/decryption in hardware. Note that only one segment is supported
         * for normal modes of operation for LUKS2, and multiple segments are used
         * only temporarily for the re-encryption workflow, which is not relevant
         * for our use case. */
        r = sym_crypt_dump_json(cd, &json, 0);
        if (r < 0)
                return log_error_errno(errno, "Failed to dump LUKS2 JSON: %m");

        r = json_parse(json, 0, &luks_meta, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "json_parse() failed: %m");

        JsonVariant *segments = json_variant_by_key(luks_meta, "segments");
        if (!segments)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No segments found in LUKS2 header");

        if (json_variant_elements(segments) != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected exactly one segment in LUKS2 header");

        JsonVariant *segment_index = json_variant_by_index(segments, 0);
        if (!segment_index)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No segment index found in LUKS2 header");

        JsonVariant *segment_object = json_variant_by_index(segments, 1);
        if (!segment_object)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No segment object found in LUKS2 header");

        JsonVariant *segment_type = json_variant_by_key(segment_object, "type");
        if (!segment_type || !json_variant_is_string(segment_type) || !streq(json_variant_string(segment_type), "crypt"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No 'crypt' segment type found in LUKS2 header");

        JsonVariant *json_offset = json_variant_by_key(segment_object, "offset");
        if (!json_offset)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No 'offset' found in 'crypt' segment in LUKS2 header");

        JsonVariant *json_size = json_variant_by_key(segment_object, "size");
        if (!json_size)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No 'size' found in 'crypt' segment in LUKS2 header");

        _cleanup_(json_variant_unrefp) JsonVariant *linear_segment = NULL;
        r = json_build(&linear_segment,
                       JSON_BUILD_OBJECT(JSON_BUILD_PAIR("segments",
                                                         JSON_BUILD_OBJECT(JSON_BUILD_PAIR(json_variant_string(segment_index),
                                                                                           JSON_BUILD_OBJECT(JSON_BUILD_PAIR("type", JSON_BUILD_STRING("linear")),
                                                                                                             JSON_BUILD_PAIR("offset", JSON_BUILD_STRING(json_variant_string(json_offset))),
                                                                                                             JSON_BUILD_PAIR("size", JSON_BUILD_STRING(json_variant_string(json_size)))))))));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        /* The new segments object will overwrite the old one. */
        r = json_variant_merge(&luks_meta, linear_segment);
        if (r < 0)
                return log_error_errno(r, "json_variant_merge of package meta with buildid failed: %m");

        _cleanup_free_ char *luks_meta_mangled = NULL;
        r = json_variant_format(luks_meta, 0, &luks_meta_mangled);
        if (r < 0)
                return log_error_errno(r, "json_variant_format failed: %m");

        device_name = sym_crypt_get_device_name(cd);
        if (!device_name)
                return log_error_errno(errno, "Failed to get device name: %m");

        fd = open(device_name, O_RDWR);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open device '%s': %m", device_name);

        /* The first binary header is at offset zero, the second one is after the first
         * binary plus the first JSON area. This helper will return the offset for the
         * next header. */
        off_t offset = 0;
        r = write_header(fd, luks_meta_mangled, &offset);
        if (r < 0)
                return log_error_errno(r, "Failed to write first LUKS2 header: %m");

        r = write_header(fd, luks_meta_mangled, &offset);
        if (r < 0)
                return log_error_errno(r, "Failed to write second LUKS2 header: %m");

        /* Load the new headers in the crypt data structure */
        r = sym_crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS2 superblock: %m");

        return 0;
}
#endif
