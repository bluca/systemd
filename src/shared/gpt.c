/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
#include "string-table.h"
#include "string-util.h"
#include "utf8.h"

/* Gently push people towards defining GPT type UUIDs for all architectures we know */
#if !defined(SD_GPT_ROOT_NATIVE) ||                                        \
        !defined(SD_GPT_ROOT_NATIVE_VERITY) ||                             \
        !defined(SD_GPT_ROOT_NATIVE_VERITY_SIG) ||                         \
        !defined(SD_GPT_USR_NATIVE) ||                                     \
        !defined(SD_GPT_USR_NATIVE_VERITY) ||                              \
        !defined(SD_GPT_USR_NATIVE_VERITY_SIG)
#pragma message "Please define GPT partition types for your architecture."
#endif

bool partition_designator_is_versioned(PartitionDesignator d) {
        /* Returns true for all designators where we want to support a concept of "versioning", i.e. which
         * likely contain software binaries (or hashes thereof) that make sense to be versioned as a
         * whole. We use this check to automatically pick the newest version of these partitions, by version
         * comparing the partition labels. */

        return IN_SET(d,
                      PARTITION_ROOT,
                      PARTITION_ROOT_SECONDARY,
                      PARTITION_ROOT_OTHER,
                      PARTITION_USR,
                      PARTITION_USR_SECONDARY,
                      PARTITION_USR_OTHER,
                      PARTITION_ROOT_VERITY,
                      PARTITION_ROOT_SECONDARY_VERITY,
                      PARTITION_ROOT_OTHER_VERITY,
                      PARTITION_USR_VERITY,
                      PARTITION_USR_SECONDARY_VERITY,
                      PARTITION_USR_OTHER_VERITY,
                      PARTITION_ROOT_VERITY_SIG,
                      PARTITION_ROOT_SECONDARY_VERITY_SIG,
                      PARTITION_ROOT_OTHER_VERITY_SIG,
                      PARTITION_USR_VERITY_SIG,
                      PARTITION_USR_SECONDARY_VERITY_SIG,
                      PARTITION_USR_OTHER_VERITY_SIG);
}

PartitionDesignator partition_verity_of(PartitionDesignator p) {
        switch (p) {

        case PARTITION_ROOT:
                return PARTITION_ROOT_VERITY;

        case PARTITION_ROOT_SECONDARY:
                return PARTITION_ROOT_SECONDARY_VERITY;

        case PARTITION_ROOT_OTHER:
                return PARTITION_ROOT_OTHER_VERITY;

        case PARTITION_USR:
                return PARTITION_USR_VERITY;

        case PARTITION_USR_SECONDARY:
                return PARTITION_USR_SECONDARY_VERITY;

        case PARTITION_USR_OTHER:
                return PARTITION_USR_OTHER_VERITY;

        case PARTITION_SYSEXT:
                return PARTITION_SYSEXT_VERITY;

        case PARTITION_PORTABLE:
                return PARTITION_PORTABLE_VERITY;

        default:
                return _PARTITION_DESIGNATOR_INVALID;
        }
}

PartitionDesignator partition_verity_sig_of(PartitionDesignator p) {
        switch (p) {

        case PARTITION_ROOT:
                return PARTITION_ROOT_VERITY_SIG;

        case PARTITION_ROOT_SECONDARY:
                return PARTITION_ROOT_SECONDARY_VERITY_SIG;

        case PARTITION_ROOT_OTHER:
                return PARTITION_ROOT_OTHER_VERITY_SIG;

        case PARTITION_USR:
                return PARTITION_USR_VERITY_SIG;

        case PARTITION_USR_SECONDARY:
                return PARTITION_USR_SECONDARY_VERITY_SIG;

        case PARTITION_USR_OTHER:
                return PARTITION_USR_OTHER_VERITY_SIG;

        case PARTITION_SYSEXT:
                return PARTITION_SYSEXT_VERITY_SIG;

        case PARTITION_PORTABLE:
                return PARTITION_PORTABLE_VERITY_SIG;

        default:
                return _PARTITION_DESIGNATOR_INVALID;
        }
}

PartitionDesignator partition_root_of_arch(Architecture arch) {
        switch (arch) {

        case native_architecture():
                return PARTITION_ROOT;

#ifdef ARCHITECTURE_SECONDARY
        case ARCHITECTURE_SECONDARY:
                return PARTITION_ROOT_SECONDARY;
#endif

        default:
                return PARTITION_ROOT_OTHER;
        }
}

PartitionDesignator partition_usr_of_arch(Architecture arch) {
        switch (arch) {

        case native_architecture():
                return PARTITION_USR;

#ifdef ARCHITECTURE_SECONDARY
        case ARCHITECTURE_SECONDARY:
                return PARTITION_USR_SECONDARY;
#endif

        default:
                return PARTITION_USR_OTHER;
        }
}

static const char *const partition_designator_table[] = {
        [PARTITION_ROOT]                      = "root",
        [PARTITION_ROOT_SECONDARY]            = "root-secondary",
        [PARTITION_ROOT_OTHER]                = "root-other",
        [PARTITION_USR]                       = "usr",
        [PARTITION_USR_SECONDARY]             = "usr-secondary",
        [PARTITION_USR_OTHER]                 = "usr-other",
        [PARTITION_HOME]                      = "home",
        [PARTITION_SRV]                       = "srv",
        [PARTITION_ESP]                       = "esp",
        [PARTITION_XBOOTLDR]                  = "xbootldr",
        [PARTITION_SWAP]                      = "swap",
        [PARTITION_ROOT_VERITY]               = "root-verity",
        [PARTITION_ROOT_SECONDARY_VERITY]     = "root-secondary-verity",
        [PARTITION_ROOT_OTHER_VERITY]         = "root-other-verity",
        [PARTITION_USR_VERITY]                = "usr-verity",
        [PARTITION_USR_SECONDARY_VERITY]      = "usr-secondary-verity",
        [PARTITION_USR_OTHER_VERITY]          = "usr-other-verity",
        [PARTITION_ROOT_VERITY_SIG]           = "root-verity-sig",
        [PARTITION_ROOT_SECONDARY_VERITY_SIG] = "root-secondary-verity-sig",
        [PARTITION_ROOT_OTHER_VERITY_SIG]     = "root-other-verity-sig",
        [PARTITION_USR_VERITY_SIG]            = "usr-verity-sig",
        [PARTITION_USR_SECONDARY_VERITY_SIG]  = "usr-secondary-verity-sig",
        [PARTITION_USR_OTHER_VERITY_SIG]      = "usr-other-verity-sig",
        [PARTITION_SYSEXT]                    = "sysext",
        [PARTITION_SYSEXT_VERITY]             = "sysext-verity",
        [PARTITION_SYSEXT_VERITY_SIG]         = "sysext-verity-sig",
        [PARTITION_PORTABLE]                  = "portable",
        [PARTITION_PORTABLE_VERITY]           = "portable-verity",
        [PARTITION_PORTABLE_VERITY_SIG]       = "portable-verity-sig",
        [PARTITION_TMP]                       = "tmp",
        [PARTITION_VAR]                       = "var",
        [PARTITION_USER_HOME]                 = "user-home",
        [PARTITION_LINUX_GENERIC]             = "linux-generic",
};

DEFINE_STRING_TABLE_LOOKUP(partition_designator, PartitionDesignator);

static const char *const partition_mountpoint_table[] = {
        [PARTITION_ROOT]                      = "/\0",
        [PARTITION_ROOT_SECONDARY]            = "/\0",
        [PARTITION_ROOT_OTHER]                = "/\0",
        [PARTITION_USR]                       = "/usr\0",
        [PARTITION_USR_SECONDARY]             = "/usr\0",
        [PARTITION_USR_OTHER]                 = "/usr\0",
        [PARTITION_HOME]                      = "/home\0",
        [PARTITION_SRV]                       = "/srv\0",
        [PARTITION_ESP]                       = "/efi\0/boot\0",
        [PARTITION_XBOOTLDR]                  = "/boot\0",
        [PARTITION_TMP]                       = "/var/tmp\0",
        [PARTITION_VAR]                       = "/var\0",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(partition_mountpoint, PartitionDesignator);

#define _GPT_ARCH_SEXTET(arch, name)                                   \
        { SD_GPT_ROOT_##arch,              "root-" name,                      ARCHITECTURE_##arch, .designator = PARTITION_ROOT_OTHER            },  \
        { SD_GPT_ROOT_##arch##_VERITY,     "root-" name "-verity",            ARCHITECTURE_##arch, .designator = PARTITION_ROOT_OTHER_VERITY     },  \
        { SD_GPT_ROOT_##arch##_VERITY_SIG, "root-" name "-verity-sig",        ARCHITECTURE_##arch, .designator = PARTITION_ROOT_OTHER_VERITY_SIG },  \
        { SD_GPT_USR_##arch,               "usr-" name,                       ARCHITECTURE_##arch, .designator = PARTITION_USR_OTHER             },  \
        { SD_GPT_USR_##arch##_VERITY,      "usr-" name "-verity",             ARCHITECTURE_##arch, .designator = PARTITION_USR_OTHER_VERITY      },  \
        { SD_GPT_USR_##arch##_VERITY_SIG,  "usr-" name "-verity-sig",         ARCHITECTURE_##arch, .designator = PARTITION_USR_OTHER_VERITY_SIG  },  \
        { SD_GPT_SYSEXT_##arch,            "sysext-" name,                    ARCHITECTURE_##arch, .designator = PARTITION_SYSEXT                 },  \
        { SD_GPT_SYSEXT_##arch##_VERITY,   "sysext-" name "-verity",          ARCHITECTURE_##arch, .designator = PARTITION_SYSEXT_VERITY          },  \
        { SD_GPT_SYSEXT_##arch##_VERITY_SIG,"sysext-" name "-verity-sig",     ARCHITECTURE_##arch, .designator = PARTITION_SYSEXT_VERITY_SIG   },  \
        { SD_GPT_PORTABLE_##arch,          "portable-" name,                  ARCHITECTURE_##arch, .designator = PARTITION_PORTABLE               },  \
        { SD_GPT_PORTABLE_##arch##_VERITY, "portable-" name "-verity",        ARCHITECTURE_##arch, .designator = PARTITION_PORTABLE_VERITY        },  \
        { SD_GPT_PORTABLE_##arch##_VERITY_SIG,"portable-" name "-verity-sig", ARCHITECTURE_##arch, .designator = PARTITION_PORTABLE_VERITY_SIG}

const GptPartitionType gpt_partition_type_table[] = {
        _GPT_ARCH_SEXTET(ALPHA,       "alpha"),
        _GPT_ARCH_SEXTET(ARC,         "arc"),
        _GPT_ARCH_SEXTET(ARM,         "arm"),
        _GPT_ARCH_SEXTET(ARM64,       "arm64"),
        _GPT_ARCH_SEXTET(IA64,        "ia64"),
        _GPT_ARCH_SEXTET(LOONGARCH64, "loongarch64"),
        _GPT_ARCH_SEXTET(MIPS_LE,     "mips-le"),
        _GPT_ARCH_SEXTET(MIPS64_LE,   "mips64-le"),
        _GPT_ARCH_SEXTET(PARISC,      "parisc"),
        _GPT_ARCH_SEXTET(PPC,         "ppc"),
        _GPT_ARCH_SEXTET(PPC64,       "ppc64"),
        _GPT_ARCH_SEXTET(PPC64_LE,    "ppc64-le"),
        _GPT_ARCH_SEXTET(RISCV32,     "riscv32"),
        _GPT_ARCH_SEXTET(RISCV64,     "riscv64"),
        _GPT_ARCH_SEXTET(S390,        "s390"),
        _GPT_ARCH_SEXTET(S390X,       "s390x"),
        _GPT_ARCH_SEXTET(TILEGX,      "tilegx"),
        _GPT_ARCH_SEXTET(X86,         "x86"),
        _GPT_ARCH_SEXTET(X86_64,      "x86-64"),
#ifdef SD_GPT_ROOT_NATIVE
        { SD_GPT_ROOT_NATIVE,                "root",                native_architecture(), .designator = PARTITION_ROOT            },
        { SD_GPT_ROOT_NATIVE_VERITY,         "root-verity",         native_architecture(), .designator = PARTITION_ROOT_VERITY     },
        { SD_GPT_ROOT_NATIVE_VERITY_SIG,     "root-verity-sig",     native_architecture(), .designator = PARTITION_ROOT_VERITY_SIG },
        { SD_GPT_USR_NATIVE,                 "usr",                 native_architecture(), .designator = PARTITION_USR             },
        { SD_GPT_USR_NATIVE_VERITY,          "usr-verity",          native_architecture(), .designator = PARTITION_USR_VERITY      },
        { SD_GPT_USR_NATIVE_VERITY_SIG,      "usr-verity-sig",      native_architecture(), .designator = PARTITION_USR_VERITY_SIG  },
        { SD_GPT_SYSEXT_NATIVE,              "sysext",              native_architecture(), .designator = PARTITION_SYSEXT          },
        { SD_GPT_SYSEXT_NATIVE_VERITY,       "sysext-verity",       native_architecture(), .designator = PARTITION_SYSEXT_VERITY   },
        { SD_GPT_SYSEXT_NATIVE_VERITY_SIG,   "sysext-verity-sig",   native_architecture(), .designator = PARTITION_SYSEXT_VERITY_SIG},
        { SD_GPT_PORTABLE_NATIVE,            "portable",            native_architecture(), .designator = PARTITION_PORTABLE        },
        { SD_GPT_PORTABLE_NATIVE_VERITY,     "portable-verity",     native_architecture(), .designator = PARTITION_PORTABLE_VERITY },
        { SD_GPT_PORTABLE_NATIVE_VERITY_SIG, "portable-verity-sig", native_architecture(), .designator = PARTITION_PORTABLE_VERITY_SIG},
#endif
#ifdef SD_GPT_ROOT_SECONDARY
        { SD_GPT_ROOT_NATIVE,            "root-secondary",            native_architecture(), .designator = PARTITION_ROOT_SECONDARY            },
        { SD_GPT_ROOT_NATIVE_VERITY,     "root-secondary-verity",     native_architecture(), .designator = PARTITION_ROOT_SECONDARY_VERITY     },
        { SD_GPT_ROOT_NATIVE_VERITY_SIG, "root-secondary-verity-sig", native_architecture(), .designator = PARTITION_ROOT_SECONDARY_VERITY_SIG },
        { SD_GPT_USR_NATIVE,             "usr-secondary",             native_architecture(), .designator = PARTITION_USR_SECONDARY             },
        { SD_GPT_USR_NATIVE_VERITY,      "usr-secondary-verity",      native_architecture(), .designator = PARTITION_USR_SECONDARY_VERITY      },
        { SD_GPT_USR_NATIVE_VERITY_SIG,  "usr-secondary-verity-sig",  native_architecture(), .designator = PARTITION_USR_SECONDARY_VERITY_SIG  },
#endif

        { SD_GPT_ESP,                    "esp",           _ARCHITECTURE_INVALID, .designator = PARTITION_ESP },
        { SD_GPT_XBOOTLDR,               "xbootldr",      _ARCHITECTURE_INVALID, .designator = PARTITION_XBOOTLDR },
        { SD_GPT_SWAP,                   "swap",          _ARCHITECTURE_INVALID, .designator = PARTITION_SWAP },
        { SD_GPT_HOME,                   "home",          _ARCHITECTURE_INVALID, .designator = PARTITION_HOME },
        { SD_GPT_SRV,                    "srv",           _ARCHITECTURE_INVALID, .designator = PARTITION_SRV },
        { SD_GPT_VAR,                    "var",           _ARCHITECTURE_INVALID, .designator = PARTITION_VAR },
        { SD_GPT_TMP,                    "tmp",           _ARCHITECTURE_INVALID, .designator = PARTITION_TMP },
        { SD_GPT_USER_HOME,              "user-home",     _ARCHITECTURE_INVALID, .designator = PARTITION_USER_HOME },
        { SD_GPT_LINUX_GENERIC,          "linux-generic", _ARCHITECTURE_INVALID, .designator = PARTITION_LINUX_GENERIC },
        {}
};

static const GptPartitionType *gpt_partition_type_find_by_uuid(sd_id128_t id) {

        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (sd_id128_equal(id, gpt_partition_type_table[i].uuid))
                        return gpt_partition_type_table + i;

        return NULL;
}

const char *gpt_partition_type_uuid_to_string(sd_id128_t id) {
        const GptPartitionType *pt;

        pt = gpt_partition_type_find_by_uuid(id);
        if (!pt)
                return NULL;

        return pt->name;
}

const char *gpt_partition_type_uuid_to_string_harder(
                sd_id128_t id,
                char buffer[static SD_ID128_UUID_STRING_MAX]) {

        const char *s;

        assert(buffer);

        s = gpt_partition_type_uuid_to_string(id);
        if (s)
                return s;

        return sd_id128_to_uuid_string(id, buffer);
}

int gpt_partition_type_uuid_from_string(const char *s, sd_id128_t *ret) {
        assert(s);

        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (streq(s, gpt_partition_type_table[i].name)) {
                        if (ret)
                                *ret = gpt_partition_type_table[i].uuid;
                        return 0;
                }

        return sd_id128_from_string(s, ret);
}

Architecture gpt_partition_type_uuid_to_arch(sd_id128_t id) {
        const GptPartitionType *pt;

        pt = gpt_partition_type_find_by_uuid(id);
        if (!pt)
                return _ARCHITECTURE_INVALID;

        return pt->arch;
}

int gpt_partition_label_valid(const char *s) {
        _cleanup_free_ char16_t *recoded = NULL;

        recoded = utf8_to_utf16(s, strlen(s));
        if (!recoded)
                return -ENOMEM;

        return char16_strlen(recoded) <= GPT_LABEL_MAX;
}

GptPartitionType gpt_partition_type_from_uuid(sd_id128_t id) {
        const GptPartitionType *pt;

        pt = gpt_partition_type_find_by_uuid(id);
        if (pt)
                return *pt;

        return (GptPartitionType) {
                .uuid = id,
                .arch = _ARCHITECTURE_INVALID,
                .designator = _PARTITION_DESIGNATOR_INVALID,
        };
}

bool gpt_partition_type_is_root(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).designator,
                      PARTITION_ROOT,
                      PARTITION_ROOT_SECONDARY,
                      PARTITION_ROOT_OTHER);
}

bool gpt_partition_type_is_root_verity(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).designator,
                      PARTITION_ROOT_VERITY,
                      PARTITION_ROOT_SECONDARY_VERITY,
                      PARTITION_ROOT_OTHER_VERITY);
}

bool gpt_partition_type_is_root_verity_sig(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).designator,
                      PARTITION_ROOT_VERITY_SIG,
                      PARTITION_ROOT_SECONDARY_VERITY_SIG,
                      PARTITION_ROOT_OTHER_VERITY_SIG);
}

bool gpt_partition_type_is_usr(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).designator,
                      PARTITION_USR,
                      PARTITION_USR_SECONDARY,
                      PARTITION_USR_OTHER);
}

bool gpt_partition_type_is_usr_verity(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).designator,
                      PARTITION_USR_VERITY,
                      PARTITION_USR_SECONDARY_VERITY,
                      PARTITION_USR_OTHER_VERITY);
}

bool gpt_partition_type_is_usr_verity_sig(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).designator,
                      PARTITION_USR_VERITY_SIG,
                      PARTITION_USR_SECONDARY_VERITY_SIG,
                      PARTITION_USR_OTHER_VERITY_SIG);
}

const char *gpt_partition_type_mountpoint_nulstr(sd_id128_t id) {
        PartitionDesignator d = gpt_partition_type_from_uuid(id).designator;
        if (d < 0)
                return NULL;

        return partition_mountpoint_to_string(d);
}

bool gpt_partition_type_knows_read_only(sd_id128_t id) {
        return gpt_partition_type_is_root(id) ||
                gpt_partition_type_is_usr(id) ||
                /* pretty much implied, but let's set the bit to make things really clear */
                gpt_partition_type_is_root_verity(id) ||
                gpt_partition_type_is_usr_verity(id) ||
                IN_SET(gpt_partition_type_from_uuid(id).designator,
                       PARTITION_SYSEXT,
                       PARTITION_SYSEXT_VERITY,
                       PARTITION_PORTABLE,
                       PARTITION_PORTABLE_VERITY,
                       PARTITION_HOME,
                       PARTITION_SRV,
                       PARTITION_VAR,
                       PARTITION_TMP,
                       PARTITION_XBOOTLDR);
}

bool gpt_partition_type_knows_growfs(sd_id128_t id) {
        return gpt_partition_type_is_root(id) ||
                gpt_partition_type_is_usr(id) ||
                IN_SET(gpt_partition_type_from_uuid(id).designator,
                       PARTITION_HOME,
                       PARTITION_SRV,
                       PARTITION_VAR,
                       PARTITION_TMP,
                       PARTITION_XBOOTLDR);
}

bool gpt_partition_type_knows_no_auto(sd_id128_t id) {
        return gpt_partition_type_is_root(id) ||
                gpt_partition_type_is_root_verity(id) ||
                gpt_partition_type_is_usr(id) ||
                gpt_partition_type_is_usr_verity(id) ||
                IN_SET(gpt_partition_type_from_uuid(id).designator,
                       PARTITION_HOME,
                       PARTITION_SRV,
                       PARTITION_VAR,
                       PARTITION_TMP,
                       PARTITION_XBOOTLDR,
                       PARTITION_SWAP);
}
