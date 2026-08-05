/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlopen-note.h"
#include "forward.h"

typedef struct ElfProgramHeader {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t virtual_address;
    uint64_t physical_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
} ElfProgramHeader;

typedef struct ElfImage {
    uint8_t elf_class;
    uint8_t data_encoding;
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t program_header_offset;
    uint16_t program_header_entry_size;
    uint32_t flags;

    ElfProgramHeader *program_headers;
    size_t n_program_headers;

    char *interpreter;
    uint64_t dynamic_flags_1;
    unsigned n_dynamic_headers;
    bool has_dynamic_flags_1;
} ElfImage;

int dlopen_dw(int log_level) _dlopen_loader_;
int dlopen_elf(int log_level) _dlopen_loader_;

bool dlopen_dw_has_dwfl_set_sysroot(void);

int elf_image_read(int fd, ElfImage **ret);
bool elf_image_is_pie(const ElfImage *image);

ElfImage* elf_image_free(ElfImage *image);
DEFINE_TRIVIAL_CLEANUP_FUNC(ElfImage*, elf_image_free);

/* Parse an ELF object in a forked process, so that errors while iterating over
 * untrusted and potentially malicious data do not propagate to the main caller's process.
 * If fork_disable_dump, the child process will not dump core if it crashes. */
int parse_elf_object(
                int fd,
                const char *executable,
                const char *root,
                bool fork_disable_dump,
                char **ret,
                sd_json_variant **ret_package_metadata,
                sd_json_variant **ret_dlopen_metadata);
