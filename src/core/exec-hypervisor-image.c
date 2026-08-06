/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-hypervisor-internal.h"

#if defined(__x86_64__)

bool kvm_errno_is_unavailable(int error) {
        return IN_SET(error, ENOENT, ENODEV, ENXIO, EACCES, EPERM, ENOTTY);
}

static int check_extension(int kvm_fd, int capability, const char *name, unsigned *ret) {
        int value;

        assert(kvm_fd >= 0);
        assert(name);

        value = ioctl(kvm_fd, KVM_CHECK_EXTENSION, capability);
        if (value < 0)
                return -errno;
        if (value == 0) {
                log_debug("KVM capability %s is unavailable, using native execution.", name);
                return 0;
        }

        if (ret)
                *ret = value;
        return 1;
}

static int plan_elf_image(
                                ElfImage *image,
                                bool require_pie,
                                void **ret_reservation,
                                size_t *ret_reservation_size,
                                uint64_t *ret_virtual_start,
                                uint64_t *ret_virtual_end,
                                uint64_t *ret_load_bias) {

        uint64_t virtual_end = 0, virtual_start = UINT64_MAX;
        bool entry_mapped = false, have_load = false;
                void *reservation;
        size_t ps;

                assert(image);
                assert(ret_reservation);
                assert(ret_reservation_size);
                assert(ret_virtual_start);
                assert(ret_virtual_end);
                assert(ret_load_bias);

                if (image->elf_class != ELFCLASS64 ||
                        image->data_encoding != ELFDATA2LSB ||
                        image->type != ET_DYN ||
                        image->machine != EM_X86_64 ||
                        image->version != EV_CURRENT ||
                        (require_pie && !elf_image_is_pie(image)))
                return -ENOEXEC;

        ps = page_size();
        assert(ISPOWEROF2(ps));

        FOREACH_ARRAY(phdr, image->program_headers, image->n_program_headers) {
                uint64_t end, end_aligned, start_aligned;

                if (phdr->type != PT_LOAD)
                        continue;

                have_load = true;
                if (phdr->file_size > phdr->memory_size)
                        return -EBADMSG;
                if (phdr->alignment > 1 &&
                    (!ISPOWEROF2(phdr->alignment) ||
                     phdr->virtual_address % phdr->alignment != phdr->offset % phdr->alignment))
                        return -EBADMSG;
                if (phdr->virtual_address % ps != phdr->offset % ps)
                        return -EBADMSG;
                if (!ADD_SAFE(&end, phdr->virtual_address, phdr->memory_size))
                        return -EOVERFLOW;

                if (image->entry >= phdr->virtual_address && image->entry < end)
                        entry_mapped = true;

                if (phdr->memory_size == 0)
                        continue;
                if (end > UINT64_MAX - (ps - 1))
                        return -EOVERFLOW;

                start_aligned = ALIGN_DOWN(phdr->virtual_address, ps);
                end_aligned = ALIGN_TO(end, ps);
                virtual_start = MIN(virtual_start, start_aligned);
                virtual_end = MAX(virtual_end, end_aligned);
        }

        FOREACH_ARRAY(a, image->program_headers, image->n_program_headers) {
                uint64_t a_end, a_start;

                if (a->type != PT_LOAD || a->memory_size == 0)
                        continue;
                assert_se(ADD_SAFE(&a_end, a->virtual_address, a->memory_size));
                a_start = ALIGN_DOWN(a->virtual_address, ps);
                a_end = ALIGN_TO(a_end, ps);

                for (ElfProgramHeader *b = a + 1;
                                 b < image->program_headers + image->n_program_headers;
                     b++) {
                        uint64_t b_end, b_start;

                        if (b->type != PT_LOAD || b->memory_size == 0)
                                continue;
                        assert_se(ADD_SAFE(&b_end, b->virtual_address, b->memory_size));
                        b_start = ALIGN_DOWN(b->virtual_address, ps);
                        b_end = ALIGN_TO(b_end, ps);

                        if (a_start < b_end && b_start < a_end)
                                return -EOPNOTSUPP;
                }
        }

        if (!have_load || !entry_mapped || virtual_start >= virtual_end)
                return -ENOEXEC;

        uint64_t span = virtual_end - virtual_start;
        if (span > SIZE_MAX)
                return -E2BIG;

        reservation = mmap(NULL, span, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (reservation == MAP_FAILED)
                return -errno;
        if ((uintptr_t) reservation < virtual_start) {
                (void) munmap(reservation, span);
                return -EADDRNOTAVAIL;
        }

        *ret_reservation = reservation;
        *ret_reservation_size = span;
        *ret_virtual_start = virtual_start;
        *ret_virtual_end = virtual_end;
        *ret_load_bias = (uintptr_t) reservation - virtual_start;

        log_debug("Reserved %zu bytes at %p for PIE image load bias 0x%" PRIx64 ".",
                  *ret_reservation_size, *ret_reservation, *ret_load_bias);
        return 0;
}

static int elf_segment_protection(const ElfProgramHeader *phdr) {
        int protection = 0;

        assert(phdr);

        if (phdr->flags & PF_R)
                protection |= PROT_READ;
        if (phdr->flags & PF_W)
                protection |= PROT_WRITE;
        if (phdr->flags & PF_X)
                protection |= PROT_EXEC;

        return protection;
}

static int map_elf_segments(
                ExecHypervisor *h,
                ElfImage *image,
                int image_fd,
                void *reservation,
                uint64_t image_virtual_start) {

        size_t n_loads = 0;
        size_t ps;

        assert(h);
        assert(image);
        assert(image_fd >= 0);
        assert(reservation);

        ps = page_size();

        FOREACH_ARRAY(phdr, image->program_headers, image->n_program_headers)
                if (phdr->type == PT_LOAD && phdr->memory_size > 0)
                        n_loads++;

        if (!GREEDY_REALLOC0(h->mappings, h->n_mappings + n_loads + 1))
                return -ENOMEM;

        size_t first_mapping = h->n_mappings;
        FOREACH_ARRAY(phdr, image->program_headers, image->n_program_headers) {
                uint64_t file_end, file_map_end, memory_end, memory_map_end, virtual_start;
                size_t file_map_size;
                int final_protection, map_protection;
                uint8_t *destination;

                if (phdr->type != PT_LOAD || phdr->memory_size == 0)
                        continue;

                assert_se(ADD_SAFE(&file_end, phdr->virtual_address, phdr->file_size));
                assert_se(ADD_SAFE(&memory_end, phdr->virtual_address, phdr->memory_size));
                virtual_start = ALIGN_DOWN(phdr->virtual_address, ps);
                file_map_end = ALIGN_TO(file_end, ps);
                memory_map_end = ALIGN_TO(memory_end, ps);
                destination = (uint8_t*) reservation + (virtual_start - image_virtual_start);
                final_protection = elf_segment_protection(phdr);
                map_protection = final_protection;

                if (phdr->file_size > 0) {
                        file_map_size = file_map_end - virtual_start;
                        if (file_end < memory_end && file_end < file_map_end) {
                                map_protection |= PROT_WRITE;
                                map_protection &= ~PROT_EXEC;
                        }

                        if (mmap(destination,
                                 file_map_size,
                                 map_protection,
                                 MAP_PRIVATE|MAP_FIXED,
                                 image_fd,
                                 ALIGN_DOWN(phdr->offset, ps)) == MAP_FAILED)
                                return -errno;

                        if (file_end < memory_end && file_end < file_map_end)
                                memset((uint8_t*) reservation +
                                               (file_end - image_virtual_start),
                                       0,
                                       MIN(memory_end, file_map_end) - file_end);

                        if (map_protection != final_protection &&
                            mprotect(destination, file_map_size, final_protection) < 0)
                                return -errno;
                } else
                        file_map_end = virtual_start;

                if (file_map_end < memory_map_end) {
                        uint8_t *anonymous = (uint8_t*) reservation +
                                (file_map_end - image_virtual_start);
                        size_t anonymous_size = memory_map_end - file_map_end;

                        if (mmap(anonymous,
                                 anonymous_size,
                                 final_protection,
                                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                                 -1,
                                 0) == MAP_FAILED)
                                return -errno;
                }

                h->mappings[h->n_mappings++] = (ExecHypervisorMapping) {
                        .host_address = destination,
                        .guest_virtual_address = (uintptr_t) destination,
                        .size = memory_map_end - virtual_start,
                        .protection = final_protection,
                        .file_backed = phdr->file_size > 0,
                };
        }

        assert(h->n_mappings == first_mapping + n_loads);
        return 0;
}

static int reserve_guest_stack(ExecHypervisor *h) {
        size_t argument_size, guard_size;

        assert(h);
        assert(h->mappings);
        assert(!h->stack_reservation);

        guard_size = page_size();
        argument_size = sc_arg_max();
        if (!ADD_SAFE(&argument_size, argument_size, guard_size))
                return -EOVERFLOW;
        h->stack_size = MAX((size_t) EXEC_HYPERVISOR_STACK_SIZE, PAGE_ALIGN(argument_size));
        if (!ADD_SAFE(&h->stack_reservation_size, guard_size, h->stack_size))
                return -EOVERFLOW;

        h->stack_reservation = mmap(NULL,
                                    h->stack_reservation_size,
                                    PROT_NONE,
                                    MAP_PRIVATE|MAP_ANONYMOUS,
                                    -1,
                                    0);
        if (h->stack_reservation == MAP_FAILED) {
                h->stack_reservation = NULL;
                return -errno;
        }

        h->stack_address = (uint8_t*) h->stack_reservation + guard_size;
        if (mmap(h->stack_address,
                 h->stack_size,
                 PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                 -1,
                 0) == MAP_FAILED)
                return -errno;

        h->mappings[h->n_mappings++] = (ExecHypervisorMapping) {
                .host_address = h->stack_address,
                .guest_virtual_address = (uintptr_t) h->stack_address,
                .size = h->stack_size,
                .protection = PROT_READ|PROT_WRITE,
        };

        return 0;
}

static int reserve_guest_heap(ExecHypervisor *h) {
        assert(h);
        assert(!h->heap_reservation);

        h->heap_reservation_size = EXEC_HYPERVISOR_HEAP_SIZE;
        h->heap_reservation = mmap(NULL,
                                   h->heap_reservation_size,
                                   PROT_NONE,
                                   MAP_PRIVATE|MAP_ANONYMOUS,
                                   -1,
                                   0);
        if (h->heap_reservation == MAP_FAILED) {
                h->heap_reservation = NULL;
                return -errno;
        }

        h->heap_break = (uintptr_t) h->heap_reservation;
        h->heap_mapped_end = h->heap_break;
        return 0;
}

int register_image_mappings(ExecHypervisor *h) {
        ExecHypervisorMapping *heap_mapping = NULL;

        assert(h);
        assert(h->vm_fd >= 0);
        assert(h->n_registered_mappings == 0);

                h->next_guest_physical_address = ALIGN_TO(
                                                MAX((uint64_t) EXEC_HYPERVISOR_SUPERVISOR_SIZE,
                                                        (uint64_t) EXEC_HYPERVISOR_GPA_ALIGNMENT),
                                                EXEC_HYPERVISOR_GPA_ALIGNMENT);

        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings) {
                struct kvm_userspace_memory_region region;
                int r;

                if (mapping->host_address == h->heap_reservation) {
                        heap_mapping = mapping;
                        continue;
                }
                if (mapping->size > UINT64_MAX - h->next_guest_physical_address)
                        return -EOVERFLOW;

                mapping->guest_physical_address = h->next_guest_physical_address;
                r = allocate_memslot(h, &mapping->slot);
                if (r < 0)
                        return r == -ENOSPC ? -E2BIG : r;
                if (!mapping->mutable)
                        mapping->stage2_writable = FLAGS_SET(mapping->protection, PROT_WRITE);
                region = (struct kvm_userspace_memory_region) {
                        .slot = mapping->slot,
                        .flags = mapping->stage2_writable ? 0 : KVM_MEM_READONLY,
                        .guest_phys_addr = mapping->guest_physical_address,
                        .memory_size = mapping->size,
                        .userspace_addr = (uintptr_t) mapping_kvm_address(mapping),
                };

                if (ioctl(h->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
                        release_memslot(h, mapping->slot);
                        return -errno;
                }

                h->next_guest_physical_address += mapping->size;
        }

        h->heap_guest_physical_address = ALIGN_TO(h->next_guest_physical_address, page_size());
        if (h->heap_reservation_size > UINT64_MAX - h->heap_guest_physical_address)
                return -EOVERFLOW;
        h->next_guest_physical_address = h->heap_guest_physical_address + h->heap_reservation_size;
        int r = allocate_memslot(h, &h->heap_slot);
        if (r < 0)
                return r == -ENOSPC ? -E2BIG : r;

        if (heap_mapping && heap_mapping->size > 0) {
                struct kvm_userspace_memory_region region = {
                        .slot = h->heap_slot,
                        .guest_phys_addr = h->heap_guest_physical_address,
                        .memory_size = heap_mapping->size,
                        .userspace_addr = (uintptr_t) heap_mapping->host_address,
                };

                if (ioctl(h->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
                        release_memslot(h, h->heap_slot);
                        h->heap_slot = UINT_MAX;
                        return -errno;
                }

                heap_mapping->guest_physical_address = h->heap_guest_physical_address;
                heap_mapping->slot = h->heap_slot;
                heap_mapping->stage2_writable = true;
        }

        return 0;
}

int allocate_supervisor_page(ExecHypervisor *h, uint64_t flags, uint64_t *ret_gpa, void **ret_host) {
        uint64_t gpa;
        int r;

        assert(h);
        assert(ret_gpa);

        r = allocate_page_table(h, &gpa);
        if (r < 0)
                return r;

        r = map_guest_page(h, gpa, gpa, flags);
        if (r < 0)
                return r;

        *ret_gpa = gpa;
        if (ret_host)
                *ret_host = page_table_at(h, gpa);
        return 0;
}

static void setup_descriptor_tables(ExecHypervisor *h) {
        uint64_t *gdt, ring0_stack_top, *tss_descriptor;
        uint8_t *tss;

        assert(h);

        gdt = ASSERT_PTR(page_table_at(h, h->gdt_gpa));
        tss = (uint8_t*) ASSERT_PTR(page_table_at(h, h->tss_gpa));
        ring0_stack_top = h->ring0_stack_gpa + page_size();

        gdt[1] = UINT64_C(0x00af9b000000ffff); /* Kernel code. */
        gdt[2] = UINT64_C(0x00cf93000000ffff); /* Kernel data. */
        gdt[3] = UINT64_C(0x00cff3000000ffff); /* User data. */
        gdt[4] = UINT64_C(0x00affb000000ffff); /* User code. */

        tss_descriptor = gdt + 5;
        tss_descriptor[0] =
                UINT64_C(0x67) |
                ((h->tss_gpa & UINT64_C(0xffffff)) << 16) |
                (UINT64_C(0x89) << 40) |
                (((h->tss_gpa >> 24) & UINT64_C(0xff)) << 56);
        tss_descriptor[1] = h->tss_gpa >> 32;
        memcpy(tss + 4, &ring0_stack_top, sizeof(ring0_stack_top));
}

static void set_idt_gate(X86IdtGate *gate, uint64_t address) {
        assert(gate);

        *gate = (X86IdtGate) {
                .offset_low = address,
                .selector = 0x08,
                .type_attributes = 0x8e,
                .offset_middle = address >> 16,
                .offset_high = address >> 32,
        };
}

static void setup_exception_stubs(ExecHypervisor *h, uint8_t *supervisor_code) {
        X86IdtGate *idt;

        assert(h);
        assert(supervisor_code);

        idt = (X86IdtGate*) ASSERT_PTR(page_table_at(h, h->idt_gpa));

        for (unsigned vector = 0; vector < EXEC_HYPERVISOR_N_EXCEPTIONS; vector++) {
                uint8_t *stub = supervisor_code +
                        EXEC_HYPERVISOR_EXCEPTION_STUB_OFFSET + vector * EXEC_HYPERVISOR_EXCEPTION_STUB_SIZE;
                uint64_t stub_gpa = h->supervisor_code_gpa + (stub - supervisor_code);

                stub[0] = 0x50; /* push %rax */
                stub[1] = 0xb8; /* mov $vector, %eax */
                unaligned_write_le32(stub + 2, vector);
                stub[6] = 0xe7; /* out %eax, $EXEC_HYPERVISOR_EXCEPTION_PORT */
                stub[7] = EXEC_HYPERVISOR_EXCEPTION_PORT;
                stub[8] = 0xf4; /* hlt */
                set_idt_gate(idt + vector, stub_gpa);
        }
}

int setup_page_tables(ExecHypervisor *h) {
        struct kvm_userspace_memory_region region;
        int r;

        assert(h);
        assert(h->vm_fd >= 0);
        assert(!h->supervisor_memory);

        h->supervisor_memory_size = EXEC_HYPERVISOR_SUPERVISOR_SIZE;
        h->supervisor_memory = mmap(NULL,
                                    h->supervisor_memory_size,
                                    PROT_READ|PROT_WRITE,
                                    MAP_PRIVATE|MAP_ANONYMOUS,
                                    -1,
                                    0);
        if (h->supervisor_memory == MAP_FAILED) {
                h->supervisor_memory = NULL;
                return -errno;
        }
        h->free_supervisor_pages = new0(bool, h->supervisor_memory_size / page_size());
        if (!h->free_supervisor_pages)
                return -ENOMEM;

        h->cr3 = 0;
        h->next_page_table_gpa = page_size();
        memzero(h->supervisor_memory, h->supervisor_memory_size);

        r = allocate_memslot(h, &h->supervisor_slot);
        if (r < 0)
                return r == -ENOSPC ? -E2BIG : r;
        region = (struct kvm_userspace_memory_region) {
                .slot = h->supervisor_slot,
                .guest_phys_addr = 0,
                .memory_size = h->supervisor_memory_size,
                .userspace_addr = (uintptr_t) h->supervisor_memory,
        };
        if (ioctl(h->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
                release_memslot(h, h->supervisor_slot);
                h->supervisor_slot = UINT_MAX;
                return -errno;
        }

        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings)
                for (size_t offset = 0; offset < mapping->size; offset += page_size()) {
                        r = map_guest_page(
                                        h,
                                        mapping->guest_virtual_address + offset,
                                        mapping->guest_physical_address + offset,
                                        guest_mapping_page_flags(mapping));
                        if (r < 0)
                                return r;
                }

        static const uint8_t supervisor_code[] = {
                0xe7, 0x10,       /* out %eax, $0x10 */
                0x48, 0x0f, 0x07, /* sysretq */
        };
        void *supervisor_host;

        r = allocate_supervisor_page(h, 0, &h->supervisor_code_gpa, &supervisor_host);
        if (r < 0)
                return r;
        memcpy(supervisor_host, supervisor_code, sizeof(supervisor_code));

        r = allocate_supervisor_page(h, X86_PAGE_NO_EXECUTE, &h->gdt_gpa, NULL);
        if (r < 0)
                return r;
        r = allocate_supervisor_page(h, X86_PAGE_NO_EXECUTE, &h->idt_gpa, NULL);
        if (r < 0)
                return r;
        r = allocate_supervisor_page(h, X86_PAGE_WRITE|X86_PAGE_NO_EXECUTE, &h->tss_gpa, NULL);
        if (r < 0)
                return r;
        r = allocate_supervisor_page(h, X86_PAGE_WRITE|X86_PAGE_NO_EXECUTE, &h->ring0_stack_gpa, NULL);
        if (r < 0)
                return r;

        static const uint8_t probe_code[] = {
                0xb8, 0x45, 0x4d, 0x56, 0x4b, /* mov $EXEC_HYPERVISOR_PROBE_MARKER, %eax */
                0x0f, 0x05,                   /* syscall */
                0xf4,                         /* hlt */
        };
        void *probe_host;

        r = allocate_supervisor_page(h, X86_PAGE_USER, &h->probe_code_gpa, &probe_host);
        if (r < 0)
                return r;
        memcpy(probe_host, probe_code, sizeof(probe_code));

        setup_descriptor_tables(h);
        setup_exception_stubs(h, supervisor_host);

        return 0;
}

static int prepare_interpreter(ExecHypervisor *h) {
        int r;

        assert(h);
        assert(h->image);

        if (!h->image->interpreter)
                return 0;
        if (!path_is_absolute(h->image->interpreter))
                return -ENOEXEC;

        h->interpreter_fd = open(h->image->interpreter, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (h->interpreter_fd < 0)
                return -errno;

        r = elf_image_read(h->interpreter_fd, &h->interpreter_image);
        if (r < 0)
                return r;
        if (h->interpreter_image->interpreter)
                return -ENOEXEC;

        r = plan_elf_image(
                        h->interpreter_image,
                        /* require_pie= */ false,
                        &h->interpreter_reservation,
                        &h->interpreter_reservation_size,
                        &h->interpreter_virtual_start,
                        &h->interpreter_virtual_end,
                        &h->interpreter_load_bias);
        if (r < 0)
                return r;

        return map_elf_segments(
                        h,
                        h->interpreter_image,
                        h->interpreter_fd,
                        h->interpreter_reservation,
                        h->interpreter_virtual_start);
}

static int exec_hypervisor_new(ExecHypervisor **ret) {
        ExecHypervisor *h;

        assert(ret);

        h = new(ExecHypervisor, 1);
        if (!h)
                return -ENOMEM;

        *h = (ExecHypervisor) {
                .machine = h,
                .kvm_fd = -EBADF,
                .vm_fd = -EBADF,
                .vcpu_fd = -EBADF,
                .image_fd = -EBADF,
                .interpreter_fd = -EBADF,
                .heap_slot = UINT_MAX,
                .supervisor_slot = UINT_MAX,
                .signal_stack = {
                        .ss_flags = SS_DISABLE,
                },
                .memory_lock = PTHREAD_MUTEX_INITIALIZER,
                .quiesce_lock = PTHREAD_MUTEX_INITIALIZER,
                .signal_lock = PTHREAD_MUTEX_INITIALIZER,
        };

        *ret = h;
        return 0;
}

int exec_hypervisor_open_existing(ExecHypervisor *source, ExecHypervisor **ret) {
        _cleanup_(exec_hypervisor_freep) ExecHypervisor *h = NULL;
        int r;

        assert(source);
        assert(ret);

        r = exec_hypervisor_new(&h);
        if (r < 0)
                return r;

        h->kvm_fd = fcntl(source->machine->kvm_fd, F_DUPFD_CLOEXEC, 3);
        if (h->kvm_fd < 0)
                return -errno;

        h->n_memslots = source->machine->n_memslots;
        h->kvm_xsave2_size = source->machine->kvm_xsave2_size;
        h->amx_guest_permission = source->machine->amx_guest_permission;
        h->free_memslots = new0(bool, h->n_memslots);
        if (!h->free_memslots)
                return -ENOMEM;
        h->hwcap = source->machine->hwcap;
        h->hwcap2 = source->machine->hwcap2;
        h->n_rseq_cpus = source->machine->n_rseq_cpus;
        h->clock_ticks = source->machine->clock_ticks;
        h->uid = source->machine->uid;
        h->euid = source->machine->euid;
        h->gid = source->machine->gid;
        h->egid = source->machine->egid;
        h->handoff_context_changed = source->handoff_context_changed;
        h->io_flusher = source->io_flusher;
        h->io_uring_task_restricted = source->io_uring_task_restricted;
        h->landlock_restricted = source->landlock_restricted;
        h->seccomp_local_filter = source->seccomp_local_filter;
        h->spec_ctrl = source->spec_ctrl;
        h->virt_spec_ctrl = source->virt_spec_ctrl;
        h->spec_store_bypass = source->spec_store_bypass;
        h->spec_indirect_branch = source->spec_indirect_branch;
        h->spec_l1d_flush = source->spec_l1d_flush;
        h->seccomp_forces_store_bypass = source->machine->seccomp_forces_store_bypass;
        h->seccomp_forces_indirect_branch = source->machine->seccomp_forces_indirect_branch;
        h->speculation_policy_initialized = source->speculation_policy_initialized;
        h->session_keyring_id = source->session_keyring_id;
        h->keyring_policy_initialized = source->keyring_policy_initialized;
        h->tsc_disabled = source->tsc_disabled;
        *ret = TAKE_PTR(h);
        return 1;
}

int exec_hypervisor_open_system(ExecHypervisor **ret) {
#if defined(__x86_64__)
        _cleanup_(exec_hypervisor_freep) ExecHypervisor *h = NULL;
        unsigned n_memslots;
        uint64_t guest_xcomp_permissions;
        int api_version, r, xsave2_size;

        assert(ret);

        r = dlopen_elf(LOG_DEBUG);
        if (r < 0) {
                if (r == -ENOMEM)
                        return r;

                log_debug_errno(r, "libelf is unavailable, using native execution: %m");
                return 0;
        }

        r = exec_hypervisor_new(&h);
        if (r < 0)
                return r;

        h->kvm_fd = open("/dev/kvm", O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (h->kvm_fd < 0) {
                if (kvm_errno_is_unavailable(errno)) {
                        log_debug_errno(errno, "/dev/kvm is unavailable, using native execution: %m");
                        return 0;
                }

                return -errno;
        }

        api_version = ioctl(h->kvm_fd, KVM_GET_API_VERSION, 0);
        if (api_version < 0)
                return -errno;
        if (api_version != KVM_API_VERSION) {
                log_debug("KVM API version %d is unsupported, using native execution.", api_version);
                return 0;
        }

        r = check_extension(h->kvm_fd, KVM_CAP_USER_MEMORY, "KVM_CAP_USER_MEMORY", NULL);
        if (r <= 0)
                return r;

        r = check_extension(h->kvm_fd, KVM_CAP_READONLY_MEM, "KVM_CAP_READONLY_MEM", NULL);
        if (r <= 0)
                return r;

        r = check_extension(h->kvm_fd, KVM_CAP_IMMEDIATE_EXIT, "KVM_CAP_IMMEDIATE_EXIT", NULL);
        if (r <= 0)
                return r;

        r = check_extension(h->kvm_fd, KVM_CAP_MEMORY_FAULT_INFO, "KVM_CAP_MEMORY_FAULT_INFO", NULL);
        if (r <= 0)
                return r;

        r = check_extension(h->kvm_fd, KVM_CAP_PRE_FAULT_MEMORY, "KVM_CAP_PRE_FAULT_MEMORY", NULL);
        if (r <= 0)
                return r;

        r = check_extension(h->kvm_fd, KVM_CAP_XSAVE, "KVM_CAP_XSAVE", NULL);
        if (r <= 0)
                return r;

        if (syscall(__NR_arch_prctl, ARCH_REQ_XCOMP_GUEST_PERM, ARCH_XCOMP_TILEDATA) >= 0) {
                if (syscall(__NR_arch_prctl, ARCH_GET_XCOMP_GUEST_PERM, &guest_xcomp_permissions) < 0)
                        return -errno;
                if (!FLAGS_SET(guest_xcomp_permissions, X86_XFEATURE_MASK_XTILE_DATA))
                        return -EPROTO;

                h->amx_guest_permission = true;
                log_debug("KVM guest AMX xstate permission is available.");
        } else if (!IN_SET(errno, EINVAL, ENODEV, EOPNOTSUPP))
                return -errno;

        xsave2_size = ioctl(h->kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_XSAVE2);
        if (xsave2_size < 0)
                return -errno;
        if (xsave2_size > 0) {
                if (xsave2_size < (int) sizeof(struct kvm_xsave))
                        return -EPROTO;
                if (xsave2_size > (int) sizeof(X86KvmXsave)) {
                        log_debug("KVM XSAVE2 state size %d exceeds the supported maximum, using native execution.",
                                  xsave2_size);
                        return 0;
                }

                h->kvm_xsave2_size = xsave2_size;
        }
        log_debug("KVM XSAVE state size is %zu bytes%s.",
                  h->kvm_xsave2_size > 0 ? h->kvm_xsave2_size : sizeof(struct kvm_xsave),
                  xsave2_size > 0 ? " through KVM_CAP_XSAVE2" : "");

        r = check_extension(h->kvm_fd, KVM_CAP_XCRS, "KVM_CAP_XCRS", NULL);
        if (r <= 0)
                return r;

        r = check_extension(h->kvm_fd, KVM_CAP_NR_MEMSLOTS, "KVM_CAP_NR_MEMSLOTS", &n_memslots);
        if (r <= 0)
                return r;

        h->n_memslots = n_memslots;
        h->free_memslots = new0(bool, h->n_memslots);
        if (!h->free_memslots)
                return -ENOMEM;
        log_debug("KVM executor probe succeeded with %u memory slots.", h->n_memslots);

        *ret = TAKE_PTR(h);
        return 1;
#else
        assert(ret);

        log_debug("KVM executor support is unavailable on this architecture, using native execution.");
        return 0;
#endif
}

static int executable_requires_kernel_credentials(int executable_fd) {
        _cleanup_free_ char *capability = NULL;
        struct stat st;
        size_t capability_size;
        int r;

        assert(executable_fd >= 0);

        if (fstat(executable_fd, &st) < 0)
                return -errno;
        if ((st.st_mode & (S_ISUID|S_ISGID)) != 0)
                return 1;

        r = fgetxattr_malloc(executable_fd, XATTR_NAME_CAPS, &capability, &capability_size);
        if (r >= 0)
                return capability_size > 0;
        if (IN_SET(r, -ENODATA, -EOPNOTSUPP, -ENOSYS))
                return 0;

        return r;
}

int exec_hypervisor_prepare_image(ExecHypervisor *h, int executable_fd, const char *executable_path) {
        _cleanup_free_ char *fd_path = NULL, *filename = NULL;
        int r;

        assert(h);
        assert(h->kvm_fd >= 0);
        assert(executable_fd >= 0);
        assert(!h->image);
        assert(!h->selected);

        if (isempty(executable_path)) {
                r = fd_get_path(executable_fd, &fd_path);
                if (r < 0)
                        return r;
                executable_path = fd_path;
        }
        r = path_extract_filename(executable_path, &filename);
        if (r < 0)
                return r;
        strlcpy(h->comm, filename, sizeof(h->comm));

        r = executable_requires_kernel_credentials(executable_fd);
        if (r < 0)
                return r;
        if (r > 0) {
                log_debug("Executable requires kernel credential handling, using native execution.");
                return 0;
        }

        r = elf_image_read(executable_fd, &h->image);
        if (r < 0) {
                if (IN_SET(r, -ENOMEM, -EIO, -EMFILE, -ENFILE))
                        return r;

                log_debug_errno(r, "Executable cannot be classified for KVM, using native execution: %m");
                return 0;
        }

        if (!elf_image_is_pie(h->image)) {
                log_debug("Executable is not an unambiguous PIE, using native execution.");
                return 0;
        }

        r = plan_elf_image(
                        h->image,
                        /* require_pie= */ true,
                        &h->image_reservation,
                        &h->image_reservation_size,
                        &h->image_virtual_start,
                        &h->image_virtual_end,
                        &h->image_load_bias);
        if (r < 0) {
                if (IN_SET(r, -ENOMEM, -EIO, -EMFILE, -ENFILE))
                        return r;

                log_debug_errno(r, "Executable cannot be mapped for KVM, using native execution: %m");
                return 0;
        }

        h->image_fd = fd_reopen(executable_fd, O_RDONLY|O_CLOEXEC);
        if (h->image_fd < 0) {
                if (IN_SET(h->image_fd, -ENOMEM, -EMFILE, -ENFILE))
                        return h->image_fd;

                log_debug_errno(h->image_fd, "Executable cannot be reopened for KVM, using native execution: %m");
                return 0;
        }

        r = map_elf_segments(
                        h,
                        h->image,
                        h->image_fd,
                        h->image_reservation,
                        h->image_virtual_start);
        if (r < 0) {
                if (IN_SET(r, -ENOMEM, -EIO, -EMFILE, -ENFILE))
                        return r;

                log_debug_errno(r, "Executable segments cannot be mapped for KVM, using native execution: %m");
                return 0;
        }

        r = prepare_interpreter(h);
        if (r < 0) {
                if (IN_SET(r, -ENOMEM, -EIO, -EMFILE, -ENFILE))
                        return r;

                log_debug_errno(r, "Executable interpreter cannot be mapped for KVM, using native execution: %m");
                return 0;
        }

        r = reserve_guest_stack(h);
        if (r < 0) {
                if (IN_SET(r, -ENOMEM, -EIO, -EMFILE, -ENFILE))
                        return r;

                log_debug_errno(r, "Guest stack cannot be reserved for KVM, using native execution: %m");
                return 0;
        }

        r = reserve_guest_heap(h);
        if (r < 0) {
                if (r == -ENOMEM)
                        return r;

                log_debug_errno(r, "Guest heap cannot be reserved for KVM, using native execution: %m");
                return 0;
        }

        random_bytes(h->random_bytes, sizeof(h->random_bytes));
        if (h->clock_ticks <= 0) {
                h->hwcap = getauxval(AT_HWCAP);
                h->hwcap2 = getauxval(AT_HWCAP2);
                h->clock_ticks = sysconf(_SC_CLK_TCK);
                if (h->clock_ticks <= 0)
                        return errno > 0 ? -errno : -EIO;
                long n_rseq_cpus = sysconf(_SC_NPROCESSORS_CONF);
                if (n_rseq_cpus <= 0 || (unsigned long) n_rseq_cpus > UINT_MAX)
                        return errno > 0 ? -errno : -EIO;
                h->n_rseq_cpus = n_rseq_cpus;
                h->uid = getuid();
                h->euid = geteuid();
                h->gid = getgid();
                h->egid = getegid();
        }

        h->selected = true;
        log_debug("Executable is an unambiguous PIE and remains eligible for KVM execution.");
        return 1;
}

#endif


