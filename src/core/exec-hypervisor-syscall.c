/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-hypervisor-internal.h"

#if defined(__x86_64__)

static bool syscall_requires_adaptation(uint32_t syscall_number) {
        switch (syscall_number) {
        case __NR_mmap:
        case __NR_io_setup:
        case __NR_io_destroy:
        case __NR_shmat:
        case __NR_mprotect:
        case __NR_pkey_mprotect:
        case __NR_pkey_alloc:
        case __NR_pkey_free:
        case __NR_munmap:
        case __NR_mremap:
        case __NR_remap_file_pages:
        case __NR_madvise:
        case __NR_process_madvise:
        case __NR_mseal:
        case __NR_map_shadow_stack:
        case __NR_brk:
        case __NR_arch_prctl:
        case __NR_ioperm:
        case __NR_iopl:
        case __NR_modify_ldt:
        case __NR_prctl:
        case __NR_set_tid_address:
        case __NR_set_robust_list:
        case __NR_io_uring_setup:
        case __NR_io_uring_enter:
        case __NR_io_uring_register:
        case __NR_landlock_restrict_self:
        case __NR_seccomp:
        case __NR_keyctl:
        case __NR_setns:
        case __NR_unshare:
        case __NR_mlock:
        case __NR_mlock2:
        case __NR_mlockall:
        case __NR_munlockall:
        case __NR_timer_create:
        case __NR_timer_delete:
        case __NR_rseq:
        case __NR_rseq_slice_yield:
        case __NR_getcpu:
        case __NR_membarrier:
        case __NR_pselect6:
        case __NR_ppoll:
        case __NR_epoll_pwait:
        case __NR_epoll_pwait2:
        case __NR_clone:
        case __NR_fork:
        case __NR_vfork:
        case __NR_execve:
        case __NR_rt_sigaction:
        case __NR_rt_sigreturn:
        case __NR_sigaltstack:
        case __NR_ioctl:
        case __NR_clone3:
        case __NR_execveat:
                return true;
        default:
                return false;
        }
}

static bool guest_syscall_filter_result(
                ExecHypervisor *h,
                uint32_t syscall_number,
                uint64_t *ret_result,
                bool *ret_kill) {

        ExecHypervisor *machine;
        void *value;
        int action;
        bool listed;

        assert(h);
        assert(ret_result);
        assert(ret_kill);

        machine = exec_hypervisor_machine(h);
        if (!machine->syscall_filter_set)
                return false;

        listed = hashmap_contains(machine->syscall_filter, INT_TO_PTR((int) syscall_number + 1));
        value = listed ? hashmap_get(machine->syscall_filter, INT_TO_PTR((int) syscall_number + 1)) : NULL;

        if (machine->syscall_allow_list) {
                if (listed && PTR_TO_INT(value) < 0)
                        return false;
                action = listed ? PTR_TO_INT(value) : machine->syscall_errno_or_action;
        } else {
                if (!listed)
                        return false;
                action = PTR_TO_INT(value);
                if (action < 0)
                        action = machine->syscall_errno_or_action;
        }

        *ret_kill = action == SECCOMP_ERROR_NUMBER_KILL;
        *ret_result = *ret_kill ? (uint64_t) -EPERM : (uint64_t) -action;
        return true;
}

static _noreturn_ void terminate_guest_for_seccomp(void) {
        const struct sigaction action = {
                .sa_handler = SIG_DFL,
        };
        sigset_t mask;

        assert_se(sigemptyset(&mask) >= 0);
        assert_se(sigaddset(&mask, SIGSYS) >= 0);
        assert_se(sigprocmask(SIG_UNBLOCK, &mask, NULL) >= 0);
        assert_se(sigaction(SIGSYS, &action, NULL) >= 0);
        assert_se(raise(SIGSYS) >= 0);
        _exit(EXIT_FAILURE);
}

uint64_t raw_host_syscall(const struct kvm_regs *regs) {
        register uint64_t argument4 asm("r10") = regs->r10;
        register uint64_t argument5 asm("r8") = regs->r8;
        register uint64_t argument6 asm("r9") = regs->r9;
        uint64_t result;

        assert(regs);

        asm volatile (
                "syscall"
                : "=a" (result)
                : "a" (regs->rax),
                  "D" (regs->rdi),
                  "S" (regs->rsi),
                  "d" (regs->rdx),
                  "r" (argument4),
                  "r" (argument5),
                  "r" (argument6)
                : "rcx", "r11", "memory");

        return result;
}

static int prepare_fork_advice_ranges(
                const ExecHypervisorSealedRange *old_ranges,
                size_t n_old_ranges,
                uint64_t start,
                uint64_t end,
                bool add,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges) {

        _cleanup_free_ ExecHypervisorSealedRange *ranges = NULL;
        size_t n_ranges = 0;

        assert(old_ranges || n_old_ranges == 0);
        assert(start < end);
        assert(ret_ranges);
        assert(ret_n_ranges);

        if (add) {
                size_t capacity;

                if (!ADD_SAFE(&capacity, n_old_ranges, 1))
                        return -EOVERFLOW;
                ranges = new(ExecHypervisorSealedRange, capacity);
                if (!ranges)
                        return -ENOMEM;
                if (n_old_ranges > 0)
                        memcpy(ranges, old_ranges, n_old_ranges * sizeof(*ranges));
                ranges[n_old_ranges] = (ExecHypervisorSealedRange) {
                        .start = start,
                        .length = end - start,
                };
                for (size_t i = 1; i < capacity; i++) {
                        ExecHypervisorSealedRange current = ranges[i];
                        size_t j = i;

                        while (j > 0 && ranges[j - 1].start > current.start) {
                                ranges[j] = ranges[j - 1];
                                j--;
                        }
                        ranges[j] = current;
                }
                for (size_t i = 0; i < capacity; i++) {
                        uint64_t range_end = ranges[i].start + ranges[i].length;

                        if (n_ranges > 0) {
                                ExecHypervisorSealedRange *previous = ranges + n_ranges - 1;
                                uint64_t previous_end = previous->start + previous->length;

                                if (ranges[i].start <= previous_end) {
                                        previous->length = MAX(previous_end, range_end) - previous->start;
                                        continue;
                                }
                        }
                        ranges[n_ranges++] = ranges[i];
                }
        } else {
                if (n_old_ranges > SIZE_MAX / 2)
                        return -EOVERFLOW;
                if (n_old_ranges > 0) {
                        ranges = new(ExecHypervisorSealedRange, n_old_ranges * 2);
                        if (!ranges)
                                return -ENOMEM;
                }
                FOREACH_ARRAY(range, old_ranges, n_old_ranges) {
                        uint64_t range_end = range->start + range->length;

                        if (start >= range_end || end <= range->start) {
                                ranges[n_ranges++] = *range;
                                continue;
                        }
                        if (start > range->start) {
                                ranges[n_ranges] = *range;
                                ranges[n_ranges++].length = start - range->start;
                        }
                        if (end < range_end) {
                                ranges[n_ranges] = *range;
                                ranges[n_ranges].start = end;
                                ranges[n_ranges++].length = range_end - end;
                        }
                }
        }

        *ret_ranges = TAKE_PTR(ranges);
        *ret_n_ranges = n_ranges;
        return 0;
}

int prepare_dontfork_ranges(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                bool add,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges) {

        assert(h);

        return prepare_fork_advice_ranges(
                        h->dontfork_ranges,
                        h->n_dontfork_ranges,
                        start,
                        end,
                        add,
                        ret_ranges,
                        ret_n_ranges);
}

int prepare_wipeonfork_ranges(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                bool add,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges) {

        assert(h);

        return prepare_fork_advice_ranges(
                        h->wipeonfork_ranges,
                        h->n_wipeonfork_ranges,
                        start,
                        end,
                        add,
                        ret_ranges,
                        ret_n_ranges);
}

static int register_existing_guest_mapping(
                ExecHypervisor *h,
                uint64_t address,
                size_t size,
                int protection,
                bool dontfork) {

        _cleanup_(gpa_reservation_done) ExecHypervisorGpaReservation gpa_reservation = {};
        _cleanup_free_ ExecHypervisorSealedRange *new_dontfork_ranges = NULL;
        ExecHypervisor *machine;
        struct kvm_userspace_memory_region region;
        size_t n_mapped_pages = 0, n_new_dontfork_ranges = 0;
        uint64_t end, gpa;
        unsigned slot = UINT_MAX;
        int r;

        assert(h);
        assert(address % page_size() == 0);
        assert(size > 0 && size % page_size() == 0);

        machine = exec_hypervisor_machine(h);
        if (!ADD_SAFE(&end, address, size) || end > UINT64_C(0x0000800000000000))
                return -EOVERFLOW;
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end;

                if (!ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size))
                        return -EOVERFLOW;
                if (address < mapping_end && end > mapping->guest_virtual_address)
                        return -EEXIST;
        }
        if (!GREEDY_REALLOC0(machine->mappings, machine->n_mappings + 1))
                return -ENOMEM;
        if (dontfork) {
                r = prepare_dontfork_ranges(
                                machine,
                                address,
                                end,
                                true,
                                &new_dontfork_ranges,
                                &n_new_dontfork_ranges);
                if (r < 0)
                        return r;
        }
        r = reserve_guest_physical(machine, size, &gpa_reservation);
        if (r < 0)
                return r;
        gpa = gpa_reservation.address;

        for (size_t offset = 0; offset < size; offset += page_size()) {
                r = map_guest_page(machine, address + offset, gpa + offset, guest_page_flags(protection));
                if (r < 0)
                        goto rollback_pages;
                n_mapped_pages++;
        }
        r = allocate_memslot(machine, &slot);
        if (r < 0) {
                if (r == -ENOSPC)
                        r = -ENOMEM;
                goto rollback_pages;
        }
        region = (struct kvm_userspace_memory_region) {
                .slot = slot,
                .guest_phys_addr = gpa,
                .memory_size = size,
                .userspace_addr = address,
        };
        if (ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
                r = -errno;
                goto rollback_slot;
        }

        machine->mappings[machine->n_mappings++] = (ExecHypervisorMapping) {
                .host_address = (void*) (uintptr_t) address,
                .guest_virtual_address = address,
                .guest_physical_address = gpa,
                .size = size,
                .protection = protection,
                .slot = slot,
                .mutable = true,
                .stage2_writable = true,
                .shared = true,
        };
        if (dontfork) {
                free(machine->dontfork_ranges);
                machine->dontfork_ranges = TAKE_PTR(new_dontfork_ranges);
                machine->n_dontfork_ranges = n_new_dontfork_ranges;
        }
        gpa_reservation.committed = true;
        return 0;

rollback_slot:
        release_memslot(machine, slot);
rollback_pages:
        for (size_t i = 0; i < n_mapped_pages; i++) {
                uint64_t page = address + i * page_size();

                unmap_guest_page(machine, page);
                reclaim_guest_page_tables(machine, page);
        }
        return r;
}

static uint64_t handle_guest_map_shadow_stack(
                ExecHypervisor *h,
                uint64_t requested_address,
                uint64_t requested_size,
                uint64_t flags) {

        _cleanup_(gpa_reservation_done) ExecHypervisorGpaReservation gpa_reservation = {};
        _cleanup_close_ int fd = -EBADF;
        ExecHypervisor *machine;
        struct kvm_userspace_memory_region region;
        struct stat st;
        uint64_t end, gpa, reservation_size;
        size_t n_mapped_pages = 0, size;
        unsigned slot = UINT_MAX;
        void *host_address = MAP_FAILED, *kvm_address = MAP_FAILED, *reservation = MAP_FAILED;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (flags & ~SHADOW_STACK_SET_TOKEN)
                return (uint64_t) -EINVAL;
        if (requested_size == 0)
                return (uint64_t) -EINVAL;
        if (FLAGS_SET(flags, SHADOW_STACK_SET_TOKEN) && requested_size < sizeof(uint64_t))
                return (uint64_t) -ENOSPC;
        if (requested_address != 0 && requested_address < UINT64_C(0x100000000))
                return (uint64_t) -ERANGE;
        if (requested_size > SIZE_MAX - (page_size() - 1))
                return (uint64_t) -EOVERFLOW;
        if (requested_address % page_size() != 0)
                return (uint64_t) -EINVAL;
        size = PAGE_ALIGN((size_t) requested_size);
        if (!ADD_SAFE(&reservation_size, size, page_size()))
                return (uint64_t) -EOVERFLOW;
        if (requested_address != 0 &&
            (!ADD_SAFE(&end, requested_address, size) || end > UINT64_C(0x0000800000000000)))
                return (uint64_t) -ENOMEM;

        if (!GREEDY_REALLOC0(machine->mappings, machine->n_mappings + 1) ||
            !GREEDY_REALLOC(machine->mapping_fds, machine->n_mapping_fds + 1))
                return (uint64_t) -ENOMEM;

        void *reservation_hint = requested_address != 0 ?
                (void*) (uintptr_t) (requested_address - page_size()) :
                (void*) UINT64_C(0x100000000);
        int reservation_flags = MAP_PRIVATE|MAP_ANONYMOUS;
        if (requested_address != 0)
                reservation_flags |= MAP_FIXED_NOREPLACE;
        reservation = mmap(
                        reservation_hint,
                        reservation_size,
                        PROT_NONE,
                        reservation_flags,
                        -1,
                        0);
        if (reservation == MAP_FAILED)
                return (uint64_t) -errno;
        host_address = (uint8_t*) reservation + page_size();
        if ((uintptr_t) host_address < UINT64_C(0x100000000) ||
            (requested_address != 0 && (uintptr_t) host_address != requested_address)) {
                r = -ENOMEM;
                goto rollback_reservation;
        }
        if (FLAGS_SET(flags, SHADOW_STACK_SET_TOKEN) && requested_size % sizeof(uint64_t) != 0) {
                r = -EINVAL;
                goto rollback_reservation;
        }

        fd = memfd_create("systemd-executor-shadow-stack", MFD_CLOEXEC);
        if (fd < 0) {
                r = -errno;
                goto rollback_reservation;
        }
        if (ftruncate(fd, size) < 0 || fstat(fd, &st) < 0) {
                r = -errno;
                goto rollback_reservation;
        }
        kvm_address = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (kvm_address == MAP_FAILED) {
                r = -errno;
                goto rollback_reservation;
        }
        host_address = mmap(host_address, size, PROT_READ, MAP_SHARED|MAP_FIXED, fd, 0);
        if (host_address == MAP_FAILED) {
                r = -errno;
                goto rollback_alias;
        }

        if (FLAGS_SET(flags, SHADOW_STACK_SET_TOKEN)) {
                uint64_t token = ((uintptr_t) host_address + requested_size) | UINT64_C(1);

                unaligned_write_le64(
                                (uint8_t*) kvm_address + requested_size - sizeof(uint64_t),
                                token);
        }

        r = reserve_guest_physical(machine, size, &gpa_reservation);
        if (r < 0)
                goto rollback_alias;
        gpa = gpa_reservation.address;
        for (size_t offset = 0; offset < size; offset += page_size()) {
                r = map_guest_page(
                                machine,
                                (uintptr_t) host_address + offset,
                                gpa + offset,
                                X86_PAGE_USER|X86_PAGE_DIRTY|X86_PAGE_NO_EXECUTE);
                if (r < 0)
                        goto rollback_pages;
                n_mapped_pages++;
        }
        r = allocate_memslot(machine, &slot);
        if (r < 0) {
                if (r == -ENOSPC)
                        r = -ENOMEM;
                goto rollback_pages;
        }
        region = (struct kvm_userspace_memory_region) {
                .slot = slot,
                .guest_phys_addr = gpa,
                .memory_size = size,
                .userspace_addr = (uintptr_t) kvm_address,
        };
        if (ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
                r = -errno;
                goto rollback_slot;
        }

        int backing_fd = fd;
        machine->mappings[machine->n_mappings++] = (ExecHypervisorMapping) {
                .host_address = host_address,
                .kvm_address = kvm_address,
                .guard_address = reservation,
                .guest_virtual_address = (uintptr_t) host_address,
                .guest_physical_address = gpa,
                .size = size,
                .protection = PROT_READ,
                .shadow_stack_protection = PROT_READ|PROT_WRITE,
                .slot = slot,
                .mutable = true,
                .stage2_writable = true,
                .file_backed = true,
                .shared = true,
                .shadow_stack = true,
                .shadow_stack_guard_reserved = true,
                .backing_fd = backing_fd,
                .backing_device = st.st_dev,
                .backing_inode = st.st_ino,
        };
        machine->mapping_fds[machine->n_mapping_fds++] = TAKE_FD(fd);
        gpa_reservation.committed = true;
        return (uintptr_t) host_address;

rollback_slot:
        release_memslot(machine, slot);
rollback_pages:
        for (size_t i = 0; i < n_mapped_pages; i++) {
                uint64_t page = (uintptr_t) host_address + i * page_size();

                unmap_guest_page(machine, page);
                reclaim_guest_page_tables(machine, page);
        }
rollback_alias:
        if (kvm_address != MAP_FAILED)
                (void) munmap(kvm_address, size);
rollback_reservation:
        if (reservation != MAP_FAILED)
                (void) munmap(reservation, reservation_size);
        return (uint64_t) r;
}

int prepare_mremap_fork_advice_ranges(
                const ExecHypervisorSealedRange *old_ranges,
                size_t n_old_ranges,
                uint64_t source,
                uint64_t old_length,
                uint64_t target,
                uint64_t new_length,
                bool dontunmap,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges) {

        _cleanup_free_ ExecHypervisorSealedRange *translated = NULL;
        ExecHypervisorSealedRange *ranges = NULL;
        uint64_t copied_length, old_end, new_end;
        size_t n_ranges = n_old_ranges, n_translated = 0;
        bool extend = false;
        int r;

        assert(old_ranges || n_old_ranges == 0);
        assert(old_length > 0);
        assert(new_length > 0);
        assert(ret_ranges);
        assert(ret_n_ranges);

        if (!ADD_SAFE(&old_end, source, old_length) || !ADD_SAFE(&new_end, target, new_length))
                return -EOVERFLOW;
        copied_length = MIN(old_length, new_length);
        if (new_length > old_length)
                FOREACH_ARRAY(range, old_ranges, n_old_ranges)
                        if (old_end - 1 >= range->start && old_end - 1 < range->start + range->length) {
                                extend = true;
                                break;
                        }

        if (target == source) {
                if (n_old_ranges > 0) {
                        ranges = memdup(old_ranges, n_old_ranges * sizeof(*ranges));
                        if (!ranges)
                                return -ENOMEM;
                }
                if (new_length < old_length) {
                        ExecHypervisorSealedRange *next = NULL;

                        r = prepare_fork_advice_ranges(
                                        ranges,
                                        n_ranges,
                                        new_end,
                                        old_end,
                                        false,
                                        &next,
                                        &n_ranges);
                        free(ranges);
                        if (r < 0)
                                return r;
                        ranges = next;
                } else if (extend) {
                        ExecHypervisorSealedRange *next = NULL;

                        r = prepare_fork_advice_ranges(
                                        ranges,
                                        n_ranges,
                                        old_end,
                                        new_end,
                                        true,
                                        &next,
                                        &n_ranges);
                        free(ranges);
                        if (r < 0)
                                return r;
                        ranges = next;
                }

                *ret_ranges = ranges;
                *ret_n_ranges = n_ranges;
                return 0;
        }

        if (n_old_ranges > 0) {
                ranges = memdup(old_ranges, n_old_ranges * sizeof(*ranges));
                translated = new(ExecHypervisorSealedRange, n_old_ranges + 1);
                if (!ranges || !translated) {
                        free(ranges);
                        return -ENOMEM;
                }
        }
        FOREACH_ARRAY(range, old_ranges, n_old_ranges) {
                uint64_t end = MIN(source + copied_length, range->start + range->length);
                uint64_t start = MAX(source, range->start);

                if (start >= end)
                        continue;
                translated[n_translated++] = (ExecHypervisorSealedRange) {
                        .start = target + start - source,
                        .length = end - start,
                };
        }
        if (extend)
                translated[n_translated++] = (ExecHypervisorSealedRange) {
                        .start = target + old_length,
                        .length = new_length - old_length,
                };

        if (!dontunmap) {
                ExecHypervisorSealedRange *next = NULL;

                r = prepare_fork_advice_ranges(
                                ranges,
                                n_ranges,
                                source,
                                old_end,
                                false,
                                &next,
                                &n_ranges);
                free(ranges);
                if (r < 0)
                        return r;
                ranges = next;
        }
        {
                ExecHypervisorSealedRange *next = NULL;

                r = prepare_fork_advice_ranges(
                                ranges,
                                n_ranges,
                                target,
                                new_end,
                                false,
                                &next,
                                &n_ranges);
                free(ranges);
                if (r < 0)
                        return r;
                ranges = next;
        }
        FOREACH_ARRAY(range, translated, n_translated) {
                ExecHypervisorSealedRange *next = NULL;

                r = prepare_fork_advice_ranges(
                                ranges,
                                n_ranges,
                                range->start,
                                range->start + range->length,
                                true,
                                &next,
                                &n_ranges);
                free(ranges);
                if (r < 0)
                        return r;
                ranges = next;
        }

        *ret_ranges = ranges;
        *ret_n_ranges = n_ranges;
        return 0;
}

uint64_t handle_guest_madvise(ExecHypervisor *h, const struct kvm_regs *regs) {
        _cleanup_free_ ExecHypervisorUserfaultRange *new_userfault_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_dontfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_wipeonfork_ranges = NULL;
        ExecHypervisor *machine;
        uint64_t covered = 0, end, length, result;
        size_t n_new_dontfork_ranges = 0;
        size_t n_new_wipeonfork_ranges = 0;
        size_t n_new_userfault_ranges;
        bool fork_advice, overlaps = false;
        int r;

        assert(h);
        assert(regs);

        if (IN_SET(regs->rdx, MADV_GUARD_INSTALL, MADV_GUARD_REMOVE))
                return (uint64_t) -EINVAL;

        if (regs->rdi % page_size() != 0 || regs->rsi == 0 ||
            regs->rsi > SIZE_MAX - (page_size() - 1))
                return raw_host_syscall(regs);
        length = PAGE_ALIGN(regs->rsi);
        if (!ADD_SAFE(&end, regs->rdi, length))
                return raw_host_syscall(regs);

        machine = exec_hypervisor_machine(h);
        fork_advice = IN_SET(
                        regs->rdx,
                        MADV_DONTFORK,
                        MADV_DOFORK,
                        MADV_WIPEONFORK,
                        MADV_KEEPONFORK);
        if (fork_advice) {
                FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                        uint64_t mapping_end, overlap_end, overlap_start;

                        if (!ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size) ||
                            regs->rdi >= mapping_end || end <= mapping->guest_virtual_address)
                                continue;
                        overlap_start = MAX(regs->rdi, mapping->guest_virtual_address);
                        overlap_end = MIN(end, mapping_end);
                        if (!ADD_SAFE(&covered, covered, overlap_end - overlap_start))
                                return (uint64_t) -EOVERFLOW;
                }
                if (covered != length)
                        return (uint64_t) -ENOMEM;
                if (IN_SET(regs->rdx, MADV_DONTFORK, MADV_DOFORK)) {
                        r = prepare_dontfork_ranges(
                                        machine,
                                        regs->rdi,
                                        end,
                                        regs->rdx == MADV_DONTFORK,
                                        &new_dontfork_ranges,
                                        &n_new_dontfork_ranges);
                        if (r < 0)
                                return (uint64_t) r;
                } else if (IN_SET(regs->rdx, MADV_WIPEONFORK, MADV_KEEPONFORK)) {
                        r = prepare_wipeonfork_ranges(
                                        machine,
                                        regs->rdi,
                                        end,
                                        regs->rdx == MADV_WIPEONFORK,
                                        &new_wipeonfork_ranges,
                                        &n_new_wipeonfork_ranges);
                        if (r < 0)
                                return (uint64_t) r;
                }

                result = raw_host_syscall(regs);
                if ((int64_t) result < 0)
                        return result;
                if (IN_SET(regs->rdx, MADV_DONTFORK, MADV_DOFORK)) {
                        free(machine->dontfork_ranges);
                        machine->dontfork_ranges = TAKE_PTR(new_dontfork_ranges);
                        machine->n_dontfork_ranges = n_new_dontfork_ranges;
                } else if (IN_SET(regs->rdx, MADV_WIPEONFORK, MADV_KEEPONFORK)) {
                        free(machine->wipeonfork_ranges);
                        machine->wipeonfork_ranges = TAKE_PTR(new_wipeonfork_ranges);
                        machine->n_wipeonfork_ranges = n_new_wipeonfork_ranges;
                }
                return result;
        }
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (regs->rdi >= range_end || end <= range->start)
                        continue;
                overlaps = true;
                if (!range->features_known)
                        return (uint64_t) -ENOSYS;
                if (!FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) || !range->write_protected)
                        continue;

                uint64_t overlap_start = MAX(regs->rdi, range->start);
                uint64_t overlap_end = MIN(end, range_end);

                for (uint64_t page = overlap_start; page < overlap_end; page += page_size()) {
                        ExecHypervisorMapping *mapping = find_mapping(machine, page);

                        if (!mapping || mapping->file_backed || mapping->shared)
                                return (uint64_t) -ENOSYS;
                }
        }
        if (!overlaps)
                return raw_host_syscall(regs);
        if (regs->rdx != MADV_DONTNEED)
                return (uint64_t) -ENOSYS;

        r = prepare_userfault_ranges_after_dontneed(
                        h,
                        regs->rdi,
                        end,
                        &new_userfault_ranges,
                        &n_new_userfault_ranges);
        if (r < 0)
                return (uint64_t) r;

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0)
                return result;

        for (uint64_t page = regs->rdi; page < end; page += page_size()) {
                ExecHypervisorMapping *mapping = find_mapping(machine, page);
                uint64_t *entry = guest_page_entry(machine, page);

                if (!mapping || !entry)
                        continue;
                FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges)
                        if (page >= range->start && page < range->start + range->length) {
                                *entry &= ~X86_PAGE_SOFTWARE_UFFD_POISON;
                                if ((range->mode & (UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_MINOR)) != 0)
                                        *entry &= ~X86_PAGE_PRESENT;
                                if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) &&
                                    range->write_protected && FLAGS_SET(mapping->protection, PROT_WRITE))
                                        *entry |= X86_PAGE_WRITE;
                                break;
                        }
        }
        if (flush_all_guest_tlbs(machine) < 0)
                _exit(EXIT_FAILURE);

        free(machine->userfault_ranges);
        machine->userfault_ranges = TAKE_PTR(new_userfault_ranges);
        machine->n_userfault_ranges = n_new_userfault_ranges;
        return result;
}

int copy_to_guest(ExecHypervisor *h, uint64_t guest_address, const void *source, size_t size) {
        ExecHypervisor *machine;
        int r;

        assert(h);
        assert(source || size == 0);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        r = validate_guest_range(machine, guest_address, size, /* writeable= */ true);
        if (r >= 0)
                memcpy((void*) (uintptr_t) guest_address, source, size);
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);

        return r;
}

int copy_from_guest(ExecHypervisor *h, void *destination, uint64_t guest_address, size_t size) {
        ExecHypervisor *machine;
        int r;

        assert(h);
        assert(destination || size == 0);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        r = validate_guest_range(machine, guest_address, size, /* writeable= */ false);
        if (r >= 0)
                memcpy(destination, (void*) (uintptr_t) guest_address, size);
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);

        return r;
}

static uint64_t handle_guest_io_setup(ExecHypervisor *h, const struct kvm_regs *regs) {
        struct procmap_query query;
        ExecHypervisor *machine;
        aio_context_t context;
        uint64_t result;
        bool dontfork;
        int protection = 0, r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &context, regs->rsi, sizeof(context));
        if (r < 0)
                return r;
        r = begin_guest_memory_transaction(h);
        if (r < 0)
                return r;
        machine = exec_hypervisor_machine(h);
        if (!GREEDY_REALLOC0(machine->aio_contexts, machine->n_aio_contexts + 1)) {
                result = (uint64_t) -ENOMEM;
                goto finish;
        }

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0)
                goto finish;
        memcpy(&context, (void*) (uintptr_t) regs->rsi, sizeof(context));
        r = query_host_mapping(context, &query);
        if (r < 0)
                goto rollback_context;
        if (query.vma_start != context || query.vma_end <= query.vma_start ||
            query.vma_end - query.vma_start > SIZE_MAX) {
                r = -EPROTO;
                goto rollback_context;
        }
        r = host_mapping_has_vm_flag(context, "dc", &dontfork);
        if (r < 0)
                goto rollback_context;
        if (FLAGS_SET(query.vma_flags, PROCMAP_QUERY_VMA_READABLE))
                protection |= PROT_READ;
        if (FLAGS_SET(query.vma_flags, PROCMAP_QUERY_VMA_WRITABLE))
                protection |= PROT_WRITE;
        if (FLAGS_SET(query.vma_flags, PROCMAP_QUERY_VMA_EXECUTABLE))
                protection |= PROT_EXEC;
        r = register_existing_guest_mapping(
                        machine,
                        query.vma_start,
                        query.vma_end - query.vma_start,
                        protection,
                        dontfork);
        if (r < 0)
                goto rollback_context;

        machine->aio_contexts[machine->n_aio_contexts++] = (GuestAioContext) {
                .id = context,
                .mapping_start = query.vma_start,
                .mapping_size = query.vma_end - query.vma_start,
        };
        goto finish;

rollback_context:
        if (syscall(__NR_io_destroy, context) < 0)
                _exit(EXIT_FAILURE);
        context = 0;
        memcpy((void*) (uintptr_t) regs->rsi, &context, sizeof(context));
        result = (uint64_t) r;
finish:
        end_guest_memory_transaction(h);
        return result;
}

static uint64_t handle_guest_io_destroy(ExecHypervisor *h, const struct kvm_regs *regs) {
        ExecHypervisor *machine;
        size_t index = SIZE_MAX;
        uint64_t result, unmap_result;
        int r;

        assert(h);
        assert(regs);

        r = begin_guest_memory_transaction(h);
        if (r < 0)
                return r;
        machine = exec_hypervisor_machine(h);
        for (size_t i = 0; i < machine->n_aio_contexts; i++)
                if (machine->aio_contexts[i].id == regs->rdi) {
                        index = i;
                        break;
                }

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0 || index == SIZE_MAX)
                goto finish;
        unmap_result = handle_guest_munmap(
                        machine,
                        machine->aio_contexts[index].mapping_start,
                        machine->aio_contexts[index].mapping_size);
        if ((int64_t) unmap_result < 0)
                _exit(EXIT_FAILURE);
        if (index + 1 < machine->n_aio_contexts)
                memmove(machine->aio_contexts + index,
                        machine->aio_contexts + index + 1,
                        (machine->n_aio_contexts - index - 1) * sizeof(machine->aio_contexts[0]));
        machine->n_aio_contexts--;

finish:
        end_guest_memory_transaction(h);
        return result;
}

int copy_guest_cstring(ExecHypervisor *h, uint64_t guest_address, size_t *remaining, char **ret) {
        _cleanup_free_ char *string = NULL;
        size_t length = 0;

        assert(h);
        assert(remaining);
        assert(ret);

        if (guest_address == 0)
                return -EFAULT;

        while (length < *remaining) {
                char *nul;
                size_t chunk;
                uint64_t address;
                int r;

                if (!ADD_SAFE(&address, guest_address, length) ||
                    address > UINT64_C(0x00007fffffffffff))
                        return -EFAULT;

                chunk = MIN(page_size() - address % page_size(), *remaining - length);
                if (!GREEDY_REALLOC(string, length + chunk))
                        return -ENOMEM;

                r = copy_from_guest(h, string + length, address, chunk);
                if (r < 0)
                        return r;

                nul = memchr(string + length, 0, chunk);
                if (nul) {
                        size_t size = nul - string + 1;

                        *remaining -= size;
                        *ret = TAKE_PTR(string);
                        return 0;
                }

                length += chunk;
        }

        return -E2BIG;
}

int copy_guest_strv(ExecHypervisor *h, uint64_t guest_address, size_t *remaining, char ***ret) {
        _cleanup_strv_free_ char **result = NULL;

        assert(h);
        assert(remaining);
        assert(ret);

        if (guest_address == 0) {
                *ret = NULL;
                return 0;
        }

        for (size_t i = 0;; i++) {
                _cleanup_free_ char *string = NULL;
                uint64_t element_address, pointer;
                int r;

                if (*remaining < sizeof(pointer) ||
                    !MUL_SAFE(&element_address, i, sizeof(pointer)) ||
                    !ADD_SAFE(&element_address, guest_address, element_address))
                        return -E2BIG;
                *remaining -= sizeof(pointer);

                r = copy_from_guest(h, &pointer, element_address, sizeof(pointer));
                if (r < 0)
                        return r;
                if (pointer == 0)
                        break;

                r = copy_guest_cstring(h, pointer, remaining, &string);
                if (r < 0)
                        return r;
                r = strv_consume(&result, TAKE_PTR(string));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(result);
        return 0;
}

void clear_guest_tid_address(ExecHypervisor *h, uint64_t clear_tid_address) {
        const uint32_t zero = 0;

        assert(h);

        if (clear_tid_address == 0)
                return;

        if (copy_to_guest(h, clear_tid_address, &zero, sizeof(zero)) >= 0)
                (void) syscall(__NR_futex,
                               (void*) (uintptr_t) clear_tid_address,
                               FUTEX_WAKE,
                               1,
                               NULL,
                               NULL,
                               0);
}

static void clear_guest_tid(ExecHypervisor *h) {
        assert(h);

        clear_guest_tid_address(h, h->clear_tid_address);
}

static uint64_t handle_guest_rseq(
                ExecHypervisor *h,
                uint64_t address,
                uint32_t length,
                int flags,
                uint32_t signature) {

        GuestRseq rseq;
        int r;

        assert(h);

        if (flags & 1) {
                if (flags != 1)
                        return (uint64_t) -EINVAL;
                if (h->rseq_address == 0 || address != h->rseq_address)
                        return (uint64_t) -EINVAL;
                if (length != h->rseq_length)
                        return (uint64_t) -EINVAL;
                if (signature != h->rseq_signature)
                        return (uint64_t) -EPERM;

                r = copy_from_guest(h, &rseq, address, sizeof(rseq));
                if (r < 0)
                        return (uint64_t) r;
                rseq.cpu_id_start = 0;
                rseq.cpu_id = UINT32_MAX;
                rseq.node_id = 0;
                rseq.mm_cid = 0;
                r = copy_to_guest(h, address, &rseq, sizeof(rseq));
                if (r < 0)
                        return (uint64_t) r;

                h->rseq_address = 0;
                h->rseq_length = 0;
                h->rseq_signature = 0;
                return 0;
        }

        if (flags != 0 ||
            length != EXEC_HYPERVISOR_RSEQ_SIZE ||
            address % EXEC_HYPERVISOR_RSEQ_ALIGNMENT != 0)
                return (uint64_t) -EINVAL;
        if (h->vcpu_id >= h->machine->n_rseq_cpus)
                return (uint64_t) -EINVAL;
        if (h->rseq_address != 0) {
                if (address != h->rseq_address || length != h->rseq_length)
                        return (uint64_t) -EINVAL;
                if (signature != h->rseq_signature)
                        return (uint64_t) -EPERM;
                return (uint64_t) -EBUSY;
        }

        r = validate_guest_range(h, address, sizeof(rseq), /* writeable= */ true);
        if (r < 0)
                return (uint64_t) r;
        r = copy_from_guest(h, &rseq, address, sizeof(rseq));
        if (r < 0)
                return (uint64_t) r;

        rseq.cpu_id_start = h->vcpu_id;
        rseq.cpu_id = h->vcpu_id;
        rseq.rseq_cs = 0;
        rseq.flags = 0;
        rseq.node_id = 0;
        rseq.mm_cid = h->vcpu_id;
        r = copy_to_guest(h, address, &rseq, sizeof(rseq));
        if (r < 0)
                return (uint64_t) r;

        h->rseq_address = address;
        h->rseq_length = length;
        h->rseq_signature = signature;
        return 0;
}

static uint64_t handle_guest_getcpu(ExecHypervisor *h, uint64_t cpu_address, uint64_t node_address) {
        uint32_t cpu, node = 0;
        int result = 0;

        assert(h);

        cpu = h->vcpu_id;
        if (cpu_address != 0 && copy_to_guest(h, cpu_address, &cpu, sizeof(cpu)) < 0)
                result = -EFAULT;
        if (node_address != 0 && copy_to_guest(h, node_address, &node, sizeof(node)) < 0)
                result = -EFAULT;

        return (uint64_t) result;
}

static uint64_t handle_guest_set_robust_list(ExecHypervisor *h, uint64_t address, uint64_t size) {
        long result;

        assert(h);

        if (size != sizeof(struct robust_list_head))
                return (uint64_t) -EINVAL;

        result = syscall(__NR_set_robust_list, (void*) (uintptr_t) address, size);
        if (result < 0)
                return (uint64_t) -errno;

        h->robust_list_address = address;
        return 0;
}

static uint64_t handle_guest_timer_create(ExecHypervisor *h, const struct kvm_regs *regs) {
        struct sigevent event;
        ExecHypervisor *machine;
        int id, r, signal_number = SIGALRM;
        uint64_t result;

        assert(h);
        assert(regs);

        r = validate_guest_range(h, regs->rdx, sizeof(id), /* writeable= */ true);
        if (r < 0)
                return (uint64_t) r;
        if (regs->rsi != 0) {
                r = copy_from_guest(h, &event, regs->rsi, sizeof(event));
                if (r < 0)
                        return (uint64_t) r;

                signal_number = (event.sigev_notify & ~SIGEV_THREAD_ID) == SIGEV_SIGNAL ?
                        event.sigev_signo : 0;
        }

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        if (!GREEDY_REALLOC0(machine->posix_timers, machine->n_posix_timers + 1)) {
                result = (uint64_t) -ENOMEM;
                goto finish;
        }

        if (machine->timer_restore_ids) {
                r = copy_from_guest(h, &id, regs->rdx, sizeof(id));
                if (r < 0) {
                        result = (uint64_t) r;
                        goto finish;
                }
                if (syscall(__NR_prctl,
                            PR_TIMER_CREATE_RESTORE_IDS,
                            PR_TIMER_CREATE_RESTORE_IDS_ON,
                            0,
                            0,
                            0) < 0) {
                        result = (uint64_t) -errno;
                        goto finish;
                }
        }

        long q = syscall(__NR_timer_create,
                         (clockid_t) regs->rdi,
                         (struct sigevent*) (uintptr_t) regs->rsi,
                         &id);
        int error = q < 0 ? errno : 0;
        if (machine->timer_restore_ids &&
            syscall(__NR_prctl,
                    PR_TIMER_CREATE_RESTORE_IDS,
                    PR_TIMER_CREATE_RESTORE_IDS_OFF,
                    0,
                    0,
                    0) < 0) {
                int reset_error = errno;

                if (q >= 0)
                        (void) syscall(__NR_timer_delete, id);
                result = (uint64_t) -reset_error;
                goto finish;
        }
        if (q < 0) {
                result = (uint64_t) -error;
                goto finish;
        }
        r = copy_to_guest(h, regs->rdx, &id, sizeof(id));
        if (r < 0) {
                (void) syscall(__NR_timer_delete, id);
                result = (uint64_t) r;
                goto finish;
        }

        machine->posix_timers[machine->n_posix_timers++] = (GuestPosixTimer) {
                .id = id,
                .signal = signal_number,
        };
        result = 0;

finish:
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return result;
}

static uint64_t handle_guest_timer_delete(ExecHypervisor *h, int id) {
        ExecHypervisor *machine;
        uint64_t result;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        result = syscall(__NR_timer_delete, id) < 0 ? (uint64_t) -errno : 0;
        if ((int64_t) result >= 0)
                for (size_t i = 0; i < machine->n_posix_timers; i++)
                        if (machine->posix_timers[i].id == id) {
                                machine->posix_timers[i] =
                                        machine->posix_timers[--machine->n_posix_timers];
                                break;
                        }
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return result;
}

static uint64_t handle_guest_mlockall(ExecHypervisor *h, int flags) {
        ExecHypervisor *machine;
        uint64_t result;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        result = syscall(__NR_mlockall, flags) < 0 ? (uint64_t) -errno : 0;
        if ((int64_t) result >= 0) {
                machine->mlockall_future = FLAGS_SET(flags, MCL_FUTURE);
                machine->mlockall_current |= FLAGS_SET(flags, MCL_CURRENT);
        }
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return result;
}

static uint64_t handle_guest_io_uring(ExecHypervisor *h, const struct kvm_regs *regs) {
        ExecHypervisor *machine;
        uint32_t opcode;
        uint64_t result;

        assert(h);
        assert(regs);

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0)
                return result;
        if (regs->rax == __NR_io_uring_register && (uint32_t) regs->rdi == UINT_MAX) {
                opcode = (uint32_t) regs->rsi & ~IORING_REGISTER_USE_REGISTERED_RING;
                if (opcode == IORING_REGISTER_QUERY)
                        return result;
                if (IN_SET(opcode, IORING_REGISTER_RESTRICTIONS, IORING_REGISTER_BPF_FILTER)) {
                        h->io_uring_task_restricted = true;
                        return result;
                }
        }

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        machine->io_uring_used = true;
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return result;
}

static uint64_t handle_guest_landlock_restrict_self(ExecHypervisor *h, const struct kvm_regs *regs) {
        uint64_t result;

        assert(h);
        assert(regs);

        result = raw_host_syscall(regs);
        if ((int64_t) result >= 0)
                h->landlock_restricted = true;
        return result;
}

static uint64_t handle_guest_seccomp(ExecHypervisor *h, const struct kvm_regs *regs) {
        bool committed, synchronize;
        uint64_t result;
        int r;

        assert(h);
        assert(regs);

        if (regs->rdi == SECCOMP_SET_MODE_STRICT)
                return regs->rsi == 0 && regs->rdx == 0 ? (uint64_t) -EOPNOTSUPP : (uint64_t) -EINVAL;

        synchronize = regs->rdi == SECCOMP_SET_MODE_FILTER &&
                FLAGS_SET(regs->rsi, SECCOMP_FILTER_FLAG_TSYNC);
        if (synchronize) {
                r = begin_guest_memory_transaction(h);
                if (r < 0)
                        return (uint64_t) r;
        }
        result = raw_host_syscall(regs);
        committed = regs->rdi == SECCOMP_SET_MODE_FILTER &&
                (synchronize ? result == 0 : (int64_t) result >= 0);
        if (committed)
                r = commit_guest_seccomp_filter(
                                h,
                                synchronize,
                                FLAGS_SET(regs->rsi, SECCOMP_FILTER_FLAG_SPEC_ALLOW));
        else
                r = 0;
        if (synchronize)
                end_guest_memory_transaction(h);
        if (r < 0)
                _exit(EXIT_FAILURE);
        return result;
}

static uint64_t handle_guest_task_context(ExecHypervisor *h, const struct kvm_regs *regs) {
        uint64_t result;

        assert(h);
        assert(regs);

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0)
                return result;
        if (regs->rax == __NR_setns || (regs->rdi & ~(uint64_t) CLONE_FILES) != 0)
                h->handoff_context_changed = true;
        return result;
}

static uint64_t handle_guest_keyctl(ExecHypervisor *h, const struct kvm_regs *regs) {
        uint64_t result;

        assert(h);
        assert(regs);

        if (regs->rdi == KEYCTL_SESSION_TO_PARENT)
                return (uint64_t) -EOPNOTSUPP;
        result = raw_host_syscall(regs);
        if ((int64_t) result >= 0 && regs->rdi == KEYCTL_JOIN_SESSION_KEYRING) {
                h->session_keyring_id = result;
                h->keyring_policy_initialized = true;
        }
        return result;
}

static uint64_t handle_guest_mlock(ExecHypervisor *h, const struct kvm_regs *regs) {
        ExecHypervisor *machine;
        uint64_t result;

        assert(h);
        assert(regs);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        result = raw_host_syscall(regs);
        if ((int64_t) result >= 0)
                machine->mlock_range_seen = true;
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return result;
}

static uint64_t handle_guest_munlockall(ExecHypervisor *h) {
        ExecHypervisor *machine;
        uint64_t result;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        result = syscall(__NR_munlockall) < 0 ? (uint64_t) -errno : 0;
        if ((int64_t) result >= 0) {
                machine->mlockall_current = false;
                machine->mlockall_future = false;
                machine->mlock_range_seen = false;
        }
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return result;
}

static uint64_t handle_guest_futex_hash(ExecHypervisor *h, const struct kvm_regs *regs) {
        ExecHypervisor *machine;
        long supported;
        uint64_t result;
        unsigned slots;

        assert(h);
        assert(regs);

        supported = syscall(__NR_prctl,
                            PR_FUTEX_HASH,
                            PR_FUTEX_HASH_GET_SLOTS,
                            0,
                            0,
                            0);
        if (supported < 0)
                return (uint64_t) -errno;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        switch (regs->rsi) {
        case PR_FUTEX_HASH_GET_SLOTS:
                result = machine->futex_hash_slots;
                break;

        case PR_FUTEX_HASH_SET_SLOTS:
                slots = regs->rdx;
                if (regs->r10 != 0 || slots == 1 || (slots != 0 && !ISPOWEROF2(slots))) {
                        result = (uint64_t) -EINVAL;
                        break;
                }
                if (slots == 0 || h->vfork_completion) {
                        result = (uint64_t) -EOPNOTSUPP;
                        break;
                }

                result = raw_host_syscall(regs);
                if ((int64_t) result >= 0) {
                        machine->futex_hash_slots = slots;
                        machine->futex_hash_custom = true;
                }
                break;

        default:
                result = (uint64_t) -EINVAL;
        }
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return result;
}

void update_guest_futex_hash_after_thread_clone(ExecHypervisor *machine, unsigned n_threads) {
        long host_slots, online;
        uint64_t target;
        unsigned slots = 16;

        assert(machine);
        assert(n_threads > 0);

        host_slots = syscall(__NR_prctl,
                             PR_FUTEX_HASH,
                             PR_FUTEX_HASH_GET_SLOTS,
                             0,
                             0,
                             0);
        if (host_slots <= 0)
                return;
        online = sysconf(_SC_NPROCESSORS_ONLN);
        if (online <= 0)
                return;
        target = UINT64_C(4) * MIN((uint64_t) n_threads, (uint64_t) online);
        while (slots < target && slots <= UINT_MAX / 2)
                slots *= 2;
        if (slots < target)
                return;

        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        if (!machine->futex_hash_custom)
                machine->futex_hash_slots = MAX(machine->futex_hash_slots, slots);
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
}

static uint64_t handle_guest_membarrier(ExecHypervisor *h, const struct kvm_regs *regs) {
        ExecHypervisor *machine;
        uint32_t required_registration = 0;
        uint64_t result;

        assert(h);
        assert(regs);

        if (IN_SET(regs->rdi,
                   MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
                   MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ)) {
                if (regs->rdi == MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ) {
                        if (regs->rsi != 0 && regs->rsi != MEMBARRIER_CMD_FLAG_CPU)
                                return (uint64_t) -EINVAL;
                } else if (regs->rsi != 0)
                        return (uint64_t) -EINVAL;

                return (uint64_t) -EINVAL;
        }

        if (regs->rdi == MEMBARRIER_CMD_PRIVATE_EXPEDITED)
                required_registration = MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
        else if (regs->rdi == MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)
                required_registration = MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        if (regs->rdi == MEMBARRIER_CMD_GET_REGISTRATIONS) {
                result = raw_host_syscall(regs);
                if ((int64_t) result >= 0)
                        result = machine->membarrier_registrations;
                goto finish;
        }
        if (required_registration != 0 &&
            !FLAGS_SET(machine->membarrier_registrations, required_registration)) {
                result = regs->rsi == 0 ? (uint64_t) -EPERM : (uint64_t) -EINVAL;
                goto finish;
        }
        if (IN_SET(regs->rdi,
                   MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
                   MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
                   MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) &&
            h->vfork_completion) {
                result = (uint64_t) -EOPNOTSUPP;
                goto finish;
        }

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0)
                goto finish;
        if (regs->rdi == MEMBARRIER_CMD_QUERY)
                result &= ~(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ |
                            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ);
        else if (IN_SET(regs->rdi,
                        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
                        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
                        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE))
                machine->membarrier_registrations |= regs->rdi;

finish:
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return result;
}

static uint64_t handle_guest_prctl(ExecHypervisor *h, const struct kvm_regs *regs) {
        ExecHypervisor *machine;
        struct kvm_sregs sregs;
        size_t size;
        long auxv_size, supported;
        int r;

        assert(h);
        assert(regs);

        machine = exec_hypervisor_machine(h);

        if (regs->rdi == PR_GET_TID_ADDRESS) {
                r = copy_to_guest(h, regs->rsi, &h->clear_tid_address, sizeof(h->clear_tid_address));
                return r < 0 ? (uint64_t) r : 0;
        }

        if (regs->rdi == PR_GET_AUXV) {
                if (regs->r10 != 0 || regs->r8 != 0)
                        return (uint64_t) -EINVAL;

                auxv_size = syscall(__NR_prctl, PR_GET_AUXV, 0, 0, 0, 0);
                if (auxv_size < 0)
                        return (uint64_t) -errno;
                if ((uint64_t) auxv_size > sizeof(machine->saved_auxv))
                        return (uint64_t) -E2BIG;

                size = MIN(regs->rdx, (uint64_t) auxv_size);
                if (size > 0) {
                        r = copy_to_guest(h, regs->rsi, machine->saved_auxv, size);
                        if (r < 0)
                                return (uint64_t) r;
                }

                return auxv_size;
        }

        if (regs->rdi == PR_SET_SYSCALL_USER_DISPATCH) {
                switch (regs->rsi) {
                case PR_SYS_DISPATCH_OFF:
                        return regs->rdx == 0 && regs->r10 == 0 && regs->r8 == 0 ? 0 : (uint64_t) -EINVAL;

                case PR_SYS_DISPATCH_EXCLUSIVE_ON:
                        if (regs->rdx != 0 && regs->rdx + regs->r10 <= regs->rdx)
                                return (uint64_t) -EINVAL;
                        break;

                case PR_SYS_DISPATCH_INCLUSIVE_ON:
                        if (regs->r10 == 0 || regs->rdx + regs->r10 <= regs->rdx)
                                return (uint64_t) -EINVAL;
                        break;

                default:
                        return (uint64_t) -EINVAL;
                }

                if (regs->r8 >= UINT64_C(0x0000800000000000))
                        return (uint64_t) -EFAULT;
                return (uint64_t) -EOPNOTSUPP;
        }

        if (regs->rdi == PR_GET_TSC) {
                uint32_t mode;

                if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                        return (uint64_t) -errno;
                mode = FLAGS_SET(sregs.cr4, X86_CR4_TSD) ? PR_TSC_SIGSEGV : PR_TSC_ENABLE;
                r = copy_to_guest(h, regs->rsi, &mode, sizeof(mode));
                return r < 0 ? (uint64_t) r : 0;
        }

        if (regs->rdi == PR_SET_TSC) {
                if (!IN_SET(regs->rsi, PR_TSC_ENABLE, PR_TSC_SIGSEGV))
                        return (uint64_t) -EINVAL;
                if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                        return (uint64_t) -errno;
                SET_FLAG(sregs.cr4, X86_CR4_TSD, regs->rsi == PR_TSC_SIGSEGV);
                if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                        return (uint64_t) -errno;
                h->tsc_disabled = regs->rsi == PR_TSC_SIGSEGV;
                return 0;
        }

        if (regs->rdi == PR_SET_MM) {
                uint32_t map_size = sizeof(struct prctl_mm_map);

                if (regs->rsi == PR_SET_MM_MAP_SIZE) {
                        if (regs->r8 != 0)
                                return (uint64_t) -EINVAL;
                        r = copy_to_guest(h, regs->rdx, &map_size, sizeof(map_size));
                        return r < 0 ? (uint64_t) r : 0;
                }
                if (regs->rsi < PR_SET_MM_START_CODE || regs->rsi > PR_SET_MM_MAP_SIZE)
                        return (uint64_t) -EINVAL;
                return (uint64_t) -EOPNOTSUPP;
        }

        if (regs->rdi == PR_SET_MDWE) {
                if (regs->rdx != 0 || regs->r10 != 0 || regs->r8 != 0 ||
                    (regs->rsi & ~(PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT)) != 0 ||
                    (FLAGS_SET(regs->rsi, PR_MDWE_NO_INHERIT) &&
                     !FLAGS_SET(regs->rsi, PR_MDWE_REFUSE_EXEC_GAIN)))
                        return (uint64_t) -EINVAL;
                if (FLAGS_SET(regs->rsi, PR_MDWE_NO_INHERIT))
                        return (uint64_t) -EOPNOTSUPP;

                return raw_host_syscall(regs);
        }

        if (regs->rdi == PR_SET_NO_NEW_PRIVS) {
                uint64_t result = raw_host_syscall(regs);

                if ((int64_t) result >= 0)
                        h->no_new_privs = true;
                return result;
        }

        if (regs->rdi == PR_GET_NO_NEW_PRIVS)
                return regs->rsi == 0 && regs->rdx == 0 && regs->r10 == 0 && regs->r8 == 0 ?
                        h->no_new_privs : (uint64_t) -EINVAL;

        if (regs->rdi == PR_SET_IO_FLUSHER) {
                uint64_t result = raw_host_syscall(regs);

                if ((int64_t) result >= 0)
                        h->io_flusher = regs->rsi != 0;
                return result;
        }

        if (regs->rdi == PR_SET_SECCOMP) {
                if (regs->rsi == SECCOMP_MODE_STRICT)
                        return (uint64_t) -EOPNOTSUPP;

                uint64_t result = raw_host_syscall(regs);

                if (result == 0 && regs->rsi == SECCOMP_MODE_FILTER) {
                        r = commit_guest_seccomp_filter(
                                        h,
                                        /* synchronize= */ false,
                                        /* allow_speculation= */ false);

                        if (r < 0)
                                _exit(EXIT_FAILURE);
                }
                return result;
        }

        if (regs->rdi == PR_TIMER_CREATE_RESTORE_IDS) {
                long host_mode;
                uint64_t result;

                if (regs->rdx != 0 || regs->r10 != 0 || regs->r8 != 0)
                        return (uint64_t) -EINVAL;
                assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
                host_mode = syscall(__NR_prctl,
                                    PR_TIMER_CREATE_RESTORE_IDS,
                                    PR_TIMER_CREATE_RESTORE_IDS_GET,
                                    0,
                                    0,
                                    0);
                if (host_mode < 0)
                        result = (uint64_t) -errno;
                else if (host_mode != 0)
                        result = (uint64_t) -EPROTO;
                else
                        switch (regs->rsi) {
                        case PR_TIMER_CREATE_RESTORE_IDS_OFF:
                                machine->timer_restore_ids = false;
                                result = 0;
                                break;
                        case PR_TIMER_CREATE_RESTORE_IDS_ON:
                                machine->timer_restore_ids = true;
                                result = 0;
                                break;
                        case PR_TIMER_CREATE_RESTORE_IDS_GET:
                                result = machine->timer_restore_ids;
                                break;
                        default:
                                result = (uint64_t) -EINVAL;
                        }
                assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);

                return result;
        }

        if (regs->rdi == PR_FUTEX_HASH)
                return handle_guest_futex_hash(h, regs);

        if (IN_SET(regs->rdi, PR_GET_SPECULATION_CTRL, PR_SET_SPECULATION_CTRL)) {
                if (regs->rdi == PR_GET_SPECULATION_CTRL) {
                        if (regs->rdx != 0 || regs->r10 != 0 || regs->r8 != 0)
                                return (uint64_t) -EINVAL;
                } else {
                        if (regs->r10 != 0 || regs->r8 != 0)
                                return (uint64_t) -EINVAL;
                }
                if (!IN_SET(regs->rsi,
                            PR_SPEC_STORE_BYPASS,
                            PR_SPEC_INDIRECT_BRANCH,
                            PR_SPEC_L1D_FLUSH))
                        return (uint64_t) -ENODEV;
                if (regs->rdi == PR_SET_SPECULATION_CTRL) {
                        if (!IN_SET(regs->rdx,
                                    PR_SPEC_ENABLE,
                                    PR_SPEC_DISABLE,
                                    PR_SPEC_FORCE_DISABLE,
                                    PR_SPEC_DISABLE_NOEXEC))
                                return (uint64_t) -ERANGE;
                        if (regs->rsi == PR_SPEC_L1D_FLUSH &&
                            !IN_SET(regs->rdx, PR_SPEC_ENABLE, PR_SPEC_DISABLE))
                                return (uint64_t) -ERANGE;
                        if (regs->rsi == PR_SPEC_INDIRECT_BRANCH && regs->rdx == PR_SPEC_DISABLE_NOEXEC)
                                return (uint64_t) -ERANGE;
                }
                if (regs->rsi == PR_SPEC_STORE_BYPASS)
                        return handle_guest_store_bypass(h, regs);
                if (regs->rsi == PR_SPEC_INDIRECT_BRANCH)
                        return handle_guest_indirect_branch(h, regs);
                return handle_guest_l1d_flush(h, regs);
        }

        if (IN_SET(regs->rdi, PR_GET_CFI, PR_SET_CFI))
                return (uint64_t) -EINVAL;

        if (regs->rdi != PR_RSEQ_SLICE_EXTENSION)
                return raw_host_syscall(regs);

        supported = syscall(
                        __NR_prctl,
                        PR_RSEQ_SLICE_EXTENSION,
                        PR_RSEQ_SLICE_EXTENSION_GET,
                        0,
                        0,
                        0);
        if (supported < 0)
                return (uint64_t) -errno;
        if (supported != 0)
                return (uint64_t) -EPROTO;

        if (regs->rsi == PR_RSEQ_SLICE_EXTENSION_GET)
                return regs->rdx == 0 ? 0 : (uint64_t) -EINVAL;
        if (regs->rsi != PR_RSEQ_SLICE_EXTENSION_SET ||
            (regs->rdx & ~PR_RSEQ_SLICE_EXT_ENABLE) != 0)
                return (uint64_t) -EINVAL;
        if (h->rseq_address == 0)
                return (uint64_t) -ENXIO;

        return (uint64_t) -EOPNOTSUPP;
}

static uint64_t handle_guest_modify_ldt(ExecHypervisor *h, int operation, uint64_t address, uint64_t size) {
        struct user_desc entry;
        uint8_t default_ldt[128] = {};
        int r;

        assert(h);

        switch (operation) {
        case 0:
                return 0;

        case 1:
        case 0x11:
                if (size != sizeof(entry))
                        return (uint32_t) -EINVAL;
                r = copy_from_guest(h, &entry, address, sizeof(entry));
                if (r < 0)
                        return (uint32_t) r;
                if (entry.entry_number >= LDT_ENTRIES ||
                    (entry.contents == 3 && (operation == 1 || entry.seg_not_present == 0)))
                        return (uint32_t) -EINVAL;

                return (uint32_t) -EOPNOTSUPP;

        case 2:
                size = MIN(size, sizeof(default_ldt));
                if (size > 0) {
                        r = copy_to_guest(h, address, default_ldt, size);
                        if (r < 0)
                                return (uint32_t) r;
                }

                return size;

        default:
                return (uint32_t) -ENOSYS;
        }
}

static uint64_t handle_guest_ioperm(uint64_t first, uint64_t count, int enable) {
        if (count == 0 || first >= UINT16_MAX + UINT64_C(1) || count > UINT16_MAX + UINT64_C(1) - first)
                return (uint64_t) -EINVAL;

        return enable == 0 ? 0 : (uint64_t) -EOPNOTSUPP;
}

static uint64_t handle_guest_iopl(uint64_t level) {
        if (level > 3)
                return (uint64_t) -EINVAL;

        return level == 0 ? 0 : (uint64_t) -EOPNOTSUPP;
}

int abort_guest_rseq_for_signal(ExecHypervisor *h, struct kvm_regs *regs) {
        GuestRseqCs critical_section;
        GuestRseq rseq;
        uint64_t end;
        uint32_t signature;
        int r;

        assert(h);
        assert(regs);

        if (h->rseq_address == 0)
                return 0;

        r = copy_from_guest(h, &rseq, h->rseq_address, sizeof(rseq));
        if (r < 0)
                return r;
        if (rseq.rseq_cs == 0)
                return 0;
        if (rseq.rseq_cs > UINT64_C(0x00007fffffffffff))
                return -EFAULT;

        r = copy_from_guest(h, &critical_section, rseq.rseq_cs, sizeof(critical_section));
        if (r < 0)
                return r;
        if (!ADD_SAFE(&end, critical_section.start_ip, critical_section.post_commit_offset) ||
            end > UINT64_C(0x0000800000000000))
                return -EFAULT;

        rseq.rseq_cs = 0;
        r = copy_to_guest(h, h->rseq_address, &rseq, sizeof(rseq));
        if (r < 0)
                return r;

        if (regs->rip - critical_section.start_ip >= critical_section.post_commit_offset)
                return 0;
        if (critical_section.abort_ip < sizeof(signature) ||
            critical_section.abort_ip > UINT64_C(0x00007fffffffffff))
                return -EFAULT;

        r = copy_from_guest(
                        h,
                        &signature,
                        critical_section.abort_ip - sizeof(signature),
                        sizeof(signature));
        if (r < 0)
                return r;
        if (signature != h->rseq_signature)
                return -EFAULT;

        regs->rip = critical_section.abort_ip;
        return 0;
}


int exec_hypervisor_run(ExecHypervisor *h, int *ret_status) {
#if defined(__x86_64__)
        long io_flusher, no_new_privs;
        int r;

        assert(h);
        assert(ret_status);
        assert(exec_hypervisor_can_run(h));
        assert(h->vcpu_fd >= 0);
        assert(h->run);

        signal_hypervisor = h;
        h->runner_tid = gettid();
        if (!h->thread_vcpu)
                h->owner_tid = h->runner_tid;
        no_new_privs = syscall(__NR_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        if (no_new_privs < 0)
                return -errno;
        h->no_new_privs = no_new_privs > 0;
        io_flusher = syscall(__NR_prctl, PR_GET_IO_FLUSHER, 0, 0, 0, 0);
        if (io_flusher < 0) {
                if (errno != EPERM)
                        return -errno;
        } else
                h->io_flusher = io_flusher > 0;
        r = initialize_guest_speculation_policy(h);
        if (r < 0)
                return r;
        h->quiesce_seen_generation = __atomic_load_n(
                        &h->machine->quiesce_generation,
                        __ATOMIC_ACQUIRE);
        r = install_guest_exec_control_signal(h);
        if (r < 0)
                return r;
        h->image_fd = safe_close(h->image_fd);
        h->interpreter_fd = safe_close(h->interpreter_fd);

        for (;;) {
                struct kvm_regs regs;
                struct kvm_sregs sregs;
                uint32_t syscall_number;
                int run_error, run_result;

                if (__atomic_load_n(&h->machine->exec_request_state, __ATOMIC_ACQUIRE) ==
                    GUEST_EXEC_REQUEST_PENDING) {
                        if (h->thread_vcpu)
                                return -ECANCELED;

                        process_guest_exec_request(h);
                }

                r = deliver_pending_guest_signal(h);
                if (r < 0)
                        return r;

                r = wait_guest_quiescence(h);
                if (r < 0)
                        return r;
                r = issue_guest_indirect_branch_barrier(h);
                if (r < 0)
                        return r;
                __atomic_store_n(&h->vcpu_in_guest, true, __ATOMIC_RELEASE);
                if ((__atomic_load_n(&h->machine->quiesce_owner_tid, __ATOMIC_ACQUIRE) > 0 &&
                     h->machine->quiesce_owner_tid != h->runner_tid) ||
                    __atomic_load_n(&h->machine->quiesce_generation, __ATOMIC_ACQUIRE) !=
                            h->quiesce_seen_generation) {
                        __atomic_store_n(&h->vcpu_in_guest, false, __ATOMIC_RELEASE);
                        continue;
                }

                run_result = ioctl(h->vcpu_fd, KVM_RUN, 0);
                run_error = run_result < 0 ? errno : 0;
                __atomic_store_n(&h->vcpu_in_guest, false, __ATOMIC_RELEASE);
                r = wait_guest_quiescence(h);
                if (r < 0)
                        return r;

                if (run_result < 0) {
                        int error = run_error;

                        if (error == EINTR)
                                continue;
                        if (IN_SET(error, EFAULT, EHWPOISON) &&
                            h->run->exit_reason == KVM_EXIT_MEMORY_FAULT) {
                                r = handle_guest_memory_fault(h, error);
                                if (r < 0)
                                        return r;
                                continue;
                        }
                        if (error == EFAULT) {
                                r = begin_guest_quiescence(h);
                                if (r < 0)
                                        return r;
                                r = mark_inaccessible_file_pages(h);
                                end_guest_quiescence(h);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        continue;
                        }
                        return -error;
                }

                if (h->run->exit_reason != KVM_EXIT_IO ||
                    h->run->io.direction != KVM_EXIT_IO_OUT ||
                    h->run->io.size != sizeof(syscall_number) ||
                    h->run->io.count != 1)
                        return -EPROTO;

                memcpy(&syscall_number,
                       (uint8_t*) h->run + h->run->io.data_offset,
                       sizeof(syscall_number));

                if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                        return -errno;

                if (h->run->io.port == EXEC_HYPERVISOR_EXCEPTION_PORT) {
                        if (syscall_number >= EXEC_HYPERVISOR_N_EXCEPTIONS ||
                            (sregs.cs.selector & 3) != 0)
                                return -EPROTO;

                        h->last_exception_vector = syscall_number;
                        h->last_exception_cr2 = sregs.cr2;
                        r = handle_guest_exception(h, syscall_number, sregs.cr2);
                        if (r < 0)
                                return r;
                        continue;
                }

                if (h->run->io.port != 0x10)
                        return -EPROTO;
                if ((sregs.cs.selector & 3) != 0)
                        return -EPROTO;

                if (ioctl(h->vcpu_fd, KVM_GET_REGS, &regs) < 0)
                        return -errno;
                if ((uint32_t) regs.rax != syscall_number)
                        return -EPROTO;

                uint64_t filtered_result;
                bool filtered_kill;
                if (guest_syscall_filter_result(h, syscall_number, &filtered_result, &filtered_kill)) {
                        if (filtered_kill)
                                terminate_guest_for_seccomp();

                        regs.rax = filtered_result;
                        goto set_guest_registers;
                }

                switch (syscall_number) {
                case __NR_map_shadow_stack:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_map_shadow_stack(h, regs.rdi, regs.rsi, regs.rdx);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_shmat:
                        regs.rax = (uint64_t) -ENOSYS;
                        break;

                case __NR_io_setup:
                        regs.rax = handle_guest_io_setup(h, &regs);
                        break;

                case __NR_io_destroy:
                        regs.rax = handle_guest_io_destroy(h, &regs);
                        break;

                case __NR_pkey_alloc:
                case __NR_pkey_free:
                        regs.rax = (uint64_t) -EOPNOTSUPP;
                        break;

                case __NR_arch_prctl:
                        regs.rax = handle_guest_arch_prctl(h, regs.rdi, regs.rsi);
                        break;

                case __NR_ioperm:
                        regs.rax = handle_guest_ioperm(regs.rdi, regs.rsi, regs.rdx);
                        break;

                case __NR_iopl:
                        regs.rax = handle_guest_iopl(regs.rdi);
                        break;

                case __NR_modify_ldt:
                        regs.rax = handle_guest_modify_ldt(h, regs.rdi, regs.rsi, regs.rdx);
                        break;

                case __NR_prctl:
                        regs.rax = handle_guest_prctl(h, &regs);
                        break;

                case __NR_ioctl: {
                        bool quiesce_ioctl = guest_ioctl_requires_quiescence(regs.rsi);

                        if (quiesce_ioctl) {
                                r = begin_guest_quiescence(h);
                                if (r < 0)
                                        return r;
                        }
                        regs.rax = handle_guest_ioctl(h, &regs);
                        if (quiesce_ioctl)
                                end_guest_quiescence(h);
                        if ((int64_t) regs.rax == -EINTR &&
                            guest_syscall_should_restart(
                                            h,
                                            syscall_number,
                                            regs.rdi,
                                            regs.rsi,
                                            regs.rdx,
                                            regs.r10)) {
                                if (regs.rcx < 2)
                                        return -EPROTO;

                                regs.rax = syscall_number;
                                regs.rcx -= 2;
                        }
                        break;
                }

                case __NR_brk:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_brk(h, regs.rdi);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_mmap:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_mmap(h, &regs);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_mprotect:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_mprotect(
                                        h, regs.rdi, regs.rsi, regs.rdx, /* pkey= */ -1);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_pkey_mprotect:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_mprotect(
                                        h, regs.rdi, regs.rsi, regs.rdx, (int) regs.r10);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_munmap:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_munmap(h, regs.rdi, regs.rsi);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_mremap: {
                        uint64_t result;

                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        r = handle_guest_mremap(h, &regs, &result);
                        end_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = result;
                        break;
                }

                case __NR_remap_file_pages:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_remap_file_pages(h, &regs);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_madvise:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_madvise(h, &regs);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_process_madvise:
                        regs.rax = handle_guest_process_madvise(h, &regs);
                        break;

                case __NR_mseal:
                        r = begin_guest_memory_transaction(h);
                        if (r < 0)
                                return r;
                        regs.rax = handle_guest_mseal(h, &regs);
                        end_guest_memory_transaction(h);
                        break;

                case __NR_rt_sigaction:
                        regs.rax = handle_guest_rt_sigaction(h, regs.rdi, regs.rsi, regs.rdx, regs.r10);
                        break;

                case __NR_rt_sigreturn:
                        r = handle_guest_rt_sigreturn(h, &regs);
                        if (r < 0)
                                return r;
                        break;

                case __NR_sigaltstack:
                        regs.rax = handle_guest_sigaltstack(h, regs.rdi, regs.rsi, regs.rsp);
                        break;

                case __NR_vfork: {
                        uint64_t result;

                        r = handle_guest_vfork(h, &regs, false, SIGCHLD, false, 0, &result);
                        if (r < 0)
                                return r;
                        regs.rax = result;
                        break;
                }

                case __NR_fork: {
                        uint64_t result;

                        r = handle_guest_fork(h, &regs, &result);
                        if (r < 0)
                                return r;
                        regs.rax = result;
                        break;
                }

                case __NR_clone: {
                        uint64_t result;

                        r = handle_guest_clone(h, &regs, &result);
                        if (r < 0)
                                regs.rax = r;
                        else
                                regs.rax = result;
                        break;
                }

                case __NR_clone3: {
                        uint64_t result;

                        r = handle_guest_clone3(h, &regs, &result);
                        if (r < 0)
                                regs.rax = r;
                        else
                                regs.rax = result;
                        break;
                }

                case __NR_execve:
                        regs.rax = handle_guest_execve(h, &regs);
                        if (h->terminate_for_exec)
                                return -ECANCELED;
                        break;

                case __NR_execveat:
                        regs.rax = handle_guest_execveat(h, &regs);
                        if (h->terminate_for_exec)
                                return -ECANCELED;
                        break;

                case __NR_set_tid_address:
                        h->clear_tid_address = regs.rdi;
                        regs.rax = gettid();
                        break;

                case __NR_set_robust_list:
                        regs.rax = handle_guest_set_robust_list(h, regs.rdi, regs.rsi);
                        break;

                case __NR_io_uring_setup:
                case __NR_io_uring_enter:
                case __NR_io_uring_register:
                        regs.rax = handle_guest_io_uring(h, &regs);
                        break;

                case __NR_landlock_restrict_self:
                        regs.rax = handle_guest_landlock_restrict_self(h, &regs);
                        break;

                case __NR_seccomp:
                        regs.rax = handle_guest_seccomp(h, &regs);
                        break;

                case __NR_keyctl:
                        regs.rax = handle_guest_keyctl(h, &regs);
                        break;

                case __NR_setns:
                case __NR_unshare:
                        regs.rax = handle_guest_task_context(h, &regs);
                        break;

                case __NR_mlock:
                case __NR_mlock2:
                        regs.rax = handle_guest_mlock(h, &regs);
                        break;

                case __NR_mlockall:
                        regs.rax = handle_guest_mlockall(h, (int) regs.rdi);
                        break;

                case __NR_munlockall:
                        regs.rax = handle_guest_munlockall(h);
                        break;

                case __NR_timer_create:
                        regs.rax = handle_guest_timer_create(h, &regs);
                        break;

                case __NR_timer_delete:
                        regs.rax = handle_guest_timer_delete(h, (int) regs.rdi);
                        break;

                case __NR_rseq:
                        regs.rax = handle_guest_rseq(h, regs.rdi, regs.rsi, regs.rdx, regs.r10);
                        break;

                case __NR_rseq_slice_yield:
                        regs.rax = 0;
                        break;

                case __NR_getcpu:
                        regs.rax = handle_guest_getcpu(h, regs.rdi, regs.rsi);
                        break;

                case __NR_membarrier:
                        regs.rax = handle_guest_membarrier(h, &regs);
                        break;

                case __NR_pselect6:
                case __NR_ppoll:
                case __NR_epoll_pwait:
                case __NR_epoll_pwait2:
                        regs.rax = handle_guest_masked_wait(h, &regs);
                        break;

                case __NR_exit_group:
                        if (h->thread_vcpu ||
                            __atomic_load_n(&h->machine->n_guest_threads, __ATOMIC_ACQUIRE) > 0) {
                                (void) raw_host_syscall(&regs);
                                return -EIO;
                        }
                        _fallthrough_;

                case __NR_exit:
                        notify_vfork_parent(h);
                        if (!h->thread_vcpu) {
                                clear_guest_tid(h);
                                r = wait_for_guest_threads(h);
                                if (r < 0)
                                        return r;
                        }
                        *ret_status = regs.rdi & 0xff;
                        return 0;

                default:
                        if (syscall_requires_adaptation(syscall_number)) {
                                h->last_unsupported_syscall = syscall_number;
                                regs.rax = (uint64_t) -ENOSYS;
                        } else {
                                uint64_t result = raw_host_syscall(&regs);

                                                                if ((int64_t) result == -EINTR &&
                                                                        guest_syscall_should_restart(
                                                                                                        h,
                                                                                                        syscall_number,
                                                                                                            regs.rdi,
                                                                                                        regs.rsi,
                                                                                                                                                                                                                regs.rdx,
                                                                                                            regs.r10)) {
                                        if (regs.rcx < 2)
                                                return -EPROTO;

                                        regs.rax = syscall_number;
                                        regs.rcx -= 2;
                                } else
                                        regs.rax = result;
                        }
                        break;
                }

set_guest_registers:
                if (ioctl(h->vcpu_fd, KVM_SET_REGS, &regs) < 0)
                        return -errno;
        }
#else
        assert(h);
        assert(ret_status);

        return -EOPNOTSUPP;
#endif
}

#endif

