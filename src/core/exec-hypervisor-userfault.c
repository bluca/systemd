/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-hypervisor-internal.h"

#if defined(__x86_64__)

static int userfault_range_is_registered(
                const ExecHypervisorUserfaultRange *range,
                uint64_t start,
                uint64_t length);
static int reconcile_unregistered_userfault_ranges(
                ExecHypervisor *h,
                uint64_t fault_page,
                dev_t device,
                ino_t inode);

static uint64_t handle_guest_userfault_register(ExecHypervisor *h, const struct kvm_regs *regs) {
        _cleanup_free_ uint64_t *old_entries = NULL;
        struct uffdio_register registration;
        struct stat fd_stat;
        ExecHypervisor *machine;
        uint64_t end, result;
        size_t n_pages;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &registration, regs->rdx, sizeof(registration));
        if (r < 0)
                return (uint64_t) r;
        if (registration.mode == 0 ||
            (registration.mode & ~(UFFDIO_REGISTER_MODE_MISSING|
                                   UFFDIO_REGISTER_MODE_WP|
                                   UFFDIO_REGISTER_MODE_MINOR)) != 0)
                return (uint64_t) -EOPNOTSUPP;
        if (registration.range.start % page_size() != 0 ||
            registration.range.len == 0 || registration.range.len % page_size() != 0 ||
            !ADD_SAFE(&end, registration.range.start, registration.range.len) ||
            end > UINT64_C(0x0000800000000000))
                return (uint64_t) -EINVAL;
        if (fstat((int) regs->rdi, &fd_stat) < 0)
                return (uint64_t) -errno;

        n_pages = registration.range.len / page_size();
        old_entries = new(uint64_t, n_pages);
        if (!old_entries)
                return (uint64_t) -ENOMEM;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
restart_overlap_check:
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (registration.range.start < range_end && end > range->start) {
                        uint64_t overlap_page = MAX(registration.range.start, range->start);
                        dev_t device = range->device;
                        ino_t inode = range->inode;

                        r = userfault_range_is_registered(range, overlap_page, page_size());
                        if (r < 0)
                                goto finish;
                        if (r > 0) {
                                r = -EBUSY;
                                goto finish;
                        }
                        r = reconcile_unregistered_userfault_ranges(h, overlap_page, device, inode);
                        if (r < 0)
                                goto finish;
                        goto restart_overlap_check;
                }
        }
        for (size_t i = 0; i < n_pages; i++) {
                uint64_t page = registration.range.start + i * page_size();
                ExecHypervisorMapping *mapping = find_mapping(machine, page);
                uint64_t *entry = guest_page_entry(machine, page);

                if (!mapping || !mapping->mutable || mapping->protection == PROT_NONE ||
                    !entry || !FLAGS_SET(*entry, X86_PAGE_PRESENT)) {
                        r = -EFAULT;
                        goto finish;
                }
                old_entries[i] = *entry;
        }
        if (!GREEDY_REALLOC0(machine->userfault_ranges, machine->n_userfault_ranges + 1)) {
                r = -ENOMEM;
                goto finish;
        }

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0) {
                r = result;
                goto finish;
        }

        if ((registration.mode & (UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_MINOR)) != 0) {
                for (size_t i = 0; i < n_pages; i++)
                        *ASSERT_PTR(guest_page_entry(machine, registration.range.start + i * page_size())) &=
                                ~X86_PAGE_PRESENT;
                r = flush_all_guest_tlbs(machine);
                if (r < 0) {
                        for (size_t i = 0; i < n_pages; i++)
                                *ASSERT_PTR(guest_page_entry(machine, registration.range.start + i * page_size())) =
                                        old_entries[i];
                        (void) ioctl((int) regs->rdi, UFFDIO_UNREGISTER, &registration.range);
                        (void) flush_all_guest_tlbs(machine);
                        goto finish;
                }
        }

        machine->userfault_ranges[machine->n_userfault_ranges++] = (ExecHypervisorUserfaultRange) {
                .start = registration.range.start,
                .length = registration.range.len,
                .mode = registration.mode,
                .fd = regs->rdi,
                .device = fd_stat.st_dev,
                .inode = fd_stat.st_ino,
        };
        FOREACH_ARRAY(context, machine->userfault_contexts, machine->n_userfault_contexts)
                if (context->device == fd_stat.st_dev && context->inode == fd_stat.st_ino) {
                        machine->userfault_ranges[machine->n_userfault_ranges - 1].features_known = true;
                        machine->userfault_ranges[machine->n_userfault_ranges - 1].features = context->features;
                        break;
                }
        if (!machine->userfault_ranges[machine->n_userfault_ranges - 1].features_known) {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *line = NULL;
                char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
                size_t allocated = 0;

                xsprintf(path, "/proc/self/fdinfo/%i", (int) regs->rdi);
                f = fopen(path, "re");
                if (f)
                        while (getline(&line, &allocated, f) >= 0) {
                                unsigned features;
                                unsigned long long api, ioctls;

                                if (sscanf(line, "API:\t%llx:%x:%llx", &api, &features, &ioctls) != 3)
                                        continue;
                                if (api != UFFD_API)
                                        break;
                                machine->userfault_ranges[machine->n_userfault_ranges - 1].features_known = true;
                                machine->userfault_ranges[machine->n_userfault_ranges - 1].features = features;
                                break;
                        }
        }
        r = 0;

finish:
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return (uint64_t) r;
}

static uint64_t handle_guest_userfault_api(ExecHypervisor *h, const struct kvm_regs *regs) {
        struct uffdio_api api;
        struct stat fd_stat;
        ExecHypervisorUserfaultContext *context = NULL;
        ExecHypervisor *machine;
        uint64_t result;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &api, regs->rdx, sizeof(api));
        if (r < 0)
                return (uint64_t) r;
        if (fstat((int) regs->rdi, &fd_stat) < 0)
                return (uint64_t) -errno;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        FOREACH_ARRAY(candidate, machine->userfault_contexts, machine->n_userfault_contexts)
                if (candidate->device == fd_stat.st_dev && candidate->inode == fd_stat.st_ino) {
                        context = candidate;
                        break;
                }
        if (!context && !GREEDY_REALLOC0(machine->userfault_contexts, machine->n_userfault_contexts + 1)) {
                assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                return (uint64_t) -ENOMEM;
        }

        result = raw_host_syscall(regs);
        if ((int64_t) result >= 0) {
                for (size_t i = 0; i < machine->n_userfault_contexts;) {
                        ExecHypervisorUserfaultContext *candidate = machine->userfault_contexts + i;
                        bool retain = candidate->device == fd_stat.st_dev && candidate->inode == fd_stat.st_ino;

                        if (!retain)
                                FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges)
                                        if (range->device == candidate->device && range->inode == candidate->inode) {
                                                retain = true;
                                                break;
                                        }
                        if (retain) {
                                i++;
                                continue;
                        }

                        memmove(candidate,
                                candidate + 1,
                                (machine->n_userfault_contexts - i - 1) * sizeof(*candidate));
                        machine->n_userfault_contexts--;
                }
                context = NULL;
                FOREACH_ARRAY(candidate, machine->userfault_contexts, machine->n_userfault_contexts)
                        if (candidate->device == fd_stat.st_dev && candidate->inode == fd_stat.st_ino) {
                                context = candidate;
                                break;
                        }
                if (!context)
                        context = machine->userfault_contexts + machine->n_userfault_contexts++;
                *context = (ExecHypervisorUserfaultContext) {
                        .device = fd_stat.st_dev,
                        .inode = fd_stat.st_ino,
                        .features = api.features,
                };
        }
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return result;
}

static int find_containing_userfault_range(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                uint64_t required_mode,
                int fd,
                size_t *ret_index) {

        ExecHypervisor *machine;
        struct stat fd_stat;

        assert(h);
        assert(start < end);
        assert(ret_index);

        if (fd >= 0 && fstat(fd, &fd_stat) < 0)
                return -errno;

        machine = exec_hypervisor_machine(h);
        for (size_t i = 0; i < machine->n_userfault_ranges; i++) {
                ExecHypervisorUserfaultRange *range = machine->userfault_ranges + i;
                uint64_t range_end = range->start + range->length;

                                if (start >= range->start && end <= range_end &&
                                        (fd < 0 || (range->device == fd_stat.st_dev && range->inode == fd_stat.st_ino)) &&
                    FLAGS_SET(range->mode, required_mode)) {
                        *ret_index = i;
                        return 0;
                }
                                if (start < range_end && end > range->start) {
                                                if (fd >= 0 && (range->device != fd_stat.st_dev || range->inode != fd_stat.st_ino))
                                                                return -ENOENT;
                        return -EOPNOTSUPP;
                                }
        }

        return -ENOENT;
}

static int ensure_userfault_split_capacity(
                ExecHypervisor *h,
                size_t range_index,
                uint64_t start,
                uint64_t end,
                bool keep_middle) {

        ExecHypervisor *machine;
        ExecHypervisorUserfaultRange *range;
        uint64_t range_end;
        size_t n_pieces;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert(range_index < machine->n_userfault_ranges);
        range = machine->userfault_ranges + range_index;
        range_end = range->start + range->length;
        assert(start >= range->start && end <= range_end && start < end);

        n_pieces = (start > range->start) + keep_middle + (end < range_end);
        if (n_pieces <= 1)
                return 0;
        if (!GREEDY_REALLOC0(
                            machine->userfault_ranges,
                            machine->n_userfault_ranges + n_pieces - 1))
                return -ENOMEM;
        return 0;
}

void coalesce_userfault_ranges(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        for (size_t i = 0; i + 1 < machine->n_userfault_ranges;) {
                ExecHypervisorUserfaultRange *first = machine->userfault_ranges + i;
                ExecHypervisorUserfaultRange *second = first + 1;

                if (first->start + first->length != second->start || first->mode != second->mode ||
                    first->device != second->device || first->inode != second->inode ||
                    first->write_protected != second->write_protected ||
                    first->features_known != second->features_known || first->features != second->features) {
                        i++;
                        continue;
                }

                first->length += second->length;
                memmove(second,
                        second + 1,
                        (machine->n_userfault_ranges - i - 2) * sizeof(*second));
                machine->n_userfault_ranges--;
        }
}

void commit_userfault_range_split(
                ExecHypervisor *h,
                size_t range_index,
                uint64_t start,
                uint64_t end,
                bool keep_middle,
                bool middle_write_protected,
                int middle_fd) {

        ExecHypervisorUserfaultRange pieces[3];
        ExecHypervisorUserfaultRange old;
        ExecHypervisor *machine;
        uint64_t old_end;
        size_t n_pieces = 0, old_count;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert(range_index < machine->n_userfault_ranges);
        old = machine->userfault_ranges[range_index];
        old_end = old.start + old.length;
        assert(start >= old.start && end <= old_end && start < end);

        if (start > old.start) {
                pieces[n_pieces] = old;
                pieces[n_pieces++].length = start - old.start;
        }
        if (keep_middle) {
                pieces[n_pieces] = old;
                pieces[n_pieces].start = start;
                pieces[n_pieces].length = end - start;
                pieces[n_pieces].write_protected = middle_write_protected;
                pieces[n_pieces++].fd = middle_fd;
        }
        if (end < old_end) {
                pieces[n_pieces] = old;
                pieces[n_pieces].start = end;
                pieces[n_pieces++].length = old_end - end;
        }

        old_count = machine->n_userfault_ranges;
        if (n_pieces > 1)
                memmove(machine->userfault_ranges + range_index + n_pieces,
                        machine->userfault_ranges + range_index + 1,
                        (old_count - range_index - 1) * sizeof(machine->userfault_ranges[0]));
        else if (n_pieces == 0)
                memmove(machine->userfault_ranges + range_index,
                        machine->userfault_ranges + range_index + 1,
                        (old_count - range_index - 1) * sizeof(machine->userfault_ranges[0]));
        if (n_pieces > 0)
                memcpy(machine->userfault_ranges + range_index, pieces, n_pieces * sizeof(pieces[0]));
        machine->n_userfault_ranges = old_count - 1 + n_pieces;
        coalesce_userfault_ranges(h);
}

static uint64_t handle_guest_userfault_unregister(ExecHypervisor *h, const struct kvm_regs *regs) {
        _cleanup_free_ ExecHypervisorUserfaultRange *new_ranges = NULL;
        struct uffdio_range requested;
        struct stat fd_stat;
        ExecHypervisor *machine;
        size_t n_new_ranges = 0;
        uint64_t end, result;
        bool tracked = false;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &requested, regs->rdx, sizeof(requested));
        if (r < 0)
                return (uint64_t) r;
        if (requested.start % page_size() != 0 || requested.len == 0 ||
            requested.len % page_size() != 0 || !ADD_SAFE(&end, requested.start, requested.len))
                return (uint64_t) -EINVAL;
        if (fstat((int) regs->rdi, &fd_stat) < 0)
                return (uint64_t) -errno;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (requested.start >= range_end || end <= range->start)
                        continue;
                if (range->device != fd_stat.st_dev || range->inode != fd_stat.st_ino) {
                        result = raw_host_syscall(regs);
                        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                        return result;
                }
                tracked = true;
        }
        if (tracked) {
                r = prepare_userfault_ranges_after_unmap(
                                h,
                                requested.start,
                                end,
                                &new_ranges,
                                &n_new_ranges);
                if (r < 0) {
                        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                        return (uint64_t) r;
                }
        }

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0 || !tracked) {
                assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                return result;
        }

        for (uint64_t page = requested.start; page < end; page += page_size()) {
                ExecHypervisorUserfaultRange *range = NULL;
                uint64_t *entry = guest_page_entry(machine, page);
                ExecHypervisorMapping *mapping = find_mapping(machine, page);

                FOREACH_ARRAY(candidate, machine->userfault_ranges, machine->n_userfault_ranges)
                        if (page >= candidate->start && page < candidate->start + candidate->length) {
                                range = candidate;
                                break;
                        }
                if (!range)
                        continue;
                if (!entry || FLAGS_SET(*entry, X86_PAGE_SOFTWARE_PROT_NONE))
                        continue;
                if ((range->mode & (UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_MINOR)) != 0 &&
                    !FLAGS_SET(*entry, X86_PAGE_SOFTWARE_UFFD_POISON))
                        *entry |= X86_PAGE_PRESENT;
                if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) &&
                    mapping && FLAGS_SET(mapping->protection, PROT_WRITE))
                        *entry |= X86_PAGE_WRITE;
        }
        free(machine->userfault_ranges);
        machine->userfault_ranges = TAKE_PTR(new_ranges);
        machine->n_userfault_ranges = n_new_ranges;
        r = flush_all_guest_tlbs(machine);
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return r < 0 ? (uint64_t) r : result;
}

static uint64_t handle_guest_userfault_writeprotect(ExecHypervisor *h, const struct kvm_regs *regs) {
        _cleanup_free_ uint64_t *old_entries = NULL;
        struct uffdio_writeprotect request, rollback;
        ExecHypervisorUserfaultRange *range = NULL;
        ExecHypervisor *machine;
        uint64_t end, result;
        size_t n_pages;
        bool enable, old_write_protected;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &request, regs->rdx, sizeof(request));
        if (r < 0)
                return (uint64_t) r;
        if ((request.mode & ~(UFFDIO_WRITEPROTECT_MODE_WP|UFFDIO_WRITEPROTECT_MODE_DONTWAKE)) != 0 ||
            request.range.start % page_size() != 0 || request.range.len == 0 ||
            request.range.len % page_size() != 0 ||
            !ADD_SAFE(&end, request.range.start, request.range.len))
                return (uint64_t) -EINVAL;

        enable = FLAGS_SET(request.mode, UFFDIO_WRITEPROTECT_MODE_WP);
        n_pages = request.range.len / page_size();
        old_entries = new(uint64_t, n_pages);
        if (!old_entries)
                return (uint64_t) -ENOMEM;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        size_t range_index;
        r = find_containing_userfault_range(
                        h,
                        request.range.start,
                        end,
                        UFFDIO_REGISTER_MODE_WP,
                        regs->rdi,
                        &range_index);
        if (r == -ENOENT) {
                r = raw_host_syscall(regs);
                goto finish;
        }
        if (r < 0)
                goto finish;
        r = ensure_userfault_split_capacity(
                        h,
                        range_index,
                        request.range.start,
                        end,
                        /* keep_middle= */ true);
        if (r < 0)
                goto finish;
        range = machine->userfault_ranges + range_index;
        old_write_protected = range->write_protected;

        for (size_t i = 0; i < n_pages; i++) {
                uint64_t page = request.range.start + i * page_size();
                ExecHypervisorMapping *mapping = find_mapping(machine, page);
                uint64_t *entry = guest_page_entry(machine, page);

                                if (!mapping || !FLAGS_SET(mapping->protection, PROT_WRITE) || !entry ||
                                        FLAGS_SET(*entry, X86_PAGE_SOFTWARE_PROT_NONE) ||
                                        (!FLAGS_SET(*entry, X86_PAGE_PRESENT) &&
                                         (range->mode & (UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_MINOR)) == 0)) {
                        r = -EFAULT;
                        goto finish;
                }
                old_entries[i] = *entry;
        }

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0) {
                r = result;
                goto finish;
        }

        for (size_t i = 0; i < n_pages; i++) {
                uint64_t *entry = ASSERT_PTR(guest_page_entry(
                                machine,
                                request.range.start + i * page_size()));

                if (enable)
                        *entry &= ~X86_PAGE_WRITE;
                else
                        *entry |= X86_PAGE_WRITE;
        }
        r = flush_all_guest_tlbs(machine);
        if (r >= 0) {
                commit_userfault_range_split(
                                h,
                                range_index,
                                request.range.start,
                                end,
                                /* keep_middle= */ true,
                                enable,
                                regs->rdi);
                goto finish;
        }

        for (size_t i = 0; i < n_pages; i++)
                *ASSERT_PTR(guest_page_entry(machine, request.range.start + i * page_size())) = old_entries[i];
        range = machine->userfault_ranges + range_index;
        range->write_protected = old_write_protected;
        rollback = request;
        rollback.mode = enable ? 0 : UFFDIO_WRITEPROTECT_MODE_WP;
        if (ioctl((int) regs->rdi, UFFDIO_WRITEPROTECT, &rollback) < 0)
                r = -EIO;
        (void) flush_all_guest_tlbs(machine);

finish:
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return (uint64_t) r;
}

static uint64_t handle_guest_userfault_copy(ExecHypervisor *h, const struct kvm_regs *regs) {
        struct uffdio_copy copy;
        ExecHypervisor *machine;
        uint64_t end, result;
        size_t range_index;
        bool write_protected;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &copy, regs->rdx, sizeof(copy));
        if (r < 0)
                return (uint64_t) r;
        if (copy.len == 0 || copy.dst % page_size() != 0 || copy.len % page_size() != 0 ||
            !ADD_SAFE(&end, copy.dst, copy.len))
                return (uint64_t) -EINVAL;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        r = find_containing_userfault_range(
                        h,
                        copy.dst,
                        end,
                        UFFDIO_REGISTER_MODE_MISSING,
                        regs->rdi,
                        &range_index);
        if (r == -ENOENT) {
                r = raw_host_syscall(regs);
                goto finish;
        }
        if (r < 0)
                goto finish;
        r = ensure_userfault_split_capacity(
                        h,
                        range_index,
                        copy.dst,
                        end,
                        /* keep_middle= */ true);
        if (r < 0)
                goto finish;

        for (uint64_t page = copy.dst; page < end; page += page_size()) {
                ExecHypervisorMapping *mapping = find_mapping(machine, page);
                uint64_t *entry = guest_page_entry(machine, page);

                if (!mapping || !entry) {
                        r = -EFAULT;
                        goto finish;
                }
        }

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0) {
                r = result;
                goto finish;
        }

        write_protected = FLAGS_SET(copy.mode, UFFDIO_COPY_MODE_WP);
        for (uint64_t page = copy.dst; page < end; page += page_size()) {
                ExecHypervisorMapping *mapping = find_mapping(machine, page);
                uint64_t *entry = ASSERT_PTR(guest_page_entry(machine, page));

                assert(mapping);
                *entry |= X86_PAGE_PRESENT;
                if (write_protected)
                        *entry &= ~X86_PAGE_WRITE;
                else if (FLAGS_SET(mapping->protection, PROT_WRITE))
                        *entry |= X86_PAGE_WRITE;
        }
        r = flush_all_guest_tlbs(machine);
        if (r < 0)
                _exit(EXIT_FAILURE);
        commit_userfault_range_split(
                        h,
                        range_index,
                        copy.dst,
                        end,
                        /* keep_middle= */ true,
                        write_protected,
                        regs->rdi);

finish:
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return (uint64_t) r;
}

static uint64_t handle_guest_userfault_zeropage(ExecHypervisor *h, const struct kvm_regs *regs) {
        struct uffdio_zeropage zero;
        ExecHypervisor *machine;
        uint64_t end, result;
        size_t range_index;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &zero, regs->rdx, sizeof(zero));
        if (r < 0)
                return (uint64_t) r;
        if ((zero.mode & ~UFFDIO_ZEROPAGE_MODE_DONTWAKE) != 0 ||
            zero.range.start % page_size() != 0 || zero.range.len == 0 ||
            zero.range.len % page_size() != 0 ||
            !ADD_SAFE(&end, zero.range.start, zero.range.len))
                return (uint64_t) -EINVAL;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        r = find_containing_userfault_range(
                        h,
                        zero.range.start,
                        end,
                        UFFDIO_REGISTER_MODE_MISSING,
                        regs->rdi,
                        &range_index);
        if (r == -ENOENT) {
                r = raw_host_syscall(regs);
                goto finish;
        }
        if (r < 0)
                goto finish;
        r = ensure_userfault_split_capacity(
                        h,
                        range_index,
                        zero.range.start,
                        end,
                        /* keep_middle= */ true);
        if (r < 0)
                goto finish;

        for (uint64_t page = zero.range.start; page < end; page += page_size())
                if (!find_mapping(machine, page) || !guest_page_entry(machine, page)) {
                        r = -EFAULT;
                        goto finish;
                }

        result = raw_host_syscall(regs);
        if ((int64_t) result < 0) {
                r = result;
                goto finish;
        }

        for (uint64_t page = zero.range.start; page < end; page += page_size()) {
                ExecHypervisorMapping *mapping = ASSERT_PTR(find_mapping(machine, page));
                uint64_t *entry = ASSERT_PTR(guest_page_entry(machine, page));

                *entry |= X86_PAGE_PRESENT;
                if (FLAGS_SET(mapping->protection, PROT_WRITE))
                        *entry |= X86_PAGE_WRITE;
        }
        r = flush_all_guest_tlbs(machine);
        if (r < 0)
                _exit(EXIT_FAILURE);
        commit_userfault_range_split(
                        h,
                        range_index,
                        zero.range.start,
                        end,
                        /* keep_middle= */ true,
                        /* middle_write_protected= */ false,
                        regs->rdi);

finish:
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return (uint64_t) r;
}

static uint64_t handle_guest_userfault_continue(ExecHypervisor *h, const struct kvm_regs *regs) {
        struct uffdio_continue completed, request;
        ExecHypervisor *machine;
        uint64_t completed_end, end, result;
        size_t range_index;
        bool write_protected;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &request, regs->rdx, sizeof(request));
        if (r < 0)
                return (uint64_t) r;
        if ((request.mode & ~(UFFDIO_CONTINUE_MODE_DONTWAKE|UFFDIO_CONTINUE_MODE_WP)) != 0 ||
            request.range.start % page_size() != 0 || request.range.len == 0 ||
            request.range.len % page_size() != 0 ||
            !ADD_SAFE(&end, request.range.start, request.range.len))
                return (uint64_t) -EINVAL;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        r = find_containing_userfault_range(
                        h,
                        request.range.start,
                        end,
                        UFFDIO_REGISTER_MODE_MINOR,
                        regs->rdi,
                        &range_index);
        if (r == -ENOENT) {
                r = raw_host_syscall(regs);
                goto finish;
        }
        if (r < 0)
                goto finish;
        r = ensure_userfault_split_capacity(
                        h,
                        range_index,
                        request.range.start,
                        end,
                        /* keep_middle= */ true);
        if (r < 0)
                goto finish;

        for (uint64_t page = request.range.start; page < end; page += page_size())
                if (!find_mapping(machine, page) || !guest_page_entry(machine, page)) {
                        r = -EFAULT;
                        goto finish;
                }

        result = raw_host_syscall(regs);
        memcpy(&completed, (void*) (uintptr_t) regs->rdx, sizeof(completed));
        if (completed.mapped <= 0) {
                r = result;
                goto finish;
        }
        if ((uint64_t) completed.mapped > request.range.len || completed.mapped % page_size() != 0) {
                r = -EPROTO;
                goto finish;
        }

        completed_end = request.range.start + completed.mapped;
        write_protected = FLAGS_SET(request.mode, UFFDIO_CONTINUE_MODE_WP);
        for (uint64_t page = request.range.start; page < completed_end; page += page_size()) {
                ExecHypervisorMapping *mapping = ASSERT_PTR(find_mapping(machine, page));
                uint64_t *entry = ASSERT_PTR(guest_page_entry(machine, page));

                *entry |= X86_PAGE_PRESENT;
                if (write_protected)
                        *entry &= ~X86_PAGE_WRITE;
                else if (FLAGS_SET(mapping->protection, PROT_WRITE))
                        *entry |= X86_PAGE_WRITE;
        }
        r = flush_all_guest_tlbs(machine);
        if (r < 0)
                _exit(EXIT_FAILURE);
        commit_userfault_range_split(
                        h,
                        range_index,
                        request.range.start,
                        completed_end,
                        /* keep_middle= */ true,
                        write_protected,
                        regs->rdi);
        r = result;

finish:
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return (uint64_t) r;
}

static uint64_t handle_guest_userfault_poison(ExecHypervisor *h, const struct kvm_regs *regs) {
        struct uffdio_poison poison;
        struct kvm_regs zeropage_regs;
        ExecHypervisor *machine;
        uint64_t end, result;
        size_t range_index;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &poison, regs->rdx, sizeof(poison));
        if (r < 0)
                return (uint64_t) r;
        if ((poison.mode & ~UFFDIO_POISON_MODE_DONTWAKE) != 0 ||
            poison.range.start % page_size() != 0 || poison.range.len == 0 ||
            poison.range.len % page_size() != 0 ||
            !ADD_SAFE(&end, poison.range.start, poison.range.len))
                return (uint64_t) -EINVAL;

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        r = find_containing_userfault_range(
                        h,
                        poison.range.start,
                        end,
                        UFFDIO_REGISTER_MODE_MISSING,
                        regs->rdi,
                        &range_index);
        if (r == -ENOENT) {
                r = raw_host_syscall(regs);
                goto finish;
        }
        if (r < 0)
                goto finish;
        r = ensure_userfault_split_capacity(
                        h,
                        range_index,
                        poison.range.start,
                        end,
                        /* keep_middle= */ true);
        if (r < 0)
                goto finish;

        for (uint64_t page = poison.range.start; page < end; page += page_size()) {
                ExecHypervisorMapping *mapping = find_mapping(machine, page);

                if (!mapping || mapping->file_backed || mapping->shared || !guest_page_entry(machine, page)) {
                        r = -EFAULT;
                        goto finish;
                }
        }

        assert_cc(sizeof(struct uffdio_poison) == sizeof(struct uffdio_zeropage));
        zeropage_regs = *regs;
        zeropage_regs.rsi = UFFDIO_ZEROPAGE;
        result = raw_host_syscall(&zeropage_regs);
        if ((int64_t) result < 0) {
                r = result;
                goto finish;
        }

        for (uint64_t page = poison.range.start; page < end; page += page_size()) {
                uint64_t *entry = ASSERT_PTR(guest_page_entry(machine, page));

                *entry = (*entry & ~X86_PAGE_PRESENT) | X86_PAGE_SOFTWARE_UFFD_POISON;
        }
        r = flush_all_guest_tlbs(machine);
        if (r < 0)
                _exit(EXIT_FAILURE);
        commit_userfault_range_split(
                        h,
                        range_index,
                        poison.range.start,
                        end,
                        /* keep_middle= */ true,
                        /* middle_write_protected= */ false,
                        regs->rdi);

finish:
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return (uint64_t) r;
}

static uint64_t handle_guest_userfault_move(ExecHypervisor *h, const struct kvm_regs *regs) {
        struct uffdio_move move, completed;
        struct stat fd_stat;
        ExecHypervisor *machine;
        uint64_t dst_end, moved_end, result, src_end;
        size_t range_index, source_split_additional = 0;
        bool allow_source_holes, destination_unpopulated_wp;
        int r;

        assert(h);
        assert(regs);

        r = copy_from_guest(h, &move, regs->rdx, sizeof(move));
        if (r < 0)
                return (uint64_t) r;
        if ((move.mode & ~(UFFDIO_MOVE_MODE_DONTWAKE|UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES)) != 0 ||
            move.len == 0 ||
            move.dst % page_size() != 0 || move.src % page_size() != 0 ||
            move.len % page_size() != 0 ||
            !ADD_SAFE(&dst_end, move.dst, move.len) || !ADD_SAFE(&src_end, move.src, move.len))
                return (uint64_t) -EINVAL;
        if (fstat((int) regs->rdi, &fd_stat) < 0)
                return (uint64_t) -errno;
        allow_source_holes = FLAGS_SET(move.mode, UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        r = find_containing_userfault_range(
                        h,
                        move.dst,
                        dst_end,
                        UFFDIO_REGISTER_MODE_MISSING,
                        regs->rdi,
                        &range_index);
        if (r == -ENOENT) {
                r = raw_host_syscall(regs);
                goto finish;
        }
        if (r < 0)
                goto finish;
        destination_unpopulated_wp = machine->userfault_ranges[range_index].write_protected;
        r = ensure_userfault_split_capacity(
                        h,
                        range_index,
                        move.dst,
                        dst_end,
                        /* keep_middle= */ true);
        if (r < 0)
                goto finish;

        for (uint64_t offset = 0; offset < move.len; offset += page_size()) {
                ExecHypervisorMapping *destination = find_mapping(machine, move.dst + offset);
                ExecHypervisorMapping *source = find_mapping(machine, move.src + offset);
                uint64_t *destination_entry = guest_page_entry(machine, move.dst + offset);
                uint64_t *source_entry = guest_page_entry(machine, move.src + offset);
                ExecHypervisorUserfaultRange *source_range = NULL;

                FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                        if (move.src + offset < range->start ||
                            move.src + offset >= range->start + range->length)
                                continue;

                        source_range = range;
                        break;
                }

                if (!destination || !source || !destination_entry || !source_entry ||
                    FLAGS_SET(*source_entry, X86_PAGE_SOFTWARE_UFFD_POISON) ||
                    (!source_range && !FLAGS_SET(*source_entry, X86_PAGE_PRESENT))) {
                        r = -EOPNOTSUPP;
                        goto finish;
                }
                if (destination->file_backed || destination->shared || source->file_backed ||
                    source->shared || destination->protection != source->protection ||
                    FLAGS_SET(*source_entry, X86_PAGE_SOFTWARE_PROT_NONE) ||
                    (source_range &&
                     (source_range->mode & ~(UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_WP)) != 0)) {
                        r = raw_host_syscall(regs);
                        goto finish;
                }
                if (FLAGS_SET(*destination_entry, X86_PAGE_PRESENT))
                        destination_unpopulated_wp = false;
                if (source_range && source_range->write_protected &&
                    !ADD_SAFE(&source_split_additional, source_split_additional, (size_t) 2)) {
                        r = -ENOMEM;
                        goto finish;
                }
        }
        if (source_split_additional > 0) {
                size_t n_ranges;

                if (!ADD_SAFE(&n_ranges, machine->n_userfault_ranges, source_split_additional) ||
                    !ADD_SAFE(&n_ranges, n_ranges, (size_t) 2) ||
                    !GREEDY_REALLOC0(machine->userfault_ranges, n_ranges)) {
                        r = -ENOMEM;
                        goto finish;
                }
        }

        result = raw_host_syscall(regs);
        memcpy(&completed, (void*) (uintptr_t) regs->rdx, sizeof(completed));
        if (completed.move <= 0) {
                if ((int64_t) result == -EEXIST && destination_unpopulated_wp) {
                        for (uint64_t page = move.dst; page < dst_end; page += page_size())
                                *ASSERT_PTR(guest_page_entry(machine, page)) |= X86_PAGE_WRITE;
                        commit_userfault_range_split(
                                        h,
                                        range_index,
                                        move.dst,
                                        dst_end,
                                        /* keep_middle= */ true,
                                        /* middle_write_protected= */ false,
                                        regs->rdi);
                        if (flush_all_guest_tlbs(machine) < 0)
                                _exit(EXIT_FAILURE);
                }
                r = result;
                goto finish;
        }
        if ((uint64_t) completed.move > move.len || completed.move % page_size() != 0) {
                r = -EPROTO;
                goto finish;
        }

        moved_end = move.dst + completed.move;
        for (uint64_t offset = 0; offset < (uint64_t) completed.move; offset += page_size()) {
                uint64_t destination_page = move.dst + offset;
                uint64_t source_page = move.src + offset;
                ExecHypervisorMapping *mapping = ASSERT_PTR(find_mapping(machine, destination_page));
                uint64_t *entry = ASSERT_PTR(guest_page_entry(machine, destination_page));

                if (allow_source_holes)
                        *entry &= ~X86_PAGE_PRESENT;
                else {
                        *entry |= X86_PAGE_PRESENT;
                        if (FLAGS_SET(mapping->protection, PROT_WRITE))
                                *entry |= X86_PAGE_WRITE;
                }

                FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges)
                        if (source_page >= range->start && source_page < range->start + range->length) {
                                uint64_t *source_entry = ASSERT_PTR(guest_page_entry(machine, source_page));

                                if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_MISSING))
                                        *source_entry &= ~X86_PAGE_PRESENT;
                                else if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) &&
                                         range->write_protected)
                                        *source_entry |= X86_PAGE_WRITE;
                                break;
                        }
        }
        r = flush_all_guest_tlbs(machine);
        if (r < 0)
                _exit(EXIT_FAILURE);
        commit_userfault_range_split(
                        h,
                        range_index,
                        move.dst,
                        moved_end,
                        /* keep_middle= */ true,
                        /* middle_write_protected= */ false,
                        regs->rdi);
        if (source_split_additional > 0)
                for (uint64_t offset = 0; offset < (uint64_t) completed.move; offset += page_size()) {
                        uint64_t source_page = move.src + offset;

                        for (size_t i = 0; i < machine->n_userfault_ranges; i++) {
                                ExecHypervisorUserfaultRange *range = machine->userfault_ranges + i;
                                bool contains_source;

                                contains_source = source_page >= range->start &&
                                        source_page < range->start + range->length;
                                if (!contains_source || !FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP))
                                        continue;
                                if (range->write_protected)
                                        commit_userfault_range_split(
                                                        h,
                                                        i,
                                                        source_page,
                                                        source_page + page_size(),
                                                        /* keep_middle= */ true,
                                                        /* middle_write_protected= */ false,
                                                        range->fd);
                                break;
                        }
                }
        r = result;

finish:
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return (uint64_t) r;
}

uint64_t handle_guest_ioctl(ExecHypervisor *h, const struct kvm_regs *regs) {
        assert(h);
        assert(regs);

        if (regs->rsi == UFFDIO_API)
                return handle_guest_userfault_api(h, regs);
        if (regs->rsi == UFFDIO_REGISTER)
                return handle_guest_userfault_register(h, regs);
        if (regs->rsi == UFFDIO_UNREGISTER)
                return handle_guest_userfault_unregister(h, regs);
        if (regs->rsi == UFFDIO_WRITEPROTECT)
                return handle_guest_userfault_writeprotect(h, regs);
        if (regs->rsi == UFFDIO_COPY)
                return handle_guest_userfault_copy(h, regs);
        if (regs->rsi == UFFDIO_ZEROPAGE)
                return handle_guest_userfault_zeropage(h, regs);
        if (regs->rsi == UFFDIO_CONTINUE)
                return handle_guest_userfault_continue(h, regs);
        if (regs->rsi == UFFDIO_POISON)
                return handle_guest_userfault_poison(h, regs);
        if (regs->rsi == UFFDIO_MOVE)
                return handle_guest_userfault_move(h, regs);

        return raw_host_syscall(regs);
}

uint64_t handle_guest_process_madvise(ExecHypervisor *h, const struct kvm_regs *regs) {
        _cleanup_free_ struct iovec *iov = NULL;
        struct iovec probe_iov = {};
        size_t iov_size, total = 0;
        uint64_t result;
        pid_t target;
        long q;
        int r;

        assert(h);
        assert(regs);

        r = pidfd_get_pid((int) regs->rdi, &target);
        if (r < 0 || target != getpid())
                return raw_host_syscall(regs);
        if (regs->r8 != 0 || regs->rdx > IOV_MAX)
                return (uint64_t) -EINVAL;
        if (regs->rdx == 0)
                return 0;
        if (!MUL_SAFE(&iov_size, regs->rdx, sizeof(*iov)))
                return (uint64_t) -EINVAL;

        iov = malloc(iov_size);
        if (!iov)
                return (uint64_t) -ENOMEM;
        r = copy_from_guest(h, iov, regs->rsi, iov_size);
        if (r < 0)
                return (uint64_t) r;
        FOREACH_ARRAY(element, iov, regs->rdx)
                if (!ADD_SAFE(&total, total, element->iov_len) || total > SSIZE_MAX)
                        return (uint64_t) -EINVAL;

        q = syscall(__NR_process_madvise, (int) regs->rdi, &probe_iov, 1, (int) regs->r10, 0);
        if (q < 0)
                return (uint64_t) -errno;
        if (q != 0)
                return (uint64_t) -EPROTO;

        r = begin_guest_memory_transaction(h);
        if (r < 0)
                return (uint64_t) r;
        total = 0;
        FOREACH_ARRAY(element, iov, regs->rdx) {
                struct kvm_regs advice_regs = {
                        .rax = __NR_madvise,
                        .rdi = (uintptr_t) element->iov_base,
                        .rsi = element->iov_len,
                        .rdx = regs->r10,
                };
                uint64_t qresult = handle_guest_madvise(h, &advice_regs);

                if ((int64_t) qresult < 0) {
                        result = total > 0 ? total : qresult;
                        goto finish;
                }
                total += element->iov_len;
        }
        result = total;

finish:
        end_guest_memory_transaction(h);
        return result;
}

bool guest_ioctl_requires_quiescence(uint64_t request) {
        return IN_SET(
                        request,
                        UFFDIO_REGISTER,
                        UFFDIO_UNREGISTER,
                        UFFDIO_WRITEPROTECT,
                        UFFDIO_COPY,
                        UFFDIO_ZEROPAGE,
                        UFFDIO_CONTINUE,
                        UFFDIO_POISON,
                        UFFDIO_MOVE);
}

int guest_userfault_delivers_sigbus(ExecHypervisor *h, uint64_t address, uint64_t error_code) {
        ExecHypervisorUserfaultRange tracked_range = {};
        ExecHypervisor *machine;
        uint64_t page;
        bool sigbus = false;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        page = ALIGN_DOWN(address, page_size());
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges)
                if (page >= range->start && page < range->start + range->length) {
                        uint64_t *entry = guest_page_entry(machine, page);

                        if (!entry || FLAGS_SET(*entry, X86_PAGE_SOFTWARE_PROT_NONE) ||
                            !range->features_known || !FLAGS_SET(range->features, UFFD_FEATURE_SIGBUS))
                                break;
                                                tracked_range = *range;
                        if (!FLAGS_SET(*entry, X86_PAGE_PRESENT))
                                sigbus = (range->mode &
                                          (UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_MINOR)) != 0;
                        else
                                sigbus = FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) &&
                                        range->write_protected && FLAGS_SET(error_code, 1|2);
                        break;
                }
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        if (!sigbus)
                return GUEST_USERFAULT_SIGBUS_NONE;

        r = begin_guest_quiescence(h);
        if (r < 0)
                return r;
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        r = userfault_range_is_registered(&tracked_range, page, page_size());
        if (r == 0) {
                r = reconcile_unregistered_userfault_ranges(
                                h, page, tracked_range.device, tracked_range.inode);
                if (r >= 0)
                        r = GUEST_USERFAULT_SIGBUS_HANDLED;
        } else if (r > 0)
                r = GUEST_USERFAULT_SIGBUS_DELIVER;
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        end_guest_quiescence(h);
        return r;
}

static int userfault_range_is_registered(
                const ExecHypervisorUserfaultRange *range,
                uint64_t start,
                uint64_t length) {

        _cleanup_close_ int fd = -EBADF;
        struct uffdio_api api = {
                .api = UFFD_API,
                .features = range->features_known ? range->features & UFFD_FEATURE_WP_ASYNC : 0,
        };
        struct uffdio_register registration = {
                .range = {
                        .start = start,
                        .len = length,
                },
                .mode = range->mode,
        };

        assert(range);
        assert(start % page_size() == 0);
        assert(length > 0);
        assert(length % page_size() == 0);

        fd = syscall(__NR_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
        if (fd < 0)
                return -errno;
        if (ioctl(fd, UFFDIO_API, &api) < 0)
                return -errno;
        if (ioctl(fd, UFFDIO_REGISTER, &registration) < 0)
                return errno == EBUSY ? 1 : -errno;
        if (ioctl(fd, UFFDIO_UNREGISTER, &registration.range) < 0)
                return -errno;

        return 0;
}

static void restore_unregistered_userfault_pages(
                ExecHypervisor *h,
                const ExecHypervisorUserfaultRange *range,
                uint64_t start,
                uint64_t end) {

        ExecHypervisor *machine;

        assert(h);
        assert(range);
        assert(start >= range->start);
        assert(end <= range->start + range->length);
        assert(start < end);

        machine = exec_hypervisor_machine(h);
        for (uint64_t page = start; page < end; page += page_size()) {
                ExecHypervisorMapping *mapping = find_mapping(machine, page);
                uint64_t *entry = guest_page_entry(machine, page);

                if (!entry || FLAGS_SET(*entry, X86_PAGE_SOFTWARE_PROT_NONE))
                        continue;
                if ((range->mode & (UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_MINOR)) != 0 &&
                    !FLAGS_SET(*entry, X86_PAGE_SOFTWARE_UFFD_POISON))
                        *entry |= X86_PAGE_PRESENT;
                if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) &&
                    mapping && FLAGS_SET(mapping->protection, PROT_WRITE))
                        *entry |= X86_PAGE_WRITE;
        }
}

static int reconcile_unregistered_userfault_ranges(
                ExecHypervisor *h,
                uint64_t fault_page,
                dev_t device,
                ino_t inode) {

        ExecHypervisor *machine;
        bool changed = false;

        assert(h);
        assert(fault_page % page_size() == 0);

        machine = exec_hypervisor_machine(h);
        for (size_t i = 0; i < machine->n_userfault_ranges;) {
                ExecHypervisorUserfaultRange range = machine->userfault_ranges[i];
                int r;

                if (range.device != device || range.inode != inode) {
                        i++;
                        continue;
                }
                r = userfault_range_is_registered(&range, range.start, range.length);
                if (r < 0)
                        return r;
                if (r == 0) {
                        restore_unregistered_userfault_pages(
                                        h, &range, range.start, range.start + range.length);
                        commit_userfault_range_split(
                                        h,
                                        i,
                                        range.start,
                                        range.start + range.length,
                                        /* keep_middle= */ false,
                                        /* middle_write_protected= */ false,
                                        /* middle_fd= */ -EBADF);
                        changed = true;
                        continue;
                }

                if (fault_page >= range.start && fault_page < range.start + range.length) {
                        r = userfault_range_is_registered(&range, fault_page, page_size());
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                r = ensure_userfault_split_capacity(
                                                h,
                                                i,
                                                fault_page,
                                                fault_page + page_size(),
                                                /* keep_middle= */ false);
                                if (r < 0)
                                        return r;
                                restore_unregistered_userfault_pages(
                                                h, &range, fault_page, fault_page + page_size());
                                commit_userfault_range_split(
                                                h,
                                                i,
                                                fault_page,
                                                fault_page + page_size(),
                                                /* keep_middle= */ false,
                                                /* middle_write_protected= */ false,
                                                /* middle_fd= */ -EBADF);
                                changed = true;
                                break;
                        }
                }
                i++;
        }

        return changed ? flush_all_guest_tlbs(machine) : 0;
}

int resolve_guest_userfault(ExecHypervisor *h, uint64_t address, uint64_t error_code) {
        ExecHypervisor *machine;
        ExecHypervisorUserfaultRange tracked_range = {};
        uint64_t page;
        uint64_t mode = 0;
        bool async_write_protect = false, handled = true, missing = false, tracked = false,
             write_protected = false;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        page = ALIGN_DOWN(address, page_size());
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges)
                if (page >= range->start && page < range->start + range->length) {
                        uint64_t *entry = guest_page_entry(machine, page);

                        if (entry && !FLAGS_SET(*entry, X86_PAGE_SOFTWARE_PROT_NONE)) {
                                tracked_range = *range;
                                tracked = true;
                                mode = range->mode;
                                missing = !FLAGS_SET(*entry, X86_PAGE_PRESENT);
                                write_protected = range->write_protected;
                                async_write_protect = range->features_known &&
                                        FLAGS_SET(range->features, UFFD_FEATURE_WP_ASYNC);
                        }
                        break;
                }
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        if (missing) {
                if ((mode & (UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_MINOR)) == 0)
                        return 0;
        } else if (!FLAGS_SET(mode, UFFDIO_REGISTER_MODE_WP) ||
                   !write_protected || !FLAGS_SET(error_code, 1|2))
                return 0;

        if (FLAGS_SET(error_code, 2)) {
                uint8_t expected = 0;

                (void) __atomic_compare_exchange_n(
                                (uint8_t*) (uintptr_t) address,
                                &expected,
                                0,
                                false,
                                __ATOMIC_RELAXED,
                                __ATOMIC_RELAXED);
        } else
                (void) *(volatile uint8_t*) (uintptr_t) address;

        r = begin_guest_quiescence(h);
        if (r < 0)
                return r;
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        uint64_t *entry = guest_page_entry(machine, page);
        if (!entry || FLAGS_SET(*entry, X86_PAGE_SOFTWARE_PROT_NONE))
                r = -EFAULT;
        else if (FLAGS_SET(*entry, X86_PAGE_SOFTWARE_UFFD_POISON)) {
                handled = false;
                r = 0;
        } else if (tracked &&
                (r = userfault_range_is_registered(&tracked_range, page, page_size())) <= 0) {
                if (r == 0)
                        r = reconcile_unregistered_userfault_ranges(
                                        h, page, tracked_range.device, tracked_range.inode);
        } else if (missing) {
                if (FLAGS_SET(*entry, X86_PAGE_PRESENT))
                        r = 0;
                else {
                        *entry |= X86_PAGE_PRESENT;
                        r = flush_all_guest_tlbs(machine);
                }
        } else if (async_write_protect) {
                size_t range_index;

                r = find_containing_userfault_range(
                                h,
                                page,
                                page + page_size(),
                                UFFDIO_REGISTER_MODE_WP,
                                -EBADF,
                                &range_index);
                if (r == -ENOENT)
                        r = FLAGS_SET(*entry, X86_PAGE_WRITE) ? 0 : -EIO;
                else if (r >= 0) {
                        ExecHypervisorMapping *mapping = find_mapping(machine, page);

                        r = ensure_userfault_split_capacity(
                                        h,
                                        range_index,
                                        page,
                                        page + page_size(),
                                        /* keep_middle= */ true);
                        if (r >= 0 && (!mapping || !FLAGS_SET(mapping->protection, PROT_WRITE)))
                                r = -EFAULT;
                        if (r >= 0) {
                                *entry |= X86_PAGE_WRITE;
                                commit_userfault_range_split(
                                                h,
                                                range_index,
                                                page,
                                                page + page_size(),
                                                /* keep_middle= */ true,
                                                /* middle_write_protected= */ false,
                                                machine->userfault_ranges[range_index].fd);
                                r = flush_all_guest_tlbs(machine);
                        }
                }
        } else if (FLAGS_SET(*entry, X86_PAGE_WRITE))
                r = 0;
        else {
                size_t range_index;

                r = find_containing_userfault_range(
                                h,
                                page,
                                page + page_size(),
                                UFFDIO_REGISTER_MODE_WP,
                                -EBADF,
                                &range_index);
                if (r >= 0)
                        r = ensure_userfault_split_capacity(
                                        h,
                                        range_index,
                                        page,
                                        page + page_size(),
                                        /* keep_middle= */ true);
                if (r >= 0) {
                        ExecHypervisorMapping *mapping = find_mapping(machine, page);

                        if (!mapping || !FLAGS_SET(mapping->protection, PROT_WRITE))
                                r = -EFAULT;
                        else {
                                *entry |= X86_PAGE_WRITE;
                                commit_userfault_range_split(
                                                h,
                                                range_index,
                                                page,
                                                page + page_size(),
                                                /* keep_middle= */ true,
                                                /* middle_write_protected= */ false,
                                                machine->userfault_ranges[range_index].fd);
                                r = flush_all_guest_tlbs(machine);
                        }
                }
        }
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        end_guest_quiescence(h);
        return r < 0 ? r : handled;
}

#endif

