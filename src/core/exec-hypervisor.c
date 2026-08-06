#include "exec-hypervisor-internal.h"

#if defined(__x86_64__)

_Thread_local ExecHypervisor *signal_hypervisor = NULL;

ExecHypervisor* exec_hypervisor_machine(ExecHypervisor *h) {
        assert(h);

        return ASSERT_PTR(h->machine);
}

void hypervisor_signal_handler(int signo, siginfo_t *info, void *context) {
        ExecHypervisor *h = signal_hypervisor;

        if (h && info && signo == EXEC_HYPERVISOR_CONTROL_SIGNAL &&
            info->si_code == SI_QUEUE && info->si_value.sival_int == EXEC_HYPERVISOR_QUIESCE_MAGIC) {
                if (h->run)
                        h->run->immediate_exit = 1;
                return;
        }
        if (h && signo == 32 &&
            __atomic_load_n(&h->machine->exec_request_state, __ATOMIC_ACQUIRE) != GUEST_EXEC_REQUEST_IDLE)
                return;

        if (h && info && signo > 0 && signo <= (int) EXEC_HYPERVISOR_N_SIGNALS) {
                PendingGuestSignal *pending = h->pending_signals + signo;

                pending->info = *info;
                __atomic_store_n(&pending->pending, 1, __ATOMIC_RELEASE);
        }
}

static int kick_guest_runner(ExecHypervisor *h) {
        siginfo_t info = {
                .si_signo = EXEC_HYPERVISOR_CONTROL_SIGNAL,
                .si_code = SI_QUEUE,
                .si_pid = getpid(),
                .si_uid = getuid(),
                .si_value.sival_int = EXEC_HYPERVISOR_QUIESCE_MAGIC,
        };

        assert(h);

        if (h->runner_tid <= 0)
                return 0;
        if (syscall(__NR_rt_tgsigqueueinfo,
                    getpid(),
                    h->runner_tid,
                    EXEC_HYPERVISOR_CONTROL_SIGNAL,
                    &info) < 0)
                return errno == ESRCH ? 1 : -errno;
        return 0;
}

int wait_guest_quiescence(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        for (;;) {
                unsigned generation = __atomic_load_n(&machine->quiesce_generation, __ATOMIC_ACQUIRE);
                pid_t owner = __atomic_load_n(&machine->quiesce_owner_tid, __ATOMIC_ACQUIRE);

                if (owner == 0 || owner == h->runner_tid) {
                        h->quiesce_seen_generation = generation;
                        if (h->run)
                                h->run->immediate_exit = 0;
                        return 0;
                }

                while (__atomic_load_n(&machine->quiesce_scan_generation, __ATOMIC_ACQUIRE) < generation) {
                        unsigned scanned = __atomic_load_n(
                                        &machine->quiesce_scan_generation,
                                        __ATOMIC_RELAXED);
                        long r = syscall(__NR_futex,
                                         &machine->quiesce_scan_generation,
                                         FUTEX_WAIT,
                                         scanned,
                                         NULL,
                                         NULL,
                                         0);

                        if (r < 0 && !IN_SET(errno, EAGAIN, EINTR))
                                return -errno;
                }

                if (h->quiesce_seen_generation != generation &&
                    __atomic_load_n(&h->quiesce_requested_generation, __ATOMIC_ACQUIRE) == generation) {
                        h->quiesce_seen_generation = generation;
                        __atomic_add_fetch(&machine->quiesce_acknowledged, 1, __ATOMIC_RELEASE);
                        (void) syscall(__NR_futex,
                                       &machine->quiesce_acknowledged,
                                       FUTEX_WAKE,
                                       INT_MAX,
                                       NULL,
                                       NULL,
                                       0);
                } else
                        h->quiesce_seen_generation = generation;

                while ((owner = __atomic_load_n(&machine->quiesce_owner_tid, __ATOMIC_ACQUIRE)) > 0 &&
                       owner != h->runner_tid) {
                        long r = syscall(__NR_futex,
                                         &machine->quiesce_owner_tid,
                                         FUTEX_WAIT,
                                         owner,
                                         NULL,
                                         NULL,
                                         0);

                        if (r < 0 && !IN_SET(errno, EAGAIN, EINTR))
                                return -errno;
                }
        }
}

int begin_guest_quiescence(ExecHypervisor *h) {
        ExecHypervisor *machine;
        unsigned expected = 0, generation;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        for (;;) {
                r = pthread_mutex_trylock(&machine->quiesce_lock);
                if (r == 0)
                        break;
                if (r != EBUSY)
                        return -r;
                r = wait_guest_quiescence(h);
                if (r < 0)
                        return r;
        }
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        assert(machine->quiesce_owner_tid == 0);
        __atomic_store_n(&machine->quiesce_owner_tid, h->runner_tid, __ATOMIC_RELEASE);
        machine->quiesce_acknowledged = 0;
        machine->quiesce_expected = 0;
        generation = __atomic_add_fetch(&machine->quiesce_generation, 1, __ATOMIC_RELEASE);
        h->quiesce_seen_generation = generation;

        FOREACH_ARRAY(thread, machine->active_vcpus, machine->n_active_vcpus) {
                if ((*thread)->runner_tid == h->runner_tid ||
                    !__atomic_load_n(&(*thread)->vcpu_in_guest, __ATOMIC_ACQUIRE))
                        continue;
                __atomic_store_n(&(*thread)->quiesce_requested_generation, generation, __ATOMIC_RELEASE);
                r = kick_guest_runner(*thread);
                if (r < 0)
                        goto fail;
                if (r == 0)
                        expected++;
        }
        if (machine->runner_tid != h->runner_tid && machine->runner_tid > 0 &&
            __atomic_load_n(&machine->vcpu_in_guest, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&machine->quiesce_requested_generation, generation, __ATOMIC_RELEASE);
                r = kick_guest_runner(machine);
                if (r < 0)
                        goto fail;
                if (r == 0)
                        expected++;
        }
        machine->quiesce_expected = expected;
        __atomic_store_n(&machine->quiesce_scan_generation, generation, __ATOMIC_RELEASE);
        (void) syscall(__NR_futex,
                       &machine->quiesce_scan_generation,
                       FUTEX_WAKE,
                       INT_MAX,
                       NULL,
                       NULL,
                       0);
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);

        while (__atomic_load_n(&machine->quiesce_acknowledged, __ATOMIC_ACQUIRE) < expected) {
                unsigned acknowledged = __atomic_load_n(&machine->quiesce_acknowledged, __ATOMIC_RELAXED);
                long n = syscall(__NR_futex,
                                 &machine->quiesce_acknowledged,
                                 FUTEX_WAIT,
                                 acknowledged,
                                 NULL,
                                 NULL,
                                 0);

                if (n < 0 && !IN_SET(errno, EAGAIN, EINTR))
                        goto fail_unlocked;
        }

        return 0;

fail:
        __atomic_store_n(&machine->quiesce_scan_generation, generation, __ATOMIC_RELEASE);
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
fail_unlocked:
        end_guest_quiescence(h);
        return r < 0 ? r : -errno;
}

void end_guest_quiescence(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        machine->quiesce_expected = 0;
        __atomic_store_n(&machine->quiesce_owner_tid, 0, __ATOMIC_RELEASE);
        (void) syscall(__NR_futex,
                       &machine->quiesce_owner_tid,
                       FUTEX_WAKE,
                       INT_MAX,
                       NULL,
                       NULL,
                       0);
        assert_se(pthread_mutex_unlock(&machine->quiesce_lock) == 0);
}

int begin_guest_memory_transaction(ExecHypervisor *h) {
        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        r = begin_guest_quiescence(h);
        if (r < 0)
                return r;
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        return 0;
}

void end_guest_memory_transaction(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        end_guest_quiescence(h);
}

int destroy_guest_aio_contexts(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(context, machine->aio_contexts, machine->n_aio_contexts)
                if (syscall(__NR_io_destroy, context->id) < 0 && errno != EINVAL)
                        return -errno;

        machine->aio_contexts = mfree(machine->aio_contexts);
        machine->n_aio_contexts = 0;
        return 0;
}

ExecHypervisor* exec_hypervisor_free(ExecHypervisor *h) {
        if (!h)
                return NULL;

        if (signal_hypervisor == h)
                signal_hypervisor = NULL;
        if (h->thread_vcpu) {
                if (h->run)
                        (void) munmap(h->run, h->run_size);
                if (!h->machine->preserve_shared_fds)
                        safe_close(h->vcpu_fd);
                return mfree(h);
        }
        (void) destroy_guest_aio_contexts(h);
        for (int signo = 1; signo <= (int) EXEC_HYPERVISOR_N_SIGNALS; signo++)
                if (h->host_signal_actions_modified[signo])
                        (void) syscall(
                                        __NR_rt_sigaction,
                                        signo,
                                        h->saved_host_signal_actions + signo,
                                        NULL,
                                        sizeof(uint64_t));

        if (h->run)
                (void) munmap(h->run, h->run_size);
        if (!h->preserve_shared_fds) {
                safe_close(h->vcpu_fd);
                safe_close(h->vm_fd);
        }
        if (h->supervisor_memory)
                (void) munmap(h->supervisor_memory, h->supervisor_memory_size);
        free(h->free_supervisor_pages);
        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings)
                if (mapping->mutable && mapping->host_address && mapping->size > 0) {
                        if (mapping->kvm_address && mapping->kvm_address != mapping->host_address)
                                (void) munmap(mapping->kvm_address, mapping->size);
                        (void) munmap(mapping->host_address, mapping->size);
                        if (mapping->guard_address && mapping->shadow_stack_guard_reserved)
                                (void) munmap(mapping->guard_address, page_size());
                }
        if (h->image_reservation)
                (void) munmap(h->image_reservation, h->image_reservation_size);
        if (h->interpreter_reservation)
                (void) munmap(h->interpreter_reservation, h->interpreter_reservation_size);
        if (h->stack_reservation)
                (void) munmap(h->stack_reservation, h->stack_reservation_size);
        if (h->heap_reservation)
                (void) munmap(h->heap_reservation, h->heap_reservation_size);
        if (h->vfork_completion)
                (void) munmap(h->vfork_completion, h->vfork_completion->size);
        FOREACH_ARRAY(thread, h->idle_vcpus, h->n_idle_vcpus)
                exec_hypervisor_free(*thread);
        free(h->idle_vcpus);
        free(h->active_vcpus);
        exec_hypervisor_free(h->exec_replacement);
        strv_free(h->deferred_exec_argv);
        strv_free(h->deferred_exec_envp);
        hashmap_free(h->syscall_filter);
        free(h->userfault_ranges);
        free(h->userfault_contexts);
        free(h->sealed_ranges);
        free(h->dontfork_ranges);
        free(h->wipeonfork_ranges);
        free(h->mappings);
        if (!h->files_shared)
                FOREACH_ARRAY(fd, h->mapping_fds, h->n_mapping_fds)
                        safe_close(*fd);
        free(h->mapping_fds);
        free(h->free_memslots);
        free(h->free_gpa_extents);
        free(h->posix_timers);
        cpu_set_done(&h->exec_cpu_affinity);
        cpu_set_done(&h->exec_mempolicy_nodes);
        elf_image_free(h->interpreter_image);
        elf_image_free(h->image);
        safe_close(h->interpreter_fd);
        safe_close(h->image_fd);
        if (!h->files_shared)
                safe_close(h->kvm_fd);
        return mfree(h);
}

int* exec_hypervisor_kvm_fd(ExecHypervisor *h) {
        assert(h);

        return &h->kvm_fd;
}

int exec_hypervisor_create_machine(ExecHypervisor *h) {
#if defined(__x86_64__)
        int r;

        assert(h);
        assert(h->kvm_fd >= 0);
        assert(h->vm_fd < 0);
        assert(h->vcpu_fd < 0);
        assert(!h->run);

        if (!h->selected)
                return 0;

        h->vm_fd = ioctl(h->kvm_fd, KVM_CREATE_VM, 0);
        if (h->vm_fd < 0) {
                if (kvm_errno_is_unavailable(errno)) {
                        log_debug_errno(errno, "KVM VM creation is unavailable, using native execution: %m");
                        return 0;
                }

                return -errno;
        }

        r = register_image_mappings(h);
        if (r < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(r) || r == -E2BIG) {
                        log_debug_errno(r, "KVM image memslots are unavailable, using native execution: %m");
                        return 0;
                }

                return r;
        }

        r = setup_page_tables(h);
        if (r < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(r) || IN_SET(r, -E2BIG, -ENOSPC)) {
                        log_debug_errno(r, "KVM image page tables are unavailable, using native execution: %m");
                        return 0;
                }

                return r;
        }

        h->vcpu_fd = ioctl(h->vm_fd, KVM_CREATE_VCPU, 0);
        if (h->vcpu_fd < 0) {
                if (kvm_errno_is_unavailable(errno)) {
                        log_debug_errno(errno, "KVM vCPU creation is unavailable, using native execution: %m");
                        return 0;
                }

                return -errno;
        }

        r = probe_vcpu_speculation_msrs(h, h->vcpu_fd);
        if (r < 0)
                return r;

        r = set_supported_cpuid(h);
        if (r < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(r)) {
                        log_debug_errno(r, "KVM CPUID setup is unavailable, using native execution: %m");
                        return 0;
                }

                return r;
        }

        long run_size = ioctl(h->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
        if (run_size < 0)
                return -errno;
        if (run_size < (long) sizeof(struct kvm_run))
                return -EPROTO;

        h->run_size = run_size;
        h->run = mmap(NULL, h->run_size, PROT_READ|PROT_WRITE, MAP_SHARED, h->vcpu_fd, 0);
        if (h->run == MAP_FAILED) {
                h->run = NULL;
                return -errno;
        }

        r = setup_vcpu_state(h);
        if (r == -EOPNOTSUPP && h->amx_supported) {
                log_debug("KVM XFD state is unavailable, using native execution.");
                return 0;
        }
        if (r < 0)
                return r;

        r = initialize_guest_speculation_policy(h);
        if (r == -EOPNOTSUPP) {
                log_debug("KVM cannot enforce the host speculation policy, using native execution.");
                return 0;
        }
        if (r < 0)
                return r;

        r = initialize_guest_keyring_policy(h);
        if (r < 0)
                return r;

        r = validate_vcpu_state(h);
        if (r < 0)
                return r;

        log_debug("Created KVM VM and vCPU in final executor address space.");
        return 1;
#else
        assert(h);

        return 0;
#endif
}

int exec_hypervisor_run_probe(ExecHypervisor *h) {
#if defined(__x86_64__)
        struct kvm_regs image_regs, probe_regs;
        struct kvm_sregs image_sregs, probe_sregs;
        uint32_t marker;

        assert(h);
        assert(h->selected);
        assert(h->vcpu_fd >= 0);
        assert(h->run);

        if (ioctl(h->vcpu_fd, KVM_GET_REGS, &image_regs) < 0)
                return -errno;
        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &image_sregs) < 0)
                return -errno;

        probe_regs = image_regs;
        probe_regs.rax = 0;
        probe_regs.rip = h->probe_code_gpa;
        probe_regs.rsp = 0;
        probe_regs.rflags = 2;
        if (ioctl(h->vcpu_fd, KVM_SET_REGS, &probe_regs) < 0)
                return -errno;

        if (ioctl(h->vcpu_fd, KVM_RUN, 0) < 0)
                return -errno;

        if (h->run->exit_reason != KVM_EXIT_IO ||
            h->run->io.direction != KVM_EXIT_IO_OUT ||
            h->run->io.port != 0x10 ||
            h->run->io.size != sizeof(marker) ||
            h->run->io.count != 1)
                return -EPROTO;

        memcpy(&marker, (uint8_t*) h->run + h->run->io.data_offset, sizeof(marker));
        if (marker != EXEC_HYPERVISOR_PROBE_MARKER)
                return -EPROTO;

        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &probe_sregs) < 0)
                return -errno;
        if ((probe_sregs.cs.selector & 3) != 0)
                return -EPROTO;

        if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &image_sregs) < 0)
                return -errno;
        if (ioctl(h->vcpu_fd, KVM_SET_REGS, &image_regs) < 0)
                return -errno;

        log_debug("KVM final-executor CPL3/CPL0 entry probe succeeded.");
        return 0;
#else
        assert(h);

        return -EOPNOTSUPP;
#endif
}

bool exec_hypervisor_can_run(const ExecHypervisor *h) {
        return h && h->selected && h->image;
}

void exec_hypervisor_set_secure_exec(ExecHypervisor *h, bool secure_exec) {
        assert(exec_hypervisor_can_run(h));

        h->secure_exec = secure_exec;
}

int exec_hypervisor_set_syscall_filter(
                ExecHypervisor *h,
                Hashmap *filter,
                bool allow_list,
                int errno_or_action) {

        _cleanup_hashmap_free_ Hashmap *copy = NULL;
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (!hashmap_isempty(filter)) {
                copy = hashmap_copy(filter);
                if (!copy)
                        return -ENOMEM;
        }

        hashmap_free(machine->syscall_filter);
        machine->syscall_filter = TAKE_PTR(copy);
        machine->syscall_allow_list = allow_list;
        machine->syscall_errno_or_action = errno_or_action;
        machine->syscall_filter_set = true;
        return 0;
}

#else

int exec_hypervisor_open_system(ExecHypervisor **ret) {
        assert(ret);

        *ret = NULL;
        log_debug("KVM executor support is unavailable on this architecture, using native execution.");
        return 0;
}

int exec_hypervisor_prepare_image(ExecHypervisor *h, int executable_fd, const char *executable_path) {
        assert(h);
        assert(executable_fd >= 0);

        return 0;
}

int exec_hypervisor_create_machine(ExecHypervisor *h) {
        assert(h);

        return 0;
}

int exec_hypervisor_run_probe(ExecHypervisor *h) {
        assert(h);

        return -EOPNOTSUPP;
}

bool exec_hypervisor_can_run(const ExecHypervisor *h) {
        return false;
}

void exec_hypervisor_set_secure_exec(ExecHypervisor *h, bool secure_exec) {
        assert(h);
}

int exec_hypervisor_prepare_stack(ExecHypervisor *h, char *const argv[], char *const envp[]) {
        assert(h);
        assert(argv);

        return -EOPNOTSUPP;
}

int exec_hypervisor_set_syscall_filter(
                ExecHypervisor *h,
                Hashmap *filter,
                bool allow_list,
                int errno_or_action) {

        assert(h);
        return 0;
}

int exec_hypervisor_run(ExecHypervisor *h, int *ret_status) {
        assert(h);
        assert(ret_status);

        return -EOPNOTSUPP;
}

int* exec_hypervisor_kvm_fd(ExecHypervisor *h) {
        assert(h);

        return NULL;
}

ExecHypervisor* exec_hypervisor_free(ExecHypervisor *h) {
        free(h);
        return NULL;
}

#endif