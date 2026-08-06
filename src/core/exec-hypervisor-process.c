/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-hypervisor-internal.h"

#if defined(__x86_64__)

static int guest_robust_futex_address(uint64_t entry, int64_t offset, uint64_t *ret) {
        uint64_t address;

        assert(ret);

        if (offset >= 0) {
                if (!ADD_SAFE(&address, entry, (uint64_t) offset))
                        return -EFAULT;
        } else {
                uint64_t magnitude = (uint64_t) (-(offset + 1)) + 1;

                if (entry < magnitude)
                        return -EFAULT;
                address = entry - magnitude;
        }
        if (address > UINT64_C(0x00007fffffffffff) || address % sizeof(uint32_t) != 0)
                return -EFAULT;

        *ret = address;
        return 0;
}

static int process_guest_robust_entry(
                ExecHypervisor *h,
                uint64_t entry,
                int64_t futex_offset,
                bool pi,
                bool pending,
                bool cleanup) {

        uint64_t futex_address;
        uint32_t value;
        pid_t owner_tid;
        int r;

        assert(h);

        r = guest_robust_futex_address(entry, futex_offset, &futex_address);
        if (r < 0)
                return 1;
        r = copy_from_guest(h, &value, futex_address, sizeof(value));
        if (r < 0)
                return 1;

        owner_tid = h->owner_tid > 0 ? h->owner_tid : gettid();
        if ((value & FUTEX_TID_MASK) == (uint32_t) owner_tid && pi)
                return -EOPNOTSUPP;
        if (!cleanup || pi)
                return 0;

        if (pending && (value & FUTEX_TID_MASK) == 0) {
                (void) syscall(__NR_futex,
                               (void*) (uintptr_t) futex_address,
                               FUTEX_WAKE,
                               1,
                               NULL,
                               NULL,
                               0);
                return 0;
        }
        if ((value & FUTEX_TID_MASK) != (uint32_t) owner_tid)
                return 0;
        r = validate_guest_range(h, futex_address, sizeof(value), /* writeable= */ true);
        if (r < 0)
                return 1;

        uint32_t *futex = (uint32_t*) (uintptr_t) futex_address;
        for (;;) {
                uint32_t expected = value;
                uint32_t replacement = (value & FUTEX_WAITERS) | FUTEX_OWNER_DIED;

                if (__atomic_compare_exchange_n(
                                    futex,
                                    &expected,
                                    replacement,
                                    false,
                                    __ATOMIC_SEQ_CST,
                                    __ATOMIC_RELAXED))
                        break;
                value = expected;
                if ((value & FUTEX_TID_MASK) != (uint32_t) owner_tid)
                        return 0;
        }

        if (value & FUTEX_WAITERS)
                (void) syscall(__NR_futex,
                               futex,
                               FUTEX_WAKE,
                               1,
                               NULL,
                               NULL,
                               0);
        return 0;
}
static int walk_guest_robust_list(ExecHypervisor *h, bool cleanup) {
        struct robust_list_head head;
        uint64_t entry, head_address, pending;
        bool entry_pi, pending_pi;
        int r;

        assert(h);
        assert(h->robust_list_address != 0);

        r = copy_from_guest(h, &head, h->robust_list_address, sizeof(head));
        if (r < 0)
                return 0;

        head_address = h->robust_list_address + offsetof(struct robust_list_head, list);
        entry = (uintptr_t) head.list.next;
        entry_pi = FLAGS_SET(entry, FUTEX_ROBUST_MOD_PI);
        entry &= ~(uint64_t) FUTEX_ROBUST_MOD_MASK;
        pending = (uintptr_t) head.list_op_pending;
        pending_pi = FLAGS_SET(pending, FUTEX_ROBUST_MOD_PI);
        pending &= ~(uint64_t) FUTEX_ROBUST_MOD_MASK;

        for (unsigned remaining = ROBUST_LIST_LIMIT; entry != head_address && remaining > 0; remaining--) {
                struct robust_list current;
                uint64_t next;
                bool next_pi;

                r = copy_from_guest(h, &current, entry, sizeof(current));
                if (entry != pending) {
                        int q = process_guest_robust_entry(
                                        h,
                                        entry,
                                        head.futex_offset,
                                        entry_pi,
                                        /* pending= */ false,
                                        cleanup);
                        if (q < 0)
                                return q;
                        if (q > 0)
                                return 0;
                }
                if (r < 0)
                        return 0;

                next = (uintptr_t) current.next;
                next_pi = FLAGS_SET(next, FUTEX_ROBUST_MOD_PI);
                entry = next & ~(uint64_t) FUTEX_ROBUST_MOD_MASK;
                entry_pi = next_pi;
        }

        if (pending != 0) {
                r = process_guest_robust_entry(
                                h,
                                pending,
                                head.futex_offset,
                                pending_pi,
                                /* pending= */ true,
                                cleanup);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int cleanup_guest_robust_list_for_exec(ExecHypervisor *h) {
        int r;

        assert(h);
        assert(!h->thread_vcpu);

        if (h->robust_list_address == 0)
                return 0;

        r = walk_guest_robust_list(h, /* cleanup= */ false);
        if (r < 0)
                return r;
        r = walk_guest_robust_list(h, /* cleanup= */ true);
        if (r < 0)
                return r;
        if (syscall(__NR_set_robust_list, NULL, sizeof(struct robust_list_head)) < 0)
                return -errno;

        h->robust_list_address = 0;
        return 0;
}

static int check_guest_robust_list_for_exec(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (machine->robust_list_address == 0)
                return 0;

        return walk_guest_robust_list(machine, /* cleanup= */ false);
}

static int check_guest_posix_timers_for_exec(ExecHypervisor *h) {
        ExecHypervisor *machine;
        sigset_t pending;
        int r = 0;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        if (machine->n_posix_timers == 0)
                goto finish;
        if (sigpending(&pending) < 0) {
                r = -errno;
                goto finish;
        }

        FOREACH_ARRAY(timer, machine->posix_timers, machine->n_posix_timers)
                if (timer->signal > 0 && sigismember(&pending, timer->signal) > 0) {
                        r = -EOPNOTSUPP;
                        break;
                }

finish:
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return r;
}

static int cleanup_guest_posix_timers_for_exec(ExecHypervisor *h) {
        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        r = check_guest_posix_timers_for_exec(machine);
        if (r < 0)
                return r;

        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        FOREACH_ARRAY(timer, machine->posix_timers, machine->n_posix_timers)
                if (syscall(__NR_timer_delete, timer->id) < 0 && errno != EINVAL) {
                        r = -errno;
                        goto finish;
                }
        machine->posix_timers = mfree(machine->posix_timers);
        machine->n_posix_timers = 0;
        r = 0;

finish:
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return r;
}

static int check_guest_mlockall_for_exec(ExecHypervisor *h) {
        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        r = machine->mlockall_future ? -EOPNOTSUPP : 0;
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return r;
}

static int check_guest_io_uring_for_exec(ExecHypervisor *h) {
        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        r = machine->io_uring_used ? -EOPNOTSUPP : 0;
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return r;
}

static int check_guest_pending_signals_for_exec(ExecHypervisor *h) {
        sigset_t pending;

        assert(h);

        if (!h->thread_vcpu)
                return 0;
        if (sigpending(&pending) < 0)
                return -errno;
        for (int signo = 1; signo <= (int) EXEC_HYPERVISOR_N_SIGNALS; signo++)
                if (sigismember(&pending, signo) > 0)
                        return -EOPNOTSUPP;

        return 0;
}

static int get_current_cpu_affinity(CPUSet *ret) {
        CPUSet affinity = {};
        size_t n_cpus = 16;
        int r;

        assert(ret);

        for (;;) {
                r = cpu_set_realloc(&affinity, n_cpus);
                if (r < 0)
                        return r;
                if (sched_getaffinity(0, affinity.allocated, affinity.set) >= 0)
                        break;
                if (errno != EINVAL)
                        return -errno;
                if (n_cpus > SIZE_MAX / 2)
                        return -EOVERFLOW;
                n_cpus *= 2;
        }

        *ret = TAKE_STRUCT(affinity);
        return 0;
}

static int get_current_mempolicy(int *ret_mode, CPUSet *ret_nodes) {
        _cleanup_(cpu_set_done) CPUSet nodes = {};
        int mode, r;

        assert(ret_mode);
        assert(ret_nodes);

        r = numa_mask_add_all(&nodes);
        if (r < 0)
                return r;
        if (get_mempolicy(
                            &mode,
                            (unsigned long*) nodes.set,
                            nodes.allocated * 8,
                            NULL,
                            0) < 0)
                return -errno;

        *ret_mode = mode;
        *ret_nodes = TAKE_STRUCT(nodes);
        return 0;
}

static int cleanup_guest_mlockall_for_exec(ExecHypervisor *h) {
        ExecHypervisor *machine;
        int r = 0;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        if (machine->mlockall_future)
                r = -EOPNOTSUPP;
        else if ((machine->mlockall_current || machine->mlock_range_seen) && syscall(__NR_munlockall) < 0)
                r = -errno;
        else {
                machine->mlockall_current = false;
                machine->mlockall_future = false;
                machine->mlock_range_seen = false;
        }
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return r;
}

static int close_cloexec_fds_for_guest_exec(ExecHypervisor *current, ExecHypervisor *next) {
        _cleanup_(fdset_freep) FDSet *fds = NULL;
        int keep[] = {
                current->kvm_fd,
                current->vm_fd,
                current->vcpu_fd,
                current->image_fd,
                current->interpreter_fd,
                next->kvm_fd,
                next->vm_fd,
                next->vcpu_fd,
                next->image_fd,
                next->interpreter_fd,
        };
        int r;

        assert(current);
        assert(next);

        r = fdset_new_fill(/* filter_cloexec= */ 1, &fds);
        if (r < 0)
                return r;

        FOREACH_ELEMENT(fd, keep)
                if (*fd >= 3)
                        (void) fdset_remove(fds, *fd);
        FOREACH_ARRAY(thread, current->idle_vcpus, current->n_idle_vcpus)
                if ((*thread)->vcpu_fd >= 3)
                        (void) fdset_remove(fds, (*thread)->vcpu_fd);
        FOREACH_ARRAY(thread, current->active_vcpus, current->n_active_vcpus)
                if ((*thread)->vcpu_fd >= 3)
                        (void) fdset_remove(fds, (*thread)->vcpu_fd);
        FOREACH_ARRAY(fd, current->mapping_fds, current->n_mapping_fds)
                if (*fd >= 3)
                        (void) fdset_remove(fds, *fd);

        for (int fd = 0; fd < 3; fd++) {
                int flags = fcntl(fd, F_GETFD);

                if (flags >= 0 && FLAGS_SET(flags, FD_CLOEXEC))
                        (void) close(fd);
        }

        return 0;
}

static int transfer_signal_state_for_guest_exec(ExecHypervisor *current, ExecHypervisor *next) {
        ExecHypervisor *machine;

        assert(current);
        assert(next);

        machine = ASSERT_PTR(current->machine);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);

        for (int signo = 1; signo <= (int) EXEC_HYPERVISOR_N_SIGNALS; signo++) {
                GuestSignalAction host_action = {};
                GuestSignalAction action = {};

                if (!machine->signal_actions_initialized[signo])
                        continue;

                if (machine->signal_actions[signo].handler == 1) {
                        host_action.handler = (uintptr_t) SIG_IGN;
                        action.handler = 1;
                } else
                        host_action.handler = (uintptr_t) SIG_DFL;

                int r = host_signal_action(signo, &host_action, NULL);
                if (r < 0) {

                        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
                        return r;
                }

                machine->host_signal_actions_modified[signo] = false;
                next->saved_host_signal_actions[signo] = host_action;
                next->signal_actions[signo] = action;
                next->signal_actions_initialized[signo] = true;
        }

        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return 0;
}

int install_guest_exec_control_signal(ExecHypervisor *h) {
        const GuestSignalAction control_action = {
                .handler = UINTPTR_MAX,
        };
        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        r = initialize_guest_signal_action(h, 32);
        if (r >= 0)
                r = set_host_signal_action(h, 32, &control_action);
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return r;
}

static int interrupt_guest_exec_runner(ExecHypervisor *h) {
        assert(h);

        if (h->run)
                h->run->immediate_exit = 1;
        if (h->runner_tid <= 0)
                return 0;
        if (syscall(__NR_tgkill, getpid(), h->runner_tid, 32) < 0 && errno != ESRCH)
                return -errno;

        return 0;
}

static int wait_for_guest_thread_count(ExecHypervisor *h, unsigned maximum) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        for (;;) {
                unsigned n;
                long r;

                n = __atomic_load_n(&machine->n_guest_threads, __ATOMIC_ACQUIRE);
                if (n <= maximum) {
                        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
                        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                        return 0;
                }

                r = syscall(__NR_futex,
                            &machine->n_guest_threads,
                            FUTEX_WAIT,
                            n,
                            NULL,
                            NULL,
                            0);
                if (r < 0 && !IN_SET(errno, EAGAIN, EINTR))
                        return -errno;
        }
}

static int finalize_deferred_shared_files_exec(ExecHypervisor *h, ExecHypervisor *next) {
        int r;

        assert(h);
        assert(next);
        assert(!h->thread_vcpu);
        assert(h->files_shared);
        assert(next->deferred_exec_argv);

        next->image_fd = safe_close(next->image_fd);
        next->interpreter_fd = safe_close(next->interpreter_fd);
        next->kvm_fd = safe_close(next->kvm_fd);
        FOREACH_ARRAY(thread, h->idle_vcpus, h->n_idle_vcpus) {
                (*thread)->vcpu_fd = safe_close((*thread)->vcpu_fd);
                (*thread)->vm_fd = -EBADF;
        }
        FOREACH_ARRAY(thread, h->active_vcpus, h->n_active_vcpus) {
                (*thread)->vcpu_fd = safe_close((*thread)->vcpu_fd);
                (*thread)->vm_fd = -EBADF;
        }
        h->vcpu_fd = safe_close(h->vcpu_fd);
        h->vm_fd = safe_close(h->vm_fd);

        if (syscall(__NR_unshare, CLONE_FILES) < 0)
                return -errno;
        h->files_shared = false;

        next->kvm_fd = fcntl(h->kvm_fd, F_DUPFD_CLOEXEC, 3);
        if (next->kvm_fd < 0)
                return -errno;
        r = exec_hypervisor_create_machine(next);
        if (r <= 0)
                return r < 0 ? r : -EOPNOTSUPP;
        r = exec_hypervisor_run_probe(next);
        if (r < 0)
                return r;
        r = exec_hypervisor_prepare_stack(next, next->deferred_exec_argv, next->deferred_exec_envp);
        if (r < 0)
                return r;

        next->deferred_exec_argv = strv_free(next->deferred_exec_argv);
        next->deferred_exec_envp = strv_free(next->deferred_exec_envp);
        return 0;
}

static int submit_guest_exec_request(
                ExecHypervisor *h,
                ExecHypervisor *replacement) {

        ExecHypervisor *machine;
        int r;

        assert(h);
        assert(replacement);

        machine = exec_hypervisor_machine(h);
        r = install_guest_exec_control_signal(h);
        if (r < 0)
                return r;

        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        if (__atomic_load_n(&machine->exec_request_state, __ATOMIC_ACQUIRE) != GUEST_EXEC_REQUEST_IDLE) {
                assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                return -EAGAIN;
        }

        machine->exec_caller = h->thread_vcpu ? h : NULL;
        machine->exec_replacement = replacement;
        __atomic_store_n(&machine->exec_request_state, GUEST_EXEC_REQUEST_PENDING, __ATOMIC_RELEASE);

        if (h->thread_vcpu) {
                r = interrupt_guest_exec_runner(machine);
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }
        FOREACH_ARRAY(thread, machine->active_vcpus, machine->n_active_vcpus) {
                if (*thread == machine->exec_caller)
                        continue;

                r = interrupt_guest_exec_runner(*thread);
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return 0;
}

static _noreturn_ void commit_guest_replacement(
                ExecHypervisor *h,
                ExecHypervisor *next,
                ExecHypervisor *caller) {

        int r, status;

        assert(h);
        assert(next);
        assert(!h->thread_vcpu);

        r = wait_for_guest_thread_count(h, caller ? 1 : 0);
        if (r < 0)
                _exit(EXIT_FAILURE);
        r = cleanup_guest_robust_list_for_exec(h);
        if (r < 0)
                _exit(EXIT_FAILURE);
        r = cleanup_guest_posix_timers_for_exec(h);
        if (r < 0)
                _exit(EXIT_FAILURE);
        r = cleanup_guest_mlockall_for_exec(h);
        if (r < 0)
                _exit(EXIT_FAILURE);
        r = destroy_guest_aio_contexts(h);
        if (r < 0)
                _exit(EXIT_FAILURE);
        if (syscall(__NR_prctl, PR_SET_NAME, next->comm, 0, 0, 0) < 0)
                _exit(EXIT_FAILURE);
        if (syscall(__NR_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
                _exit(EXIT_FAILURE);
        if (next->deferred_exec_argv) {
                r = finalize_deferred_shared_files_exec(h, next);
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }

        r = close_cloexec_fds_for_guest_exec(h, next);
        if (r < 0)
                _exit(EXIT_FAILURE);
        r = transfer_signal_state_for_guest_exec(h, next);
        if (r < 0)
                _exit(EXIT_FAILURE);

        notify_vfork_parent(h);
        if (caller) {
                if (next->exec_core_sched_supported) {
                        uint64_t cookie = UINT64_MAX;

                        if (syscall(__NR_prctl,
                                    PR_SCHED_CORE,
                                    PR_SCHED_CORE_SHARE_FROM,
                                    caller->runner_tid,
                                    PR_SCHED_CORE_SCOPE_THREAD,
                                    0) < 0 ||
                            syscall(__NR_prctl,
                                    PR_SCHED_CORE,
                                    PR_SCHED_CORE_GET,
                                    0,
                                    PR_SCHED_CORE_SCOPE_THREAD,
                                    &cookie) < 0 ||
                            cookie != next->exec_core_sched_cookie)
                                _exit(EXIT_FAILURE);
                }
                caller->terminate_for_exec = true;
                __atomic_store_n(&h->exec_request_state, GUEST_EXEC_REQUEST_COMMITTED, __ATOMIC_RELEASE);
                (void) syscall(__NR_futex,
                               &h->exec_request_state,
                               FUTEX_WAKE,
                               INT_MAX,
                               NULL,
                               NULL,
                               0);

                r = wait_for_guest_thread_count(h, 0);
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }
        if (!next->exec_signal_mask_set)
                _exit(EXIT_FAILURE);
        r = set_host_signal_mask(&next->exec_signal_mask);
        if (r < 0)
                _exit(EXIT_FAILURE);
        if (!next->exec_timer_slack_set ||
            syscall(__NR_prctl, PR_SET_TIMERSLACK, next->exec_timer_slack, 0, 0, 0) < 0)
                _exit(EXIT_FAILURE);
        if (!next->exec_sched_attr_set)
                _exit(EXIT_FAILURE);
        r = RET_NERRNO(sched_setattr(/* pid= */ 0, &next->exec_sched_attr, /* flags= */ 0));
        if (r < 0)
                _exit(EXIT_FAILURE);
        r = RET_NERRNO(setpriority(PRIO_PROCESS, 0, next->exec_sched_attr.sched_nice));
        if (r < 0)
                _exit(EXIT_FAILURE);
        if (!next->exec_cpu_affinity_set)
                _exit(EXIT_FAILURE);
        r = RET_NERRNO(sched_setaffinity(
                                0,
                                next->exec_cpu_affinity.allocated,
                                next->exec_cpu_affinity.set));
        if (r < 0)
                _exit(EXIT_FAILURE);
        if (next->exec_mempolicy_set) {
                size_t count = cpu_set_count(&next->exec_mempolicy_nodes);

                r = RET_NERRNO(set_mempolicy(
                                        next->exec_mempolicy,
                                        count > 0 ? (unsigned long*) next->exec_mempolicy_nodes.set : NULL,
                                        count > 0 ? next->exec_mempolicy_nodes.allocated * 8 : 0));
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }
                if (!next->exec_ioprio_set ||
                        syscall(__NR_ioprio_set, IOPRIO_WHO_PROCESS, 0, next->exec_ioprio) < 0)
                                _exit(EXIT_FAILURE);
                if (!next->exec_personality_set ||
                        syscall(__NR_personality, next->exec_personality) < 0)
                                _exit(EXIT_FAILURE);
                if (!next->exec_mce_kill_set)
                        _exit(EXIT_FAILURE);
                if (next->exec_mce_kill == PR_MCE_KILL_DEFAULT) {
                        if (syscall(__NR_prctl, PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 0, 0) < 0)
                                _exit(EXIT_FAILURE);
                } else if (syscall(
                                   __NR_prctl,
                                   PR_MCE_KILL,
                                   PR_MCE_KILL_SET,
                                   next->exec_mce_kill,
                                   0,
                                   0) < 0)
                        _exit(EXIT_FAILURE);
                if (!next->exec_pdeathsig_set ||
                        syscall(__NR_prctl, PR_SET_PDEATHSIG, next->exec_pdeathsig, 0, 0, 0) < 0)
                                _exit(EXIT_FAILURE);
                if (next->exec_no_new_privs &&
                        syscall(__NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                                _exit(EXIT_FAILURE);

        if (h->exec_replacement == next)
                h->exec_replacement = NULL;
        (void) exec_hypervisor_free(h);

        r = exec_hypervisor_run(next, &status);
        (void) exec_hypervisor_free(next);
        _exit(r < 0 ? EXIT_FAILURE : status);
}

_noreturn_ void process_guest_exec_request(ExecHypervisor *h) {
        ExecHypervisor *caller, *replacement;

        assert(h);
        assert(!h->thread_vcpu);
        assert(__atomic_load_n(&h->exec_request_state, __ATOMIC_ACQUIRE) == GUEST_EXEC_REQUEST_PENDING);

        caller = h->exec_caller;
        replacement = ASSERT_PTR(h->exec_replacement);
        commit_guest_replacement(h, replacement, caller);
}

static int wait_for_guest_exec_commit(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);
        assert(h->thread_vcpu);

        machine = exec_hypervisor_machine(h);
        while (__atomic_load_n(&machine->exec_request_state, __ATOMIC_ACQUIRE) == GUEST_EXEC_REQUEST_PENDING) {
                long r;

                r = syscall(__NR_futex,
                            &machine->exec_request_state,
                            FUTEX_WAIT,
                            GUEST_EXEC_REQUEST_PENDING,
                            NULL,
                            NULL,
                            0);
                if (r < 0 && !IN_SET(errno, EAGAIN, EINTR))
                        return -errno;
        }

        return h->terminate_for_exec ? 0 : -EIO;
}

static int check_guest_keyrings_for_exec(ExecHypervisor *h) {
        static const int keyrings[] = {
                KEY_SPEC_THREAD_KEYRING,
                KEY_SPEC_PROCESS_KEYRING,
        };
        long session;

        assert(h);

        FOREACH_ELEMENT(keyring, keyrings) {
                long id;

                id = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, *keyring, 0, 0, 0);
                if (id >= 0 || errno != ENOKEY)
                        return -EOPNOTSUPP;
        }

        session = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0, 0, 0);
        if (session < 0 || !h->keyring_policy_initialized || session != h->session_keyring_id)
                return -EOPNOTSUPP;
        if (h->thread_vcpu && session != h->machine->session_keyring_id)
                return -EOPNOTSUPP;

        return 0;
}

static uint64_t replace_guest_image(
                ExecHypervisor *h,
                int *executable_fd,
                const char *executable_path,
                char **argv,
                char **envp) {

        _cleanup_(exec_hypervisor_freep) ExecHypervisor *next = NULL;
        _cleanup_(cpu_set_done) CPUSet cpu_affinity = {};
        _cleanup_(cpu_set_done) CPUSet mempolicy_nodes = {};
        bool core_sched_supported = false, defer_shared_files_finalize, files_committed = false, mempolicy_set;
        struct sched_attr sched_attr = {
                .size = sizeof(sched_attr),
        };
        sigset_t signal_mask;
        long ioprio;
        int mempolicy = MPOL_DEFAULT;
        long mce_kill;
        long timer_slack;
        uint64_t core_sched_cookie = 0;
        int r;

        assert(h);
        assert(executable_fd);
        assert(*executable_fd >= 0);
        assert(argv);

        r = check_guest_keyrings_for_exec(h);
        if (r < 0)
                return (uint64_t) r;
        if (h->machine->n_sealed_ranges > 0)
                return (uint64_t) -ENOEXEC;
        if (strv_length(argv) == 0)
                return (uint64_t) -EINVAL;
        if (h->thread_vcpu && !h->no_new_privs && h->machine->no_new_privs)
                return (uint64_t) -EOPNOTSUPP;
        if (h->thread_vcpu && h->io_flusher != h->machine->io_flusher)
                return (uint64_t) -EOPNOTSUPP;
        if (h->thread_vcpu &&
            (h->io_uring_task_restricted || h->machine->io_uring_task_restricted ||
             h->landlock_restricted || h->machine->landlock_restricted ||
             h->seccomp_local_filter || h->machine->seccomp_local_filter ||
             h->handoff_context_changed || h->machine->handoff_context_changed))
                return (uint64_t) -EOPNOTSUPP;
        r = get_host_signal_mask(&signal_mask);
        if (r < 0)
                return (uint64_t) r;
        timer_slack = syscall(__NR_prctl, PR_GET_TIMERSLACK, 0, 0, 0, 0);
        if (timer_slack < 0)
                return (uint64_t) -errno;
        if (sched_getattr(/* pid= */ 0, &sched_attr, sizeof(sched_attr), /* flags= */ 0) < 0)
                return (uint64_t) -errno;
        if (h->thread_vcpu) {
                if (syscall(__NR_prctl,
                            PR_SCHED_CORE,
                            PR_SCHED_CORE_GET,
                            0,
                            PR_SCHED_CORE_SCOPE_THREAD,
                            &core_sched_cookie) < 0) {
                        if (!IN_SET(errno, EINVAL, ENODEV))
                                return (uint64_t) -errno;
                } else
                        core_sched_supported = true;
        }
        r = get_current_cpu_affinity(&cpu_affinity);
        if (r < 0)
                return (uint64_t) r;
        r = get_current_mempolicy(&mempolicy, &mempolicy_nodes);
        if (r < 0 && r != -ENOSYS)
                return (uint64_t) r;
        mempolicy_set = r >= 0;
        ioprio = syscall(__NR_ioprio_get, IOPRIO_WHO_PROCESS, 0);
        if (ioprio < 0)
                return (uint64_t) -errno;
        errno = 0;
        unsigned long execution_personality = syscall(__NR_personality, ULONG_MAX);
        if (execution_personality == ULONG_MAX && errno != 0)
                return (uint64_t) -errno;
        int pdeathsig;
        if (syscall(__NR_prctl, PR_GET_PDEATHSIG, &pdeathsig, 0, 0, 0) < 0)
                return (uint64_t) -errno;
        mce_kill = syscall(__NR_prctl, PR_MCE_KILL_GET, 0, 0, 0, 0);
        if (mce_kill < 0)
                return (uint64_t) -errno;
        if (!IN_SET(mce_kill, PR_MCE_KILL_DEFAULT, PR_MCE_KILL_EARLY, PR_MCE_KILL_LATE))
                return (uint64_t) -EPROTO;
        r = check_guest_robust_list_for_exec(h);
        if (r < 0)
                return (uint64_t) r;
        r = check_guest_posix_timers_for_exec(h);
        if (r < 0)
                return (uint64_t) r;
        r = check_guest_mlockall_for_exec(h);
        if (r < 0)
                return (uint64_t) r;
        r = check_guest_io_uring_for_exec(h);
        if (r < 0)
                return (uint64_t) r;
        r = check_guest_pending_signals_for_exec(h);
        if (r < 0)
                return (uint64_t) r;
        defer_shared_files_finalize = h->machine->files_shared &&
                (h->thread_vcpu || __atomic_load_n(&h->machine->n_guest_threads, __ATOMIC_ACQUIRE) > 0);

        r = exec_hypervisor_open_existing(h, &next);
        if (r < 0)
                return (uint64_t) r;
        if (r == 0)
                return (uint64_t) -ENOSYS;
        if (next->spec_store_bypass == (PR_SPEC_PRCTL | PR_SPEC_DISABLE_NOEXEC)) {
                next->spec_store_bypass = PR_SPEC_PRCTL | PR_SPEC_ENABLE;
                next->spec_ctrl &= ~X86_SPEC_CTRL_SSBD;
                next->virt_spec_ctrl &= ~X86_SPEC_CTRL_SSBD;
        }
        next->exec_core_sched_supported = core_sched_supported;
        next->exec_core_sched_cookie = core_sched_cookie;
        next->exec_signal_mask = signal_mask;
        next->exec_signal_mask_set = true;
        next->exec_timer_slack = timer_slack;
        next->exec_timer_slack_set = true;
        next->exec_sched_attr = sched_attr;
        next->exec_sched_attr_set = true;
        next->exec_cpu_affinity = TAKE_STRUCT(cpu_affinity);
        next->exec_cpu_affinity_set = true;
        if (mempolicy_set) {
                next->exec_mempolicy = mempolicy;
                next->exec_mempolicy_nodes = TAKE_STRUCT(mempolicy_nodes);
                next->exec_mempolicy_set = true;
        }
        next->exec_ioprio = ioprio;
        next->exec_ioprio_set = true;
        next->exec_personality = execution_personality;
        next->exec_personality_set = true;
        next->exec_mce_kill = mce_kill;
        next->exec_mce_kill_set = true;
        next->exec_pdeathsig = pdeathsig;
        next->exec_pdeathsig_set = true;
        next->exec_no_new_privs = h->no_new_privs;

        r = exec_hypervisor_prepare_image(next, *executable_fd, executable_path);
        if (r < 0)
                return (uint64_t) r;
        if (r == 0)
                return (uint64_t) -ENOEXEC;

        if (defer_shared_files_finalize) {
                next->deferred_exec_argv = strv_copy(argv);
                next->deferred_exec_envp = strv_copy(envp);
                if (!next->deferred_exec_argv || (envp && !next->deferred_exec_envp))
                        return (uint64_t) -ENOMEM;

                next->image_fd = safe_close(next->image_fd);
                next->interpreter_fd = safe_close(next->interpreter_fd);
                next->kvm_fd = safe_close(next->kvm_fd);
                *executable_fd = safe_close(*executable_fd);

                if (h->machine->syscall_filter_set) {
                        r = exec_hypervisor_set_syscall_filter(
                                        next,
                                        h->machine->syscall_filter,
                                        h->machine->syscall_allow_list,
                                        h->machine->syscall_errno_or_action);
                        if (r < 0)
                                return (uint64_t) r;
                }

                r = submit_guest_exec_request(h, next);
                if (r < 0)
                        return (uint64_t) r;
                TAKE_PTR(next);
                if (!h->thread_vcpu)
                        process_guest_exec_request(h);
                return (uint64_t) wait_for_guest_exec_commit(h);
        }

        if (h->machine->files_shared) {
                next->image_fd = safe_close(next->image_fd);
                next->interpreter_fd = safe_close(next->interpreter_fd);
                next->kvm_fd = safe_close(next->kvm_fd);
                *executable_fd = safe_close(*executable_fd);

                FOREACH_ARRAY(thread, h->machine->idle_vcpus, h->machine->n_idle_vcpus)
                        (*thread)->vcpu_fd = safe_close((*thread)->vcpu_fd);
                h->vcpu_fd = safe_close(h->vcpu_fd);
                h->vm_fd = safe_close(h->vm_fd);
                files_committed = true;

                if (syscall(__NR_unshare, CLONE_FILES) < 0)
                        _exit(EXIT_FAILURE);
                h->machine->files_shared = false;

                next->kvm_fd = fcntl(h->machine->kvm_fd, F_DUPFD_CLOEXEC, 3);
                if (next->kvm_fd < 0)
                        _exit(EXIT_FAILURE);
        }

        r = exec_hypervisor_create_machine(next);
        if (r < 0) {
                if (files_committed)
                        _exit(EXIT_FAILURE);
                return (uint64_t) r;
        }
        if (r == 0) {
                if (files_committed)
                        _exit(EXIT_FAILURE);
                return (uint64_t) -ENOSYS;
        }

        r = exec_hypervisor_run_probe(next);
        if (r < 0) {
                if (files_committed)
                        _exit(EXIT_FAILURE);
                return (uint64_t) r;
        }
        r = exec_hypervisor_prepare_stack(next, argv, envp);
        if (r < 0) {
                if (files_committed)
                        _exit(EXIT_FAILURE);
                return (uint64_t) r;
        }

        if (h->machine->syscall_filter_set) {
                r = exec_hypervisor_set_syscall_filter(
                                next,
                                h->machine->syscall_filter,
                                h->machine->syscall_allow_list,
                                h->machine->syscall_errno_or_action);
                if (r < 0) {
                        if (files_committed)
                                _exit(EXIT_FAILURE);
                        return (uint64_t) r;
                }
        }

        if (!h->thread_vcpu &&
            __atomic_load_n(&h->machine->n_guest_threads, __ATOMIC_ACQUIRE) == 0)
                commit_guest_replacement(h, TAKE_PTR(next), NULL);

        r = submit_guest_exec_request(h, next);
        if (r < 0) {
                if (files_committed)
                        _exit(EXIT_FAILURE);
                return (uint64_t) r;
        }
        TAKE_PTR(next);

        if (!h->thread_vcpu)
                process_guest_exec_request(h);

        return (uint64_t) wait_for_guest_exec_commit(h);
}

uint64_t handle_guest_execve(ExecHypervisor *h, const struct kvm_regs *regs) {
        _cleanup_strv_free_ char **argv = NULL, **envp = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int executable_fd = -EBADF;
        size_t argument_budget, path_budget = PATH_MAX;
        int r;

        assert(h);
        assert(regs);

        r = copy_guest_cstring(h, regs->rdi, &path_budget, &path);
        if (r < 0)
                return (uint64_t) r;
        if (isempty(path))
                return (uint64_t) -ENOENT;

        argument_budget = sc_arg_max();
        r = copy_guest_strv(h, regs->rsi, &argument_budget, &argv);
        if (r < 0)
                return (uint64_t) r;
        r = copy_guest_strv(h, regs->rdx, &argument_budget, &envp);
        if (r < 0)
                return (uint64_t) r;

        if (faccessat(AT_FDCWD, path, X_OK, AT_EACCESS) < 0)
                return (uint64_t) -errno;
        executable_fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (executable_fd < 0)
                return (uint64_t) -errno;

        uint64_t result = replace_guest_image(h, &executable_fd, path, argv, envp);
        if (h->terminate_for_exec)
                executable_fd = -EBADF;
        if ((int64_t) result != -ENOEXEC)
                return result;
        if (h->machine->syscall_filter_set)
                return (uint64_t) -ENOSYS;

        execve(path, argv, envp);
        return (uint64_t) -errno;
}

uint64_t handle_guest_execveat(ExecHypervisor *h, const struct kvm_regs *regs) {
        _cleanup_strv_free_ char **argv = NULL, **envp = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int executable_fd = -EBADF;
        size_t argument_budget, path_budget = PATH_MAX;
        int flags, r;

        assert(h);
        assert(regs);

        flags = regs->r8;
        if ((flags & ~(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)) != 0)
                return (uint64_t) -EINVAL;

        r = copy_guest_cstring(h, regs->rsi, &path_budget, &path);
        if (r < 0)
                return (uint64_t) r;
        if (isempty(path) && !FLAGS_SET(flags, AT_EMPTY_PATH))
                return (uint64_t) -ENOENT;

        argument_budget = sc_arg_max();
        r = copy_guest_strv(h, regs->rdx, &argument_budget, &argv);
        if (r < 0)
                return (uint64_t) r;
        r = copy_guest_strv(h, regs->r10, &argument_budget, &envp);
        if (r < 0)
                return (uint64_t) r;

        if (faccessat(regs->rdi,
                      path,
                      X_OK,
                      AT_EACCESS | (flags & AT_SYMLINK_NOFOLLOW) | (isempty(path) ? AT_EMPTY_PATH : 0)) < 0)
                return (uint64_t) -errno;

        if (isempty(path))
                executable_fd = fd_reopen(regs->rdi, O_RDONLY|O_CLOEXEC);
        else {
                executable_fd = openat(
                                regs->rdi,
                                path,
                                O_RDONLY|O_CLOEXEC|O_NOCTTY|
                                        (FLAGS_SET(flags, AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0));
        }
        if (executable_fd < 0)
                return (uint64_t) (isempty(path) ? executable_fd : -errno);

        uint64_t result = replace_guest_image(h, &executable_fd, path, argv, envp);
        if (h->terminate_for_exec)
                executable_fd = -EBADF;
        if ((int64_t) result != -ENOEXEC)
                return result;
        if (h->machine->syscall_filter_set)
                return (uint64_t) -ENOSYS;

        (void) syscall(__NR_execveat, (int) regs->rdi, path, argv, envp, flags);
        return (uint64_t) -errno;
}

static int read_process_memory_exact(pid_t pid, void *destination, const void *source, size_t size) {
        size_t offset = 0;

        assert(pid > 0);
        assert(destination || size == 0);
        assert(source || size == 0);

        while (offset < size) {
                struct iovec local = {
                        .iov_base = (uint8_t*) destination + offset,
                        .iov_len = size - offset,
                };
                struct iovec remote = {
                        .iov_base = (uint8_t*) (uintptr_t) source + offset,
                        .iov_len = size - offset,
                };
                ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (n == 0)
                        return -EIO;
                offset += n;
        }

        return 0;
}

static int synchronize_vfork_mapping_bytes(
                pid_t child,
                uint64_t start,
                size_t size,
                const ExecHypervisorMapping *parent_mapping,
                bool *ret_host_protection_changed) {

        _cleanup_free_ uint8_t *buffer = NULL;
        size_t buffer_size, offset = 0;
        int host_protection;
        bool changed = false;

        assert(child > 0);
        assert(size > 0);
        assert(parent_mapping);
        assert(ret_host_protection_changed);

        buffer_size = MIN(size, page_size());
        buffer = malloc(buffer_size);
        if (!buffer)
                return -ENOMEM;

        host_protection = parent_mapping->protection;
        if (!FLAGS_SET(host_protection, PROT_READ)) {
                host_protection |= PROT_READ;
                if (mprotect((void*) (uintptr_t) start, size, host_protection) < 0)
                        return -errno;
                changed = true;
        }

        while (offset < size) {
                size_t n = MIN(buffer_size, size - offset);
                int r;

                r = read_process_memory_exact(
                                child,
                                buffer,
                                (void*) (uintptr_t) (start + offset),
                                n);
                if (r < 0)
                        return r;
                if (memcmp((void*) (uintptr_t) (start + offset), buffer, n) != 0) {
                        if (!FLAGS_SET(host_protection, PROT_WRITE)) {
                                host_protection |= PROT_WRITE;
                                if (mprotect((void*) (uintptr_t) start, size, host_protection) < 0)
                                        return -errno;
                                changed = true;
                        }
                        memcpy((void*) (uintptr_t) (start + offset), buffer, n);
                }
                offset += n;
        }

        *ret_host_protection_changed = changed;
        return 0;
}

static int set_guest_fork_advice_inheritance(ExecHypervisor *h, bool inherit);

static int mapping_compare_guest_address(const ExecHypervisorMapping *a, const ExecHypervisorMapping *b) {
        assert(a);
        assert(b);

        return CMP(a->guest_virtual_address, b->guest_virtual_address);
}

static bool vfork_mapping_backing_matches(
                const ExecHypervisorMapping *parent_mapping,
                const ExecHypervisorMapping *child_mapping,
                uint64_t start) {

        uint64_t child_offset, parent_offset;

        assert(parent_mapping);
        assert(child_mapping);

        if (parent_mapping->file_backed != child_mapping->file_backed ||
            parent_mapping->shared != child_mapping->shared ||
            parent_mapping->grows_down != child_mapping->grows_down)
                return false;
        if (!parent_mapping->file_backed)
                return true;
        if (parent_mapping->backing_device != child_mapping->backing_device ||
            parent_mapping->backing_inode != child_mapping->backing_inode ||
            !ADD_SAFE(
                                &parent_offset,
                                parent_mapping->file_offset,
                                start - parent_mapping->guest_virtual_address) ||
            !ADD_SAFE(
                                &child_offset,
                                child_mapping->file_offset,
                                start - child_mapping->guest_virtual_address))
                return false;

        return parent_offset == child_offset;
}

static int create_vfork_mapping(
                ExecHypervisor *h,
                pid_t child,
                const ExecHypervisorMapping *child_mapping,
                uint64_t start,
                size_t size,
                bool replace) {

        _cleanup_close_ int backing_fd = -EBADF, pidfd = -EBADF;
        struct kvm_regs regs;
        uint64_t q;

        assert(h);
        assert(child > 0);
        assert(child_mapping);
        assert(size > 0);

        if (child_mapping->file_backed) {
                if (child_mapping->backing_fd < 0)
                        return -ENOSYS;
                pidfd = syscall(__NR_pidfd_open, child, 0);
                if (pidfd < 0)
                        return -errno;
                backing_fd = syscall(__NR_pidfd_getfd, pidfd, child_mapping->backing_fd, 0);
                if (backing_fd < 0)
                        return -errno;
        }

        regs = (struct kvm_regs) {
                .rdi = start,
                .rsi = size,
                .rdx = child_mapping->protection,
                .r10 = (replace ? MAP_FIXED : MAP_FIXED_NOREPLACE) |
                        (child_mapping->file_backed ? 0 : MAP_ANONYMOUS) |
                        (child_mapping->shared ? MAP_SHARED : MAP_PRIVATE) |
                        (child_mapping->grows_down && start == child_mapping->guest_virtual_address ?
                                        MAP_GROWSDOWN : 0),
                .r8 = child_mapping->file_backed ? backing_fd : -1,
                .r9 = child_mapping->file_offset + start - child_mapping->guest_virtual_address,
        };

        q = handle_guest_mmap(h, &regs);
        if ((int64_t) q < 0)
                return (int64_t) q;
        return q == start ? 0 : -EPROTO;
}

static int synchronize_vfork_new_mappings(
                ExecHypervisor *h,
                pid_t child,
                const ExecHypervisorMapping *child_mappings,
                size_t n_child_mappings) {

        ExecHypervisor *machine;

        assert(h);
        assert(child > 0);
        assert(child_mappings || n_child_mappings == 0);

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(child_mapping, child_mappings, n_child_mappings) {
                uint64_t child_end, cursor;

                if (!ADD_SAFE(&child_end, child_mapping->guest_virtual_address, child_mapping->size))
                        return -EOVERFLOW;
                cursor = child_mapping->guest_virtual_address;
                while (cursor < child_end) {
                        ExecHypervisorMapping *parent_mapping = find_mapping(machine, cursor);
                        uint64_t end = child_end;
                        bool host_protection_changed;
                        int r;

                        if (parent_mapping) {
                                uint64_t parent_end;

                                if (!ADD_SAFE(
                                                    &parent_end,
                                                    parent_mapping->guest_virtual_address,
                                                    parent_mapping->size))
                                        return -EOVERFLOW;
                                cursor = MIN(child_end, parent_end);
                                continue;
                        }

                        FOREACH_ARRAY(candidate, machine->mappings, machine->n_mappings)
                                if (candidate->guest_virtual_address > cursor)
                                        end = MIN(end, candidate->guest_virtual_address);
                        r = create_vfork_mapping(
                                        h,
                                        child,
                                        child_mapping,
                                        cursor,
                                        end - cursor,
                                        /* replace= */ false);
                        if (r < 0)
                                return r;
                        parent_mapping = find_mapping(machine, cursor);
                        if (!parent_mapping)
                                return -EFAULT;
                        r = synchronize_vfork_mapping_bytes(
                                        child,
                                        cursor,
                                        end - cursor,
                                        parent_mapping,
                                        &host_protection_changed);
                        if (r < 0)
                                return r;
                        if (host_protection_changed) {
                                uint64_t q = handle_guest_mprotect(
                                                machine,
                                                cursor,
                                                end - cursor,
                                                child_mapping->protection,
                                                /* pkey= */ -1);

                                if ((int64_t) q < 0)
                                        return (int64_t) q;
                        }
                        cursor = end;
                }
        }

        return 0;
}

static int synchronize_vfork_mappings(ExecHypervisor *h, pid_t child) {
        _cleanup_free_ ExecHypervisorMapping *child_mappings = NULL;
        _cleanup_free_ ExecHypervisorMapping *parent_mappings = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *child_dontfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *child_wipeonfork_ranges = NULL;
        ExecHypervisor child_state, *machine;
        size_t dontfork_size, mapping_size, n_parent_mappings, wipeonfork_size;
        int r;

        assert(h);
        assert(child > 0);

        machine = exec_hypervisor_machine(h);
        r = read_process_memory_exact(child, &child_state, h, sizeof(child_state));
        if (r < 0)
                return r;
        if (!MUL_SAFE(&mapping_size, child_state.n_mappings, sizeof(*child_mappings)))
                return -EOVERFLOW;
        if (mapping_size > 0) {
                child_mappings = malloc(mapping_size);
                if (!child_mappings)
                        return -ENOMEM;
                r = read_process_memory_exact(child, child_mappings, child_state.mappings, mapping_size);
                if (r < 0)
                        return r;
                typesafe_qsort(child_mappings, child_state.n_mappings, mapping_compare_guest_address);
        }
        if (!MUL_SAFE(
                            &dontfork_size,
                            child_state.n_dontfork_ranges,
                            sizeof(*child_dontfork_ranges)))
                return -EOVERFLOW;
        if (dontfork_size > 0) {
                child_dontfork_ranges = malloc(dontfork_size);
                if (!child_dontfork_ranges)
                        return -ENOMEM;
                r = read_process_memory_exact(
                                child,
                                child_dontfork_ranges,
                                child_state.dontfork_ranges,
                                dontfork_size);
                if (r < 0)
                        return r;
        }
        if (!MUL_SAFE(
                            &wipeonfork_size,
                            child_state.n_wipeonfork_ranges,
                            sizeof(*child_wipeonfork_ranges)))
                return -EOVERFLOW;
        if (wipeonfork_size > 0) {
                child_wipeonfork_ranges = malloc(wipeonfork_size);
                if (!child_wipeonfork_ranges)
                        return -ENOMEM;
                r = read_process_memory_exact(
                                child,
                                child_wipeonfork_ranges,
                                child_state.wipeonfork_ranges,
                                wipeonfork_size);
                if (r < 0)
                        return r;
        }
        r = begin_guest_memory_transaction(h);
        if (r < 0)
                return r;
        r = set_guest_fork_advice_inheritance(machine, true);
        if (r < 0)
                goto finish;
        if (handle_guest_brk(machine, child_state.heap_break) != child_state.heap_break) {
                r = -EIO;
                goto finish;
        }
        n_parent_mappings = machine->n_mappings;
        if (n_parent_mappings > 0) {
                parent_mappings = memdup(
                                machine->mappings,
                                n_parent_mappings * sizeof(*parent_mappings));
                if (!parent_mappings) {
                        r = -ENOMEM;
                        goto finish;
                }
                typesafe_qsort(parent_mappings, n_parent_mappings, mapping_compare_guest_address);
        }
        FOREACH_ARRAY(original_mapping, parent_mappings, n_parent_mappings)
        {
                uint64_t cursor = original_mapping->guest_virtual_address;
                uint64_t range_end = original_mapping->guest_virtual_address + original_mapping->size;

                FOREACH_ARRAY(child_mapping, child_mappings, child_state.n_mappings) {
                        ExecHypervisorMapping *parent_mapping;
                        uint64_t child_end, start, end;
                        bool host_protection_changed;
                        size_t size;

                        if (!ADD_SAFE(&child_end, child_mapping->guest_virtual_address, child_mapping->size) ||
                            original_mapping->guest_virtual_address >= child_end ||
                            range_end <= child_mapping->guest_virtual_address)
                                continue;
                        start = MAX(original_mapping->guest_virtual_address, child_mapping->guest_virtual_address);
                        start = MAX(start, cursor);
                        end = MIN(range_end, child_end);
                        if (start >= end)
                                continue;
                        if (start > cursor) {
                                if (!original_mapping->mutable) {
                                        r = -ENOSYS;
                                        goto finish;
                                }
                                uint64_t q = handle_guest_munmap(machine, cursor, start - cursor);

                                if ((int64_t) q < 0) {
                                        r = (int64_t) q;
                                        goto finish;
                                }
                        }
                        size = end - start;
                        parent_mapping = find_mapping(machine, start);
                        if (!parent_mapping || start + size > parent_mapping->guest_virtual_address + parent_mapping->size) {
                                r = -ENOSYS;
                                goto finish;
                        }
                        if (!vfork_mapping_backing_matches(parent_mapping, child_mapping, start)) {
                                r = create_vfork_mapping(
                                                machine,
                                                child,
                                                child_mapping,
                                                start,
                                                size,
                                                /* replace= */ true);
                                if (r < 0)
                                        goto finish;
                                parent_mapping = find_mapping(machine, start);
                                if (!parent_mapping) {
                                        r = -EFAULT;
                                        goto finish;
                                }
                        }
                        r = synchronize_vfork_mapping_bytes(
                                        child,
                                        start,
                                        size,
                                        parent_mapping,
                                        &host_protection_changed);
                        if (r < 0)
                                goto finish;
                        if (host_protection_changed ||
                            parent_mapping->protection != child_mapping->protection) {
                                uint64_t q = handle_guest_mprotect(
                                                machine,
                                                start,
                                                size,
                                                child_mapping->protection,
                                                /* pkey= */ -1);

                                if ((int64_t) q < 0) {
                                        r = (int64_t) q;
                                        goto finish;
                                }
                        }
                        cursor = end;
                }
                if (cursor < range_end) {
                        if (!original_mapping->mutable) {
                                r = -ENOSYS;
                                goto finish;
                        }
                        uint64_t q = handle_guest_munmap(machine, cursor, range_end - cursor);

                        if ((int64_t) q < 0) {
                                r = (int64_t) q;
                                goto finish;
                        }
                }
        }

        r = synchronize_vfork_new_mappings(
                        machine,
                        child,
                        child_mappings,
                        child_state.n_mappings);
        if (r < 0)
                goto finish;

        free(machine->dontfork_ranges);
        machine->dontfork_ranges = TAKE_PTR(child_dontfork_ranges);
        machine->n_dontfork_ranges = child_state.n_dontfork_ranges;
        free(machine->wipeonfork_ranges);
        machine->wipeonfork_ranges = TAKE_PTR(child_wipeonfork_ranges);
        machine->n_wipeonfork_ranges = child_state.n_wipeonfork_ranges;
        r = set_guest_fork_advice_inheritance(machine, false);
        if (r < 0)
                goto finish;
        r = 0;
finish:
        if (r < 0 && set_guest_fork_advice_inheritance(machine, false) < 0)
                _exit(EXIT_FAILURE);
        end_guest_memory_transaction(h);
        return r;
}

static int wait_vfork_completion(ExecHypervisor *h, VforkCompletion *completion, pid_t child, int exit_signal) {
        assert(completion);
        assert(child > 0);

        for (;;) {
                const struct timespec timeout = {
                        .tv_sec = 1,
                };
                siginfo_t info = {};
                long n;

                if (__atomic_load_n(&completion->completed, __ATOMIC_ACQUIRE) != 0) {
                        int r = synchronize_vfork_mappings(h, child);

                        __atomic_store_n(&completion->synchronized, 1, __ATOMIC_RELEASE);
                        (void) syscall(__NR_futex,
                                       &completion->synchronized,
                                       FUTEX_WAKE,
                                       INT_MAX,
                                       NULL,
                                       NULL,
                                       0);
                        return r;
                }

                if (waitid(
                                    P_PID,
                                    child,
                                    &info,
                                    WEXITED|WNOHANG|WNOWAIT|(exit_signal == SIGCHLD ? 0 : __WCLONE)) < 0)
                        return -errno;
                if (info.si_pid == child)
                        return 0;

                n = syscall(__NR_futex,
                            &completion->completed,
                            FUTEX_WAIT,
                            0,
                            &timeout,
                            NULL,
                            0);
                if (n < 0 && !IN_SET(errno, EAGAIN, EINTR, ETIMEDOUT))
                        return -errno;
        }
}

static int set_guest_fork_advice_inheritance(ExecHypervisor *h, bool inherit) {
        ExecHypervisor *machine;
        size_t changed_dontfork = 0, changed_wipeonfork = 0;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(range, machine->dontfork_ranges, machine->n_dontfork_ranges) {
                if (madvise(
                                    (void*) (uintptr_t) range->start,
                                    range->length,
                                    inherit ? MADV_DOFORK : MADV_DONTFORK) < 0) {
                        r = -errno;
                        goto rollback;
                }
                changed_dontfork++;
        }
        FOREACH_ARRAY(range, machine->wipeonfork_ranges, machine->n_wipeonfork_ranges) {
                if (madvise(
                                    (void*) (uintptr_t) range->start,
                                    range->length,
                                    inherit ? MADV_KEEPONFORK : MADV_WIPEONFORK) < 0) {
                        r = -errno;
                        goto rollback;
                }
                changed_wipeonfork++;
        }

        return 0;

rollback:
        if (!inherit)
                return r;
        for (size_t i = 0; i < changed_wipeonfork; i++)
                if (madvise(
                                    (void*) (uintptr_t) machine->wipeonfork_ranges[i].start,
                                    machine->wipeonfork_ranges[i].length,
                                    MADV_WIPEONFORK) < 0)
                        _exit(EXIT_FAILURE);
        for (size_t i = 0; i < changed_dontfork; i++)
                if (madvise(
                                    (void*) (uintptr_t) machine->dontfork_ranges[i].start,
                                    machine->dontfork_ranges[i].length,
                                    MADV_DONTFORK) < 0)
                        _exit(EXIT_FAILURE);
        return r;
}

int handle_guest_vfork(
                ExecHypervisor *h,
                struct kvm_regs *regs,
                bool legacy_clone,
                int exit_signal,
                bool set_tls,
                uint64_t tls,
                uint64_t *ret) {

        X86KvmXsave xsave;
        struct kvm_sregs sregs;
        VforkCompletion *completion;
        size_t completion_size;
        pid_t child;
        int r;

        assert(h);
        assert(regs);
        assert(ret);

        if (h->machine->n_userfault_ranges > 0) {
                *ret = (uint64_t) -ENOSYS;
                return 0;
        }
        if (h->thread_vcpu || __atomic_load_n(&h->machine->n_guest_threads, __ATOMIC_ACQUIRE) > 0) {
                *ret = (uint64_t) -ENOSYS;
                return 0;
        }
                if (h->machine->mlockall_current || h->machine->mlockall_future || h->machine->mlock_range_seen ||
                        h->machine->membarrier_registrations != 0) {
                *ret = (uint64_t) -EOPNOTSUPP;
                return 0;
        }
        if (set_tls && tls > UINT64_C(0x00007fffffffffff)) {
                *ret = (uint64_t) -EPERM;
                return 0;
        }
        if (h->vfork_completion) {
                *ret = (uint64_t) -EDEADLK;
                return 0;
        }
        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;
        r = get_vcpu_xsave(h, h->vcpu_fd, &xsave);
        if (r < 0)
                return r;

        if (sizeof(VforkCompletion) > SIZE_MAX - (page_size() - 1))
                return -EOVERFLOW;
        completion_size = PAGE_ALIGN(sizeof(VforkCompletion));
        completion = mmap(NULL,
                          completion_size,
                          PROT_READ|PROT_WRITE,
                          MAP_SHARED|MAP_ANONYMOUS,
                          -1,
                          0);
        if (completion == MAP_FAILED)
                return -errno;
        *completion = (VforkCompletion) {
                .size = completion_size,
        };

        r = set_guest_fork_advice_inheritance(h, true);
        if (r < 0) {
                (void) munmap(completion, completion_size);
                return r;
        }

        child = legacy_clone || exit_signal != SIGCHLD ?
                syscall(__NR_clone, exit_signal, NULL, NULL, NULL, 0) :
                fork();
        if (child < 0) {
                r = -errno;
                if (set_guest_fork_advice_inheritance(h, false) < 0)
                        _exit(EXIT_FAILURE);
                (void) munmap(completion, completion_size);
                *ret = (uint64_t) r;
                return 0;
        }
        if (child == 0) {
                if (set_guest_fork_advice_inheritance(h, false) < 0)
                        _exit(EXIT_FAILURE);
                h->vfork_completion = completion;
                h->posix_timers = mfree(h->posix_timers);
                h->n_posix_timers = 0;
                h->timer_restore_ids = false;
                h->io_uring_used = false;
                h->membarrier_registrations = 0;
                h->mlockall_current = false;
                h->mlockall_future = false;
                h->mlock_range_seen = false;
                h->robust_list_address = 0;
                h->rseq_address = 0;
                h->rseq_length = 0;
                h->rseq_signature = 0;
                h->xfeatures_allocated = h->xfeatures_default;
                h->xsave_frame_size = h->xsave_default_size;
                h->xfd = h->amx_supported ? X86_XFEATURE_MASK_XTILE_DATA : 0;
                h->xfd_err = 0;
                reset_dynamic_xsave(h, &xsave);
                if (set_tls)
                        sregs.fs.base = tls;
                r = recreate_hypervisor_machine_after_fork(h, regs, &sregs, &xsave);
                if (r < 0) {
                        notify_vfork_parent(h);
                        _exit(EXIT_FAILURE);
                }

                *ret = 0;
                return 0;
        }

        if (set_guest_fork_advice_inheritance(h, false) < 0)
                _exit(EXIT_FAILURE);

        r = wait_vfork_completion(h, completion, child, exit_signal);
        (void) munmap(completion, completion_size);
        if (r < 0)
                return r;

        *ret = child;
        return 0;
}

static int handle_guest_process_clone(
                ExecHypervisor *h,
                struct kvm_regs *regs,
                bool legacy_clone,
                int exit_signal,
                uint64_t host_flags,
                uint64_t cgroup,
                uint64_t pidfd,
                uint64_t set_tid,
                uint64_t set_tid_size,
                bool set_tls,
                uint64_t tls,
                uint64_t *ret) {

        ExecHypervisor *machine;
        X86KvmXsave xsave;
        struct kvm_sregs sregs;
        pid_t child;
        bool old_files_shared;
        int r;

        assert(h);
        assert(regs);
        assert(ret);

        if (set_tls && tls > UINT64_C(0x00007fffffffffff)) {
                *ret = (uint64_t) -EPERM;
                return 0;
        }

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges)
                if (!range->features_known || FLAGS_SET(range->features, UFFD_FEATURE_EVENT_FORK)) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }

        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;
        r = get_vcpu_xsave(h, h->vcpu_fd, &xsave);
        if (r < 0)
                return r;

        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        old_files_shared = machine->files_shared;
        if (FLAGS_SET(host_flags, CLONE_FILES))
                machine->files_shared = true;
        if (!legacy_clone && host_flags == 0 && cgroup == 0 && set_tid_size == 0 && exit_signal == SIGCHLD)
                child = fork();
        else if (legacy_clone) {
                assert(cgroup == 0);
                assert(set_tid == 0);
                assert(set_tid_size == 0);

                child = syscall(__NR_clone, host_flags | (uint32_t) exit_signal, NULL, pidfd, NULL, 0);
        }
        else {
                const struct clone_args args = {
                        .flags = host_flags,
                        .exit_signal = exit_signal,
                        .cgroup = cgroup,
                        .pidfd = pidfd,
                        .set_tid = set_tid,
                        .set_tid_size = set_tid_size,
                };

                child = syscall(__NR_clone3, &args, sizeof(args));
        }
        if (child < 0) {
                machine->files_shared = old_files_shared;
                *ret = (uint64_t) -errno;
                assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                return 0;
        }
        if (child == 0) {
                if (h->thread_vcpu) {
                        ExecHypervisor caller = *h;

                        if (caller.run)
                                (void) munmap(caller.run, caller.run_size);
                        safe_close(caller.vcpu_fd);

                        *h = *machine;
                        h->machine = h;
                        h->thread_vcpu = false;
                        h->clear_tid_address = 0;
                        h->io_flusher = caller.io_flusher;
                        h->tsc_disabled = caller.tsc_disabled;
                        h->no_new_privs = caller.no_new_privs;
                        h->io_uring_task_restricted = caller.io_uring_task_restricted;
                        h->landlock_restricted = caller.landlock_restricted;
                        h->seccomp_local_filter = caller.seccomp_local_filter;
                        h->handoff_context_changed = caller.handoff_context_changed;
                        h->spec_ctrl = caller.spec_ctrl;
                        h->virt_spec_ctrl = caller.virt_spec_ctrl;
                        h->spec_store_bypass = caller.spec_store_bypass;
                        h->spec_indirect_branch = caller.spec_indirect_branch;
                        h->spec_l1d_flush = caller.spec_l1d_flush;
                        h->xfeatures_allocated = h->xfeatures_default;
                        h->xsave_frame_size = h->xsave_default_size;
                        h->speculation_policy_initialized = caller.speculation_policy_initialized;
                        h->session_keyring_id = caller.session_keyring_id;
                        h->keyring_policy_initialized = caller.keyring_policy_initialized;
                        h->rseq_address = caller.rseq_address;
                        h->rseq_length = caller.rseq_length;
                        h->rseq_signature = caller.rseq_signature;
                        h->signal_stack = caller.signal_stack;
                        h->n_signal_frames = caller.n_signal_frames;
                        memcpy(h->signal_frames, caller.signal_frames, sizeof(h->signal_frames));
                        memzero(h->pending_signals, sizeof(h->pending_signals));
                        h->vfork_completion = NULL;
                        signal_hypervisor = h;
                        free(machine);
                }
                h->posix_timers = mfree(h->posix_timers);
                h->n_posix_timers = 0;
                h->timer_restore_ids = false;
                h->io_uring_used = false;
                h->membarrier_registrations = 0;
                h->futex_hash_slots = 0;
                h->futex_hash_custom = false;
                h->mlockall_current = false;
                h->mlockall_future = false;
                h->mlock_range_seen = false;
                h->robust_list_address = 0;

                h->xfeatures_allocated = h->xfeatures_default;
                h->xsave_frame_size = h->xsave_default_size;
                h->xfd = h->amx_supported ? X86_XFEATURE_MASK_XTILE_DATA : 0;
                h->xfd_err = 0;
                reset_dynamic_xsave(h, &xsave);

                h->memory_lock = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
                h->quiesce_lock = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
                h->signal_lock = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
                r = reconcile_dontfork_mappings_after_fork(h);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                if (set_tls)
                        sregs.fs.base = tls;
                r = recreate_hypervisor_machine_after_fork(h, regs, &sregs, &xsave);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                h->runner_tid = h->owner_tid = gettid();

                *ret = 0;
                return 0;
        }

        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        *ret = child;
        return 0;
}

int handle_guest_fork(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret) {
        return handle_guest_process_clone(h, regs, false, SIGCHLD, 0, 0, 0, 0, 0, false, 0, ret);
}

static int create_guest_thread_vcpu(
                ExecHypervisor *h,
                const struct kvm_regs *parent_regs,
                uint64_t stack_pointer,
                bool set_tls,
                uint64_t tls,
                uint64_t clear_tid_address,
                ExecHypervisor **ret) {

        _cleanup_(exec_hypervisor_freep) ExecHypervisor *thread = NULL;
        X86KvmXsave xsave;
        struct kvm_sregs sregs;
        struct kvm_regs regs;
        ExecHypervisor *machine;
        uint8_t *tss;
        uint64_t ring0_stack_top, ring0_stack_gpa, tss_gpa;
        long run_size;
        bool reused = false;
        unsigned vcpu_id;
        int r;

        assert(h);
        assert(parent_regs);
        assert(ret);

        machine = ASSERT_PTR(h->machine);
        assert(machine->xstate_profile_initialized);
        assert(machine->xsave_default_size >= X86_AVX_XSAVE_SIZE);

        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        if (machine->n_idle_vcpus > 0) {
                thread = machine->idle_vcpus[--machine->n_idle_vcpus];
                reused = true;
        }
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);

        if (!thread) {
                thread = new(ExecHypervisor, 1);
                if (!thread)
                        return -ENOMEM;

                assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
                r = allocate_supervisor_page(machine, X86_PAGE_WRITE|X86_PAGE_NO_EXECUTE, &tss_gpa, (void**) &tss);
                if (r >= 0)
                        r = allocate_supervisor_page(
                                        machine,
                                        X86_PAGE_WRITE|X86_PAGE_NO_EXECUTE,
                                        &ring0_stack_gpa,
                                        NULL);
                assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                if (r < 0)
                        return r;

                ring0_stack_top = ring0_stack_gpa + page_size();
                memcpy(tss + 4, &ring0_stack_top, sizeof(ring0_stack_top));
        } else {
                tss_gpa = thread->tss_gpa;
                ring0_stack_gpa = thread->ring0_stack_gpa;
        }

        int vcpu_fd = reused ? thread->vcpu_fd : -EBADF;
        struct kvm_run *run = reused ? thread->run : NULL;
        size_t mapped_run_size = reused ? thread->run_size : 0;
        unsigned assigned_vcpu_id = reused ? thread->vcpu_id : 0;

        *thread = *machine;
        thread->machine = machine;
        thread->vcpu_fd = vcpu_fd;
        thread->run = run;
        thread->run_size = mapped_run_size;
        thread->tss_gpa = tss_gpa;
        thread->ring0_stack_gpa = ring0_stack_gpa;
        thread->clear_tid_address = clear_tid_address;
        thread->robust_list_address = 0;
        thread->posix_timers = NULL;
        thread->n_posix_timers = 0;
        thread->timer_restore_ids = false;
        thread->io_uring_used = false;
        thread->membarrier_registrations = 0;
        thread->mlockall_current = false;
        thread->mlockall_future = false;
        thread->mlock_range_seen = false;
        thread->no_new_privs = h->no_new_privs;
        thread->io_flusher = h->io_flusher;
        thread->io_uring_task_restricted = h->io_uring_task_restricted;
        thread->landlock_restricted = h->landlock_restricted;
        thread->seccomp_local_filter = h->seccomp_local_filter;
        thread->handoff_context_changed = h->handoff_context_changed;
        thread->tsc_disabled = h->tsc_disabled;
        thread->spec_ctrl = h->spec_ctrl;
        thread->virt_spec_ctrl = h->virt_spec_ctrl;
        thread->spec_store_bypass = h->spec_store_bypass;
        thread->spec_indirect_branch = h->spec_indirect_branch;
        thread->spec_l1d_flush = h->spec_l1d_flush;
        thread->xfeatures_allocated = machine->xfeatures_default;
        thread->xsave_frame_size = machine->xsave_default_size;
        thread->xfd = machine->amx_supported ? X86_XFEATURE_MASK_XTILE_DATA : 0;
        thread->xfd_err = 0;
        thread->speculation_policy_initialized = h->speculation_policy_initialized;
        thread->session_keyring_id = h->session_keyring_id;
        thread->keyring_policy_initialized = h->keyring_policy_initialized;
        thread->rseq_address = 0;
        thread->rseq_length = 0;
        thread->rseq_signature = 0;
        thread->vcpu_id = assigned_vcpu_id;
        memzero(thread->pending_signals, sizeof(thread->pending_signals));
        memzero(thread->signal_frames, sizeof(thread->signal_frames));
        thread->n_signal_frames = 0;
        thread->signal_stack = (stack_t) {
                .ss_flags = SS_DISABLE,
        };
        thread->vfork_completion = NULL;
        thread->idle_vcpus = NULL;
        thread->n_idle_vcpus = 0;
        thread->active_vcpus = NULL;
        thread->n_active_vcpus = 0;
        thread->exec_caller = NULL;
        thread->exec_replacement = NULL;
        thread->exec_request_state = GUEST_EXEC_REQUEST_IDLE;
        thread->quiesce_requested_generation = 0;
        thread->quiesce_seen_generation = __atomic_load_n(
                        &machine->quiesce_generation,
                        __ATOMIC_ACQUIRE);
        thread->runner_tid = 0;
        thread->thread_vcpu = true;
        thread->terminate_for_exec = false;
        thread->vcpu_in_guest = false;

        if (!reused) {
                vcpu_id = __atomic_fetch_add(&machine->next_vcpu_id, 1, __ATOMIC_RELAXED) + 1;
                thread->vcpu_id = vcpu_id;
                thread->vcpu_fd = ioctl(machine->vm_fd, KVM_CREATE_VCPU, vcpu_id);
                if (thread->vcpu_fd < 0)
                        return -errno;

                r = set_supported_cpuid_fd(machine, thread->vcpu_fd);
                if (r < 0)
                        return r;

                run_size = ioctl(machine->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
                if (run_size < (long) sizeof(struct kvm_run))
                        return run_size < 0 ? -errno : -EPROTO;

                thread->run_size = run_size;
                thread->run = mmap(NULL, thread->run_size, PROT_READ|PROT_WRITE, MAP_SHARED, thread->vcpu_fd, 0);
                if (thread->run == MAP_FAILED) {
                        thread->run = NULL;
                        return -errno;
                }
        }

        r = set_vcpu_syscall_msrs(machine, thread->vcpu_fd);
        if (r < 0)
                return r;

        r = set_vcpu_speculation_msrs(thread, thread->vcpu_fd);
        if (r < 0)
                return r;

        r = set_vcpu_xfd_state(thread, thread->vcpu_fd);
        if (r < 0)
                return r;

        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;
        r = get_vcpu_xsave(h, h->vcpu_fd, &xsave);
        if (r < 0)
                return r;
        reset_dynamic_xsave(machine, &xsave);

        if (set_tls)
                sregs.fs.base = tls;
        sregs.tr.base = tss_gpa;
        if (ioctl(thread->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                return -errno;
        r = set_vcpu_xcr0(machine, thread->vcpu_fd);
        if (r < 0)
                return r;
        r = set_vcpu_xsave(thread->vcpu_fd, &xsave);
        if (r < 0)
                return r;

        regs = *parent_regs;
        regs.rax = 0;
        regs.rip = parent_regs->rcx;
        regs.rflags = parent_regs->r11;
        regs.rsp = stack_pointer;
        if (ioctl(thread->vcpu_fd, KVM_SET_REGS, &regs) < 0)
                return -errno;

        *ret = TAKE_PTR(thread);
        return 0;
}

static int register_active_guest_thread(ExecHypervisor *machine, ExecHypervisor *thread) {
        assert(machine);
        assert(thread);
        assert(!machine->thread_vcpu);

        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        if (__atomic_load_n(&machine->exec_request_state, __ATOMIC_ACQUIRE) != GUEST_EXEC_REQUEST_IDLE) {
                assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                return -EAGAIN;
        }
        if (!GREEDY_REALLOC0(machine->active_vcpus, machine->n_active_vcpus + 1)) {
                assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                return -ENOMEM;
        }

        machine->active_vcpus[machine->n_active_vcpus++] = thread;
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return 0;
}

static void unregister_active_guest_thread(ExecHypervisor *machine, ExecHypervisor *thread) {
        assert(machine);
        assert(thread);
        assert(!machine->thread_vcpu);

        for (size_t i = 0; i < machine->n_active_vcpus; i++)
                if (machine->active_vcpus[i] == thread) {
                        machine->active_vcpus[i] = machine->active_vcpus[--machine->n_active_vcpus];
                        return;
                }

        assert_not_reached();
}

static void* guest_thread_worker(void *userdata) {
        _cleanup_(exec_hypervisor_freep) ExecHypervisor *thread = NULL;
        GuestThreadStart *start = ASSERT_PTR(userdata);
        ExecHypervisor *machine;
        uint64_t clear_tid_address;
        int r, status;

        assert_se(pthread_mutex_lock(&start->mutex) == 0);
        thread = start->thread;
        signal_hypervisor = thread;
        start->tid = gettid();
        thread->runner_tid = start->tid;
        start->ready = true;
        assert_se(pthread_cond_signal(&start->condition) == 0);
        while (!start->start)
                assert_se(pthread_cond_wait(&start->condition, &start->mutex) == 0);
        start->started = true;
        assert_se(pthread_cond_signal(&start->condition) == 0);
        assert_se(pthread_mutex_unlock(&start->mutex) == 0);

        r = exec_hypervisor_run(thread, &status);
        if (r < 0 && !thread->terminate_for_exec)
                log_debug_errno(r, "Guest thread vCPU failed: %m");
        if (thread->terminate_for_exec) {
                if (syscall(__NR_set_robust_list, NULL, sizeof(struct robust_list_head)) < 0)
                        _exit(EXIT_FAILURE);
                thread->robust_list_address = 0;
        }

        if (!thread->thread_vcpu) {
                int exit_status = r < 0 ? EXIT_FAILURE : status;

                thread = exec_hypervisor_free(thread);
                _exit(exit_status);
        }

        clear_tid_address = thread->clear_tid_address;
        machine = thread->machine;
        thread->clear_tid_address = 0;

        signal_hypervisor = NULL;
        clear_guest_tid_address(machine, clear_tid_address);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        unregister_active_guest_thread(machine, thread);
        if (GREEDY_REALLOC0(machine->idle_vcpus, machine->n_idle_vcpus + 1))
                machine->idle_vcpus[machine->n_idle_vcpus++] = TAKE_PTR(thread);
        __atomic_sub_fetch(&machine->n_guest_threads, 1, __ATOMIC_RELEASE);
        (void) syscall(__NR_futex,
                       &machine->n_guest_threads,
                       FUTEX_WAKE,
                       INT_MAX,
                       NULL,
                       NULL,
                       0);
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        thread = exec_hypervisor_free(thread);
        return NULL;
}

static int validate_guest_thread_clone(
                ExecHypervisor *h,
                uint64_t flags,
                uint64_t stack_pointer,
                uint64_t parent_tid_address,
                uint64_t child_tid_address,
                uint64_t tls) {

        const uint64_t required_flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;
        const uint64_t supported_flags = required_flags |
                CLONE_FS |
                CLONE_FILES |
                CLONE_SYSVSEM |
                CLONE_DETACHED |
                CLONE_PARENT |
                CLONE_SETTLS |
                CLONE_PARENT_SETTID |
                CLONE_CHILD_SETTID |
                CLONE_CHILD_CLEARTID;
        const uint64_t copy_time_flags = CLONE_VFORK |
                CLONE_PIDFD |
                CLONE_PTRACE |
                CLONE_UNTRACED |
                CLONE_IO |
                CLONE_NEWNS |
                CLONE_NEWCGROUP |
                CLONE_NEWUTS |
                CLONE_NEWIPC |
                CLONE_NEWNET |
                CLONE_NEWTIME |
                CLONE_INTO_CGROUP |
                CLONE_EMPTY_MNTNS;
        int r;

        assert(h);

        if ((flags & required_flags) != required_flags)
                return -EINVAL;
        if ((flags & (CLONE_NEWUSER|CLONE_NEWPID)) != 0 ||
            FLAGS_SET(flags, CLONE_NEWNS | CLONE_FS) ||
            FLAGS_SET(flags, CLONE_NEWUSER | CLONE_FS) ||
            FLAGS_SET(flags, CLONE_NEWIPC | CLONE_SYSVSEM))
                return -EINVAL;
        if ((flags & ~(supported_flags|copy_time_flags)) != 0)
                return -ENOSYS;
        if (FLAGS_SET(flags, CLONE_SETTLS) && tls > UINT64_C(0x00007fffffffffff))
                return -EPERM;
        if (stack_pointer == 0)
                return -EINVAL;
        r = validate_guest_range(h, stack_pointer - sizeof(uint64_t), sizeof(uint64_t), /* writeable= */ true);
        if (r < 0)
                return r;
        if (FLAGS_SET(flags, CLONE_PARENT_SETTID)) {
                r = validate_guest_range(h, parent_tid_address, sizeof(pid_t), /* writeable= */ true);
                if (r < 0)
                        return r;
        }
        if ((flags & (CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID)) != 0) {
                r = validate_guest_range(h, child_tid_address, sizeof(pid_t), /* writeable= */ true);
                if (r < 0)
                        return r;
        }
        if ((flags & (CLONE_FS|CLONE_FILES|CLONE_SYSVSEM)) != (CLONE_FS|CLONE_FILES|CLONE_SYSVSEM) ||
            (flags & copy_time_flags) != 0)
                return -EOPNOTSUPP;
        return 0;
}

static int handle_guest_thread_clone(
                ExecHypervisor *h,
                struct kvm_regs *regs,
                uint64_t flags,
                uint64_t stack_pointer,
                uint64_t parent_tid_address,
                uint64_t child_tid_address,
                uint64_t tls,
                uint64_t *ret) {

        _cleanup_(exec_hypervisor_freep) ExecHypervisor *thread = NULL;
        GuestThreadStart start = {
                .mutex = PTHREAD_MUTEX_INITIALIZER,
                .condition = PTHREAD_COND_INITIALIZER,
        };
        pthread_attr_t attributes;
        ExecHypervisor *machine;
        pthread_t worker;
        bool registered = false;
        int r;

        assert(h);
        assert(regs);
        assert(ret);

        machine = exec_hypervisor_machine(h);

        r = validate_guest_thread_clone(
                        h,
                        flags,
                        stack_pointer,
                        parent_tid_address,
                        child_tid_address,
                        tls);
        if (r < 0)
                return r;

        r = create_guest_thread_vcpu(
                        h,
                        regs,
                        stack_pointer,
                        FLAGS_SET(flags, CLONE_SETTLS),
                        tls,
                        FLAGS_SET(flags, CLONE_CHILD_CLEARTID) ? child_tid_address : 0,
                        &thread);
        if (r < 0)
                return r;
        start.thread = thread;

        r = pthread_attr_init(&attributes);
        if (r != 0)
                return -r;
        r = register_active_guest_thread(machine, thread);
        if (r >= 0) {
                registered = true;
                r = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
        }
        if (r >= 0)
                r = pthread_create(&worker, &attributes, guest_thread_worker, &start);
        assert_se(pthread_attr_destroy(&attributes) == 0);
        if (r != 0) {
                if (r > 0)
                        r = -r;
                if (registered) {
                        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
                        unregister_active_guest_thread(machine, thread);
                        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
                }
                return r;
        }

        r = reapply_guest_reserved_signal_actions(h);
        if (r < 0)
                _exit(EXIT_FAILURE);

        unsigned n_guest_threads = __atomic_add_fetch(&h->machine->n_guest_threads, 1, __ATOMIC_RELAXED);
        update_guest_futex_hash_after_thread_clone(h->machine, n_guest_threads);
        TAKE_PTR(thread);
        assert_se(pthread_mutex_lock(&start.mutex) == 0);
        while (!start.ready)
                assert_se(pthread_cond_wait(&start.condition, &start.mutex) == 0);

        r = 0;
        if (FLAGS_SET(flags, CLONE_PARENT_SETTID))
                r = copy_to_guest(h, parent_tid_address, &start.tid, sizeof(start.tid));
        if (r >= 0 && FLAGS_SET(flags, CLONE_CHILD_SETTID))
                r = copy_to_guest(h, child_tid_address, &start.tid, sizeof(start.tid));
        start.start = true;
        assert_se(pthread_cond_signal(&start.condition) == 0);
        while (!start.started)
                assert_se(pthread_cond_wait(&start.condition, &start.mutex) == 0);
        assert_se(pthread_mutex_unlock(&start.mutex) == 0);
        assert_se(pthread_cond_destroy(&start.condition) == 0);
        assert_se(pthread_mutex_destroy(&start.mutex) == 0);
        if (r < 0)
                return r;

        *ret = start.tid;
        return 0;
}

int handle_guest_clone(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret) {
        const uint64_t supported_host_flags = CLONE_FILES |
                CLONE_FS |
                CLONE_IO |
                CLONE_PARENT |
                CLONE_PIDFD |
                CLONE_PTRACE |
                CLONE_SYSVSEM |
                CLONE_UNTRACED |
                CLONE_NEWCGROUP |
                CLONE_NEWIPC |
                CLONE_NEWNET |
                CLONE_NEWNS |
                CLONE_NEWPID |
                CLONE_NEWUSER |
                CLONE_NEWUTS;
        const uint64_t allowed_flags = CSIGNAL |
                CLONE_DETACHED |
                CLONE_VM |
                CLONE_VFORK |
                CLONE_CHILD_CLEARTID |
                CLONE_CHILD_SETTID |
                CLONE_PARENT_SETTID |
                CLONE_SETTLS |
                supported_host_flags;
        uint64_t flags, process_flags;
        bool vfork_like;
        int exit_signal;
        int r;

        assert(h);
        assert(regs);
        assert(ret);

        flags = (uint32_t) regs->rdi;
        process_flags = flags & supported_host_flags;
        exit_signal = flags & CSIGNAL;
        if (FLAGS_SET(flags, CLONE_PIDFD | CLONE_PARENT_SETTID) ||
            FLAGS_SET(flags, CLONE_PIDFD | CLONE_DETACHED))
                return -EINVAL;
        if (FLAGS_SET(flags, CLONE_PIDFD) || FLAGS_SET(flags, CLONE_PARENT_SETTID)) {
                r = validate_guest_range(h, regs->rdx, sizeof(pid_t), /* writeable= */ true);
                if (r < 0)
                        return r;
        }
        if (FLAGS_SET(flags, CLONE_THREAD)) {
                if ((unsigned) exit_signal > EXEC_HYPERVISOR_N_SIGNALS)
                        return -EINVAL;
                r = handle_guest_thread_clone(
                                h,
                                regs,
                                flags & ~CSIGNAL,
                                regs->rsi,
                                regs->rdx,
                                regs->r10,
                                regs->r8,
                                ret);
                return r;
        }

        vfork_like = FLAGS_SET(flags, CLONE_VM | CLONE_VFORK);
        if (FLAGS_SET(flags, CLONE_VM) != FLAGS_SET(flags, CLONE_VFORK) ||
            (vfork_like && process_flags != 0) ||
            (flags & ~allowed_flags) != 0 ||
            regs->rsi != 0)
                return -ENOSYS;
        if (FLAGS_SET(flags, CLONE_CHILD_SETTID) || FLAGS_SET(flags, CLONE_CHILD_CLEARTID)) {
                r = validate_guest_range(h, regs->r10, sizeof(pid_t), /* writeable= */ true);
                if (r < 0)
                        return r;
        }

        r = vfork_like ?
                handle_guest_vfork(
                                h,
                                regs,
                                true,
                                exit_signal,
                                FLAGS_SET(flags, CLONE_SETTLS),
                                regs->r8,
                                ret) :
                handle_guest_process_clone(
                                h,
                                regs,
                                true,
                                exit_signal,
                                process_flags,
                                0,
                                FLAGS_SET(flags, CLONE_PIDFD) ? regs->rdx : 0,
                                0,
                                0,
                                FLAGS_SET(flags, CLONE_SETTLS),
                                regs->r8,
                                ret);
        if (r < 0 || (int64_t) *ret < 0)
                return r;

        if (*ret == 0) {
                pid_t tid = gettid();

                if (FLAGS_SET(flags, CLONE_CHILD_SETTID)) {
                        r = copy_to_guest(h, regs->r10, &tid, sizeof(tid));
                        if (r < 0)
                                return r;
                }
                if (FLAGS_SET(flags, CLONE_CHILD_CLEARTID))
                        h->clear_tid_address = regs->r10;
        } else if (FLAGS_SET(flags, CLONE_PARENT_SETTID)) {
                pid_t tid = *ret;

                r = copy_to_guest(h, regs->rdx, &tid, sizeof(tid));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int clear_guest_caught_signal_actions(ExecHypervisor *h) {
        GuestSignalAction default_action = {};
        ExecHypervisor *machine;
        int r = 0;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        for (int signo = 1; signo <= (int) EXEC_HYPERVISOR_N_SIGNALS; signo++) {
                if (!machine->signal_actions_initialized[signo] ||
                    machine->signal_actions[signo].handler <= 1)
                        continue;

                r = set_host_signal_action(h, signo, &default_action);
                if (r < 0)
                        break;
                machine->signal_actions[signo] = default_action;
        }
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);

        return r;
}

int handle_guest_clone3(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret) {
        const uint64_t supported_host_flags = CLONE_FILES |
                CLONE_FS |
                CLONE_INTO_CGROUP |
                CLONE_IO |
                CLONE_PARENT |
                CLONE_PIDFD |
                CLONE_PTRACE |
                CLONE_SYSVSEM |
                CLONE_UNTRACED |
                CLONE_NEWCGROUP |
                CLONE_NEWIPC |
                CLONE_NEWNET |
                CLONE_NEWNS |
                CLONE_NEWPID |
                CLONE_NEWTIME |
                CLONE_NEWUSER |
                CLONE_NEWUTS;
        const uint64_t allowed_flags = CLONE_VM |
                CLONE_VFORK |
                CLONE_PIDFD |
                CLONE_CLEAR_SIGHAND |
                CLONE_CHILD_CLEARTID |
                CLONE_CHILD_SETTID |
                CLONE_PARENT_SETTID |
                CLONE_SETTLS |
                supported_host_flags;
        struct clone_args args = {};
        bool vfork_like;
        uint64_t host_flags;
        size_t size;
        int r;

        assert(h);
        assert(regs);
        assert(ret);

        if (regs->rsi > page_size())
                return -E2BIG;
        if (regs->rsi < CLONE_ARGS_SIZE_VER0)
                return -EINVAL;
        size = MIN((uint64_t) sizeof(args), regs->rsi);
        r = copy_from_guest(h, &args, regs->rdi, size);
        if (r < 0)
                return r;
        for (size_t offset = sizeof(args); offset < regs->rsi;) {
                uint8_t buffer[64];
                uint64_t address;
                size_t n = MIN(sizeof(buffer), regs->rsi - offset);

                if (!ADD_SAFE(&address, regs->rdi, offset))
                        return -EFAULT;
                r = copy_from_guest(h, buffer, address, n);
                if (r < 0)
                        return r;
                if (!memeqzero(buffer, n))
                        return -E2BIG;
                offset += n;
        }
        if ((!args.set_tid && args.set_tid_size > 0) || (args.set_tid && args.set_tid_size == 0) ||
            args.set_tid_size > EXEC_HYPERVISOR_MAX_PID_NS_LEVEL)
                return -EINVAL;
        if (args.set_tid_size > 0) {
                size_t set_tid_size;

                if (!MUL_SAFE(&set_tid_size, args.set_tid_size, sizeof(pid_t)))
                        return -EOVERFLOW;
                r = validate_guest_range(h, args.set_tid, set_tid_size, /* writeable= */ false);
                if (r < 0)
                        return r;
        }
        if (FLAGS_SET(args.flags, CLONE_DETACHED))
                return -EINVAL;
        if (args.exit_signal > EXEC_HYPERVISOR_N_SIGNALS ||
            FLAGS_SET(args.flags, CLONE_SIGHAND | CLONE_CLEAR_SIGHAND) ||
            (FLAGS_SET(args.flags, CLONE_THREAD) && !FLAGS_SET(args.flags, CLONE_SIGHAND)) ||
            (FLAGS_SET(args.flags, CLONE_SIGHAND) && !FLAGS_SET(args.flags, CLONE_VM)) ||
            (FLAGS_SET(args.flags, CLONE_PARENT) && args.exit_signal != 0) ||
            FLAGS_SET(args.flags, CLONE_NEWNS | CLONE_FS) ||
            FLAGS_SET(args.flags, CLONE_NEWUSER | CLONE_FS) ||
            FLAGS_SET(args.flags, CLONE_NEWIPC | CLONE_SYSVSEM) ||
            (FLAGS_SET(args.flags, CLONE_THREAD) &&
             (args.flags & (CLONE_NEWUSER | CLONE_NEWPID | CLONE_AUTOREAP | CLONE_NNP |
                            CLONE_PIDFD_AUTOKILL)) != 0) ||
            (FLAGS_SET(args.flags, CLONE_THREAD | CLONE_EMPTY_MNTNS) && FLAGS_SET(args.flags, CLONE_FS)))
                return -EINVAL;
        if (FLAGS_SET(args.flags, CLONE_INTO_CGROUP) &&
            (args.cgroup > INT_MAX || regs->rsi < CLONE_ARGS_SIZE_VER2))
                return -EINVAL;
        if (FLAGS_SET(args.flags, CLONE_PIDFD)) {
                if (args.pidfd == 0)
                        return -EFAULT;
                if (FLAGS_SET(args.flags, CLONE_PARENT_SETTID) && args.pidfd == args.parent_tid)
                        return -EINVAL;
                r = validate_guest_range(h, args.pidfd, sizeof(int), /* writeable= */ true);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(args.flags, CLONE_THREAD)) {
                uint64_t stack_pointer;

                if (args.exit_signal != 0)
                        return -EINVAL;
                if (!ADD_SAFE(&stack_pointer, args.stack, args.stack_size))
                        return -EOVERFLOW;
                r = validate_guest_thread_clone(
                                h,
                                args.flags,
                                stack_pointer,
                                args.parent_tid,
                                args.child_tid,
                                args.tls);
                if (r < 0)
                        return r;
                if (args.set_tid_size != 0) {
                        pid_t set_tid[EXEC_HYPERVISOR_MAX_PID_NS_LEVEL];

                        r = copy_from_guest(
                                        h,
                                        set_tid,
                                        args.set_tid,
                                        args.set_tid_size * sizeof(pid_t));
                        if (r < 0)
                                return r;
                        for (size_t i = 0; i < args.set_tid_size; i++)
                                if (set_tid[i] <= 0)
                                        return -EINVAL;
                        return -EOPNOTSUPP;
                }
                return handle_guest_thread_clone(
                                h,
                                regs,
                                args.flags,
                                stack_pointer,
                                args.parent_tid,
                                args.child_tid,
                                args.tls,
                                ret);
        }

        vfork_like = FLAGS_SET(args.flags, CLONE_VM|CLONE_VFORK);
        host_flags = args.flags & supported_host_flags;
        if ((FLAGS_SET(args.flags, CLONE_VM) != FLAGS_SET(args.flags, CLONE_VFORK)) ||
            (args.flags & ~allowed_flags) != 0 ||
            (vfork_like && host_flags != 0) ||
            args.stack != 0 ||
            args.stack_size != 0)
                return -ENOSYS;

        if (FLAGS_SET(args.flags, CLONE_PARENT_SETTID)) {
                r = validate_guest_range(h, args.parent_tid, sizeof(pid_t), /* writeable= */ true);
                if (r < 0)
                        return r;
        }
        if (FLAGS_SET(args.flags, CLONE_CHILD_SETTID) || FLAGS_SET(args.flags, CLONE_CHILD_CLEARTID)) {
                r = validate_guest_range(h, args.child_tid, sizeof(pid_t), /* writeable= */ true);
                if (r < 0)
                        return r;
        }

        r = vfork_like ?
                handle_guest_vfork(
                                h,
                                regs,
                                false,
                                args.exit_signal,
                                FLAGS_SET(args.flags, CLONE_SETTLS),
                                args.tls,
                                ret) :
                handle_guest_process_clone(
                                h,
                                regs,
                                false,
                                args.exit_signal,
                                host_flags,
                                args.cgroup,
                                args.pidfd,
                                args.set_tid,
                                args.set_tid_size,
                                FLAGS_SET(args.flags, CLONE_SETTLS),
                                args.tls,
                                ret);
        if (r < 0 || (int64_t) *ret < 0)
                return r;

        if (*ret == 0) {
                pid_t tid = gettid();

                if (FLAGS_SET(args.flags, CLONE_CLEAR_SIGHAND)) {
                        r = clear_guest_caught_signal_actions(h);
                        if (r < 0)
                                return r;
                }

                if (FLAGS_SET(args.flags, CLONE_CHILD_SETTID)) {
                        r = copy_to_guest(h, args.child_tid, &tid, sizeof(tid));
                        if (r < 0)
                                return r;
                }
                if (FLAGS_SET(args.flags, CLONE_CHILD_CLEARTID))
                        h->clear_tid_address = args.child_tid;
        } else {
                pid_t tid = *ret;

                if (FLAGS_SET(args.flags, CLONE_PARENT_SETTID)) {
                        r = copy_to_guest(h, args.parent_tid, &tid, sizeof(tid));
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int socket_timeout_is_set(int fd, int option) {
        struct timeval timeout;
        socklen_t timeout_size = sizeof(timeout);

        if (getsockopt(fd, SOL_SOCKET, option, &timeout, &timeout_size) < 0)
                return -errno;
        if (timeout_size != sizeof(timeout))
                return -EIO;

        return timeout.tv_sec != 0 || timeout.tv_usec != 0;
}

bool guest_syscall_should_restart(
                ExecHypervisor *h,
                uint32_t syscall_number,
                uint64_t argument1,
                uint64_t argument2,
                uint64_t argument3,
                uint64_t argument4) {

        bool restart = false;
        int r;

        assert(h);

        if (IN_SET(syscall_number, __NR_accept, __NR_accept4, __NR_recvfrom, __NR_recvmsg, __NR_recvmmsg)) {
                if (socket_timeout_is_set((int) argument1, SO_RCVTIMEO) != 0)
                        return false;
        } else if (IN_SET(syscall_number, __NR_connect, __NR_sendmmsg, __NR_sendmsg, __NR_sendto)) {
                if (socket_timeout_is_set((int) argument1, SO_SNDTIMEO) != 0)
                        return false;
        } else if (IN_SET(syscall_number, __NR_read, __NR_readv)) {
                r = socket_timeout_is_set((int) argument1, SO_RCVTIMEO);
                if (r > 0 || (r < 0 && r != -ENOTSOCK))
                        return false;
        } else if (IN_SET(syscall_number, __NR_write, __NR_writev)) {
                r = socket_timeout_is_set((int) argument1, SO_SNDTIMEO);
                if (r > 0 || (r < 0 && r != -ENOTSOCK))
                        return false;
        }

        if (syscall_number == __NR_fcntl) {
                if (!IN_SET(argument2, F_SETLKW, F_OFD_SETLKW))
                        return false;
        } else if (syscall_number == __NR_flock) {
                if (!IN_SET(argument2, LOCK_SH, LOCK_EX))
                        return false;
        } else if (syscall_number == __NR_futex) {
                if (!IN_SET(argument2 & FUTEX_CMD_MASK, FUTEX_WAIT, FUTEX_WAIT_BITSET) || argument4 != 0)
                        return false;
        } else if (syscall_number == __NR_ioctl) {
                if (argument2 != TCXONC || !IN_SET(argument3, TCIOFF, TCION))
                        return false;
        } else if (!IN_SET(syscall_number, __NR_futex_wait, __NR_futex_waitv) &&
                   !IN_SET(
                            syscall_number,
                            __NR_accept,
                            __NR_accept4,
                            __NR_connect,
                            __NR_getrandom,
                            __NR_mq_timedreceive,
                            __NR_mq_timedsend,
                            __NR_open,
                            __NR_openat,
                            __NR_openat2,
                            __NR_read,
                            __NR_readv,
                            __NR_recvfrom,
                            __NR_recvmmsg,
                            __NR_recvmsg,
                            __NR_sendmmsg,
                            __NR_sendmsg,
                            __NR_sendto,
                            __NR_wait4,
                            __NR_waitid,
                            __NR_write,
                            __NR_writev))
                return false;

        assert_se(pthread_mutex_lock(&h->machine->signal_lock) == 0);
        for (int signo = 1; signo <= (int) EXEC_HYPERVISOR_N_SIGNALS; signo++)
                if (__atomic_load_n(&h->pending_signals[signo].pending, __ATOMIC_ACQUIRE) != 0 &&
                    h->machine->signal_actions[signo].handler > 1 &&
                    FLAGS_SET(h->machine->signal_actions[signo].flags, SA_RESTART)) {
                        restart = true;
                        break;
                }
        assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);

        return restart;
}

int wait_for_guest_threads(ExecHypervisor *h) {
        return wait_for_guest_thread_count(h, 0);
}

#endif

