/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-hypervisor-internal.h"

#if defined(__x86_64__)

int host_signal_action(
                int signo,
                const GuestSignalAction *action,
                GuestSignalAction *old_action) {

        assert(signo > 0 && signo <= (int) EXEC_HYPERVISOR_N_SIGNALS);

        if (syscall(__NR_rt_sigaction, signo, action, old_action, sizeof(uint64_t)) < 0)
                return -errno;

        return 0;
}

int get_host_signal_mask(sigset_t *ret) {
        uint64_t mask;

        assert(ret);

        if (syscall(__NR_rt_sigprocmask, SIG_SETMASK, NULL, &mask, sizeof(mask)) < 0)
                return -errno;

        assert_se(sigemptyset(ret) >= 0);
        memcpy(ret, &mask, sizeof(mask));
        return 0;
}

int set_host_signal_mask(const sigset_t *mask) {
        uint64_t kernel_mask;

        assert(mask);

        memcpy(&kernel_mask, mask, sizeof(kernel_mask));
        if (syscall(__NR_rt_sigprocmask, SIG_SETMASK, &kernel_mask, NULL, sizeof(kernel_mask)) < 0)
                return -errno;

        return 0;
}

typedef struct GuestPselectSigsetArgpack {
        uint64_t mask;
        uint64_t size;
} GuestPselectSigsetArgpack;

typedef struct GuestWaitSignalMasks {
        bool valid;
        sigset_t frame;
        sigset_t handler;
} GuestWaitSignalMasks;

static int prepare_guest_wait_signal_masks(
                ExecHypervisor *h,
                const struct kvm_regs *regs,
                GuestWaitSignalMasks *ret_masks) {

        GuestPselectSigsetArgpack argpack;
        uint64_t address, kernel_mask, size;
        int r;

        assert(h);
        assert(regs);
        assert(ret_masks);

        *ret_masks = (GuestWaitSignalMasks) {};
        switch (regs->rax) {
        case __NR_pselect6:
                if (regs->r9 == 0)
                        return 0;
                r = copy_from_guest(h, &argpack, regs->r9, sizeof(argpack));
                if (r < 0)
                        return 0;
                address = argpack.mask;
                size = argpack.size;
                break;
        case __NR_ppoll:
                address = regs->r10;
                size = regs->r8;
                break;
        case __NR_epoll_pwait:
        case __NR_epoll_pwait2:
                address = regs->r8;
                size = regs->r9;
                break;
        default:
                return -EINVAL;
        }

        if (address == 0 || size != sizeof(kernel_mask))
                return 0;
        r = copy_from_guest(h, &kernel_mask, address, sizeof(kernel_mask));
        if (r < 0)
                return 0;
        r = get_host_signal_mask(&ret_masks->frame);
        if (r < 0)
                return r;
        assert_se(sigemptyset(&ret_masks->handler) >= 0);
        memcpy(&ret_masks->handler, &kernel_mask, sizeof(kernel_mask));
        (void) sigdelset(&ret_masks->handler, SIGKILL);
        (void) sigdelset(&ret_masks->handler, SIGSTOP);
        ret_masks->valid = true;
        return 0;
}

static void arm_guest_wait_signal_masks(ExecHypervisor *h, const GuestWaitSignalMasks *masks) {
        assert(h);
        assert(masks);

        if (!masks->valid)
                return;
        for (int signo = 1; signo <= (int) EXEC_HYPERVISOR_N_SIGNALS; signo++) {
                if (__atomic_load_n(&h->pending_signals[signo].pending, __ATOMIC_ACQUIRE) == 0 ||
                    sigismember(&masks->handler, signo) != 0)
                        continue;

                h->wait_signal_frame_mask = masks->frame;
                h->wait_signal_handler_mask = masks->handler;
                h->wait_signal_signo = signo;
                return;
        }
}

uint64_t handle_guest_masked_wait(ExecHypervisor *h, const struct kvm_regs *regs) {
        GuestWaitSignalMasks masks;
        uint64_t result;
        int r;

        assert(h);
        assert(regs);

        r = prepare_guest_wait_signal_masks(h, regs, &masks);
        if (r < 0)
                return (uint64_t) r;
        result = raw_host_syscall(regs);
        if ((int64_t) result == -EINTR)
                arm_guest_wait_signal_masks(h, &masks);
        return result;
}

int initialize_guest_signal_action(ExecHypervisor *h, int signo) {
        ExecHypervisor *machine;
        GuestSignalAction action;

        assert(h);
        assert(signo > 0 && signo <= (int) EXEC_HYPERVISOR_N_SIGNALS);

        machine = ASSERT_PTR(h->machine);
        if (machine->signal_actions_initialized[signo])
                return 0;
        int r = host_signal_action(signo, NULL, &action);
        if (r < 0)
                return r;

        machine->saved_host_signal_actions[signo] = action;
        machine->signal_actions[signo].handler = action.handler == (uintptr_t) SIG_IGN ? 1 : 0;
        machine->signal_actions_initialized[signo] = true;
        return 0;
}

int set_host_signal_action(ExecHypervisor *h, int signo, const GuestSignalAction *action) {
        ExecHypervisor *machine;
        GuestSignalAction host_action = {};

        assert(h);
        assert(signo > 0 && signo <= (int) EXEC_HYPERVISOR_N_SIGNALS);
        assert(action);

        machine = ASSERT_PTR(h->machine);
        if (action->handler == 0)
                host_action.handler = (uintptr_t) SIG_DFL;
        else if (action->handler == 1)
                host_action.handler = (uintptr_t) SIG_IGN;
        else {
                host_action.handler = (uintptr_t) hypervisor_signal_handler;
                host_action.flags = SA_SIGINFO |
                        SA_RESTORER |
                        (action->flags & (SA_NOCLDSTOP|SA_NOCLDWAIT));
                host_action.restorer = (uintptr_t) exec_hypervisor_restore_rt;
        }

        int r = host_signal_action(signo, &host_action, NULL);
        if (r < 0)
                return r;

        machine->host_signal_actions_modified[signo] = true;
        signal_hypervisor = h;
        return 0;
}

int reapply_guest_reserved_signal_actions(ExecHypervisor *h) {
        static const int reserved_signals[] = { 32, 33 };
        ExecHypervisor *machine;
        int r = 0;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        FOREACH_ELEMENT(signo, reserved_signals)
                if (machine->signal_actions_initialized[*signo] &&
                    machine->signal_actions[*signo].handler > 1) {
                        r = set_host_signal_action(h, *signo, machine->signal_actions + *signo);
                        if (r < 0)
                                break;
                }
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);

        return r;
}

uint64_t handle_guest_rt_sigaction(
                ExecHypervisor *h,
                uint64_t signo,
                uint64_t action_address,
                uint64_t old_action_address,
                uint64_t sigset_size) {

        GuestSignalAction action;
        ExecHypervisor *machine;
        int r;

        assert(h);
        machine = ASSERT_PTR(h->machine);

        if (signo == 0 || signo > EXEC_HYPERVISOR_N_SIGNALS || sigset_size != sizeof(uint64_t))
                return (uint64_t) -EINVAL;
        if (IN_SET(signo, SIGKILL, SIGSTOP) && action_address != 0)
                return (uint64_t) -EINVAL;

        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        r = initialize_guest_signal_action(h, signo);
        if (r < 0)
                goto finish;

        if (old_action_address != 0) {
                r = copy_to_guest(
                                h,
                                old_action_address,
                                machine->signal_actions + signo,
                                sizeof(machine->signal_actions[signo]));
                if (r < 0)
                        goto finish;
        }
        if (action_address == 0) {
                r = 0;
                goto finish;
        }

        r = copy_from_guest(h, &action, action_address, sizeof(action));
        if (r < 0)
                goto finish;
        if (action.handler > 1 && !FLAGS_SET(action.flags, SA_RESTORER)) {
                r = -ENOSYS;
                goto finish;
        }

        r = set_host_signal_action(h, signo, &action);
        if (r < 0)
                goto finish;

        machine->signal_actions[signo] = action;
        r = 0;

finish:
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return (uint64_t) r;
}

static bool guest_on_signal_stack(const ExecHypervisor *h, uint64_t stack_pointer) {
        uint64_t end;

        assert(h);

        if (FLAGS_SET(h->signal_stack.ss_flags, SS_DISABLE|SS_AUTODISARM) ||
            !ADD_SAFE(&end, (uintptr_t) h->signal_stack.ss_sp, h->signal_stack.ss_size))
                return false;

        return stack_pointer > (uintptr_t) h->signal_stack.ss_sp && stack_pointer <= end;
}

uint64_t handle_guest_sigaltstack(
                ExecHypervisor *h,
                uint64_t stack_address,
                uint64_t old_stack_address,
                uint64_t stack_pointer) {

        stack_t stack;
        ExecHypervisor *machine;
        bool on_stack;
        int r = 0;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        on_stack = guest_on_signal_stack(h, stack_pointer);
        if (old_stack_address != 0) {
                stack = h->signal_stack;
                if (on_stack)
                        stack.ss_flags |= SS_ONSTACK;

                r = copy_to_guest(h, old_stack_address, &stack, sizeof(stack));
                if (r < 0)
                        goto finish;
        }
        if (stack_address == 0)
                goto finish;
        if (on_stack) {
                r = -EPERM;
                goto finish;
        }

        r = copy_from_guest(h, &stack, stack_address, sizeof(stack));
        if (r < 0)
                goto finish;
        if ((stack.ss_flags & ~(SS_DISABLE|SS_AUTODISARM)) != 0) {
                r = -EINVAL;
                goto finish;
        }

        if (FLAGS_SET(stack.ss_flags, SS_DISABLE))
                h->signal_stack = (stack_t) {
                        .ss_flags = SS_DISABLE,
                };
        else {
                uint64_t end;

                if (stack.ss_size < guest_min_signal_stack_size(h->machine->xsave_permitted_size) ||
                    !ADD_SAFE(&end, (uintptr_t) stack.ss_sp, stack.ss_size) ||
                    end > UINT64_C(0x0000800000000000)) {
                        r = -ENOMEM;
                        goto finish;
                }

                stack.ss_flags &= SS_AUTODISARM;
                h->signal_stack = stack;
        }

finish:
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
        return (uint64_t) r;
}

static void restore_guest_signal_stack(ExecHypervisor *h, const stack_t *stack) {
        ExecHypervisor *machine;
        uint64_t end;

        assert(h);
        assert(stack);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        if ((stack->ss_flags & ~(SS_DISABLE|SS_AUTODISARM)) != 0)
                goto finish;

        if (FLAGS_SET(stack->ss_flags, SS_DISABLE)) {
                h->signal_stack = (stack_t) {
                        .ss_flags = SS_DISABLE,
                };
                goto finish;
        }

        if (stack->ss_size < guest_min_signal_stack_size(h->machine->xsave_permitted_size) ||
            !ADD_SAFE(&end, (uintptr_t) stack->ss_sp, stack->ss_size) ||
            end > UINT64_C(0x0000800000000000))
                goto finish;

        h->signal_stack = *stack;
        h->signal_stack.ss_flags &= SS_AUTODISARM;

finish:
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);
}

static int request_guest_xcomp_permission(ExecHypervisor *h) {
        ExecHypervisor *machine;
        size_t minimum_size;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (!machine->amx_supported)
                return -EOPNOTSUPP;
        if (FLAGS_SET(machine->xfeatures_permitted, X86_XFEATURE_MASK_XTILE_DATA))
                return 0;

        r = begin_guest_quiescence(h);
        if (r < 0)
                return r;

        minimum_size = guest_min_signal_stack_size(machine->xsave_size);
        assert_se(pthread_mutex_lock(&machine->signal_lock) == 0);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        if ((!FLAGS_SET(machine->signal_stack.ss_flags, SS_DISABLE) &&
             machine->signal_stack.ss_size < minimum_size))
                r = -ENOSPC;
        else {
                FOREACH_ARRAY(thread, machine->active_vcpus, machine->n_active_vcpus)
                        if (!FLAGS_SET((*thread)->signal_stack.ss_flags, SS_DISABLE) &&
                            (*thread)->signal_stack.ss_size < minimum_size) {
                                r = -ENOSPC;
                                break;
                        }

                if (r >= 0) {
                        machine->xfeatures_permitted = machine->xfeatures;
                        machine->xsave_permitted_size = machine->xsave_size;
                }
        }
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        assert_se(pthread_mutex_unlock(&machine->signal_lock) == 0);

        end_guest_quiescence(h);
        return r;
}

uint64_t handle_guest_arch_prctl(ExecHypervisor *h, uint64_t operation, uint64_t address) {
        struct kvm_sregs sregs;
        int r;

        assert(h);

        switch (operation) {
        case ARCH_GET_CPUID:
                return 1;

        case ARCH_SET_CPUID:
                if (address > 1)
                        return (uint64_t) -EINVAL;
                return address == 1 ? 0 : (uint64_t) -EOPNOTSUPP;

        case ARCH_GET_XCOMP_SUPP:
        case ARCH_GET_XCOMP_GUEST_PERM:
                r = copy_to_guest(h, address, &h->machine->xfeatures, sizeof(h->machine->xfeatures));
                return r < 0 ? (uint64_t) r : 0;

        case ARCH_GET_XCOMP_PERM:
                r = copy_to_guest(h, address,
                                  &h->machine->xfeatures_permitted,
                                  sizeof(h->machine->xfeatures_permitted));
                return r < 0 ? (uint64_t) r : 0;

        case ARCH_REQ_XCOMP_PERM:
                if (address >= X86_XFEATURE_MAX)
                        return (uint64_t) -EINVAL;
                if (address != ARCH_XCOMP_TILEDATA)
                        return (uint64_t) -EOPNOTSUPP;

                r = request_guest_xcomp_permission(h);
                return r < 0 ? (uint64_t) r : 0;

        case ARCH_REQ_XCOMP_GUEST_PERM:
                if (address >= X86_XFEATURE_MAX)
                        return (uint64_t) -EINVAL;
                if (address != ARCH_XCOMP_TILEDATA || !h->machine->amx_supported)
                        return (uint64_t) -EOPNOTSUPP;
                return 0;

        case ARCH_GET_UNTAG_MASK: {
                uint64_t mask = UINT64_MAX;

                r = copy_to_guest(h, address, &mask, sizeof(mask));
                return r < 0 ? (uint64_t) r : 0;
        }

        case ARCH_GET_MAX_TAG_BITS: {
                uint64_t bits = 0;

                r = copy_to_guest(h, address, &bits, sizeof(bits));
                return r < 0 ? (uint64_t) r : 0;
        }

        case ARCH_ENABLE_TAGGED_ADDR:
        case ARCH_FORCE_TAGGED_SVA:
        case ARCH_SHSTK_ENABLE:
        case ARCH_SHSTK_DISABLE:
        case ARCH_SHSTK_LOCK:
        case ARCH_SHSTK_UNLOCK:
                return (uint64_t) -EOPNOTSUPP;

        case ARCH_SHSTK_STATUS: {
                uint64_t status = 0;

                r = copy_to_guest(h, address, &status, sizeof(status));
                return r < 0 ? (uint64_t) r : 0;
        }

        case ARCH_SET_FS:
        case ARCH_SET_GS:
                if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                        return (uint64_t) -errno;
                if (address > UINT64_C(0x00007fffffffffff))
                        return (uint64_t) -EPERM;

                if (operation == ARCH_SET_FS)
                        sregs.fs.base = address;
                else
                        sregs.gs.base = address;

                if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                        return (uint64_t) -errno;
                return 0;

        case ARCH_GET_FS:
        case ARCH_GET_GS: {
                if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                        return (uint64_t) -errno;
                uint64_t base = operation == ARCH_GET_FS ? sregs.fs.base : sregs.gs.base;

                r = copy_to_guest(h, address, &base, sizeof(base));
                return r < 0 ? (uint64_t) r : 0;
        }

        default:
                return (uint64_t) -EINVAL;
        }
}

static int main_program_header_address(const ExecHypervisor *h, uint64_t *ret) {
        uint64_t table_end, table_size;

        assert(h);
        assert(h->image);
        assert(ret);

        FOREACH_ARRAY(phdr, h->image->program_headers, h->image->n_program_headers)
                if (phdr->type == PT_PHDR) {
                        *ret = h->image_load_bias + phdr->virtual_address;
                        return 0;
                }

        if (!MUL_SAFE(&table_size,
                      h->image->n_program_headers,
                      h->image->program_header_entry_size) ||
            !ADD_SAFE(&table_end, h->image->program_header_offset, table_size))
                return -EOVERFLOW;

        FOREACH_ARRAY(phdr, h->image->program_headers, h->image->n_program_headers) {
                uint64_t segment_end;

                if (phdr->type != PT_LOAD ||
                    !ADD_SAFE(&segment_end, phdr->offset, phdr->file_size))
                        continue;
                if (h->image->program_header_offset < phdr->offset || table_end > segment_end)
                        continue;

                *ret = h->image_load_bias + phdr->virtual_address +
                        (h->image->program_header_offset - phdr->offset);
                return 0;
        }

        return -ENOEXEC;
}

int exec_hypervisor_prepare_stack(ExecHypervisor *h, char *const argv[], char *const envp[]) {
#if defined(__x86_64__)
        static const char platform[] = "x86_64";
        enum { N_AUXILIARY_ENTRIES = 22 };
        size_t argc, envc, metadata_size, strings_size = 0;
        uintptr_t platform_address, random_address, stack_begin, stack_end, strings_begin, string_cursor;
        Elf64_auxv_t *auxiliary;
        struct kvm_regs regs;
        uint64_t program_header_address;
        uint64_t *word;
        int r;

        assert(h);
        assert(exec_hypervisor_can_run(h));
        assert(h->stack_address);
        assert(h->vcpu_fd >= 0);

        argc = strv_length(argv);
        envc = strv_length(envp);
        if (argc == 0)
                return -EINVAL;

        STRV_FOREACH(argument, argv)
                if (!ADD_SAFE(&strings_size, strings_size, strlen(*argument) + 1))
                        return -E2BIG;
        STRV_FOREACH(variable, envp)
                if (!ADD_SAFE(&strings_size, strings_size, strlen(*variable) + 1))
                        return -E2BIG;
        if (!ADD_SAFE(&strings_size, strings_size, sizeof(h->random_bytes)) ||
            !ADD_SAFE(&strings_size, strings_size, sizeof(platform)))
                return -E2BIG;

        r = main_program_header_address(h, &program_header_address);
        if (r < 0)
                return r;

        size_t n_words;
        if (!ADD_SAFE(&n_words, argc, envc) ||
            !ADD_SAFE(&n_words, n_words, 3) ||
            !MUL_SAFE(&metadata_size, n_words, sizeof(uint64_t)) ||
            !ADD_SAFE(&metadata_size, metadata_size, N_AUXILIARY_ENTRIES * sizeof(Elf64_auxv_t)))
                return -E2BIG;

        stack_begin = (uintptr_t) h->stack_address;
        stack_end = stack_begin + h->stack_size;
        if (strings_size > h->stack_size)
                return -E2BIG;
        strings_begin = stack_end - strings_size;
        if (metadata_size > strings_begin - stack_begin)
                return -E2BIG;

        uintptr_t stack_pointer = ALIGN_DOWN(strings_begin - metadata_size, 16);
        if (stack_pointer < stack_begin)
                return -E2BIG;

        word = (uint64_t*) stack_pointer;
        string_cursor = strings_begin;
        *word++ = argc;
        STRV_FOREACH(argument, argv) {
                size_t size = strlen(*argument) + 1;

                *word++ = string_cursor;
                memcpy((void*) string_cursor, *argument, size);
                string_cursor += size;
        }
        *word++ = 0;
        STRV_FOREACH(variable, envp) {
                size_t size = strlen(*variable) + 1;

                *word++ = string_cursor;
                memcpy((void*) string_cursor, *variable, size);
                string_cursor += size;
        }
        *word++ = 0;

        random_address = string_cursor;
        memcpy((void*) string_cursor, h->random_bytes, sizeof(h->random_bytes));
        string_cursor += sizeof(h->random_bytes);
        platform_address = string_cursor;
        memcpy((void*) string_cursor, platform, sizeof(platform));
        string_cursor += sizeof(platform);

        auxiliary = (Elf64_auxv_t*) word;
        auxiliary[0] = (Elf64_auxv_t) { .a_type = AT_PHDR, .a_un.a_val = program_header_address };
        auxiliary[1] = (Elf64_auxv_t) { .a_type = AT_PHENT, .a_un.a_val = h->image->program_header_entry_size };
        auxiliary[2] = (Elf64_auxv_t) { .a_type = AT_PHNUM, .a_un.a_val = h->image->n_program_headers };
        auxiliary[3] = (Elf64_auxv_t) { .a_type = AT_PAGESZ, .a_un.a_val = page_size() };
        auxiliary[4] = (Elf64_auxv_t) { .a_type = AT_BASE, .a_un.a_val = h->interpreter_image ? h->interpreter_load_bias : 0 };
        auxiliary[5] = (Elf64_auxv_t) { .a_type = AT_FLAGS, .a_un.a_val = 0 };
        auxiliary[6] = (Elf64_auxv_t) { .a_type = AT_ENTRY, .a_un.a_val = h->image_load_bias + h->image->entry };
        auxiliary[7] = (Elf64_auxv_t) { .a_type = AT_EXECFN, .a_un.a_val = ((uint64_t*) stack_pointer)[1] };
        auxiliary[8] = (Elf64_auxv_t) { .a_type = AT_UID, .a_un.a_val = h->uid };
        auxiliary[9] = (Elf64_auxv_t) { .a_type = AT_EUID, .a_un.a_val = h->euid };
        auxiliary[10] = (Elf64_auxv_t) { .a_type = AT_GID, .a_un.a_val = h->gid };
        auxiliary[11] = (Elf64_auxv_t) { .a_type = AT_EGID, .a_un.a_val = h->egid };
        auxiliary[12] = (Elf64_auxv_t) { .a_type = AT_SECURE, .a_un.a_val = h->secure_exec };
        auxiliary[13] = (Elf64_auxv_t) { .a_type = AT_RANDOM, .a_un.a_val = random_address };
        auxiliary[14] = (Elf64_auxv_t) { .a_type = AT_PLATFORM, .a_un.a_val = platform_address };
        auxiliary[15] = (Elf64_auxv_t) { .a_type = AT_HWCAP, .a_un.a_val = h->hwcap };
        auxiliary[16] = (Elf64_auxv_t) { .a_type = AT_HWCAP2, .a_un.a_val = h->hwcap2 };
        auxiliary[17] = (Elf64_auxv_t) { .a_type = AT_CLKTCK, .a_un.a_val = h->clock_ticks };
        auxiliary[18] = (Elf64_auxv_t) {
                .a_type = AT_MINSIGSTKSZ,
                .a_un.a_val = guest_min_signal_stack_size(h->machine->xsave_size),
        };
        auxiliary[19] = (Elf64_auxv_t) { .a_type = AT_RSEQ_FEATURE_SIZE, .a_un.a_val = EXEC_HYPERVISOR_RSEQ_FEATURE_SIZE };
        auxiliary[20] = (Elf64_auxv_t) { .a_type = AT_RSEQ_ALIGN, .a_un.a_val = EXEC_HYPERVISOR_RSEQ_ALIGNMENT };
        auxiliary[21] = (Elf64_auxv_t) { .a_type = AT_NULL, .a_un.a_val = 0 };
        memzero(h->saved_auxv, sizeof(h->saved_auxv));
        memcpy(h->saved_auxv, auxiliary, N_AUXILIARY_ENTRIES * sizeof(Elf64_auxv_t));

        assert(string_cursor == stack_end);
        assert((uintptr_t) (auxiliary + N_AUXILIARY_ENTRIES) <= strings_begin);

        if (ioctl(h->vcpu_fd, KVM_GET_REGS, &regs) < 0)
                return -errno;
        regs.rsp = stack_pointer;
        if (ioctl(h->vcpu_fd, KVM_SET_REGS, &regs) < 0)
                return -errno;

        r = validate_translation(h, stack_pointer, /* writeable= */ true);
        if (r < 0)
                return r;

        return 0;
#else
        assert(h);
        assert(argv);

        return -EOPNOTSUPP;
#endif
}

int validate_guest_range(ExecHypervisor *h, uint64_t address, size_t size, bool writeable) {
        uint64_t end, page;

        assert(h);

        if (size == 0)
                return 0;
        if (!ADD_SAFE(&end, address, size) || end > UINT64_C(0x0000800000000000))
                return -EFAULT;

        page = ALIGN_DOWN(address, page_size());
        while (page < end) {
                uint64_t *entry = guest_page_entry(h, page);

                if (!entry ||
                    !FLAGS_SET(*entry, X86_PAGE_PRESENT) ||
                    (writeable && !FLAGS_SET(*entry, X86_PAGE_WRITE)))
                        return -EFAULT;
                page += page_size();
        }

        return 0;
}

static void populate_guest_ucontext(
                GuestSignalFrame *frame,
                X86SignalXstate *signal_xstate,
                uint64_t guest_xstate_address,
                const struct kvm_regs *regs,
                const struct kvm_sregs *sregs,
                const X86KvmXsave *xsave,
                uint64_t supported_xfeatures,
                size_t xsave_size,
                const sigset_t *mask) {

        const X86FxsaveArea *fxsave;
        X86FpxSwBytes *sw_bytes;
        greg_t *gregs;

        assert(frame);
        assert(signal_xstate);
        assert(regs);
        assert(sregs);
        assert(xsave);
        assert(supported_xfeatures >= X86_XFEATURE_MASK_AVX);
        assert(xsave_size >= X86_AVX_XSAVE_SIZE);
        assert(xsave_size <= X86_KVM_XSAVE_MAX_SIZE);
        assert(mask);

        fxsave = xsave_fxsave_const(xsave);

        frame->context.uc_sigmask = *mask;
        gregs = frame->context.uc_mcontext.gregs;
        gregs[REG_R8] = regs->r8;
        gregs[REG_R9] = regs->r9;
        gregs[REG_R10] = regs->r10;
        gregs[REG_R11] = regs->r11;
        gregs[REG_R12] = regs->r12;
        gregs[REG_R13] = regs->r13;
        gregs[REG_R14] = regs->r14;
        gregs[REG_R15] = regs->r15;
        gregs[REG_RDI] = regs->rdi;
        gregs[REG_RSI] = regs->rsi;
        gregs[REG_RBP] = regs->rbp;
        gregs[REG_RBX] = regs->rbx;
        gregs[REG_RDX] = regs->rdx;
        gregs[REG_RAX] = regs->rax;
        gregs[REG_RCX] = regs->rcx;
        gregs[REG_RSP] = regs->rsp;
        gregs[REG_RIP] = regs->rip;
        gregs[REG_EFL] = regs->rflags;
        gregs[REG_CSGSFS] = sregs->cs.selector |
                (uint64_t) sregs->gs.selector << 16 |
                (uint64_t) sregs->fs.selector << 32;
        gregs[REG_CR2] = sregs->cr2;

        signal_xstate->fxsave = *fxsave;
        sw_bytes = (X86FpxSwBytes*) ((uint8_t*) &signal_xstate->fxsave + X86_FXSAVE_SW_RESERVED_OFFSET);
        *sw_bytes = (X86FpxSwBytes) {
                .magic1 = X86_FP_XSTATE_MAGIC1,
                .extended_size = xsave_size + sizeof(uint32_t),
                .xfeatures = supported_xfeatures,
                .xstate_size = xsave_size,
        };
        signal_xstate->header.xfeatures =
                (xsave_header_const(xsave)->xfeatures & supported_xfeatures) |
                X86_XFEATURE_MASK_FP_SSE;
        memcpy(signal_xstate->extended,
               (const uint8_t*) xsave->region + X86_YMMH_OFFSET,
               xsave_size - X86_YMMH_OFFSET);
        unaligned_write_le32((uint8_t*) signal_xstate + xsave_size, X86_FP_XSTATE_MAGIC2);
        frame->context.uc_mcontext.fpregs = (fpregset_t) (uintptr_t) guest_xstate_address;
}

static void add_guest_signal_mask(sigset_t *mask, uint64_t guest_mask) {
        assert(mask);

        for (int signo = 1; signo <= (int) EXEC_HYPERVISOR_N_SIGNALS; signo++)
                if (guest_mask & (UINT64_C(1) << (signo - 1)))
                        (void) sigaddset(mask, signo);
}

static int force_fatal_guest_signal(ExecHypervisor *h, int signo) {
        GuestSignalAction default_action = {};
        sigset_t mask;
        int r;

        assert(h);
        assert(signo > 0 && signo <= (int) EXEC_HYPERVISOR_N_SIGNALS);

        r = get_host_signal_mask(&mask);
        if (r < 0)
                return r;
        (void) sigdelset(&mask, signo);
        r = set_host_signal_mask(&mask);
        if (r < 0)
                return r;

        assert_se(pthread_mutex_lock(&h->machine->signal_lock) == 0);
        r = set_host_signal_action(h, signo, &default_action);
        assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);
        if (r < 0)
                return r;
        if (raise(signo) < 0)
                return -errno;

        return -EFAULT;
}

static int deliver_guest_signal_with_masks(
                ExecHypervisor *h,
                const siginfo_t *signal_info,
                const sigset_t *frame_mask,
                const sigset_t *handler_mask) {
        GuestSignalAction action, default_action = {};
        GuestSignalFrame frame = {};
        ExecHypervisorSignalFrame *saved;
        X86KvmXsave xsave;
        struct kvm_regs regs;
        struct kvm_sregs sregs;
        sigset_t mask;
        stack_t signal_stack;
        uint64_t frame_address, stack_end, stack_pointer, xstate_address, xstate_storage_address;
        size_t frame_size;
        X86SignalXstate *signal_xstate;
        bool on_signal_stack;
        int r;
        int signo;

        assert(h);
        assert(signal_info);

        signo = signal_info->si_signo;
        assert(signo > 0 && signo <= (int) EXEC_HYPERVISOR_N_SIGNALS);

        assert_se(pthread_mutex_lock(&h->machine->signal_lock) == 0);
        action = h->machine->signal_actions[signo];
        assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);
        if (action.handler <= 1)
                return 0;
        if (h->n_signal_frames >= EXEC_HYPERVISOR_MAX_SIGNAL_FRAMES)
                return -EOVERFLOW;

        frame_size = guest_signal_frame_size(h->xsave_frame_size);

        if (ioctl(h->vcpu_fd, KVM_GET_REGS, &regs) < 0 ||
            ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;
        r = get_vcpu_xsave(h, h->vcpu_fd, &xsave);
        if (r < 0)
                return r;

        if ((sregs.cs.selector & 3) == 0) {
                if (regs.rip != h->supervisor_code_gpa && regs.rip != h->supervisor_code_gpa + 2)
                        return -EPROTO;

                regs.rip = regs.rcx;
                regs.rflags = regs.r11;
                sregs.cs = make_code_segment(0x23, 3);
                sregs.ss = make_data_segment(0x1b, 3);
        } else if ((sregs.cs.selector & 3) != 3)
                return -EPROTO;

        r = abort_guest_rseq_for_signal(h, &regs);
        if (r < 0)
                return force_fatal_guest_signal(h, SIGSEGV);

        r = get_host_signal_mask(&mask);
        if (r < 0)
                return r;

        assert_se(pthread_mutex_lock(&h->machine->signal_lock) == 0);
        signal_stack = h->signal_stack;
        on_signal_stack = guest_on_signal_stack(h, regs.rsp);
        assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);
        stack_end = regs.rsp;
        if (FLAGS_SET(action.flags, SA_ONSTACK) &&
            !on_signal_stack &&
            !FLAGS_SET(signal_stack.ss_flags, SS_DISABLE)) {
                if (!ADD_SAFE(&stack_end, (uintptr_t) signal_stack.ss_sp, signal_stack.ss_size))
                        return -EFAULT;
                on_signal_stack = true;
        }

        if (stack_end < 128 + frame_size + 16)
                return -EFAULT;
        stack_pointer = stack_end - 128 - frame_size;
        frame_address = ALIGN_DOWN(stack_pointer, 16) - 8;
        if (on_signal_stack && frame_address < (uintptr_t) signal_stack.ss_sp)
                return -EFAULT;
        r = validate_guest_range(h, frame_address, frame_size, /* writeable= */ true);
        if (r < 0)
                return r;

        xstate_storage_address = frame_address + offsetof(GuestSignalFrame, xstate_storage);
        xstate_address = ALIGN_TO(xstate_storage_address, 64);
        assert(xstate_address - xstate_storage_address <= 63);
        signal_xstate = (X86SignalXstate*) (
                        frame.xstate_storage + xstate_address - xstate_storage_address);

        frame.restorer = action.restorer;
        frame.context.uc_stack = signal_stack;
        frame.info = *signal_info;
        populate_guest_ucontext(
                        &frame,
                        signal_xstate,
                        xstate_address,
                        &regs,
                        &sregs,
                        &xsave,
                        h->xfeatures_allocated,
                        h->xsave_frame_size,
                        frame_mask ?: &mask);
        r = copy_to_guest(h, frame_address, &frame, frame_size);
        if (r < 0)
                return r;

        saved = h->signal_frames + h->n_signal_frames;
        *saved = (ExecHypervisorSignalFrame) {
                .guest_address = frame_address,
                .guest_xstate_address = xstate_address,
                .size = frame_size,
                .xfeatures = h->xfeatures_allocated,
                .xsave_size = h->xsave_frame_size,
                .regs = regs,
                .sregs = sregs,
                .xsave = xsave,
                .mask = frame_mask ? *frame_mask : mask,
        };

        if (handler_mask)
                mask = *handler_mask;
        add_guest_signal_mask(&mask, action.mask);
        if (!FLAGS_SET(action.flags, SA_NODEFER))
                (void) sigaddset(&mask, signo);
        r = set_host_signal_mask(&mask);
        if (r < 0)
                return r;

        if (FLAGS_SET(action.flags, SA_RESETHAND)) {
                assert_se(pthread_mutex_lock(&h->machine->signal_lock) == 0);
                r = set_host_signal_action(h, signo, &default_action);
                if (r < 0) {
                        assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);
                        return r;
                }
                h->machine->signal_actions[signo] = default_action;
                assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);
        }

        regs.rax = 0;
        regs.rdi = signo;
        regs.rsi = frame_address + offsetof(GuestSignalFrame, info);
        regs.rdx = frame_address + offsetof(GuestSignalFrame, context);
        regs.rip = action.handler;
        regs.rsp = frame_address;

        if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                return -errno;
        if (ioctl(h->vcpu_fd, KVM_SET_REGS, &regs) < 0)
                return -errno;

        assert_se(pthread_mutex_lock(&h->machine->signal_lock) == 0);
        if (FLAGS_SET(h->signal_stack.ss_flags, SS_AUTODISARM))
                h->signal_stack = (stack_t) { .ss_flags = SS_DISABLE };
        assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);
        h->n_signal_frames++;
        return 1;
}

static int deliver_guest_signal(ExecHypervisor *h, const siginfo_t *signal_info) {
        return deliver_guest_signal_with_masks(h, signal_info, NULL, NULL);
}

static int deliver_synchronous_guest_signal(ExecHypervisor *h, const siginfo_t *info) {
        GuestSignalAction action, default_action = {};
        sigset_t mask;
        int r;

        assert(h);
        assert(info);
        assert(info->si_signo > 0 && info->si_signo <= (int) EXEC_HYPERVISOR_N_SIGNALS);

        assert_se(pthread_mutex_lock(&h->machine->signal_lock) == 0);
        r = initialize_guest_signal_action(h, info->si_signo);
        if (r >= 0)
                action = h->machine->signal_actions[info->si_signo];
        assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);
        if (r < 0)
                return r;
        if (action.handler > 1)
                return deliver_guest_signal(h, info);

        r = get_host_signal_mask(&mask);
        if (r < 0)
                return r;
        (void) sigdelset(&mask, info->si_signo);
        r = set_host_signal_mask(&mask);
        if (r < 0)
                return r;

        assert_se(pthread_mutex_lock(&h->machine->signal_lock) == 0);
        r = set_host_signal_action(h, info->si_signo, &default_action);
        assert_se(pthread_mutex_unlock(&h->machine->signal_lock) == 0);
        if (r < 0)
                return r;
        if (raise(info->si_signo) < 0)
                return -errno;

        return -EFAULT;
}

int deliver_pending_guest_signal(ExecHypervisor *h) {
        assert(h);

        for (int signo = 1; signo <= (int) EXEC_HYPERVISOR_N_SIGNALS; signo++) {
                PendingGuestSignal *pending = h->pending_signals + signo;
                siginfo_t info;
                int r;

                if (__atomic_load_n(&pending->pending, __ATOMIC_ACQUIRE) == 0)
                        continue;

                info = pending->info;
                __atomic_store_n(&pending->pending, 0, __ATOMIC_RELEASE);
                if (info.si_signo != signo)
                        return -EPROTO;

                if (h->wait_signal_signo == signo) {
                        sigset_t frame_mask = h->wait_signal_frame_mask;
                        sigset_t handler_mask = h->wait_signal_handler_mask;

                        h->wait_signal_signo = 0;
                        r = deliver_guest_signal_with_masks(h, &info, &frame_mask, &handler_mask);
                } else
                        r = deliver_guest_signal(h, &info);
                if (r != 0)
                        return r;
        }

        return 0;
}

static bool exception_has_error_code(uint32_t vector) {
        return IN_SET(vector, 8, 10, 11, 12, 13, 14, 17, 21, 29, 30);
}

static int handle_guest_growdown_fault(ExecHypervisor *h, uint64_t fault_address, uint64_t error_code) {
        _cleanup_(gpa_reservation_done) ExecHypervisorGpaReservation gpa_reservation = {};
        ExecHypervisor *machine;
        ExecHypervisorMapping old_mapping;
        struct kvm_userspace_memory_region region;
        uint64_t fault_page, gpa, nearest_start = UINT64_MAX;
        size_t growth_size, mapping_index = SIZE_MAX, n_mapped_pages = 0;
        unsigned slot = UINT_MAX;
        int temporary_protection, r;
        bool host_expanded = false;

        assert(h);

        if (FLAGS_SET(error_code, 1))
                return 0;
        fault_page = ALIGN_DOWN(fault_address, page_size());

        r = begin_guest_memory_transaction(h);
        if (r < 0)
                return r;
        machine = exec_hypervisor_machine(h);
        if (find_mapping(machine, fault_page))
                goto not_handled;
        for (size_t i = 0; i < machine->n_mappings; i++) {
                ExecHypervisorMapping *mapping = machine->mappings + i;

                if (fault_page < mapping->guest_virtual_address &&
                    mapping->guest_virtual_address < nearest_start) {
                        nearest_start = mapping->guest_virtual_address;
                        mapping_index = i;
                }
        }
        if (mapping_index == SIZE_MAX || !machine->mappings[mapping_index].grows_down)
                goto not_handled;

        old_mapping = machine->mappings[mapping_index];
        if (!old_mapping.mutable || old_mapping.file_backed || old_mapping.shared)
                goto not_handled;
        growth_size = old_mapping.guest_virtual_address - fault_page;
        if (growth_size == 0 || !GREEDY_REALLOC0(machine->mappings, machine->n_mappings + 1)) {
                r = growth_size == 0 ? 0 : -ENOMEM;
                goto finish;
        }
        r = reserve_guest_physical(machine, growth_size, &gpa_reservation);
        if (r < 0)
                goto finish;
        gpa = gpa_reservation.address;
        r = allocate_memslot(machine, &slot);
        if (r < 0) {
                if (r == -ENOSPC)
                        r = -ENOMEM;
                goto finish;
        }
        for (size_t offset = 0; offset < growth_size; offset += page_size()) {
                r = map_guest_page(
                                machine,
                                fault_page + offset,
                                gpa + offset,
                                guest_page_flags(old_mapping.protection));
                if (r < 0)
                        goto rollback_pages;
                n_mapped_pages++;
        }

        temporary_protection = (old_mapping.protection & ~PROT_EXEC) | PROT_READ | PROT_WRITE;
        if (mprotect(
                            (void*) (uintptr_t) old_mapping.guest_virtual_address,
                            old_mapping.size,
                            temporary_protection | PROT_GROWSDOWN) < 0) {
                r = 0;
                goto rollback_pages;
        }
        if (syscall(__NR_gettimeofday, (void*) (uintptr_t) fault_page, NULL) < 0) {
                if (mprotect(
                                    (void*) (uintptr_t) old_mapping.guest_virtual_address,
                                    old_mapping.size,
                                    old_mapping.protection | PROT_GROWSDOWN) < 0)
                        _exit(EXIT_FAILURE);
                r = 0;
                goto rollback_pages;
        }
        host_expanded = true;
        memzero((void*) (uintptr_t) fault_page, sizeof(struct timeval));
        if (mprotect(
                            (void*) (uintptr_t) fault_page,
                            growth_size + old_mapping.size,
                            old_mapping.protection | PROT_GROWSDOWN) < 0) {
                r = -errno;
                goto rollback_host;
        }

        region = (struct kvm_userspace_memory_region) {
                .slot = slot,
                .guest_phys_addr = gpa,
                .memory_size = growth_size,
                .userspace_addr = fault_page,
        };
        if (ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
                r = -errno;
                goto rollback_host;
        }

        machine->mappings[mapping_index].grows_down = false;
        machine->mappings[machine->n_mappings++] = (ExecHypervisorMapping) {
                .host_address = (void*) (uintptr_t) fault_page,
                .guest_virtual_address = fault_page,
                .guest_physical_address = gpa,
                .size = growth_size,
                .protection = old_mapping.protection,
                .slot = slot,
                .growdown_id = old_mapping.growdown_id,
                .mutable = true,
                .stage2_writable = true,
                .grows_down = true,
        };
        gpa_reservation.committed = true;
        if (flush_all_guest_tlbs(machine) < 0)
                _exit(EXIT_FAILURE);
        end_guest_memory_transaction(h);
        return 1;

rollback_host:
        if (host_expanded && munmap((void*) (uintptr_t) fault_page, growth_size) < 0)
                _exit(EXIT_FAILURE);
        if (mprotect(
                            (void*) (uintptr_t) old_mapping.guest_virtual_address,
                            old_mapping.size,
                            old_mapping.protection | PROT_GROWSDOWN) < 0)
                _exit(EXIT_FAILURE);
rollback_pages:
        for (size_t i = 0; i < n_mapped_pages; i++) {
                uint64_t page = fault_page + i * page_size();

                unmap_guest_page(machine, page);
                reclaim_guest_page_tables(machine, page);
        }
        if (slot != UINT_MAX)
                release_memslot(machine, slot);
        goto finish;

not_handled:
        r = 0;
finish:
        end_guest_memory_transaction(h);
        return r;
}

static int prepare_guest_exception_state(
                ExecHypervisor *h,
                uint32_t vector,
                uint64_t *ret_error_code,
                uint64_t *ret_instruction_pointer) {
        struct kvm_regs regs;
        struct kvm_sregs sregs;
        uint64_t *exception_stack;
        size_t offset, words;

        assert(h);
        assert(ret_error_code);
        assert(ret_instruction_pointer);

        if (ioctl(h->vcpu_fd, KVM_GET_REGS, &regs) < 0 ||
            ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;
        if ((sregs.cs.selector & 3) != 0)
                return -EPROTO;

        offset = exception_has_error_code(vector) ? 1 : 0;
        words = 1 + offset + 5;
        if (regs.rsp < h->ring0_stack_gpa ||
            regs.rsp > h->ring0_stack_gpa + page_size() ||
            words * sizeof(uint64_t) > h->ring0_stack_gpa + page_size() - regs.rsp)
                return -EFAULT;

        exception_stack = (uint64_t*) ((uint8_t*) h->supervisor_memory + regs.rsp);
                *ret_error_code = offset > 0 ? exception_stack[1] : 0;
                if ((exception_stack[offset + 2] & 3) != 3 ||
                                                (exception_stack[offset + 5] & ~UINT64_C(3)) != 0x18 ||
                        exception_stack[offset + 1] > UINT64_C(0x00007fffffffffff) ||
                        exception_stack[offset + 4] > UINT64_C(0x00007fffffffffff))
                return -EPROTO;

                regs.rax = exception_stack[0];
                regs.rip = exception_stack[offset + 1];
                regs.rflags = exception_stack[offset + 3];
                regs.rsp = exception_stack[offset + 4];
                *ret_instruction_pointer = regs.rip;
        sregs.cs = make_code_segment(0x23, 3);
        sregs.ss = make_data_segment(0x1b, 3);

        if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                return -errno;
        if (ioctl(h->vcpu_fd, KVM_SET_REGS, &regs) < 0)
                return -errno;

        return 0;
}

static int guest_exception_signal(
                uint32_t vector,
                uint64_t error_code,
                int *ret_signo,
                int *ret_signal_code) {

        assert(ret_signo);
        assert(ret_signal_code);

        switch (vector) {
        case 0:
                *ret_signo = SIGFPE;
                *ret_signal_code = FPE_INTDIV;
                return 0;
        case 1:
                *ret_signo = SIGTRAP;
                *ret_signal_code = TRAP_TRACE;
                return 0;
        case 3:
                *ret_signo = SIGTRAP;
                *ret_signal_code = TRAP_BRKPT;
                return 0;
        case 6:
                *ret_signo = SIGILL;
                *ret_signal_code = ILL_ILLOPN;
                return 0;
        case 14:
                *ret_signo = SIGSEGV;
                *ret_signal_code = FLAGS_SET(error_code, 1) ? SEGV_ACCERR : SEGV_MAPERR;
                return 0;
        case 16:
        case 19:
                *ret_signo = SIGFPE;
                *ret_signal_code = FPE_FLTINV;
                return 0;
        case 17:
                *ret_signo = SIGBUS;
                *ret_signal_code = BUS_ADRALN;
                return 0;
        default:
                *ret_signo = SIGSEGV;
                *ret_signal_code = SI_KERNEL;
                return 0;
        }
}

int handle_guest_exception(ExecHypervisor *h, uint32_t vector, uint64_t fault_address) {
        siginfo_t info = {};
        uint64_t error_code, instruction_pointer;
        int r, signal_code, signo;

        assert(h);

        r = prepare_guest_exception_state(h, vector, &error_code, &instruction_pointer);
        if (r < 0)
                return r;
        if (vector == 7 && h->machine->amx_supported) {
                r = get_vcpu_xfd_state(h, h->vcpu_fd);
                if (r < 0)
                        return r;
                if (h->xfd_err == X86_XFEATURE_MASK_XTILE_DATA &&
                    FLAGS_SET(h->xfd, X86_XFEATURE_MASK_XTILE_DATA)) {
                        h->xfd_err = 0;
                        if (!FLAGS_SET(h->machine->xfeatures_permitted, X86_XFEATURE_MASK_XTILE_DATA)) {
                                r = set_vcpu_xfd_state(h, h->vcpu_fd);
                                if (r < 0)
                                        return r;

                                info = (siginfo_t) {
                                        .si_signo = SIGILL,
                                        .si_code = ILL_ILLOPC,
                                        .si_addr = (void*) (uintptr_t) instruction_pointer,
                                };
                                return deliver_synchronous_guest_signal(h, &info);
                        }

                        h->xfd = 0;
                        h->xfeatures_allocated = h->machine->xfeatures;
                        h->xsave_frame_size = h->machine->xsave_size;
                        return set_vcpu_xfd_state(h, h->vcpu_fd);
                }

        }
        if (vector == 14) {
                uint64_t *entry = guest_page_entry(h, ALIGN_DOWN(fault_address, page_size()));

                r = handle_guest_growdown_fault(h, fault_address, error_code);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                if (entry && FLAGS_SET(*entry, X86_PAGE_SOFTWARE_UFFD_POISON)) {
                        info.si_signo = SIGBUS;
                        info.si_code = BUS_MCEERR_AR;
                        info.si_addr = (void*) (uintptr_t) fault_address;
                        return deliver_synchronous_guest_signal(h, &info);
                }
                r = guest_userfault_delivers_sigbus(h, fault_address, error_code);
                if (r < 0)
                        return r;
                if (r == GUEST_USERFAULT_SIGBUS_HANDLED)
                        return 0;
                if (r == GUEST_USERFAULT_SIGBUS_DELIVER) {
                        info.si_signo = SIGBUS;
                        info.si_code = BUS_ADRERR;
                        info.si_addr = (void*) (uintptr_t) fault_address;
                        return deliver_synchronous_guest_signal(h, &info);
                }
                r = resolve_guest_userfault(h, fault_address, error_code);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                entry = guest_page_entry(h, ALIGN_DOWN(fault_address, page_size()));
                if (entry && FLAGS_SET(*entry, X86_PAGE_SOFTWARE_UFFD_POISON)) {
                        info.si_signo = SIGBUS;
                        info.si_code = BUS_MCEERR_AR;
                        info.si_addr = (void*) (uintptr_t) fault_address;
                        return deliver_synchronous_guest_signal(h, &info);
                }
        }
        r = guest_exception_signal(vector, error_code, &signo, &signal_code);
        if (r < 0)
                return r;
        if (vector == 14) {
                uint64_t *entry = guest_page_entry(h, ALIGN_DOWN(fault_address, page_size()));

                if (entry && FLAGS_SET(*entry, X86_PAGE_SOFTWARE_PROT_NONE))
                        signal_code = SEGV_ACCERR;
                else if (entry && FLAGS_SET(*entry, X86_PAGE_SOFTWARE_SIGBUS)) {
                        ExecHypervisorMapping *mapping = find_mapping(h, fault_address);

                        if (!mapping || !mapping->file_backed)
                                return -EPROTO;
                        r = probe_file_mapping_page(mapping, ALIGN_DOWN(fault_address, page_size()));
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                *entry = (*entry | X86_PAGE_PRESENT) & ~X86_PAGE_SOFTWARE_SIGBUS;
                                return flush_guest_tlb(h);
                        }

                        info.si_signo = SIGBUS;
                        info.si_code = BUS_ADRERR;
                        info.si_addr = (void*) (uintptr_t) fault_address;
                        return deliver_synchronous_guest_signal(h, &info);
                }
        }

        info.si_signo = signo;
        info.si_code = signal_code;
        info.si_addr = (void*) (uintptr_t) (vector == 14 ? fault_address : instruction_pointer);
        return deliver_synchronous_guest_signal(h, &info);
}

int handle_guest_memory_fault(ExecHypervisor *h, int error) {
        ExecHypervisorMapping *mapping;
        siginfo_t info = {
                .si_signo = SIGBUS,
                .si_code = error == EHWPOISON ? BUS_MCEERR_AR : BUS_ADRERR,
        };
        uint64_t address, mapping_offset;
        uint64_t *entry;

        assert(h);
        assert(IN_SET(error, EFAULT, EHWPOISON));

        if (h->run->memory_fault.flags != 0)
                return -EPROTO;
        mapping = find_mapping_by_gpa(
                        h,
                        h->run->memory_fault.gpa,
                        h->run->memory_fault.size);
        if (!mapping)
                return -EFAULT;

        mapping_offset = h->run->memory_fault.gpa - mapping->guest_physical_address;
        if (!ADD_SAFE(&address, mapping->guest_virtual_address, mapping_offset))
                return -EOVERFLOW;
        entry = guest_page_entry(h, ALIGN_DOWN(address, page_size()));
        if (!entry || !FLAGS_SET(*entry, X86_PAGE_PRESENT) ||
            (*entry & X86_PAGE_ADDRESS_MASK) != ALIGN_DOWN(h->run->memory_fault.gpa, page_size()))
                return -EPROTO;

        info.si_addr = (void*) (uintptr_t) address;
        return deliver_synchronous_guest_signal(h, &info);
}

static int restore_guest_ucontext(struct kvm_regs *regs, const GuestSignalFrame *frame) {
        const greg_t *gregs;
        uint64_t rflags;

        assert(regs);
        assert(frame);

        gregs = frame->context.uc_mcontext.gregs;
        if ((uint64_t) gregs[REG_RIP] > UINT64_C(0x00007fffffffffff) ||
            (uint64_t) gregs[REG_RSP] > UINT64_C(0x00007fffffffffff))
                return -EFAULT;

        regs->r8 = gregs[REG_R8];
        regs->r9 = gregs[REG_R9];
        regs->r10 = gregs[REG_R10];
        regs->r11 = gregs[REG_R11];
        regs->r12 = gregs[REG_R12];
        regs->r13 = gregs[REG_R13];
        regs->r14 = gregs[REG_R14];
        regs->r15 = gregs[REG_R15];
        regs->rdi = gregs[REG_RDI];
        regs->rsi = gregs[REG_RSI];
        regs->rbp = gregs[REG_RBP];
        regs->rbx = gregs[REG_RBX];
        regs->rdx = gregs[REG_RDX];
        regs->rax = gregs[REG_RAX];
        regs->rcx = gregs[REG_RCX];
        regs->rsp = gregs[REG_RSP];
        regs->rip = gregs[REG_RIP];

        rflags = gregs[REG_EFL];
        regs->rflags = (regs->rflags & ~UINT64_C(0x50dd5)) | (rflags & UINT64_C(0x50dd5)) | 2;
        return 0;
}

static int restore_guest_fpu(
                X86KvmXsave *xsave,
                const GuestSignalFrame *frame,
                uint64_t frame_address,
                uint64_t guest_xstate_address,
                uint64_t supported_xfeatures,
                size_t xsave_size) {

        X86FxsaveArea *fxsave;
        const X86FpxSwBytes *sw_bytes;
        const X86SignalXstate *signal_xstate;
        uint64_t storage_address, storage_offset;
        uint32_t mxcsr_mask;

        assert(xsave);
        assert(frame);
        assert(supported_xfeatures >= X86_XFEATURE_MASK_AVX);
        assert(xsave_size >= X86_AVX_XSAVE_SIZE);
        assert(xsave_size <= X86_KVM_XSAVE_MAX_SIZE);

        fxsave = xsave_fxsave(xsave);
        storage_address = frame_address + offsetof(GuestSignalFrame, xstate_storage);
        if (guest_xstate_address < storage_address ||
            guest_xstate_address - storage_address > 63 ||
            (uintptr_t) frame->context.uc_mcontext.fpregs != guest_xstate_address)
                return -EFAULT;

        storage_offset = guest_xstate_address - storage_address;
        signal_xstate = (const X86SignalXstate*) (frame->xstate_storage + storage_offset);
        sw_bytes = (const X86FpxSwBytes*) (
                        (const uint8_t*) &signal_xstate->fxsave + X86_FXSAVE_SW_RESERVED_OFFSET);
        if (sw_bytes->magic1 != X86_FP_XSTATE_MAGIC1 ||
                        sw_bytes->extended_size != xsave_size + sizeof(uint32_t) ||
                        sw_bytes->xfeatures != supported_xfeatures ||
                        sw_bytes->xstate_size != xsave_size ||
                        unaligned_read_le32((const uint8_t*) signal_xstate + xsave_size) != X86_FP_XSTATE_MAGIC2 ||
                        (signal_xstate->header.xfeatures & ~supported_xfeatures) != 0 ||
            (signal_xstate->header.xfeatures & X86_XFEATURE_MASK_FP_SSE) != X86_XFEATURE_MASK_FP_SSE ||
            signal_xstate->header.xcomp_bv != 0 ||
            !memeqzero(signal_xstate->header.reserved, sizeof(signal_xstate->header.reserved)))
                return -EINVAL;

        mxcsr_mask = fxsave->mxcsr_mask != 0 ? fxsave->mxcsr_mask : UINT32_C(0x0000ffff);
        if ((signal_xstate->fxsave.mxcsr & ~mxcsr_mask) != 0)
                return -EINVAL;

        fxsave->fcw = signal_xstate->fxsave.fcw;
        fxsave->fsw = signal_xstate->fxsave.fsw;
        fxsave->ftw = signal_xstate->fxsave.ftw;
        fxsave->fop = signal_xstate->fxsave.fop;
        fxsave->rip = signal_xstate->fxsave.rip;
        fxsave->rdp = signal_xstate->fxsave.rdp;
        fxsave->mxcsr = signal_xstate->fxsave.mxcsr;
        memcpy(fxsave->st, signal_xstate->fxsave.st, sizeof(fxsave->st));
        memcpy(fxsave->xmm, signal_xstate->fxsave.xmm, sizeof(fxsave->xmm));
        memcpy((uint8_t*) xsave->region + X86_YMMH_OFFSET,
               signal_xstate->extended,
               xsave_size - X86_YMMH_OFFSET);
        xsave_header(xsave)->xfeatures = signal_xstate->header.xfeatures;
        return 0;
}

int handle_guest_rt_sigreturn(ExecHypervisor *h, struct kvm_regs *regs) {
        GuestSignalFrame frame = {};
        ExecHypervisorSignalFrame *saved;
        X86KvmXsave xsave;
        int r;

        assert(h);
        assert(regs);

        if (h->n_signal_frames == 0)
                return -EFAULT;

        saved = h->signal_frames + h->n_signal_frames - 1;
        if (regs->rsp != saved->guest_address + sizeof(uint64_t))
                return -EFAULT;

        r = copy_from_guest(h, &frame, saved->guest_address, saved->size);
        if (r < 0)
                return r;
        xsave = saved->xsave;
        r = restore_guest_fpu(
                        &xsave,
                        &frame,
                        saved->guest_address,
                        saved->guest_xstate_address,
                        saved->xfeatures,
                        saved->xsave_size);
        if (r < 0)
                return r;

        if (FLAGS_SET(xsave_header_const(&xsave)->xfeatures, X86_XFEATURE_MASK_XTILE_DATA) &&
            FLAGS_SET(h->xfd, X86_XFEATURE_MASK_XTILE_DATA)) {
                if (!FLAGS_SET(h->machine->xfeatures_permitted, X86_XFEATURE_MASK_XTILE_DATA))
                        return -EINVAL;

                h->xfd = 0;
                h->xfd_err = 0;
                h->xfeatures_allocated = h->machine->xfeatures;
                h->xsave_frame_size = h->machine->xsave_size;
                r = set_vcpu_xfd_state(h, h->vcpu_fd);
                if (r < 0)
                        return r;
        }

        r = set_host_signal_mask(&frame.context.uc_sigmask);
        if (r < 0)
                return r;
        if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &saved->sregs) < 0)
                return -errno;
        r = set_vcpu_xsave(h->vcpu_fd, &xsave);
        if (r < 0)
                return r;

        *regs = saved->regs;
        r = restore_guest_ucontext(regs, &frame);
        if (r < 0)
                return r;
        restore_guest_signal_stack(h, &frame.context.uc_stack);
        h->n_signal_frames--;
        return 0;
}

static int expose_vfork_child_mappings_for_sync(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);
        assert(h->vfork_completion);

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings)
                if (!FLAGS_SET(mapping->protection, PROT_READ) &&
                    mprotect(
                                        (void*) (uintptr_t) mapping->guest_virtual_address,
                                        mapping->size,
                                        mapping->protection | PROT_READ) < 0)
                        return -errno;

        return 0;
}

void notify_vfork_parent(ExecHypervisor *h) {
        assert(h);

        if (!h->vfork_completion)
                return;
        if (expose_vfork_child_mappings_for_sync(h) < 0)
                _exit(EXIT_FAILURE);

        __atomic_store_n(&h->vfork_completion->completed, 1, __ATOMIC_RELEASE);
        (void) syscall(__NR_futex,
                       &h->vfork_completion->completed,
                       FUTEX_WAKE,
                       INT_MAX,
                       NULL,
                       NULL,
                       0);
        while (__atomic_load_n(&h->vfork_completion->synchronized, __ATOMIC_ACQUIRE) == 0) {
                long r = syscall(__NR_futex,
                                 &h->vfork_completion->synchronized,
                                 FUTEX_WAIT,
                                 0,
                                 NULL,
                                 NULL,
                                 0);

                if (r < 0 && !IN_SET(errno, EAGAIN, EINTR))
                        _exit(EXIT_FAILURE);
        }
        (void) munmap(h->vfork_completion, h->vfork_completion->size);
        h->vfork_completion = NULL;
}

#endif

