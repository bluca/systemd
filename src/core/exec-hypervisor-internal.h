/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <elf.h>
#if defined(__x86_64__)
#include <asm/ldt.h>
#include <asm/prctl.h>
#endif
#include <linux/aio_abi.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/fs.h>
#include <linux/ioprio.h>
#include <linux/io_uring.h>
#include <linux/keyctl.h>
#include <linux/kvm.h>
#include <linux/magic.h>
#include <linux/membarrier.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/userfaultfd.h>
#include <linux/xattr.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/auxv.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "elf-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "exec-hypervisor.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fdset.h"
#include "format-util.h"
#include "hashmap.h"
#include "log.h"
#include "memory-util.h"
#include "numa-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "random-util.h"
#include "seccomp-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unaligned.h"
#include "xattr-util.h"

#if defined(__x86_64__)

#ifndef KVM_CAP_MEMORY_FAULT_INFO
#define KVM_CAP_MEMORY_FAULT_INFO 232
#endif

#ifndef KVM_CAP_XSAVE2
#define KVM_CAP_XSAVE2 208
#endif

#ifndef KVM_GET_XSAVE2
#define KVM_GET_XSAVE2 _IOR(KVMIO, 0xcf, struct kvm_xsave)
#endif

#ifndef SHADOW_STACK_SET_TOKEN
#define SHADOW_STACK_SET_TOKEN (1U << 0)
#endif

#ifndef ARCH_REQ_XCOMP_GUEST_PERM
#define ARCH_REQ_XCOMP_GUEST_PERM 0x1025
#endif

#ifndef ARCH_XCOMP_TILEDATA
#define ARCH_XCOMP_TILEDATA 18
#endif

#ifndef MADV_GUARD_REMOVE
#define MADV_GUARD_REMOVE 103
#endif

#ifndef PR_SYS_DISPATCH_EXCLUSIVE_ON
#define PR_SYS_DISPATCH_EXCLUSIVE_ON PR_SYS_DISPATCH_ON
#endif

#ifndef PR_SYS_DISPATCH_INCLUSIVE_ON
#define PR_SYS_DISPATCH_INCLUSIVE_ON 2
#endif

#ifndef FUTEX_ROBUST_MOD_PI
#define FUTEX_ROBUST_MOD_PI UINT64_C(1)
#define FUTEX_ROBUST_MOD_MASK FUTEX_ROBUST_MOD_PI
#endif

#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif

#ifndef __NR_rseq_slice_yield
#define __NR_rseq_slice_yield 471
#endif

#ifndef PR_FUTEX_HASH
#define PR_FUTEX_HASH 78
#define PR_FUTEX_HASH_SET_SLOTS 1
#define PR_FUTEX_HASH_GET_SLOTS 2
#endif

#ifndef PR_GET_CFI
#define PR_GET_CFI 80
#define PR_SET_CFI 81
#define PR_CFI_BRANCH_LANDING_PADS 0
#define PR_CFI_ENABLE (1UL << 0)
#endif

#ifndef IORING_REGISTER_QUERY
#define IORING_REGISTER_QUERY 35
#endif

#ifndef IORING_REGISTER_BPF_FILTER
#define IORING_REGISTER_BPF_FILTER 37
#endif

#ifndef KVM_CAP_PRE_FAULT_MEMORY
#define KVM_CAP_PRE_FAULT_MEMORY 236
#endif

#define EXEC_HYPERVISOR_SUPERVISOR_SIZE (16U * 1024U * 1024U)
#define EXEC_HYPERVISOR_GPA_ALIGNMENT (2U * 1024U * 1024U)
#define EXEC_HYPERVISOR_STACK_SIZE (1024U * 1024U)
#define EXEC_HYPERVISOR_HEAP_SIZE (64U * 1024U * 1024U)
#define X86_PAGE_PRESENT (UINT64_C(1) << 0)
#define X86_PAGE_WRITE (UINT64_C(1) << 1)
#define X86_PAGE_USER (UINT64_C(1) << 2)
#define X86_PAGE_DIRTY (UINT64_C(1) << 6)
#define X86_PAGE_SOFTWARE_PROT_NONE (UINT64_C(1) << 9)
#define X86_PAGE_SOFTWARE_SIGBUS (UINT64_C(1) << 10)
#define X86_PAGE_SOFTWARE_UFFD_POISON (UINT64_C(1) << 11)
#define X86_PAGE_ADDRESS_MASK UINT64_C(0x000ffffffffff000)
#define X86_PAGE_NO_EXECUTE (UINT64_C(1) << 63)
#define X86_CR0_PE (UINT64_C(1) << 0)
#define X86_CR0_MP (UINT64_C(1) << 1)
#define X86_CR0_ET (UINT64_C(1) << 4)
#define X86_CR0_NE (UINT64_C(1) << 5)
#define X86_CR0_WP (UINT64_C(1) << 16)
#define X86_CR0_PG (UINT64_C(1) << 31)
#define X86_CR4_PAE (UINT64_C(1) << 5)
#define X86_CR4_TSD (UINT64_C(1) << 2)
#define X86_CR4_OSFXSR (UINT64_C(1) << 9)
#define X86_CR4_OSXMMEXCPT (UINT64_C(1) << 10)
#define X86_CR4_FSGSBASE (UINT64_C(1) << 16)
#define X86_CR4_OSXSAVE (UINT64_C(1) << 18)
#define X86_CR4_CET (UINT64_C(1) << 23)
#define X86_EFER_SCE (UINT64_C(1) << 0)
#define X86_EFER_LME (UINT64_C(1) << 8)
#define X86_EFER_LMA (UINT64_C(1) << 10)
#define X86_EFER_NXE (UINT64_C(1) << 11)
#define X86_MSR_STAR UINT32_C(0xc0000081)
#define X86_MSR_LSTAR UINT32_C(0xc0000082)
#define X86_MSR_FMASK UINT32_C(0xc0000084)
#define X86_MSR_IA32_SPEC_CTRL UINT32_C(0x00000048)
#define X86_MSR_IA32_PRED_CMD UINT32_C(0x00000049)
#define X86_MSR_IA32_FLUSH_CMD UINT32_C(0x0000010b)
#define X86_MSR_IA32_XFD UINT32_C(0x000001c4)
#define X86_MSR_IA32_XFD_ERR UINT32_C(0x000001c5)
#define X86_MSR_IA32_U_CET UINT32_C(0x000006a0)
#define X86_MSR_IA32_PL3_SSP UINT32_C(0x000006a7)
#define X86_MSR_AMD64_VIRT_SPEC_CTRL UINT32_C(0xc001011f)
#define X86_SPEC_CTRL_IBRS (UINT64_C(1) << 0)
#define X86_SPEC_CTRL_STIBP (UINT64_C(1) << 1)
#define X86_SPEC_CTRL_SSBD (UINT64_C(1) << 2)
#define X86_PRED_CMD_IBPB (UINT64_C(1) << 0)
#define X86_FLUSH_CMD_L1D (UINT64_C(1) << 0)
#define EXEC_HYPERVISOR_PROBE_MARKER UINT32_C(0x4b564d45)
#define EXEC_HYPERVISOR_EXCEPTION_PORT UINT16_C(0x12)
#define EXEC_HYPERVISOR_EXCEPTION_STUB_OFFSET 64U
#define EXEC_HYPERVISOR_EXCEPTION_STUB_SIZE 9U
#define EXEC_HYPERVISOR_N_EXCEPTIONS 32U
#define X86_XFEATURE_MAX 19U
#define EXEC_HYPERVISOR_N_SIGNALS 64U
#define EXEC_HYPERVISOR_MAX_SIGNAL_FRAMES 16U
#define EXEC_HYPERVISOR_RSEQ_SIZE 32U
#define EXEC_HYPERVISOR_RSEQ_FEATURE_SIZE 28U
#define EXEC_HYPERVISOR_RSEQ_ALIGNMENT 32U
#define EXEC_HYPERVISOR_AUXV_MAX_ENTRIES 64U
#define EXEC_HYPERVISOR_COMM_SIZE 16U
#define EXEC_HYPERVISOR_MAX_PID_NS_LEVEL 32U
#define EXEC_HYPERVISOR_CONTROL_SIGNAL 32
#define EXEC_HYPERVISOR_QUIESCE_MAGIC INT32_C(0x4b564d51)

#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31)
#endif

#ifndef CLONE_AUTOREAP
#define CLONE_AUTOREAP (UINT64_C(1) << 34)
#define CLONE_NNP (UINT64_C(1) << 35)
#define CLONE_PIDFD_AUTOKILL (UINT64_C(1) << 36)
#define CLONE_EMPTY_MNTNS (UINT64_C(1) << 37)
#endif

#ifndef AT_RSEQ_FEATURE_SIZE
#define AT_RSEQ_FEATURE_SIZE 27
#endif

#ifndef AT_RSEQ_ALIGN
#define AT_RSEQ_ALIGN 28
#endif

__asm__(
        ".pushsection .text.exec_hypervisor_restore_rt,\"ax\",@progbits\n"
        ".hidden exec_hypervisor_restore_rt\n"
        ".type exec_hypervisor_restore_rt,@function\n"
        "exec_hypervisor_restore_rt:\n"
        "mov $15, %eax\n"
        "syscall\n"
        "ud2\n"
        ".size exec_hypervisor_restore_rt, . - exec_hypervisor_restore_rt\n"
        ".popsection\n");

extern void exec_hypervisor_restore_rt(void);

typedef struct X86IdtGate {
        uint16_t offset_low;
        uint16_t selector;
        uint8_t ist;
        uint8_t type_attributes;
        uint16_t offset_middle;
        uint32_t offset_high;
        uint32_t reserved;
} _packed_ X86IdtGate;

assert_cc(sizeof(X86IdtGate) == 16);

typedef struct X86FxsaveArea {
        uint16_t fcw;
        uint16_t fsw;
        uint16_t ftw;
        uint16_t fop;
        uint64_t rip;
        uint64_t rdp;
        uint32_t mxcsr;
        uint32_t mxcsr_mask;
        uint8_t st[128];
        uint8_t xmm[256];
        uint8_t reserved[96];
} _packed_ X86FxsaveArea;

assert_cc(sizeof(X86FxsaveArea) == 512);
assert_cc(offsetof(X86FxsaveArea, mxcsr) == 24);

typedef struct X86XsaveHeader {
        uint64_t xfeatures;
        uint64_t xcomp_bv;
        uint64_t reserved[6];
} _packed_ X86XsaveHeader;

assert_cc(sizeof(X86XsaveHeader) == 64);

#define X86_KVM_XSAVE_MAX_SIZE (16U * 1024U)

typedef struct X86KvmXsave {
        uint32_t region[X86_KVM_XSAVE_MAX_SIZE / sizeof(uint32_t)];
} X86KvmXsave;

assert_cc(sizeof(X86KvmXsave) >= sizeof(struct kvm_xsave));

#define X86_XFEATURE_MASK_FP_SSE UINT64_C(3)
#define X86_XFEATURE_MASK_AVX UINT64_C(7)
#define X86_XFEATURE_MASK_AVX512 UINT64_C(0xe7)
#define X86_XFEATURE_MASK_CET_USER (UINT64_C(1) << 11)
#define X86_XFEATURE_MASK_XTILE_CFG (UINT64_C(1) << 17)
#define X86_XFEATURE_MASK_XTILE_DATA (UINT64_C(1) << 18)
#define X86_XFEATURE_MASK_XTILE (X86_XFEATURE_MASK_XTILE_CFG|X86_XFEATURE_MASK_XTILE_DATA)
#define X86_AVX_XSAVE_SIZE 832U
#define X86_AVX512_XSAVE_SIZE 2432U
#define X86_YMMH_OFFSET 576U
#define X86_YMMH_SIZE 256U
#define X86_OPMASK_OFFSET 832U
#define X86_OPMASK_SIZE 64U
#define X86_ZMM_HI256_OFFSET 896U
#define X86_ZMM_HI256_SIZE 512U
#define X86_HI16_ZMM_OFFSET 1408U
#define X86_HI16_ZMM_SIZE 1024U
#define X86_HWCAP2_FSGSBASE UINT64_C(2)

typedef struct X86FpxSwBytes {
        uint32_t magic1;
        uint32_t extended_size;
        uint64_t xfeatures;
        uint32_t xstate_size;
        uint32_t padding[7];
} _packed_ X86FpxSwBytes;

assert_cc(sizeof(X86FpxSwBytes) == 48);

#define X86_FP_XSTATE_MAGIC1 UINT32_C(0x46505853)
#define X86_FP_XSTATE_MAGIC2 UINT32_C(0x46505845)
#define X86_FXSAVE_SW_RESERVED_OFFSET 464U

typedef struct X86SignalXstate {
        X86FxsaveArea fxsave;
        X86XsaveHeader header;
        uint8_t extended[X86_KVM_XSAVE_MAX_SIZE - X86_YMMH_OFFSET];
} _packed_ X86SignalXstate;

assert_cc(offsetof(X86SignalXstate, header) == sizeof(X86FxsaveArea));
assert_cc(offsetof(X86SignalXstate, extended) == X86_YMMH_OFFSET);
assert_cc(sizeof(X86SignalXstate) == X86_KVM_XSAVE_MAX_SIZE);

#define X86_SIGNAL_XSTATE_STORAGE_SIZE (sizeof(X86SignalXstate) + sizeof(uint32_t) + 63U)

#define CPUID_BIT(n) (UINT32_C(1) << (n))
#define CPUID_7_0_EBX_UNSUPPORTED_STATE ( \
                CPUID_BIT(14) | /* MPX */ \
                CPUID_BIT(16) | /* AVX512F */ \
                CPUID_BIT(17) | /* AVX512DQ */ \
                CPUID_BIT(21) | /* AVX512IFMA */ \
                CPUID_BIT(26) | /* AVX512PF */ \
                CPUID_BIT(27) | /* AVX512ER */ \
                CPUID_BIT(28) | /* AVX512CD */ \
                CPUID_BIT(30) | /* AVX512BW */ \
                CPUID_BIT(31))  /* AVX512VL */
#define CPUID_7_0_ECX_UNSUPPORTED_STATE ( \
                CPUID_BIT(1)  | /* AVX512VBMI */ \
                CPUID_BIT(3)  | /* PKU */ \
                CPUID_BIT(4)  | /* OSPKE */ \
                CPUID_BIT(6)  | /* AVX512VBMI2 */ \
                CPUID_BIT(7)  | /* CET shadow stack */ \
                CPUID_BIT(8)  | /* GFNI */ \
                CPUID_BIT(9)  | /* VAES */ \
                CPUID_BIT(10) | /* VPCLMULQDQ */ \
                CPUID_BIT(11) | /* AVX512VNNI */ \
                CPUID_BIT(12) | /* AVX512BITALG */ \
                CPUID_BIT(14) | /* AVX512VPOPCNTDQ */ \
                CPUID_BIT(29))  /* ENQCMD/PASID */
#define CPUID_7_0_EDX_UNSUPPORTED_STATE ( \
                CPUID_BIT(2)  | /* AVX5124VNNIW */ \
                CPUID_BIT(3)  | /* AVX5124FMAPS */ \
                CPUID_BIT(5)  | /* UINTR */ \
                CPUID_BIT(8)  | /* AVX512VP2INTERSECT */ \
                CPUID_BIT(20) | /* CET indirect branch tracking */ \
                CPUID_BIT(22) | /* AMX_BF16 */ \
                CPUID_BIT(23) | /* AVX512FP16 */ \
                CPUID_BIT(24) | /* AMX_TILE */ \
                CPUID_BIT(25) | /* AMX_INT8 */ \
                CPUID_BIT(26) | /* IBRS and IBPB */ \
                CPUID_BIT(27) | /* STIBP */ \
                CPUID_BIT(28) | /* L1D flush */ \
                CPUID_BIT(31))  /* SSBD */
#define CPUID_80000001_ECX_UNSUPPORTED_STATE ( \
                CPUID_BIT(11) | /* XOP */ \
                CPUID_BIT(15) | /* LWP */ \
                CPUID_BIT(16))  /* FMA4 */
#define CPUID_80000008_EBX_UNSUPPORTED_SPECULATION ( \
                CPUID_BIT(12) | /* IBPB */ \
                CPUID_BIT(14) | /* IBRS */ \
                CPUID_BIT(15) | /* STIBP */ \
                CPUID_BIT(17) | /* STIBP always on */ \
                CPUID_BIT(19) | /* IBRS same-mode protection */ \
                CPUID_BIT(24) | /* SSBD */ \
                CPUID_BIT(25) | /* virtual SSBD */ \
                CPUID_BIT(26) | /* store bypass not affected */ \
                CPUID_BIT(28) | /* predictive store forwarding disable */ \
                CPUID_BIT(29) | /* branch type confusion not affected */ \
                CPUID_BIT(30))  /* IBPB clears return predictor */

typedef struct ExecHypervisorMapping {
        void *host_address;
        void *kvm_address;
        void *guard_address;
        uint64_t guest_virtual_address;
        uint64_t guest_physical_address;
        size_t size;
        int protection;
        int shadow_stack_protection;
        unsigned slot;
        uint64_t growdown_id;
        bool mutable;
        bool stage2_writable;
        bool file_backed;
        bool shared;
        bool grows_down;
        bool shadow_stack;
        bool shadow_stack_guard_reserved;
        int backing_fd;
        uint64_t file_offset;
        dev_t backing_device;
        ino_t backing_inode;
} ExecHypervisorMapping;

static inline void* mapping_kvm_address(const ExecHypervisorMapping *mapping) {
        assert(mapping);

        return mapping->kvm_address ?: mapping->host_address;
}

typedef struct ExecHypervisorUserfaultRange {
        uint64_t start;
        uint64_t length;
        uint64_t mode;
        int fd;
        dev_t device;
        ino_t inode;
        bool write_protected;
        bool features_known;
        uint64_t features;
} ExecHypervisorUserfaultRange;

typedef struct ExecHypervisorUserfaultContext {
        dev_t device;
        ino_t inode;
        uint64_t features;
} ExecHypervisorUserfaultContext;

typedef enum GuestUserfaultSigbusDisposition {
        GUEST_USERFAULT_SIGBUS_NONE,
        GUEST_USERFAULT_SIGBUS_DELIVER,
        GUEST_USERFAULT_SIGBUS_HANDLED,
} GuestUserfaultSigbusDisposition;

typedef struct ExecHypervisorGpaExtent {
        uint64_t address;
        uint64_t size;
} ExecHypervisorGpaExtent;

typedef struct ExecHypervisorGpaReservation {
        ExecHypervisor *machine;
        uint64_t address;
        uint64_t size;
        bool committed;
} ExecHypervisorGpaReservation;

typedef struct ExecHypervisorMemslotReservation {
        ExecHypervisor *machine;
        unsigned *slots;
        size_t n_slots;
        bool committed;
} ExecHypervisorMemslotReservation;

typedef struct ExecHypervisorSealedRange {
        uint64_t start;
        uint64_t length;
} ExecHypervisorSealedRange;

typedef struct GuestAioContext {
        aio_context_t id;
        uint64_t mapping_start;
        size_t mapping_size;
} GuestAioContext;

typedef struct GuestSignalAction {
        uint64_t handler;
        uint64_t flags;
        uint64_t restorer;
        uint64_t mask;
} GuestSignalAction;

typedef struct GuestRseq {
        uint32_t cpu_id_start;
        uint32_t cpu_id;
        uint64_t rseq_cs;
        uint32_t flags;
        uint32_t node_id;
        uint32_t mm_cid;
        uint32_t padding;
} GuestRseq;

assert_cc(sizeof(GuestRseq) == EXEC_HYPERVISOR_RSEQ_SIZE);

typedef struct GuestRseqCs {
        uint32_t version;
        uint32_t flags;
        uint64_t start_ip;
        uint64_t post_commit_offset;
        uint64_t abort_ip;
} GuestRseqCs;

assert_cc(sizeof(GuestRseqCs) == 32);

typedef struct GuestSignalFrame {
        uint64_t restorer;
        ucontext_t context;
        siginfo_t info;
        uint8_t xstate_storage[X86_SIGNAL_XSTATE_STORAGE_SIZE];
} GuestSignalFrame;

static inline size_t guest_signal_frame_size(size_t xsave_size) {
        size_t size;

        assert(xsave_size >= X86_AVX_XSAVE_SIZE);
        assert(xsave_size <= X86_KVM_XSAVE_MAX_SIZE);

        size = ALIGN_TO(offsetof(GuestSignalFrame, xstate_storage) +
                        MAX(xsave_size, (size_t) X86_AVX512_XSAVE_SIZE) + sizeof(uint32_t) + 63U,
                        alignof(GuestSignalFrame));
        assert(size <= sizeof(GuestSignalFrame));
        return size;
}

static inline size_t guest_min_signal_stack_size(size_t xsave_size) {
        return ALIGN_TO(128U + guest_signal_frame_size(xsave_size) + 16U, 16U);
}

typedef struct ExecHypervisorSignalFrame {
        uint64_t guest_address;
        uint64_t guest_xstate_address;
        size_t size;
        uint64_t xfeatures;
        size_t xsave_size;
        struct kvm_regs regs;
        struct kvm_sregs sregs;
        X86KvmXsave xsave;
        sigset_t mask;
} ExecHypervisorSignalFrame;

typedef struct PendingGuestSignal {
        volatile sig_atomic_t pending;
        siginfo_t info;
} PendingGuestSignal;

typedef struct VforkCompletion {
        int completed;
        int synchronized;
        size_t size;
} VforkCompletion;

typedef enum GuestExecRequestState {
        GUEST_EXEC_REQUEST_IDLE,
        GUEST_EXEC_REQUEST_PENDING,
        GUEST_EXEC_REQUEST_COMMITTED,
} GuestExecRequestState;

typedef struct GuestThreadStart {
        pthread_mutex_t mutex;
        pthread_cond_t condition;
        ExecHypervisor *thread;
        bool ready;
        bool start;
        bool started;
        pid_t tid;
} GuestThreadStart;

typedef struct GuestPosixTimer {
        int id;
        int signal;
} GuestPosixTimer;

struct ExecHypervisor {
        ExecHypervisor *machine;
        int kvm_fd;
        int vm_fd;
        int vcpu_fd;
        int image_fd;
        int interpreter_fd;
        struct kvm_run *run;
        size_t run_size;
        unsigned n_memslots;
        ElfImage *image;
        void *image_reservation;
        size_t image_reservation_size;
        uint64_t image_virtual_start;
        uint64_t image_virtual_end;
        uint64_t image_load_bias;
        ElfImage *interpreter_image;
        void *interpreter_reservation;
        size_t interpreter_reservation_size;
        uint64_t interpreter_virtual_start;
        uint64_t interpreter_virtual_end;
        uint64_t interpreter_load_bias;
        void *stack_reservation;
        size_t stack_reservation_size;
        void *stack_address;
        size_t stack_size;
        void *heap_reservation;
        size_t heap_reservation_size;
        uint64_t heap_break;
        uint64_t heap_mapped_end;
        uint64_t heap_guest_physical_address;
        unsigned heap_slot;
        ExecHypervisorMapping *mappings;
        size_t n_mappings;
        size_t n_registered_mappings;
        int *mapping_fds;
        size_t n_mapping_fds;
        ExecHypervisorSealedRange *sealed_ranges;
        size_t n_sealed_ranges;
        ExecHypervisorSealedRange *dontfork_ranges;
        size_t n_dontfork_ranges;
        ExecHypervisorSealedRange *wipeonfork_ranges;
        size_t n_wipeonfork_ranges;
        GuestAioContext *aio_contexts;
        size_t n_aio_contexts;
        bool *free_memslots;
        unsigned supervisor_slot;
        ExecHypervisorUserfaultRange *userfault_ranges;
        size_t n_userfault_ranges;
        ExecHypervisorUserfaultContext *userfault_contexts;
        size_t n_userfault_contexts;
        ExecHypervisorGpaExtent *free_gpa_extents;
        size_t n_free_gpa_extents;
        uint64_t next_guest_physical_address;
        void *supervisor_memory;
        size_t supervisor_memory_size;
        bool *free_supervisor_pages;
        uint64_t next_page_table_gpa;
        uint64_t cr3;
        uint64_t supervisor_code_gpa;
        uint64_t gdt_gpa;
        uint64_t idt_gpa;
        uint64_t tss_gpa;
        uint64_t ring0_stack_gpa;
        uint64_t probe_code_gpa;
        uint8_t random_bytes[16];
        unsigned long hwcap;
        unsigned long hwcap2;
        uint64_t xfeatures;
        uint64_t xfeatures_default;
        uint64_t xfeatures_permitted;
        uint64_t xfd;
        uint64_t xfd_err;
        uint64_t cet_user;
        uint64_t cet_ssp;
        uint64_t shstk_features;
        uint64_t shstk_features_locked;
        uint64_t shstk_address;
        size_t shstk_size;
        uint64_t spec_ctrl;
        uint64_t virt_spec_ctrl;
        uint64_t spec_store_bypass;
        uint64_t spec_indirect_branch;
        uint64_t spec_l1d_flush;
        uint64_t spec_ctrl_supported_mask;
        uint64_t virt_spec_ctrl_supported_mask;
        size_t xsave_size;
        size_t xsave_default_size;
        size_t xsave_permitted_size;
        size_t kvm_xsave2_size;
        size_t xtilecfg_offset;
        size_t xtilecfg_size;
        size_t xtiledata_offset;
        size_t xtiledata_size;
        size_t cet_user_offset;
        size_t cet_user_size;
        unsigned n_rseq_cpus;
        bool fsgsbase;
        bool amx_guest_permission;
        bool amx_supported;
        bool shstk_available;
        bool xstate_profile_initialized;
        bool pred_cmd_ibpb_supported;
        bool flush_cmd_l1d_supported;
        bool seccomp_forces_store_bypass;
        bool seccomp_forces_indirect_branch;
        bool speculation_policy_initialized;
        int session_keyring_id;
        bool keyring_policy_initialized;
        long clock_ticks;
        uid_t uid;
        uid_t euid;
        gid_t gid;
        gid_t egid;
        char comm[EXEC_HYPERVISOR_COMM_SIZE];
        Elf64_auxv_t saved_auxv[EXEC_HYPERVISOR_AUXV_MAX_ENTRIES];
        Hashmap *syscall_filter;
        int syscall_errno_or_action;
        bool syscall_allow_list;
        bool syscall_filter_set;
        uint32_t last_exception_vector;
        uint64_t last_exception_cr2;
        uint32_t last_unsupported_syscall;
        uint64_t xfeatures_allocated;
        size_t xsave_frame_size;
        uint64_t clear_tid_address;
        uint64_t robust_list_address;
        GuestPosixTimer *posix_timers;
        size_t n_posix_timers;
        uint64_t rseq_address;
        uint32_t rseq_length;
        uint32_t rseq_signature;
        unsigned vcpu_id;
        GuestSignalAction signal_actions[EXEC_HYPERVISOR_N_SIGNALS + 1];
        GuestSignalAction saved_host_signal_actions[EXEC_HYPERVISOR_N_SIGNALS + 1];
        bool signal_actions_initialized[EXEC_HYPERVISOR_N_SIGNALS + 1];
        bool host_signal_actions_modified[EXEC_HYPERVISOR_N_SIGNALS + 1];
        PendingGuestSignal pending_signals[EXEC_HYPERVISOR_N_SIGNALS + 1];
        ExecHypervisorSignalFrame signal_frames[EXEC_HYPERVISOR_MAX_SIGNAL_FRAMES];
        size_t n_signal_frames;
        int wait_signal_signo;
        sigset_t wait_signal_frame_mask;
        sigset_t wait_signal_handler_mask;
        stack_t signal_stack;
        sigset_t exec_signal_mask;
        unsigned long exec_timer_slack;
        struct sched_attr exec_sched_attr;
        CPUSet exec_cpu_affinity;
        int exec_mempolicy;
        CPUSet exec_mempolicy_nodes;
        uint64_t exec_core_sched_cookie;
        int exec_ioprio;
        int exec_mce_kill;
        int exec_pdeathsig;
        unsigned long exec_personality;
        VforkCompletion *vfork_completion;
        pthread_mutex_t memory_lock;
        pthread_mutex_t quiesce_lock;
        pthread_mutex_t signal_lock;
        ExecHypervisor **idle_vcpus;
        size_t n_idle_vcpus;
        ExecHypervisor **active_vcpus;
        size_t n_active_vcpus;
        ExecHypervisor *exec_caller;
        ExecHypervisor *exec_replacement;
        char **deferred_exec_argv;
        char **deferred_exec_envp;
        unsigned next_vcpu_id;
        uint64_t next_growdown_id;
        unsigned n_guest_threads;
        unsigned futex_hash_slots;
        unsigned exec_request_state;
        uint32_t membarrier_registrations;
        unsigned quiesce_generation;
        unsigned quiesce_scan_generation;
        unsigned quiesce_acknowledged;
        unsigned quiesce_expected;
        pid_t quiesce_owner_tid;
        unsigned quiesce_requested_generation;
        unsigned quiesce_seen_generation;
        pid_t runner_tid;
        pid_t owner_tid;
        bool files_shared;
        bool preserve_shared_fds;
        bool exec_cpu_affinity_set;
        bool exec_core_sched_supported;
        bool exec_ioprio_set;
        bool exec_mce_kill_set;
        bool exec_mempolicy_set;
        bool exec_no_new_privs;
        bool exec_pdeathsig_set;
        bool exec_personality_set;
        bool exec_sched_attr_set;
        bool exec_signal_mask_set;
        bool exec_timer_slack_set;
        bool thread_vcpu;
        bool io_flusher;
        bool io_uring_used;
        bool io_uring_task_restricted;
        bool futex_hash_custom;
        bool handoff_context_changed;
        bool landlock_restricted;
        bool mlockall_current;
        bool mlockall_future;
        bool mlock_range_seen;
        bool no_new_privs;
        bool seccomp_local_filter;
        bool secure_exec;
        bool timer_restore_ids;
        bool tsc_disabled;
        bool terminate_for_exec;
        bool vcpu_in_guest;
        bool selected;
};

ExecHypervisor* exec_hypervisor_machine(ExecHypervisor *h);
int register_image_mappings(ExecHypervisor *h);
uint64_t* guest_page_entry(ExecHypervisor *h, uint64_t gva);
int setup_page_tables(ExecHypervisor *h);

int set_supported_cpuid_fd(ExecHypervisor *h, int vcpu_fd);
int set_supported_cpuid(ExecHypervisor *h);
struct kvm_segment make_code_segment(uint16_t selector, uint8_t dpl);
struct kvm_segment make_data_segment(uint16_t selector, uint8_t dpl);
int set_vcpu_syscall_msrs(ExecHypervisor *h, int vcpu_fd);
int set_vcpu_xfd_state(ExecHypervisor *h, int vcpu_fd);
int get_vcpu_xfd_state(ExecHypervisor *h, int vcpu_fd);
int set_vcpu_speculation_msrs(ExecHypervisor *h, int vcpu_fd);
int issue_guest_indirect_branch_barrier(ExecHypervisor *h);
int commit_guest_seccomp_filter(ExecHypervisor *h, bool synchronize, bool allow_speculation);
int initialize_guest_speculation_policy(ExecHypervisor *h);
int initialize_guest_keyring_policy(ExecHypervisor *h);
uint64_t handle_guest_store_bypass(ExecHypervisor *h, const struct kvm_regs *regs);
uint64_t handle_guest_indirect_branch(ExecHypervisor *h, const struct kvm_regs *regs);
uint64_t handle_guest_l1d_flush(ExecHypervisor *h, const struct kvm_regs *regs);
int probe_vcpu_speculation_msrs(ExecHypervisor *h, int vcpu_fd);
X86FxsaveArea* xsave_fxsave(X86KvmXsave *xsave);
const X86FxsaveArea* xsave_fxsave_const(const X86KvmXsave *xsave);
const X86XsaveHeader* xsave_header_const(const X86KvmXsave *xsave);
X86XsaveHeader* xsave_header(X86KvmXsave *xsave);
void reset_dynamic_xsave(ExecHypervisor *h, X86KvmXsave *xsave);
int get_vcpu_xsave(ExecHypervisor *h, int vcpu_fd, X86KvmXsave *ret);
int set_vcpu_xsave(int vcpu_fd, const X86KvmXsave *xsave);
int set_vcpu_xcr0(ExecHypervisor *h, int vcpu_fd);
int setup_vcpu_state(ExecHypervisor *h);
int validate_translation(ExecHypervisor *h, uint64_t address, bool writeable);
int validate_vcpu_state(ExecHypervisor *h);
int reconcile_dontfork_mappings_after_fork(ExecHypervisor *h);
int recreate_hypervisor_machine_after_fork(
                ExecHypervisor *h,
                struct kvm_regs *regs,
                const struct kvm_sregs *old_sregs,
                const X86KvmXsave *xsave);

int begin_guest_quiescence(ExecHypervisor *h);
int wait_guest_quiescence(ExecHypervisor *h);
void end_guest_quiescence(ExecHypervisor *h);
int begin_guest_memory_transaction(ExecHypervisor *h);
void end_guest_memory_transaction(ExecHypervisor *h);
int flush_all_guest_tlbs(ExecHypervisor *h);
ExecHypervisorMapping* find_mapping(ExecHypervisor *h, uint64_t address);
int prepare_userfault_ranges_after_unmap(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                ExecHypervisorUserfaultRange **ret_ranges,
                size_t *ret_n_ranges);
uint64_t raw_host_syscall(const struct kvm_regs *regs);
uint64_t handle_guest_madvise(ExecHypervisor *h, const struct kvm_regs *regs);
int copy_from_guest(ExecHypervisor *h, void *destination, uint64_t guest_address, size_t size);

void coalesce_userfault_ranges(ExecHypervisor *h);
void commit_userfault_range_split(
                ExecHypervisor *h,
                size_t range_index,
                uint64_t start,
                uint64_t end,
                bool keep_middle,
                bool middle_write_protected,
                int middle_fd);
uint64_t handle_guest_ioctl(ExecHypervisor *h, const struct kvm_regs *regs);
uint64_t handle_guest_process_madvise(ExecHypervisor *h, const struct kvm_regs *regs);
bool guest_ioctl_requires_quiescence(uint64_t request);
int guest_userfault_delivers_sigbus(ExecHypervisor *h, uint64_t address, uint64_t error_code);
int resolve_guest_userfault(ExecHypervisor *h, uint64_t address, uint64_t error_code);

extern _Thread_local ExecHypervisor *signal_hypervisor;

int allocate_memslot(ExecHypervisor *h, unsigned *ret_slot);
void release_memslot(ExecHypervisor *h, unsigned slot);
void gpa_reservation_done(ExecHypervisorGpaReservation *reservation);
int reserve_guest_physical(
                ExecHypervisor *h,
                uint64_t size,
                ExecHypervisorGpaReservation *ret_reservation);
void hypervisor_signal_handler(int signo, siginfo_t *info, void *context);
void reclaim_guest_page_tables(ExecHypervisor *h, uint64_t gva);
int map_guest_page(ExecHypervisor *h, uint64_t gva, uint64_t gpa, uint64_t flags);
void unmap_guest_page(ExecHypervisor *h, uint64_t gva);
uint64_t guest_page_flags(int protection);
int flush_guest_tlb(ExecHypervisor *h);
ExecHypervisorMapping* find_mapping_by_gpa(ExecHypervisor *h, uint64_t gpa, uint64_t size);
int probe_file_mapping_page(const ExecHypervisorMapping *mapping, uint64_t page);
int copy_to_guest(ExecHypervisor *h, uint64_t guest_address, const void *source, size_t size);
int abort_guest_rseq_for_signal(ExecHypervisor *h, struct kvm_regs *regs);

int host_signal_action(int signo, const GuestSignalAction *action, GuestSignalAction *old_action);
int get_host_signal_mask(sigset_t *ret);
int set_host_signal_mask(const sigset_t *mask);
uint64_t handle_guest_masked_wait(ExecHypervisor *h, const struct kvm_regs *regs);
int initialize_guest_signal_action(ExecHypervisor *h, int signo);
int set_host_signal_action(ExecHypervisor *h, int signo, const GuestSignalAction *action);
int reapply_guest_reserved_signal_actions(ExecHypervisor *h);
uint64_t handle_guest_rt_sigaction(
                ExecHypervisor *h,
                uint64_t signo,
                uint64_t action_address,
                uint64_t old_action_address,
                uint64_t sigset_size);
uint64_t handle_guest_sigaltstack(
                ExecHypervisor *h,
                uint64_t stack_address,
                uint64_t old_stack_address,
                uint64_t stack_pointer);
uint64_t handle_guest_arch_prctl(ExecHypervisor *h, uint64_t operation, uint64_t address);
int validate_guest_range(ExecHypervisor *h, uint64_t address, size_t size, bool writeable);
int deliver_pending_guest_signal(ExecHypervisor *h);
int handle_guest_exception(ExecHypervisor *h, uint32_t vector, uint64_t fault_address);
int handle_guest_memory_fault(ExecHypervisor *h, int error);
int handle_guest_rt_sigreturn(ExecHypervisor *h, struct kvm_regs *regs);
void notify_vfork_parent(ExecHypervisor *h);

int destroy_guest_aio_contexts(ExecHypervisor *h);
uint64_t handle_guest_mmap(ExecHypervisor *h, const struct kvm_regs *regs);
uint64_t handle_guest_mprotect(
                ExecHypervisor *h,
                uint64_t address,
                uint64_t requested_length,
                int protection,
                int pkey);
uint64_t handle_guest_munmap(ExecHypervisor *h, uint64_t address, uint64_t requested_length);
uint64_t handle_guest_brk(ExecHypervisor *h, uint64_t requested);
int allocate_supervisor_page(ExecHypervisor *h, uint64_t flags, uint64_t *ret_gpa, void **ret_host);
int exec_hypervisor_open_existing(ExecHypervisor *source, ExecHypervisor **ret);
int copy_guest_cstring(ExecHypervisor *h, uint64_t guest_address, size_t *remaining, char **ret);
int copy_guest_strv(ExecHypervisor *h, uint64_t guest_address, size_t *remaining, char ***ret);
void clear_guest_tid_address(ExecHypervisor *h, uint64_t clear_tid_address);
void update_guest_futex_hash_after_thread_clone(ExecHypervisor *machine, unsigned n_threads);

int install_guest_exec_control_signal(ExecHypervisor *h);
_noreturn_ void process_guest_exec_request(ExecHypervisor *h);
uint64_t handle_guest_execve(ExecHypervisor *h, const struct kvm_regs *regs);
uint64_t handle_guest_execveat(ExecHypervisor *h, const struct kvm_regs *regs);
int handle_guest_vfork(
                ExecHypervisor *h,
                struct kvm_regs *regs,
                bool legacy_clone,
                int exit_signal,
                bool set_tls,
                uint64_t tls,
                uint64_t *ret);
int handle_guest_fork(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret);
int handle_guest_clone(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret);
int handle_guest_clone3(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret);
bool guest_syscall_should_restart(
                ExecHypervisor *h,
                uint32_t syscall_number,
                uint64_t argument1,
                uint64_t argument2,
                uint64_t argument3,
                uint64_t argument4);
int wait_for_guest_threads(ExecHypervisor *h);

void memslot_reservation_done(ExecHypervisorMemslotReservation *reservation);
int reserve_memslots(
                ExecHypervisor *h,
                size_t n_slots,
                ExecHypervisorMemslotReservation *ret_reservation);
int ensure_gpa_release_capacity(ExecHypervisor *h, size_t additional);
int release_guest_physical(ExecHypervisor *h, uint64_t address, uint64_t size);
int prepare_dontfork_ranges(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                bool add,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges);
int prepare_wipeonfork_ranges(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                bool add,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges);
int prepare_mremap_fork_advice_ranges(
                const ExecHypervisorSealedRange *old_ranges,
                size_t n_old_ranges,
                uint64_t source,
                uint64_t old_length,
                uint64_t target,
                uint64_t new_length,
                bool dontunmap,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges);

uint64_t* page_table_at(ExecHypervisor *h, uint64_t gpa);
int allocate_page_table(ExecHypervisor *h, uint64_t *ret_gpa);
uint64_t guest_mapping_page_flags(const ExecHypervisorMapping *mapping);
int query_host_mapping(uint64_t address, struct procmap_query *ret_query);
int host_mapping_has_vm_flag(uint64_t address, const char *flag, bool *ret);
int mark_inaccessible_file_pages(ExecHypervisor *h);
int prepare_userfault_ranges_after_dontneed(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                ExecHypervisorUserfaultRange **ret_ranges,
                size_t *ret_n_ranges);
uint64_t handle_guest_remap_file_pages(ExecHypervisor *h, const struct kvm_regs *regs);
int handle_guest_mremap(ExecHypervisor *h, const struct kvm_regs *regs, uint64_t *ret);
uint64_t handle_guest_mseal(ExecHypervisor *h, const struct kvm_regs *regs);
bool kvm_errno_is_unavailable(int error);

#endif
