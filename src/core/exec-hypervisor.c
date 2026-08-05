/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

static void* mapping_kvm_address(const ExecHypervisorMapping *mapping) {
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

typedef struct ExecHypervisorGpaExtent {
        uint64_t address;
        uint64_t size;
} ExecHypervisorGpaExtent;

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

static size_t guest_signal_frame_size(size_t xsave_size) {
        size_t size;

        assert(xsave_size >= X86_AVX_XSAVE_SIZE);
        assert(xsave_size <= X86_KVM_XSAVE_MAX_SIZE);

        size = ALIGN_TO(offsetof(GuestSignalFrame, xstate_storage) +
                        MAX(xsave_size, (size_t) X86_AVX512_XSAVE_SIZE) + sizeof(uint32_t) + 63U,
                        alignof(GuestSignalFrame));
        assert(size <= sizeof(GuestSignalFrame));
        return size;
}

static size_t guest_min_signal_stack_size(size_t xsave_size) {
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

static _Thread_local ExecHypervisor *signal_hypervisor = NULL;

static ExecHypervisor* exec_hypervisor_machine(ExecHypervisor *h) {
        assert(h);

        return ASSERT_PTR(h->machine);
}

static int allocate_memslot(ExecHypervisor *h, unsigned *ret_slot) {
        ExecHypervisor *machine;

        assert(h);
        assert(ret_slot);

        machine = exec_hypervisor_machine(h);
        assert(machine->free_memslots);

        for (unsigned slot = 0; slot < machine->n_registered_mappings; slot++)
                if (machine->free_memslots[slot]) {
                        machine->free_memslots[slot] = false;
                        *ret_slot = slot;
                        return 0;
                }

        if (machine->n_registered_mappings >= machine->n_memslots)
                return -ENOSPC;

        *ret_slot = machine->n_registered_mappings++;
        return 0;
}

static void release_memslot(ExecHypervisor *h, unsigned slot) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert(machine->free_memslots);
        assert(slot < machine->n_registered_mappings);
        assert(!machine->free_memslots[slot]);

        if (slot + 1 < machine->n_registered_mappings) {
                machine->free_memslots[slot] = true;
                return;
        }

        machine->n_registered_mappings--;
        while (machine->n_registered_mappings > 0 &&
               machine->free_memslots[machine->n_registered_mappings - 1]) {
                machine->free_memslots[machine->n_registered_mappings - 1] = false;
                machine->n_registered_mappings--;
        }
}

typedef struct ExecHypervisorMemslotReservation {
        ExecHypervisor *machine;
        unsigned *slots;
        size_t n_slots;
        bool committed;
} ExecHypervisorMemslotReservation;

static void memslot_reservation_done(ExecHypervisorMemslotReservation *reservation) {
        if (!reservation)
                return;

        if (!reservation->committed)
                for (size_t i = reservation->n_slots; i > 0; i--)
                        release_memslot(reservation->machine, reservation->slots[i - 1]);
        free(reservation->slots);
        *reservation = (ExecHypervisorMemslotReservation) {};
}

static int reserve_memslots(
                ExecHypervisor *h,
                size_t n_slots,
                ExecHypervisorMemslotReservation *ret_reservation) {

        ExecHypervisorMemslotReservation reservation = {
                .machine = exec_hypervisor_machine(h),
        };
        int r;

        assert(h);
        assert(ret_reservation);

        if (n_slots == 0) {
                *ret_reservation = reservation;
                return 0;
        }

        reservation.slots = new(unsigned, n_slots);
        if (!reservation.slots)
                return -ENOMEM;
        for (; reservation.n_slots < n_slots; reservation.n_slots++) {
                r = allocate_memslot(h, reservation.slots + reservation.n_slots);
                if (r < 0) {
                        memslot_reservation_done(&reservation);
                        return r;
                }
        }

        *ret_reservation = reservation;
        return 0;
}

static int ensure_gpa_release_capacity(ExecHypervisor *h, size_t additional) {
        ExecHypervisor *machine;
        size_t required;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (!ADD_SAFE(&required, machine->n_free_gpa_extents, additional))
                return -EOVERFLOW;
        if (!GREEDY_REALLOC0(machine->free_gpa_extents, required))
                return -ENOMEM;
        return 0;
}

static int release_guest_physical(ExecHypervisor *h, uint64_t address, uint64_t size) {
        ExecHypervisor *machine;
        uint64_t end;
        size_t i;
        int r;

        assert(h);
        assert(size > 0);
        assert(address % page_size() == 0);
        assert(size % page_size() == 0);

        machine = exec_hypervisor_machine(h);
        if (!ADD_SAFE(&end, address, size))
                return -EOVERFLOW;
        r = ensure_gpa_release_capacity(machine, 1);
        if (r < 0)
                return r;

        for (i = 0; i < machine->n_free_gpa_extents && machine->free_gpa_extents[i].address < address; i++)
                ;
        if ((i > 0 && machine->free_gpa_extents[i - 1].address + machine->free_gpa_extents[i - 1].size > address) ||
            (i < machine->n_free_gpa_extents && end > machine->free_gpa_extents[i].address))
                return -EEXIST;

        if (i > 0 && machine->free_gpa_extents[i - 1].address + machine->free_gpa_extents[i - 1].size == address) {
                machine->free_gpa_extents[i - 1].size += size;
                if (i < machine->n_free_gpa_extents &&
                    machine->free_gpa_extents[i - 1].address + machine->free_gpa_extents[i - 1].size ==
                            machine->free_gpa_extents[i].address) {
                        machine->free_gpa_extents[i - 1].size += machine->free_gpa_extents[i].size;
                        memmove(machine->free_gpa_extents + i,
                                machine->free_gpa_extents + i + 1,
                                (machine->n_free_gpa_extents - i - 1) * sizeof(machine->free_gpa_extents[0]));
                        machine->n_free_gpa_extents--;
                }
        } else if (i < machine->n_free_gpa_extents && end == machine->free_gpa_extents[i].address) {
                machine->free_gpa_extents[i].address = address;
                machine->free_gpa_extents[i].size += size;
        } else {
                memmove(machine->free_gpa_extents + i + 1,
                        machine->free_gpa_extents + i,
                        (machine->n_free_gpa_extents - i) * sizeof(machine->free_gpa_extents[0]));
                machine->free_gpa_extents[i] = (ExecHypervisorGpaExtent) {
                        .address = address,
                        .size = size,
                };
                machine->n_free_gpa_extents++;
        }

        while (machine->n_free_gpa_extents > 0) {
                ExecHypervisorGpaExtent *last = machine->free_gpa_extents + machine->n_free_gpa_extents - 1;

                if (last->address + last->size != machine->next_guest_physical_address)
                        break;
                machine->next_guest_physical_address = last->address;
                machine->n_free_gpa_extents--;
        }
        return 0;
}

static int allocate_guest_physical(ExecHypervisor *h, uint64_t size, uint64_t *ret_address) {
        ExecHypervisor *machine;
        uint64_t address;

        assert(h);
        assert(size > 0);
        assert(size % page_size() == 0);
        assert(ret_address);

        machine = exec_hypervisor_machine(h);
        for (size_t i = 0; i < machine->n_free_gpa_extents; i++) {
                ExecHypervisorGpaExtent *extent = machine->free_gpa_extents + i;

                if (extent->size < size)
                        continue;
                address = extent->address;
                extent->address += size;
                extent->size -= size;
                if (extent->size == 0) {
                        memmove(extent,
                                extent + 1,
                                (machine->n_free_gpa_extents - i - 1) * sizeof(machine->free_gpa_extents[0]));
                        machine->n_free_gpa_extents--;
                }
                *ret_address = address;
                return 0;
        }

        address = ALIGN_TO(machine->next_guest_physical_address, page_size());
        if (size > UINT64_MAX - address)
                return -EOVERFLOW;
        machine->next_guest_physical_address = address + size;
        *ret_address = address;
        return 0;
}

typedef struct ExecHypervisorGpaReservation {
        ExecHypervisor *machine;
        uint64_t address;
        uint64_t size;
        bool committed;
} ExecHypervisorGpaReservation;

static void gpa_reservation_done(ExecHypervisorGpaReservation *reservation) {
        if (!reservation || reservation->size == 0)
                return;
        if (!reservation->committed)
                assert_se(release_guest_physical(
                                reservation->machine,
                                reservation->address,
                                reservation->size) >= 0);
        *reservation = (ExecHypervisorGpaReservation) {};
}

static int reserve_guest_physical(
                ExecHypervisor *h,
                uint64_t size,
                ExecHypervisorGpaReservation *ret_reservation) {

        ExecHypervisorGpaReservation reservation = {
                .machine = exec_hypervisor_machine(h),
                .size = size,
        };
        int r;

        assert(h);
        assert(ret_reservation);

        r = ensure_gpa_release_capacity(h, 1);
        if (r < 0)
                return r;
        r = allocate_guest_physical(h, size, &reservation.address);
        if (r < 0)
                return r;

        *ret_reservation = reservation;
        return 0;
}

static void hypervisor_signal_handler(int signo, siginfo_t *info, void *context) {
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

static int wait_guest_quiescence(ExecHypervisor *h) {
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

static void end_guest_quiescence(ExecHypervisor *h);

static int begin_guest_quiescence(ExecHypervisor *h) {
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

static void end_guest_quiescence(ExecHypervisor *h) {
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

static int begin_guest_memory_transaction(ExecHypervisor *h) {
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

static void end_guest_memory_transaction(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        end_guest_quiescence(h);
}

static int destroy_guest_aio_contexts(ExecHypervisor *h) {
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

static bool kvm_errno_is_unavailable(int error) {
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

static int register_image_mappings(ExecHypervisor *h) {
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

static uint64_t* page_table_at(ExecHypervisor *h, uint64_t gpa) {
        ExecHypervisor *machine;

        assert(h);
        assert(gpa % page_size() == 0);

        machine = exec_hypervisor_machine(h);
        assert(machine->supervisor_memory);

        if (gpa >= machine->supervisor_memory_size || page_size() > machine->supervisor_memory_size - gpa)
                return NULL;

        return (uint64_t*) ((uint8_t*) machine->supervisor_memory + gpa);
}

static int allocate_page_table(ExecHypervisor *h, uint64_t *ret_gpa) {
        ExecHypervisor *machine;
        uint64_t *table;

        assert(h);
        assert(ret_gpa);

        machine = exec_hypervisor_machine(h);
        assert(machine->free_supervisor_pages);

        for (uint64_t gpa = page_size(); gpa < machine->next_page_table_gpa; gpa += page_size())
                if (machine->free_supervisor_pages[gpa / page_size()]) {
                        machine->free_supervisor_pages[gpa / page_size()] = false;
                        table = ASSERT_PTR(page_table_at(machine, gpa));
                        memzero(table, page_size());
                        *ret_gpa = gpa;
                        return 0;
                }

        table = page_table_at(machine, machine->next_page_table_gpa);
        if (!table)
                return -ENOSPC;

        memzero(table, page_size());
        *ret_gpa = machine->next_page_table_gpa;
        machine->next_page_table_gpa += page_size();
        return 0;
}

static void release_page_table(ExecHypervisor *h, uint64_t gpa) {
        ExecHypervisor *machine;
        size_t index;

        assert(h);
        assert(gpa >= page_size());
        assert(gpa % page_size() == 0);

        machine = exec_hypervisor_machine(h);
        assert(machine->free_supervisor_pages);
        assert(gpa < machine->next_page_table_gpa);
        index = gpa / page_size();
        assert(!machine->free_supervisor_pages[index]);
        memzero(ASSERT_PTR(page_table_at(machine, gpa)), page_size());

        if (gpa + page_size() < machine->next_page_table_gpa) {
                machine->free_supervisor_pages[index] = true;
                return;
        }

        machine->next_page_table_gpa = gpa;
        while (machine->next_page_table_gpa > page_size()) {
                index = machine->next_page_table_gpa / page_size() - 1;
                if (!machine->free_supervisor_pages[index])
                        break;
                machine->free_supervisor_pages[index] = false;
                machine->next_page_table_gpa -= page_size();
        }
}

static int ensure_guest_page_entry(ExecHypervisor *h, uint64_t gva, uint64_t **ret) {
        const unsigned indices[] = {
                (gva >> 39) & 0x1ff,
                (gva >> 30) & 0x1ff,
                (gva >> 21) & 0x1ff,
                (gva >> 12) & 0x1ff,
        };
        ExecHypervisor *machine;
        uint64_t *created_entries[3];
        uint64_t created_gpas[3];
        size_t n_created = 0;
        uint64_t table_gpa;
        int r;

        assert(h);
                assert(ret);

        machine = exec_hypervisor_machine(h);

        if (gva > UINT64_C(0x00007fffffffffff) ||
                        gva % page_size() != 0)
                return -EINVAL;

        table_gpa = machine->cr3;
        for (size_t level = 0; level < 3; level++) {
                uint64_t child_gpa, *entry, *table;

                table = page_table_at(h, table_gpa);
                if (!table) {
                        r = -EFAULT;
                        goto rollback;
                }
                entry = table + indices[level];

                if (!FLAGS_SET(*entry, X86_PAGE_PRESENT)) {
                        r = allocate_page_table(h, &child_gpa);
                        if (r < 0)
                                goto rollback;

                        *entry = child_gpa | X86_PAGE_PRESENT | X86_PAGE_WRITE | X86_PAGE_USER;
                        created_entries[n_created] = entry;
                        created_gpas[n_created++] = child_gpa;
                }

                table_gpa = *entry & X86_PAGE_ADDRESS_MASK;
        }

        uint64_t *table = page_table_at(h, table_gpa);
        if (!table) {
                r = -EFAULT;
                goto rollback;
        }

        *ret = table + indices[3];
        return 0;

rollback:
        while (n_created > 0) {
                n_created--;
                *created_entries[n_created] = 0;
                release_page_table(h, created_gpas[n_created]);
        }
        return r;
}

static void reclaim_guest_page_tables(ExecHypervisor *h, uint64_t gva) {
        const unsigned indices[] = {
                (gva >> 39) & 0x1ff,
                (gva >> 30) & 0x1ff,
                (gva >> 21) & 0x1ff,
                (gva >> 12) & 0x1ff,
        };
        uint64_t *parent_entries[3], table_gpas[4], *tables[4];
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        table_gpas[0] = machine->cr3;
        tables[0] = page_table_at(machine, table_gpas[0]);
        if (!tables[0])
                return;

        for (size_t level = 0; level < 3; level++) {
                parent_entries[level] = tables[level] + indices[level];
                if (!FLAGS_SET(*parent_entries[level], X86_PAGE_PRESENT))
                        return;
                table_gpas[level + 1] = *parent_entries[level] & X86_PAGE_ADDRESS_MASK;
                tables[level + 1] = page_table_at(machine, table_gpas[level + 1]);
                if (!tables[level + 1])
                        return;
        }
        if (tables[3][indices[3]] != 0)
                return;

        for (size_t level = 3; level > 0; level--) {
                if (!memeqzero(tables[level], page_size()))
                        break;
                *parent_entries[level - 1] = 0;
                release_page_table(machine, table_gpas[level]);
        }
}

static int map_guest_page(ExecHypervisor *h, uint64_t gva, uint64_t gpa, uint64_t flags) {
        uint64_t *entry;
        int r;

        assert(h);

        if (gpa % page_size() != 0)
                return -EINVAL;

        r = ensure_guest_page_entry(h, gva, &entry);
        if (r < 0)
                return r;
        if (*entry != 0)
                return -EEXIST;

        *entry = gpa | flags;
        if (!FLAGS_SET(flags, X86_PAGE_SOFTWARE_PROT_NONE))
                *entry |= X86_PAGE_PRESENT;
        return 0;
}

static void unmap_guest_page(ExecHypervisor *h, uint64_t gva) {
        const unsigned indices[] = {
                (gva >> 39) & 0x1ff,
                (gva >> 30) & 0x1ff,
                (gva >> 21) & 0x1ff,
                (gva >> 12) & 0x1ff,
        };
        ExecHypervisor *machine;
        uint64_t table_gpa;

        assert(h);

        machine = exec_hypervisor_machine(h);
        table_gpa = machine->cr3;
        for (size_t level = 0; level < 3; level++) {
                uint64_t *table = page_table_at(h, table_gpa);

                if (!table || !FLAGS_SET(table[indices[level]], X86_PAGE_PRESENT))
                        return;
                table_gpa = table[indices[level]] & X86_PAGE_ADDRESS_MASK;
        }

        uint64_t *table = page_table_at(h, table_gpa);
        if (table)
                table[indices[3]] = 0;
}

static uint64_t* guest_page_entry(ExecHypervisor *h, uint64_t gva) {
        const unsigned indices[] = {
                (gva >> 39) & 0x1ff,
                (gva >> 30) & 0x1ff,
                (gva >> 21) & 0x1ff,
                (gva >> 12) & 0x1ff,
        };
        ExecHypervisor *machine;
        uint64_t table_gpa;

        assert(h);

        machine = exec_hypervisor_machine(h);
        table_gpa = machine->cr3;
        for (size_t level = 0; level < 3; level++) {
                uint64_t *table = page_table_at(h, table_gpa);

                if (!table || !FLAGS_SET(table[indices[level]], X86_PAGE_PRESENT))
                        return NULL;
                table_gpa = table[indices[level]] & X86_PAGE_ADDRESS_MASK;
        }

        uint64_t *table = page_table_at(h, table_gpa);
        return table ? table + indices[3] : NULL;
}

static uint64_t guest_page_flags(int protection) {
        uint64_t flags = X86_PAGE_USER;

        if (protection == PROT_NONE)
                flags |= X86_PAGE_SOFTWARE_PROT_NONE;
        if (FLAGS_SET(protection, PROT_WRITE))
                flags |= X86_PAGE_WRITE;
        if (!FLAGS_SET(protection, PROT_EXEC))
                flags |= X86_PAGE_NO_EXECUTE;

        return flags;
}

static uint64_t guest_mapping_page_flags(const ExecHypervisorMapping *mapping) {
        int protection;
        uint64_t flags;

        assert(mapping);

        protection = mapping->shadow_stack ? mapping->shadow_stack_protection : mapping->protection;
        flags = guest_page_flags(protection);
        if (mapping->shadow_stack && FLAGS_SET(protection, PROT_WRITE))
                flags = (flags & ~X86_PAGE_WRITE) | X86_PAGE_DIRTY;

        return flags;
}

static uint64_t guest_mapping_page_value(const ExecHypervisorMapping *mapping, uint64_t gpa) {
        int protection;

        assert(mapping);

        protection = mapping->shadow_stack ? mapping->shadow_stack_protection : mapping->protection;
        return gpa | guest_mapping_page_flags(mapping) | (protection == PROT_NONE ? 0 : X86_PAGE_PRESENT);
}

static uint64_t guest_page_value(uint64_t gpa, int protection) {
        uint64_t flags;

        flags = guest_page_flags(protection);
        return gpa | flags | (protection == PROT_NONE ? 0 : X86_PAGE_PRESENT);
}

static int flush_guest_tlb(ExecHypervisor *h) {
        struct kvm_sregs sregs;

        assert(h);

        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;
        if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                return -errno;

        return 0;
}

static int flush_all_guest_tlbs(ExecHypervisor *h) {
        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        r = flush_guest_tlb(machine);
        if (r < 0)
                return r;

        FOREACH_ARRAY(thread, machine->active_vcpus, machine->n_active_vcpus) {
                r = flush_guest_tlb(*thread);
                if (r < 0)
                        return r;
        }

        return 0;
}

static ExecHypervisorMapping* find_mapping(ExecHypervisor *h, uint64_t address) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t end;

                if (ADD_SAFE(&end, mapping->guest_virtual_address, mapping->size) &&
                    address >= mapping->guest_virtual_address && address < end)
                        return mapping;
        }

        return NULL;
}

static int query_host_mapping(uint64_t address, struct procmap_query *ret_query) {
        _cleanup_close_ int fd = -EBADF;
        struct procmap_query query = {
                .size = sizeof(query),
                .query_addr = address,
        };

        assert(ret_query);

        fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        if (ioctl(fd, PROCMAP_QUERY, &query) < 0)
                return -errno;

        *ret_query = query;
        return 0;
}

static int host_mapping_has_vm_flag(uint64_t address, const char *flag, bool *ret) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL;
        size_t allocated = 0;
        bool target = false;

        assert(flag);
        assert(ret);

        f = fopen("/proc/self/smaps", "re");
        if (!f)
                return -errno;
        while (getline(&line, &allocated, f) >= 0) {
                unsigned long end, start;

                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                        target = address >= start && address < end;
                        continue;
                }
                if (!target || !startswith(line, "VmFlags:"))
                        continue;

                const char *p = line + STRLEN("VmFlags:");
                for (;;) {
                        _cleanup_free_ char *word = NULL;
                        int r;

                        r = extract_first_word(&p, &word, NULL, 0);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;
                        if (streq(word, flag)) {
                                *ret = true;
                                return 0;
                        }
                }

                *ret = false;
                return 0;
        }
        if (ferror(f))
                return errno > 0 ? -errno : -EIO;
        return -ENOENT;
}

static int host_mapping_protection(uint64_t start, uint64_t end, int *ret_protection) {
        struct procmap_query query;
        int protection = 0, r;

        assert(start < end);
        assert(ret_protection);

        r = query_host_mapping(start, &query);
        if (r < 0)
                return r;
        if (query.vma_start > start || query.vma_end < end)
                return -EFAULT;

        if (FLAGS_SET(query.vma_flags, PROCMAP_QUERY_VMA_READABLE))
                protection |= PROT_READ;
        if (FLAGS_SET(query.vma_flags, PROCMAP_QUERY_VMA_WRITABLE))
                protection |= PROT_WRITE;
        if (FLAGS_SET(query.vma_flags, PROCMAP_QUERY_VMA_EXECUTABLE))
                protection |= PROT_EXEC;

        *ret_protection = protection;
        return 0;
}

static int allocate_growdown_id(ExecHypervisor *h, uint64_t *ret) {
        ExecHypervisor *machine;

        assert(h);
        assert(ret);

        machine = exec_hypervisor_machine(h);
        machine->next_growdown_id++;
        if (machine->next_growdown_id == 0)
                return -EOVERFLOW;

        *ret = machine->next_growdown_id;
        return 0;
}

static void normalize_growdown_owners(ExecHypervisorMapping *mappings, size_t n_mappings) {
        assert(mappings || n_mappings == 0);

        for (size_t i = 0; i < n_mappings; i++) {
                size_t owner = i;

                if (mappings[i].growdown_id == 0)
                        continue;
                for (size_t j = 0; j < n_mappings; j++)
                        if (mappings[j].growdown_id == mappings[i].growdown_id &&
                            mappings[j].guest_virtual_address < mappings[owner].guest_virtual_address)
                                owner = j;
                mappings[i].grows_down = i == owner;
        }
}

static ExecHypervisorMapping* find_mapping_by_gpa(ExecHypervisor *h, uint64_t gpa, uint64_t size) {
        ExecHypervisor *machine;
        uint64_t end;

        assert(h);

        if (size == 0 || !ADD_SAFE(&end, gpa, size))
                return NULL;

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end;

                if (ADD_SAFE(&mapping_end, mapping->guest_physical_address, mapping->size) &&
                    gpa >= mapping->guest_physical_address && end <= mapping_end)
                        return mapping;
        }

        return NULL;
}

static int probe_file_mapping_page(const ExecHypervisorMapping *mapping, uint64_t page) {
        char byte;
        struct iovec local = {
                .iov_base = &byte,
                .iov_len = sizeof(byte),
        };
        struct iovec remote;
        uint64_t offset;
        ssize_t n;

        assert(mapping);
        assert(mapping->file_backed);
        assert(page >= mapping->guest_virtual_address);

        offset = page - mapping->guest_virtual_address;
        if (offset >= mapping->size)
                return -EFAULT;
        remote = (struct iovec) {
                .iov_base = (uint8_t*) mapping->host_address + offset,
                .iov_len = sizeof(byte),
        };

        n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if (n == (ssize_t) sizeof(byte))
                return 1;
        if (n < 0 && errno == EFAULT)
                return 0;
        return n < 0 ? -errno : -EIO;
}

static int mark_inaccessible_file_pages(ExecHypervisor *h) {
        ExecHypervisor *machine;
        unsigned n_marked = 0;
        int r = 0;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert_se(pthread_mutex_lock(&machine->memory_lock) == 0);
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                if (!mapping->file_backed || !FLAGS_SET(mapping->protection, PROT_READ))
                        continue;

                for (uint64_t offset = 0; offset < mapping->size; offset += page_size()) {
                        uint64_t page = mapping->guest_virtual_address + offset;
                        uint64_t *entry = guest_page_entry(machine, page);

                        if (!entry || !FLAGS_SET(*entry, X86_PAGE_PRESENT))
                                continue;
                        r = probe_file_mapping_page(mapping, page);
                        if (r < 0)
                                goto finish;
                        if (r > 0)
                                continue;

                        *entry = (*entry & ~X86_PAGE_PRESENT) | X86_PAGE_SOFTWARE_SIGBUS;
                        n_marked++;
                }
        }

        if (n_marked > 0) {
                r = flush_all_guest_tlbs(h);
                if (r < 0)
                        goto finish;
        }
        r = n_marked;

finish:
        assert_se(pthread_mutex_unlock(&machine->memory_lock) == 0);
        return r;
}

typedef struct ExecHypervisorFixedMapChange {
        ExecHypervisorMapping old_mapping;
        ExecHypervisorMapping pieces[3];
        size_t n_pieces;
} ExecHypervisorFixedMapChange;

static int set_mapping_memory_region(ExecHypervisor *h, const ExecHypervisorMapping *mapping);
static int remove_mapping_memory_region(ExecHypervisor *h, unsigned slot);
static void coalesce_userfault_ranges(ExecHypervisor *h);
static int prepare_dontfork_ranges(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                bool add,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges);
static int prepare_wipeonfork_ranges(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                bool add,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges);
static int prepare_mremap_fork_advice_ranges(
                const ExecHypervisorSealedRange *old_ranges,
                size_t n_old_ranges,
                uint64_t source,
                uint64_t old_length,
                uint64_t target,
                uint64_t new_length,
                bool dontunmap,
                ExecHypervisorSealedRange **ret_ranges,
                size_t *ret_n_ranges);
static void commit_userfault_range_split(
                ExecHypervisor *h,
                size_t range_index,
                uint64_t start,
                uint64_t end,
                bool keep_middle,
                bool middle_write_protected,
                int middle_fd);

static int retain_mapping_fd(ExecHypervisor *h, int fd, int *ret_fd, struct stat *ret_stat) {
        ExecHypervisor *machine;
        struct stat st;
        int copy;

        assert(h);
        assert(fd >= 0);
        assert(ret_fd);
        assert(ret_stat);

        machine = exec_hypervisor_machine(h);
        if (fstat(fd, &st) < 0)
                return -errno;
        copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;
        if (!GREEDY_REALLOC(machine->mapping_fds, machine->n_mapping_fds + 1)) {
                safe_close(copy);
                return -ENOMEM;
        }
        machine->mapping_fds[machine->n_mapping_fds++] = copy;

        *ret_fd = copy;
        *ret_stat = st;
        return 0;
}

static void close_unused_mapping_fds(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        for (size_t i = 0; i < machine->n_mapping_fds;) {
                int fd = machine->mapping_fds[i];
                bool used = false;

                FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings)
                        if (mapping->file_backed && mapping->backing_fd == fd) {
                                used = true;
                                break;
                        }
                if (used) {
                        i++;
                        continue;
                }

                safe_close(fd);
                machine->mapping_fds[i] = machine->mapping_fds[--machine->n_mapping_fds];
        }
}

static int rollback_fixed_map_memory_regions(
                ExecHypervisor *h, const ExecHypervisorFixedMapChange *changes, size_t n_changes) {

        int first_error = 0;

        assert(h);
        assert(changes || n_changes == 0);

        FOREACH_ARRAY(change, changes, n_changes)
        FOREACH_ARRAY(piece, change->pieces, change->n_pieces)
        (void) remove_mapping_memory_region(h, piece->slot);
        FOREACH_ARRAY(change, changes, n_changes) {
                int r = set_mapping_memory_region(h, &change->old_mapping);

                if (r < 0 && first_error >= 0)
                        first_error = r;
        }

        return first_error;
}

static int prepare_userfault_ranges_after_unmap(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                ExecHypervisorUserfaultRange **ret_ranges,
                size_t *ret_n_ranges) {

        _cleanup_free_ ExecHypervisorUserfaultRange *ranges = NULL;
        ExecHypervisor *machine;
        size_t n_ranges = 0, range_index = 0;

        assert(h);
        assert(start < end);
        assert(ret_ranges);
        assert(ret_n_ranges);

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (start >= range_end || end <= range->start)
                        n_ranges++;
                else {
                        n_ranges += start > range->start;
                        n_ranges += end < range_end;
                }
        }
        if (n_ranges > 0) {
                ranges = new(ExecHypervisorUserfaultRange, n_ranges);
                if (!ranges)
                        return -ENOMEM;
        }

        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (start >= range_end || end <= range->start) {
                        ranges[range_index++] = *range;
                        continue;
                }
                if (start > range->start) {
                        ranges[range_index] = *range;
                        ranges[range_index++].length = start - range->start;
                }
                if (end < range_end) {
                        ranges[range_index] = *range;
                        ranges[range_index].start = end;
                        ranges[range_index++].length = range_end - end;
                }
        }
        assert(range_index == n_ranges);

        *ret_ranges = TAKE_PTR(ranges);
        *ret_n_ranges = n_ranges;
        return 0;
}

static int prepare_userfault_ranges_after_dontneed(
                ExecHypervisor *h,
                uint64_t start,
                uint64_t end,
                ExecHypervisorUserfaultRange **ret_ranges,
                size_t *ret_n_ranges) {

        _cleanup_free_ ExecHypervisorUserfaultRange *ranges = NULL;
        ExecHypervisor *machine;
        size_t n_ranges = 0, range_index = 0;

        assert(h);
        assert(start < end);
        assert(ret_ranges);
        assert(ret_n_ranges);

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (start >= range_end || end <= range->start ||
                    !FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) || !range->write_protected)
                        n_ranges++;
                else {
                        n_ranges += start > range->start;
                        n_ranges++;
                        n_ranges += end < range_end;
                }
        }
        if (n_ranges > 0) {
                ranges = new(ExecHypervisorUserfaultRange, n_ranges);
                if (!ranges)
                        return -ENOMEM;
        }

        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (start >= range_end || end <= range->start ||
                    !FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) || !range->write_protected) {
                        ranges[range_index++] = *range;
                        continue;
                }

                uint64_t overlap_start = MAX(start, range->start);
                uint64_t overlap_end = MIN(end, range_end);

                if (overlap_start > range->start) {
                        ranges[range_index] = *range;
                        ranges[range_index++].length = overlap_start - range->start;
                }
                ranges[range_index] = *range;
                ranges[range_index].start = overlap_start;
                ranges[range_index].length = overlap_end - overlap_start;
                ranges[range_index++].write_protected = false;
                if (overlap_end < range_end) {
                        ranges[range_index] = *range;
                        ranges[range_index].start = overlap_end;
                        ranges[range_index++].length = range_end - overlap_end;
                }
        }
        assert(range_index == n_ranges);

        *ret_ranges = TAKE_PTR(ranges);
        *ret_n_ranges = n_ranges;
        return 0;
}

typedef struct ExecHypervisorShadowStackGuardRelease {
        ExecHypervisor *machine;
        void *address;
        bool released;
        bool committed;
} ExecHypervisorShadowStackGuardRelease;

static void set_shadow_stack_guard_reserved(ExecHypervisor *h, void *address, bool reserved) {
        assert(h);
        assert(address);

        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings)
                if (mapping->shadow_stack && mapping->guard_address == address)
                        mapping->shadow_stack_guard_reserved = reserved;
}

static int reserve_shadow_stack_guard(ExecHypervisor *h, void *address) {
        void *p;

        assert(h);
        assert(address);

        p = mmap(
                        address,
                        page_size(),
                        PROT_NONE,
                        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,
                        -1,
                        0);
        if (p == MAP_FAILED)
                return -errno;
        if (p != address)
                _exit(EXIT_FAILURE);

        set_shadow_stack_guard_reserved(h, address, true);
        return 0;
}

static void shadow_stack_guard_release_done(ExecHypervisorShadowStackGuardRelease *release) {
        if (!release || !release->released || release->committed)
                return;

        if (reserve_shadow_stack_guard(release->machine, release->address) < 0)
                _exit(EXIT_FAILURE);
}

static int release_shadow_stack_guard(
                ExecHypervisor *h,
                uint64_t address,
                uint64_t length,
                ExecHypervisorShadowStackGuardRelease *ret_release) {

        assert(h);
        assert(ret_release);

        if (length != page_size())
                return 0;

        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings) {
                if (!mapping->shadow_stack || !mapping->shadow_stack_guard_reserved ||
                    mapping->guard_address != (void*) (uintptr_t) address)
                        continue;

                if (munmap(mapping->guard_address, page_size()) < 0)
                        return -errno;
                set_shadow_stack_guard_reserved(h, mapping->guard_address, false);
                *ret_release = (ExecHypervisorShadowStackGuardRelease) {
                        .machine = h,
                        .address = mapping->guard_address,
                        .released = true,
                };
                return 1;
        }

        return 0;
}

static int restore_shadow_stack_guards_after_unmap(ExecHypervisor *h, uint64_t start, uint64_t end) {
        int r;

        assert(h);
        assert(start <= end);

        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings) {
                uint64_t guard;

                if (!mapping->shadow_stack || mapping->shadow_stack_guard_reserved)
                        continue;
                guard = (uintptr_t) mapping->guard_address;
                if (guard < start || guard + page_size() > end)
                        continue;

                r = reserve_shadow_stack_guard(h, mapping->guard_address);
                if (r < 0)
                        return r;
        }

        return 0;
}

static uint64_t handle_guest_mmap_fixed(
                ExecHypervisor *h,
                const struct kvm_regs *regs,
                uint64_t length,
                int protection,
                int flags) {

        _cleanup_free_ ExecHypervisorFixedMapChange *changes = NULL;
        _cleanup_free_ ExecHypervisorMapping *new_mappings = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_dontfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_wipeonfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorUserfaultRange *new_userfault_ranges = NULL;
        _cleanup_free_ uint64_t *old_entries = NULL;
        _cleanup_(memslot_reservation_done) ExecHypervisorMemslotReservation slot_reservation = {};
        ExecHypervisor *machine;
        uint64_t covered = 0, end, growdown_id = 0;
        size_t change_index = 0, n_changes = 0, n_extra_slots = 0, n_new_mappings = 0;
        size_t n_new_dontfork_ranges, n_new_userfault_ranges, n_new_wipeonfork_ranges, n_pages;
        void *address;
        int backing_fd = -EBADF, effective_protection, r, rollback_error;
        struct stat backing_stat = {};

        assert(h);
        assert(regs);
        assert(FLAGS_SET(flags, MAP_FIXED));

        machine = exec_hypervisor_machine(h);

        if (FLAGS_SET(flags, MAP_GROWSDOWN)) {
                r = allocate_growdown_id(machine, &growdown_id);
                if (r < 0)
                        return r;
        }

        if (regs->rdi % page_size() != 0 ||
            !ADD_SAFE(&end, regs->rdi, length) ||
            end > UINT64_C(0x0000800000000000))
                return -EINVAL;
        FOREACH_ARRAY(range, machine->sealed_ranges, machine->n_sealed_ranges)
                if (regs->rdi < range->start + range->length && end > range->start)
                        return -EPERM;

        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end, overlap_end, overlap_start;

                if (!ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size) ||
                    regs->rdi >= mapping_end || end <= mapping->guest_virtual_address)
                        continue;
                if (!mapping->mutable)
                        return -ENOSYS;

                overlap_start = MAX(regs->rdi, mapping->guest_virtual_address);
                overlap_end = MIN(end, mapping_end);
                if (!ADD_SAFE(&covered, covered, overlap_end - overlap_start))
                        return -EOVERFLOW;
                n_changes++;
                n_extra_slots += overlap_start > mapping->guest_virtual_address;
                n_extra_slots += overlap_end < mapping_end;
        }
        if (n_changes == 0 || covered != length)
                return -ENOSYS;
        r = prepare_userfault_ranges_after_unmap(
                        h,
                        regs->rdi,
                        end,
                        &new_userfault_ranges,
                        &n_new_userfault_ranges);
        if (r < 0)
                return r;
        r = prepare_wipeonfork_ranges(
                        machine,
                        regs->rdi,
                        end,
                        false,
                        &new_wipeonfork_ranges,
                        &n_new_wipeonfork_ranges);
        if (r < 0)
                return r;
        r = prepare_dontfork_ranges(
                        machine,
                        regs->rdi,
                        end,
                        false,
                        &new_dontfork_ranges,
                        &n_new_dontfork_ranges);
        if (r < 0)
                return r;
        r = reserve_memslots(h, n_extra_slots, &slot_reservation);
        if (r < 0)
                return r == -ENOSPC ? -ENOMEM : r;
        if (!FLAGS_SET(flags, MAP_ANONYMOUS)) {
                r = retain_mapping_fd(machine, regs->r8, &backing_fd, &backing_stat);
                if (r < 0)
                        return r;
        }

        changes = new(ExecHypervisorFixedMapChange, n_changes);
        new_mappings = new(ExecHypervisorMapping, machine->n_mappings + n_extra_slots);
        n_pages = length / page_size();
        old_entries = new(uint64_t, n_pages);
        if (!changes || !new_mappings || !old_entries)
                return -ENOMEM;

        size_t next_slot = 0;
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                ExecHypervisorFixedMapChange *change;
                uint64_t mapping_end, overlap_end, overlap_start;
                size_t piece_index = 0;

                assert_se(ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size));
                if (regs->rdi >= mapping_end || end <= mapping->guest_virtual_address) {
                        new_mappings[n_new_mappings++] = *mapping;
                        continue;
                }

                change = changes + change_index++;
                overlap_start = MAX(regs->rdi, mapping->guest_virtual_address);
                overlap_end = MIN(end, mapping_end);
                change->old_mapping = *mapping;
                if (overlap_start > mapping->guest_virtual_address) {
                        change->pieces[piece_index] = *mapping;
                        change->pieces[piece_index++].size = overlap_start - mapping->guest_virtual_address;
                }

                ExecHypervisorMapping replacement = *mapping;
                replacement.host_address = (uint8_t*) mapping->host_address +
                        overlap_start - mapping->guest_virtual_address;
                replacement.guest_virtual_address = overlap_start;
                replacement.guest_physical_address += overlap_start - mapping->guest_virtual_address;
                replacement.size = overlap_end - overlap_start;
                replacement.protection = protection;
                replacement.growdown_id = growdown_id;
                replacement.stage2_writable = true;
                replacement.file_backed = !FLAGS_SET(flags, MAP_ANONYMOUS);
                replacement.shared = FLAGS_SET(flags, MAP_SHARED);
                replacement.grows_down = FLAGS_SET(flags, MAP_GROWSDOWN);
                replacement.backing_fd = backing_fd;
                replacement.file_offset = replacement.file_backed ?
                        regs->r9 + overlap_start - regs->rdi : 0;
                replacement.backing_device = backing_stat.st_dev;
                replacement.backing_inode = backing_stat.st_ino;
                change->pieces[piece_index++] = replacement;

                if (overlap_end < mapping_end) {
                        change->pieces[piece_index] = *mapping;
                        change->pieces[piece_index].host_address = (uint8_t*) mapping->host_address +
                                overlap_end - mapping->guest_virtual_address;
                        change->pieces[piece_index].guest_virtual_address = overlap_end;
                        change->pieces[piece_index].guest_physical_address +=
                                overlap_end - mapping->guest_virtual_address;
                        if (change->pieces[piece_index].file_backed)
                                change->pieces[piece_index].file_offset +=
                                        overlap_end - mapping->guest_virtual_address;
                        change->pieces[piece_index++].size = mapping_end - overlap_end;
                        change->pieces[piece_index - 1].grows_down = false;
                }
                change->n_pieces = piece_index;
                assert(change->n_pieces > 0 && change->n_pieces <= ELEMENTSOF(change->pieces));
                for (size_t i = 0; i < change->n_pieces; i++) {
                        change->pieces[i].slot = i == 0 ? mapping->slot : slot_reservation.slots[next_slot++];
                        new_mappings[n_new_mappings++] = change->pieces[i];
                }
        }
        assert(change_index == n_changes);
        assert(next_slot == n_extra_slots);
        assert(n_new_mappings == machine->n_mappings + n_extra_slots);
        normalize_growdown_owners(new_mappings, n_new_mappings);

        for (size_t i = 0; i < n_pages; i++) {
                uint64_t *entry = guest_page_entry(h, regs->rdi + i * page_size());

                if (!entry)
                        return -EFAULT;
                old_entries[i] = *entry;
                *entry = 0;
        }
        r = flush_all_guest_tlbs(h);
        if (r < 0)
                goto restore_page_tables;

        FOREACH_ARRAY(change, changes, n_changes) {
                r = remove_mapping_memory_region(h, change->old_mapping.slot);
                if (r < 0)
                        goto rollback_regions;
                FOREACH_ARRAY(piece, change->pieces, change->n_pieces) {
                        r = set_mapping_memory_region(h, piece);
                        if (r < 0)
                                goto rollback_regions;
                }
        }

        address = mmap((void*) (uintptr_t) regs->rdi,
                       length,
                       protection,
                       flags,
                       (int) regs->r8,
                       regs->r9);
        if (address == MAP_FAILED) {
                r = -errno;
                goto rollback_regions;
        }
        if ((uintptr_t) address != regs->rdi)
                _exit(EXIT_FAILURE);
        r = host_mapping_protection(regs->rdi, end, &effective_protection);
        if (r < 0)
                _exit(EXIT_FAILURE);

        FOREACH_ARRAY(mapping, new_mappings, n_new_mappings) {
                uint64_t mapping_end;

                assert_se(ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size));
                if (mapping->guest_virtual_address >= regs->rdi && mapping_end <= end)
                        mapping->protection = effective_protection;
        }

        for (size_t i = 0; i < n_pages; i++) {
                uint64_t *entry = ASSERT_PTR(guest_page_entry(h, regs->rdi + i * page_size()));

                *entry = guest_page_value(old_entries[i] & X86_PAGE_ADDRESS_MASK, effective_protection);
        }
        r = flush_all_guest_tlbs(h);
        if (r < 0)
                _exit(EXIT_FAILURE);

        free(machine->mappings);
        machine->mappings = TAKE_PTR(new_mappings);
        machine->n_mappings = n_new_mappings;
        free(machine->userfault_ranges);
        machine->userfault_ranges = TAKE_PTR(new_userfault_ranges);
        machine->n_userfault_ranges = n_new_userfault_ranges;
        free(machine->dontfork_ranges);
        machine->dontfork_ranges = TAKE_PTR(new_dontfork_ranges);
        machine->n_dontfork_ranges = n_new_dontfork_ranges;
        free(machine->wipeonfork_ranges);
        machine->wipeonfork_ranges = TAKE_PTR(new_wipeonfork_ranges);
        machine->n_wipeonfork_ranges = n_new_wipeonfork_ranges;
        close_unused_mapping_fds(machine);
        slot_reservation.committed = true;

        return (uintptr_t) address;

rollback_regions:
        rollback_error = rollback_fixed_map_memory_regions(h, changes, n_changes);
        if (rollback_error < 0)
                _exit(EXIT_FAILURE);
restore_page_tables:
        for (size_t i = 0; i < n_pages; i++)
                *ASSERT_PTR(guest_page_entry(h, regs->rdi + i * page_size())) = old_entries[i];
        if (flush_all_guest_tlbs(h) < 0)
                _exit(EXIT_FAILURE);
        return r;
}

static uint64_t handle_guest_mmap(ExecHypervisor *h, const struct kvm_regs *regs) {
        _cleanup_(shadow_stack_guard_release_done) ExecHypervisorShadowStackGuardRelease guard_release = {};
        _cleanup_(gpa_reservation_done) ExecHypervisorGpaReservation gpa_reservation = {};
        ExecHypervisor *machine;
        struct kvm_userspace_memory_region region;
        uint64_t gpa, growdown_id = 0, length;
        void *address;
        size_t n_mapped_pages = 0;
        unsigned slot;
        int backing_fd = -EBADF, protection, flags, r;
        struct stat backing_stat = {};

        assert(h);
        assert(regs);

        machine = exec_hypervisor_machine(h);
        assert(machine->vm_fd >= 0);

        if (regs->rsi == 0 || regs->rsi > SIZE_MAX - (page_size() - 1))
                return -EINVAL;
        length = PAGE_ALIGN(regs->rsi);
        protection = regs->rdx;
        flags = regs->r10;

        if (regs->r9 % page_size() != 0)
                return -EINVAL;
        if (!FLAGS_SET(flags, MAP_ANONYMOUS) && (int) regs->r8 < 0)
                return -EBADF;
        if (!FLAGS_SET(flags, MAP_ANONYMOUS) && fd_is_fs_type((int) regs->r8, SECRETMEM_MAGIC) > 0)
                return -EOPNOTSUPP;
        if (FLAGS_SET(flags, MAP_FIXED) || FLAGS_SET(flags, MAP_FIXED_NOREPLACE)) {
                r = release_shadow_stack_guard(machine, regs->rdi, length, &guard_release);
                if (r < 0)
                        return r;
                if (FLAGS_SET(flags, MAP_FIXED) && r == 0)
                        return handle_guest_mmap_fixed(h, regs, length, protection, flags);
        }
        if (FLAGS_SET(flags, MAP_GROWSDOWN)) {
                r = allocate_growdown_id(machine, &growdown_id);
                if (r < 0)
                        return r;
        }
        if (!GREEDY_REALLOC0(machine->mappings, machine->n_mappings + 1))
                return -ENOMEM;

        address = mmap((void*) (uintptr_t) regs->rdi,
                       length,
                       protection,
                       flags,
                       (int) regs->r8,
                       regs->r9);
        if (address == MAP_FAILED)
                return -errno;
        if ((uintptr_t) address > UINT64_C(0x00007fffffffffff) ||
            length > UINT64_C(0x0000800000000000) - (uintptr_t) address) {
                (void) munmap(address, length);
                return -EOVERFLOW;
        }
        r = host_mapping_protection(
                        (uintptr_t) address,
                        (uintptr_t) address + length,
                        &protection);
        if (r < 0) {
                (void) munmap(address, length);
                return r;
        }
        if (!FLAGS_SET(flags, MAP_ANONYMOUS)) {
                r = retain_mapping_fd(machine, regs->r8, &backing_fd, &backing_stat);
                if (r < 0) {
                        (void) munmap(address, length);
                        return r;
                }
        }

        r = reserve_guest_physical(h, length, &gpa_reservation);
        if (r < 0) {
                (void) munmap(address, length);
                return r;
        }
        gpa = gpa_reservation.address;

        for (size_t offset = 0; offset < length; offset += page_size()) {
                r = map_guest_page(
                                h,
                                (uintptr_t) address + offset,
                                gpa + offset,
                                guest_page_flags(protection));
                if (r < 0) {
                        for (size_t rollback = 0; rollback < n_mapped_pages; rollback++)
                                unmap_guest_page(h, (uintptr_t) address + rollback * page_size());
                        (void) munmap(address, length);
                        return r == -ENOSPC ? -ENOMEM : r;
                }

                n_mapped_pages++;
        }

        r = allocate_memslot(machine, &slot);
        if (r < 0) {
                for (size_t rollback = 0; rollback < n_mapped_pages; rollback++)
                        unmap_guest_page(h, (uintptr_t) address + rollback * page_size());
                (void) munmap(address, length);
                return r == -ENOSPC ? -ENOMEM : r;
        }
        region = (struct kvm_userspace_memory_region) {
                .slot = slot,
                .guest_phys_addr = gpa,
                .memory_size = length,
                .userspace_addr = (uintptr_t) address,
        };
        if (ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
                int error = errno;

                release_memslot(machine, slot);
                for (size_t rollback = 0; rollback < n_mapped_pages; rollback++)
                        unmap_guest_page(h, (uintptr_t) address + rollback * page_size());
                (void) munmap(address, length);
                return -error;
        }

        machine->mappings[machine->n_mappings++] = (ExecHypervisorMapping) {
                .host_address = address,
                .guest_virtual_address = (uintptr_t) address,
                .guest_physical_address = gpa,
                .size = length,
                .protection = protection,
                .slot = slot,
                .growdown_id = growdown_id,
                .mutable = true,
                .stage2_writable = true,
                .file_backed = !FLAGS_SET(flags, MAP_ANONYMOUS),
                .shared = FLAGS_SET(flags, MAP_SHARED),
                .grows_down = FLAGS_SET(flags, MAP_GROWSDOWN),
                .backing_fd = backing_fd,
                .file_offset = FLAGS_SET(flags, MAP_ANONYMOUS) ? 0 : regs->r9,
                .backing_device = backing_stat.st_dev,
                .backing_inode = backing_stat.st_ino,
        };
        gpa_reservation.committed = true;
        guard_release.committed = true;
        return (uintptr_t) address;
}

static uint64_t handle_guest_remap_file_pages(ExecHypervisor *h, const struct kvm_regs *regs) {
        ExecHypervisor *machine;
        struct kvm_regs mmap_regs;
        uint64_t end, offset, size, start;
        dev_t device = 0;
        ino_t inode = 0;
        int backing_fd = -EBADF, protection = 0;
        bool found = false;

        assert(h);
        assert(regs);

        if (regs->rdx != 0)
                return (uint64_t) -EINVAL;
        start = ALIGN_DOWN(regs->rdi, page_size());
        size = ALIGN_DOWN(regs->rsi, page_size());
        if (size == 0 || !ADD_SAFE(&end, start, size) ||
            !MUL_SAFE(&offset, regs->r10, page_size()))
                return (uint64_t) -EINVAL;

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end;

                if (!ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size) ||
                    start >= mapping_end || end <= mapping->guest_virtual_address)
                        continue;
                if (!mapping->mutable || !mapping->file_backed || !mapping->shared || mapping->backing_fd < 0)
                        return (uint64_t) -EINVAL;
                if (!found) {
                        backing_fd = mapping->backing_fd;
                        device = mapping->backing_device;
                        inode = mapping->backing_inode;
                        protection = mapping->protection;
                        found = true;
                } else if (mapping->backing_device != device || mapping->backing_inode != inode ||
                           mapping->protection != protection)
                        return (uint64_t) -EINVAL;
        }
        if (!found)
                return (uint64_t) -EINVAL;

        mmap_regs = (struct kvm_regs) {
                .rdi = start,
                .rsi = size,
                .rdx = protection,
                .r10 = MAP_SHARED | MAP_FIXED | MAP_POPULATE | (regs->r8 & MAP_NONBLOCK),
                .r8 = backing_fd,
                .r9 = offset,
        };
        uint64_t result = handle_guest_mmap_fixed(machine, &mmap_regs, size, protection, mmap_regs.r10);

        return result == start ? 0 : result;
}

static uint64_t handle_guest_mprotect(
                ExecHypervisor *h,
                uint64_t address,
                uint64_t requested_length,
                int protection,
                int pkey) {

        _cleanup_free_ ExecHypervisorFixedMapChange *changes = NULL;
        _cleanup_free_ ExecHypervisorMapping *new_mappings = NULL;
        _cleanup_free_ uint64_t *old_entries = NULL;
        _cleanup_(memslot_reservation_done) ExecHypervisorMemslotReservation slot_reservation = {};
        ExecHypervisor *machine;
        uint64_t covered = 0, end, length;
        size_t change_index = 0, n_changes = 0, n_extra_slots = 0, n_new_mappings = 0, n_pages;
        int r, rollback_error;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (!IN_SET(pkey, -1, 0))
                return (uint64_t) -ENOSYS;
        if (address % page_size() != 0 || requested_length > SIZE_MAX - (page_size() - 1))
                return (uint64_t) -EINVAL;
        if (requested_length == 0) {
                long q = pkey < 0 ? mprotect((void *) (uintptr_t) address, 0, protection) :
                                      syscall(__NR_pkey_mprotect, address, 0, protection, pkey);

                return q < 0 ? (uint64_t) -errno : (uint64_t) q;
        }
        length = PAGE_ALIGN(requested_length);
        if (!ADD_SAFE(&end, address, length) || end > UINT64_C(0x0000800000000000))
                return (uint64_t) -ENOMEM;
        FOREACH_ARRAY(range, machine->sealed_ranges, machine->n_sealed_ranges)
                if (address < range->start + range->length && end > range->start)
                        return (uint64_t) -EPERM;

        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end, overlap_end, overlap_start;

                if (!ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size) ||
                    address >= mapping_end || end <= mapping->guest_virtual_address)
                        continue;

                overlap_start = MAX(address, mapping->guest_virtual_address);
                overlap_end = MIN(end, mapping_end);
                if (!ADD_SAFE(&covered, covered, overlap_end - overlap_start))
                        return (uint64_t) -EOVERFLOW;
                n_changes++;
                n_extra_slots += overlap_start > mapping->guest_virtual_address;
                n_extra_slots += overlap_end < mapping_end;
        }
        if (n_changes == 0 || covered != length)
                return (uint64_t) -ENOMEM;
        r = reserve_memslots(h, n_extra_slots, &slot_reservation);
        if (r < 0)
                return (uint64_t) (r == -ENOSPC ? -ENOMEM : r);

        changes = new(ExecHypervisorFixedMapChange, n_changes);
        new_mappings = new(ExecHypervisorMapping, machine->n_mappings + n_extra_slots);
        n_pages = length / page_size();
        old_entries = new(uint64_t, n_pages);
        if (!changes || !new_mappings || !old_entries)
                return (uint64_t) -ENOMEM;

        size_t next_slot = 0;
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                ExecHypervisorFixedMapChange *change;
                uint64_t mapping_end, overlap_end, overlap_start;
                size_t piece_index = 0;

                assert_se(ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size));
                if (address >= mapping_end || end <= mapping->guest_virtual_address) {
                        new_mappings[n_new_mappings++] = *mapping;
                        continue;
                }

                change = changes + change_index++;
                overlap_start = MAX(address, mapping->guest_virtual_address);
                overlap_end = MIN(end, mapping_end);
                change->old_mapping = *mapping;
                if (overlap_start > mapping->guest_virtual_address) {
                        change->pieces[piece_index] = *mapping;
                        change->pieces[piece_index++].size = overlap_start - mapping->guest_virtual_address;
                }

                ExecHypervisorMapping protected = *mapping;
                protected.host_address = (uint8_t*) mapping->host_address +
                        overlap_start - mapping->guest_virtual_address;
                if (protected.kvm_address)
                        protected.kvm_address = (uint8_t*) mapping->kvm_address +
                                overlap_start - mapping->guest_virtual_address;
                protected.guest_virtual_address = overlap_start;
                protected.guest_physical_address += overlap_start - mapping->guest_virtual_address;
                if (protected.file_backed)
                        protected.file_offset += overlap_start - mapping->guest_virtual_address;
                protected.size = overlap_end - overlap_start;
                if (protected.shadow_stack) {
                        protected.protection = protection & ~PROT_WRITE;
                        protected.shadow_stack_protection = protection;
                } else
                        protected.protection = protection;
                protected.grows_down = mapping->grows_down && overlap_start == mapping->guest_virtual_address;
                if (FLAGS_SET(protection, PROT_WRITE))
                        protected.stage2_writable = true;
                change->pieces[piece_index++] = protected;

                if (overlap_end < mapping_end) {
                        change->pieces[piece_index] = *mapping;
                        change->pieces[piece_index].host_address = (uint8_t*) mapping->host_address +
                                overlap_end - mapping->guest_virtual_address;
                        if (change->pieces[piece_index].kvm_address)
                                change->pieces[piece_index].kvm_address = (uint8_t*) mapping->kvm_address +
                                        overlap_end - mapping->guest_virtual_address;
                        change->pieces[piece_index].guest_virtual_address = overlap_end;
                        change->pieces[piece_index].guest_physical_address +=
                                overlap_end - mapping->guest_virtual_address;
                        if (change->pieces[piece_index].file_backed)
                                change->pieces[piece_index].file_offset +=
                                        overlap_end - mapping->guest_virtual_address;
                        change->pieces[piece_index++].size = mapping_end - overlap_end;
                        change->pieces[piece_index - 1].grows_down = false;
                }
                change->n_pieces = piece_index;
                for (size_t i = 0; i < change->n_pieces; i++) {
                        change->pieces[i].slot = i == 0 ? mapping->slot : slot_reservation.slots[next_slot++];
                        new_mappings[n_new_mappings++] = change->pieces[i];
                }
        }
        assert(change_index == n_changes);
        assert(next_slot == n_extra_slots);
        assert(n_new_mappings == machine->n_mappings + n_extra_slots);
        normalize_growdown_owners(new_mappings, n_new_mappings);

        for (size_t i = 0; i < n_pages; i++) {
                uint64_t *entry = guest_page_entry(h, address + i * page_size());

                if (!entry)
                        return (uint64_t) -EFAULT;
                old_entries[i] = *entry;
                *entry = 0;
        }
        r = flush_all_guest_tlbs(h);
        if (r < 0)
                goto restore_page_tables;

        FOREACH_ARRAY(change, changes, n_changes) {
                r = remove_mapping_memory_region(h, change->old_mapping.slot);
                if (r < 0)
                        goto rollback_regions;
                FOREACH_ARRAY(piece, change->pieces, change->n_pieces) {
                        r = set_mapping_memory_region(h, piece);
                        if (r < 0)
                                goto rollback_regions;
                }
        }

        long q = pkey < 0 ? mprotect((void *) (uintptr_t) address, length, protection) :
                            syscall(__NR_pkey_mprotect, address, length, protection, pkey);
        if (q < 0) {
                r = -errno;
                goto rollback_regions;
        }

        FOREACH_ARRAY(mapping, new_mappings, n_new_mappings) {
                uint64_t mapping_end;

                assert_se(ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size));
                if (mapping->guest_virtual_address < address || mapping_end > end)
                        continue;
                if (mapping->shadow_stack &&
                    mprotect(mapping->host_address, mapping->size, mapping->protection) < 0)
                        _exit(EXIT_FAILURE);
                r = host_mapping_protection(
                                mapping->guest_virtual_address,
                                mapping_end,
                                &mapping->protection);
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }

        for (size_t i = 0; i < n_pages; i++) {
                uint64_t *entry = ASSERT_PTR(guest_page_entry(h, address + i * page_size()));
                uint64_t page = address + i * page_size();
                const ExecHypervisorMapping *effective_mapping = NULL;

                FOREACH_ARRAY(mapping, new_mappings, n_new_mappings)
                        if (page >= mapping->guest_virtual_address &&
                            page < mapping->guest_virtual_address + mapping->size) {
                                effective_mapping = mapping;
                                break;
                        }

                *entry = guest_mapping_page_value(
                                ASSERT_PTR(effective_mapping),
                                old_entries[i] & X86_PAGE_ADDRESS_MASK);
                if (FLAGS_SET(old_entries[i], X86_PAGE_SOFTWARE_UFFD_POISON)) {
                        *entry = (*entry & ~X86_PAGE_PRESENT) | X86_PAGE_SOFTWARE_UFFD_POISON;
                        continue;
                }
                FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges)
                        if (page >= range->start && page < range->start + range->length) {
                                if ((range->mode &
                                     (UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_MINOR)) != 0 &&
                                    !FLAGS_SET(old_entries[i], X86_PAGE_PRESENT))
                                        *entry &= ~X86_PAGE_PRESENT;
                                if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) && range->write_protected)
                                        *entry &= ~X86_PAGE_WRITE;
                                break;
                        }
        }
        if (flush_all_guest_tlbs(h) < 0)
                _exit(EXIT_FAILURE);

        free(machine->mappings);
        machine->mappings = TAKE_PTR(new_mappings);
        machine->n_mappings = n_new_mappings;
        slot_reservation.committed = true;
        return 0;

rollback_regions:
        rollback_error = rollback_fixed_map_memory_regions(h, changes, n_changes);
        if (rollback_error < 0)
                _exit(EXIT_FAILURE);
restore_page_tables:
        for (size_t i = 0; i < n_pages; i++)
                *ASSERT_PTR(guest_page_entry(h, address + i * page_size())) = old_entries[i];
        if (flush_all_guest_tlbs(h) < 0)
                _exit(EXIT_FAILURE);
        return (uint64_t) r;
}

typedef struct ExecHypervisorMunmapChange {
        ExecHypervisorMapping old_mapping;
        ExecHypervisorMapping prefix;
        ExecHypervisorMapping suffix;
        bool have_prefix;
        bool have_suffix;
} ExecHypervisorMunmapChange;

static int set_mapping_memory_region(ExecHypervisor *h, const ExecHypervisorMapping *mapping) {
        const struct kvm_userspace_memory_region region = {
                .slot = mapping->slot,
                .flags = mapping->stage2_writable ? 0 : KVM_MEM_READONLY,
                .guest_phys_addr = mapping->guest_physical_address,
                .memory_size = mapping->size,
                .userspace_addr = (uintptr_t) mapping_kvm_address(mapping),
        };

        assert(h);
        assert(mapping);
        assert(mapping->size > 0);

        if (ioctl(h->machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
                return -errno;
        return 0;
}

static int remove_mapping_memory_region(ExecHypervisor *h, unsigned slot) {
        const struct kvm_userspace_memory_region region = {
                .slot = slot,
        };

        assert(h);

        if (ioctl(h->machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
                return -errno;
        return 0;
}

static int rollback_munmap_memory_regions(
                ExecHypervisor *h,
                const ExecHypervisorMunmapChange *changes,
                size_t n_changes) {

        int first_error = 0;

        assert(h);
        assert(changes || n_changes == 0);

        FOREACH_ARRAY(change, changes, n_changes) {
                (void) remove_mapping_memory_region(h, change->old_mapping.slot);
                if (change->have_prefix && change->have_suffix)
                        (void) remove_mapping_memory_region(h, change->suffix.slot);
        }
        FOREACH_ARRAY(change, changes, n_changes) {
                int r = set_mapping_memory_region(h, &change->old_mapping);

                if (r < 0 && first_error >= 0)
                        first_error = r;
        }

        return first_error;
}

static int remove_shadow_stack_mappings(
                ExecHypervisor *h,
                size_t mapping_index,
                size_t n_mappings) {

        _cleanup_free_ uint64_t *old_entries = NULL;
        ExecHypervisor *machine;
        ExecHypervisorMapping mapping;
        size_t n_pages, n_removed_regions = 0, size = 0;
        int r;

        assert(h);
        assert(n_mappings > 0);

        machine = exec_hypervisor_machine(h);
        assert(mapping_index + n_mappings <= machine->n_mappings);
        mapping = machine->mappings[mapping_index];
        assert(mapping.shadow_stack);
        assert(mapping.kvm_address);
        assert(mapping.guard_address);
        for (size_t i = 0; i < n_mappings; i++) {
                ExecHypervisorMapping *piece = machine->mappings + mapping_index + i;

                assert(piece->shadow_stack);
                assert(piece->guard_address == mapping.guard_address);
                assert(piece->shadow_stack_guard_reserved == mapping.shadow_stack_guard_reserved);
                assert(piece->guest_virtual_address == mapping.guest_virtual_address + size);
                assert(piece->guest_physical_address == mapping.guest_physical_address + size);
                assert(piece->host_address == (uint8_t*) mapping.host_address + size);
                assert(piece->kvm_address == (uint8_t*) mapping.kvm_address + size);
                assert_se(ADD_SAFE(&size, size, piece->size));
        }

        n_pages = size / page_size();
        old_entries = new(uint64_t, n_pages);
        if (!old_entries)
                return -ENOMEM;
        r = ensure_gpa_release_capacity(machine, 1);
        if (r < 0)
                return r;

        for (size_t i = 0; i < n_pages; i++) {
                uint64_t *entry = ASSERT_PTR(guest_page_entry(
                                machine,
                                mapping.guest_virtual_address + i * page_size()));

                old_entries[i] = *entry;
                *entry = 0;
        }
        r = flush_all_guest_tlbs(machine);
        if (r < 0)
                goto restore_page_tables;
        for (; n_removed_regions < n_mappings; n_removed_regions++) {
                r = remove_mapping_memory_region(
                                machine,
                                machine->mappings[mapping_index + n_removed_regions].slot);
                if (r < 0)
                        goto restore_regions;
        }
        if (munmap(mapping.host_address, size) < 0) {
                r = -errno;
                goto restore_regions;
        }
        if (munmap(mapping.kvm_address, size) < 0 ||
            (mapping.shadow_stack_guard_reserved && munmap(mapping.guard_address, page_size()) < 0))
                _exit(EXIT_FAILURE);

        r = release_guest_physical(machine, mapping.guest_physical_address, size);
        if (r < 0)
                _exit(EXIT_FAILURE);
        for (size_t i = n_mappings; i > 0; i--)
                release_memslot(machine, machine->mappings[mapping_index + i - 1].slot);
        memmove(
                        machine->mappings + mapping_index,
                        machine->mappings + mapping_index + n_mappings,
                        (machine->n_mappings - mapping_index - n_mappings) * sizeof(*machine->mappings));
        machine->n_mappings -= n_mappings;
        close_unused_mapping_fds(machine);
        for (size_t i = 0; i < n_pages; i++)
                reclaim_guest_page_tables(machine, mapping.guest_virtual_address + i * page_size());
        return 0;

restore_regions:
        for (size_t i = 0; i < n_removed_regions; i++)
                if (set_mapping_memory_region(machine, machine->mappings + mapping_index + i) < 0)
                        _exit(EXIT_FAILURE);
restore_page_tables:
        for (size_t i = 0; i < n_pages; i++)
                *ASSERT_PTR(guest_page_entry(machine, mapping.guest_virtual_address + i * page_size())) =
                        old_entries[i];
        if (flush_all_guest_tlbs(machine) < 0)
                _exit(EXIT_FAILURE);
        return r;
}

static uint64_t handle_guest_munmap(ExecHypervisor *h, uint64_t address, uint64_t requested_length) {
        _cleanup_free_ ExecHypervisorMunmapChange *changes = NULL;
        _cleanup_free_ ExecHypervisorMapping *new_mappings = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_dontfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_wipeonfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorUserfaultRange *new_userfault_ranges = NULL;
        _cleanup_free_ uint64_t *old_entries = NULL;
        _cleanup_(memslot_reservation_done) ExecHypervisorMemslotReservation slot_reservation = {};
        ExecHypervisor *machine;
        uint64_t end, length;
        size_t change_index = 0, n_changes = 0, n_new_dontfork_ranges, n_new_mappings = 0, n_new_userfault_ranges;
        size_t n_new_wipeonfork_ranges;
        size_t n_pages, n_suffix_slots = 0;
        int r, rollback_error;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (address % page_size() != 0 || requested_length == 0 ||
            requested_length > SIZE_MAX - (page_size() - 1))
                return (uint64_t) -EINVAL;
        length = PAGE_ALIGN(requested_length);
        if (!ADD_SAFE(&end, address, length) || end > UINT64_C(0x0000800000000000))
                return (uint64_t) -EINVAL;
        FOREACH_ARRAY(range, machine->sealed_ranges, machine->n_sealed_ranges)
                if (address < range->start + range->length && end > range->start)
                        return (uint64_t) -EPERM;

        for (size_t i = 0; i < machine->n_mappings; i++) {
                ExecHypervisorMapping *mapping = machine->mappings + i;
                uint64_t mapping_end, shadow_stack_end;
                size_t first, last;

                if (!ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size) ||
                    address >= mapping_end || end <= mapping->guest_virtual_address || !mapping->shadow_stack)
                        continue;
                first = i;
                while (first > 0 && machine->mappings[first - 1].shadow_stack &&
                       machine->mappings[first - 1].guard_address == mapping->guard_address)
                        first--;
                last = i + 1;
                while (last < machine->n_mappings && machine->mappings[last].shadow_stack &&
                       machine->mappings[last].guard_address == mapping->guard_address)
                        last++;
                if (!ADD_SAFE(
                                    &shadow_stack_end,
                                    machine->mappings[last - 1].guest_virtual_address,
                                    machine->mappings[last - 1].size))
                        return (uint64_t) -EOVERFLOW;
                if (address != machine->mappings[first].guest_virtual_address || end != shadow_stack_end)
                        return (uint64_t) -EOPNOTSUPP;
                return (uint64_t) remove_shadow_stack_mappings(machine, first, last - first);
        }

        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end, overlap_end, overlap_start;

                if (!ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size) ||
                    address >= mapping_end || end <= mapping->guest_virtual_address)
                        continue;
                if (!mapping->mutable)
                        return (uint64_t) -ENOSYS;

                overlap_start = MAX(address, mapping->guest_virtual_address);
                overlap_end = MIN(end, mapping_end);
                n_changes++;
                n_suffix_slots += overlap_start > mapping->guest_virtual_address && overlap_end < mapping_end;
        }
        if (n_changes == 0)
                return 0;
        r = prepare_userfault_ranges_after_unmap(
                        h,
                        address,
                        end,
                        &new_userfault_ranges,
                        &n_new_userfault_ranges);
        if (r < 0)
                return (uint64_t) r;
        r = prepare_wipeonfork_ranges(
                        machine,
                        address,
                        end,
                        false,
                        &new_wipeonfork_ranges,
                        &n_new_wipeonfork_ranges);
        if (r < 0)
                return (uint64_t) r;
        r = prepare_dontfork_ranges(
                        machine,
                        address,
                        end,
                        false,
                        &new_dontfork_ranges,
                        &n_new_dontfork_ranges);
        if (r < 0)
                return (uint64_t) r;
        r = ensure_gpa_release_capacity(h, n_changes);
        if (r < 0)
                return (uint64_t) r;
        r = reserve_memslots(h, n_suffix_slots, &slot_reservation);
        if (r < 0)
                return (uint64_t) (r == -ENOSPC ? -ENOMEM : r);

        changes = new(ExecHypervisorMunmapChange, n_changes);
        new_mappings = new(ExecHypervisorMapping, machine->n_mappings + n_suffix_slots);
        n_pages = length / page_size();
        old_entries = new(uint64_t, n_pages);
        if (!changes || !new_mappings || !old_entries)
                return (uint64_t) -ENOMEM;

        size_t next_slot = 0;
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end, overlap_end, overlap_start;

                assert_se(ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size));
                if (address >= mapping_end || end <= mapping->guest_virtual_address) {
                        new_mappings[n_new_mappings++] = *mapping;
                        continue;
                }

                ExecHypervisorMunmapChange *change = changes + change_index++;
                overlap_start = MAX(address, mapping->guest_virtual_address);
                overlap_end = MIN(end, mapping_end);
                change->old_mapping = *mapping;
                change->have_prefix = overlap_start > mapping->guest_virtual_address;
                change->have_suffix = overlap_end < mapping_end;
                if (change->have_prefix) {
                        change->prefix = *mapping;
                        change->prefix.size = overlap_start - mapping->guest_virtual_address;
                        new_mappings[n_new_mappings++] = change->prefix;
                }
                if (change->have_suffix) {
                        change->suffix = *mapping;
                        change->suffix.host_address = (uint8_t*) mapping->host_address +
                                overlap_end - mapping->guest_virtual_address;
                        change->suffix.guest_virtual_address = overlap_end;
                        change->suffix.guest_physical_address += overlap_end - mapping->guest_virtual_address;
                        if (change->suffix.file_backed)
                                change->suffix.file_offset += overlap_end - mapping->guest_virtual_address;
                        change->suffix.size = mapping_end - overlap_end;
                        change->suffix.grows_down = mapping->grows_down && !change->have_prefix;
                        if (change->have_prefix)
                                change->suffix.slot = slot_reservation.slots[next_slot++];
                        new_mappings[n_new_mappings++] = change->suffix;
                }
        }
        assert(change_index == n_changes);
        assert(next_slot == n_suffix_slots);
        assert(n_new_mappings <= machine->n_mappings + n_suffix_slots);
        normalize_growdown_owners(new_mappings, n_new_mappings);

        for (size_t i = 0; i < n_pages; i++) {
                uint64_t *entry = guest_page_entry(h, address + i * page_size());

                if (entry) {
                        old_entries[i] = *entry;
                        *entry = 0;
                }
        }
        r = flush_all_guest_tlbs(h);
        if (r < 0)
                goto restore_page_tables;

        FOREACH_ARRAY(change, changes, n_changes) {
                const ExecHypervisorMapping *first = change->have_prefix ? &change->prefix :
                        change->have_suffix ? &change->suffix : NULL;

                r = remove_mapping_memory_region(h, change->old_mapping.slot);
                if (r < 0)
                        goto rollback_regions;
                if (first) {
                        r = set_mapping_memory_region(h, first);
                        if (r < 0)
                                goto rollback_regions;
                }
                if (change->have_prefix && change->have_suffix) {
                        r = set_mapping_memory_region(h, &change->suffix);
                        if (r < 0)
                                goto rollback_regions;
                }
        }

        if (munmap((void*) (uintptr_t) address, length) < 0) {
                r = -errno;
                goto rollback_regions;
        }

        for (uint64_t page = address; page < end; page += page_size())
                reclaim_guest_page_tables(h, page);

        FOREACH_ARRAY(change, changes, n_changes) {
                uint64_t mapping_end = change->old_mapping.guest_virtual_address + change->old_mapping.size;
                uint64_t overlap_start = MAX(address, change->old_mapping.guest_virtual_address);
                uint64_t overlap_end = MIN(end, mapping_end);

                r = release_guest_physical(
                                h,
                                change->old_mapping.guest_physical_address +
                                        overlap_start - change->old_mapping.guest_virtual_address,
                                overlap_end - overlap_start);
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }

        FOREACH_ARRAY(change, changes, n_changes)
                if (!change->have_prefix && !change->have_suffix)
                        release_memslot(h, change->old_mapping.slot);

        free(machine->mappings);
        machine->mappings = TAKE_PTR(new_mappings);
        machine->n_mappings = n_new_mappings;
        free(machine->userfault_ranges);
        machine->userfault_ranges = TAKE_PTR(new_userfault_ranges);
        machine->n_userfault_ranges = n_new_userfault_ranges;
        free(machine->dontfork_ranges);
        machine->dontfork_ranges = TAKE_PTR(new_dontfork_ranges);
        machine->n_dontfork_ranges = n_new_dontfork_ranges;
        free(machine->wipeonfork_ranges);
        machine->wipeonfork_ranges = TAKE_PTR(new_wipeonfork_ranges);
        machine->n_wipeonfork_ranges = n_new_wipeonfork_ranges;
        close_unused_mapping_fds(machine);
        slot_reservation.committed = true;
        r = restore_shadow_stack_guards_after_unmap(machine, address, end);
        if (r < 0)
                _exit(EXIT_FAILURE);
        return 0;

rollback_regions:
        rollback_error = rollback_munmap_memory_regions(h, changes, n_changes);
        if (rollback_error < 0)
                _exit(EXIT_FAILURE);
restore_page_tables:
        for (size_t i = 0; i < n_pages; i++) {
                uint64_t *entry;

                if (old_entries[i] == 0)
                        continue;
                entry = guest_page_entry(h, address + i * page_size());
                if (!entry)
                        _exit(EXIT_FAILURE);
                *entry = old_entries[i];
        }
        if (flush_all_guest_tlbs(h) < 0)
                _exit(EXIT_FAILURE);
        return (uint64_t) r;
}

static int rollback_host_mremap(
                void *new_address,
                size_t new_size,
                void *old_address,
                size_t old_size) {

        void *p;

        assert(new_address);
        assert(old_address);

        if (new_address == old_address)
                p = mremap(new_address, new_size, old_size, 0);
        else
                p = mremap(new_address, new_size, old_size, MREMAP_MAYMOVE|MREMAP_FIXED, old_address);
        if (p == MAP_FAILED)
                return -errno;
        if (p != old_address)
                return -EPROTO;

        return 0;
}

static int restore_staged_mremap_target(
                ExecHypervisor *h, void *staged_address, const ExecHypervisorMapping *mapping) {

        int r;

        assert(h);
        assert(staged_address);
        assert(mapping);

        r = rollback_host_mremap(staged_address, mapping->size, mapping->host_address, mapping->size);
        if (r < 0)
                return r;
        return set_mapping_memory_region(h, mapping);
}

static int handle_guest_mremap(ExecHypervisor *h, const struct kvm_regs *regs, uint64_t *ret);

static int handle_guest_mremap_partial(
                ExecHypervisor *h,
                const struct kvm_regs *regs,
                uint64_t old_length,
                uint64_t new_length,
                uint64_t target,
                uint64_t *ret) {

        _cleanup_free_ ExecHypervisorMapping *new_mappings = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_dontfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_wipeonfork_ranges = NULL;
        _cleanup_free_ uint64_t *old_entries = NULL;
        _cleanup_(gpa_reservation_done) ExecHypervisorGpaReservation gpa_reservation = {};
        _cleanup_(memslot_reservation_done) ExecHypervisorMemslotReservation slot_reservation = {};
        ExecHypervisorFixedMapChange change = {};
        ExecHypervisorMapping *mapping = NULL;
        ExecHypervisor *machine;
        ExecHypervisorUserfaultRange old_userfault_range = {};
        uint64_t destination_gpa, mapping_end, moved_source_gpa, source_end, target_end;
        size_t mapping_index, new_pages, n_new_mappings, n_pieces, next_slot = 0, old_pages,
                                                                   userfault_index = SIZE_MAX;
        size_t n_new_dontfork_ranges, n_new_wipeonfork_ranges;
        void *new_address, *reservation;
        bool fixed, preserve_userfault_move = false;
        int r;

        assert(h);
        assert(regs);
        assert(old_length > 0);
        assert(new_length > 0);
        assert(ret);

        machine = exec_hypervisor_machine(h);
        fixed = FLAGS_SET(regs->r10, MREMAP_FIXED);
        assert(fixed ? old_length == new_length : new_length >= old_length);
        assert_se(ADD_SAFE(&source_end, regs->rdi, old_length));

        FOREACH_ARRAY(candidate, machine->mappings, machine->n_mappings) {
                uint64_t candidate_end;

                assert_se(ADD_SAFE(&candidate_end, candidate->guest_virtual_address, candidate->size));
                if (regs->rdi < candidate->guest_virtual_address || source_end > candidate_end)
                        continue;
                if (!candidate->mutable || mapping) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
                mapping = candidate;
                mapping_end = candidate_end;
        }
        if (!mapping || (regs->rdi == mapping->guest_virtual_address && old_length == mapping->size)) {
                *ret = (uint64_t) -ENOSYS;
                return 0;
        }

        if (!fixed && new_length == old_length) {
                *ret = regs->rdi;
                return 0;
        }

        if (!fixed && new_length > old_length && source_end == mapping_end) {
                struct kvm_regs whole_regs = *regs;
                uint64_t expanded_length, result;

                if (!ADD_SAFE(&expanded_length, mapping->size, new_length - old_length)) {
                        *ret = (uint64_t) -ENOMEM;
                        return 0;
                }

                whole_regs.rdi = mapping->guest_virtual_address;
                whole_regs.rsi = mapping->size;
                whole_regs.rdx = expanded_length;
                whole_regs.r10 = 0;
                r = handle_guest_mremap(h, &whole_regs, &result);
                if (r < 0)
                        return r;
                if (result == mapping->guest_virtual_address) {
                        *ret = regs->rdi;
                        return 0;
                }
                if (result != (uint64_t) -ENOMEM) {
                        *ret = result;
                        return 0;
                }
        }

        if (!fixed) {
                reservation = mmap(NULL, new_length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (reservation == MAP_FAILED) {
                        *ret = (uint64_t) -errno;
                        return 0;
                }
                target = (uintptr_t) reservation;
                if (target > UINT64_C(0x00007fffffffffff) ||
                    new_length > UINT64_C(0x0000800000000000) - target) {
                        (void) munmap(reservation, new_length);
                        *ret = (uint64_t) -ENOMEM;
                        return 0;
                }
                if (munmap(reservation, new_length) < 0) {
                        *ret = (uint64_t) -errno;
                        return 0;
                }
        }
        assert_se(ADD_SAFE(&target_end, target, new_length));

        FOREACH_ARRAY(candidate, machine->mappings, machine->n_mappings) {
                uint64_t candidate_end;

                assert_se(ADD_SAFE(&candidate_end, candidate->guest_virtual_address, candidate->size));
                if (target < candidate_end && target_end > candidate->guest_virtual_address) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
        }
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (target < range_end && target_end > range->start) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
                if (regs->rdi >= range_end || source_end <= range->start)
                        continue;
                if (userfault_index != SIZE_MAX || regs->rdi < range->start || source_end > range_end ||
                    !range->features_known) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
                userfault_index = range - machine->userfault_ranges;
                old_userfault_range = *range;
                preserve_userfault_move = FLAGS_SET(range->features, UFFD_FEATURE_EVENT_REMAP);
        }
        if (userfault_index != SIZE_MAX &&
            !GREEDY_REALLOC0(machine->userfault_ranges, machine->n_userfault_ranges + 3)) {
                *ret = (uint64_t) -ENOMEM;
                return 0;
        }
        r = prepare_mremap_fork_advice_ranges(
                        machine->dontfork_ranges,
                        machine->n_dontfork_ranges,
                        regs->rdi,
                        old_length,
                        target,
                        new_length,
                        false,
                        &new_dontfork_ranges,
                        &n_new_dontfork_ranges);
        if (r < 0) {
                *ret = (uint64_t) r;
                return 0;
        }
        r = prepare_mremap_fork_advice_ranges(
                        machine->wipeonfork_ranges,
                        machine->n_wipeonfork_ranges,
                        regs->rdi,
                        old_length,
                        target,
                        new_length,
                        false,
                        &new_wipeonfork_ranges,
                        &n_new_wipeonfork_ranges);
        if (r < 0) {
                *ret = (uint64_t) r;
                return 0;
        }

        moved_source_gpa = mapping->guest_physical_address + regs->rdi - mapping->guest_virtual_address;
        destination_gpa = moved_source_gpa;
        if (new_length != old_length) {
                r = reserve_guest_physical(h, new_length, &gpa_reservation);
                if (r < 0) {
                        *ret = (uint64_t) r;
                        return 0;
                }
                destination_gpa = gpa_reservation.address;
        }

        change.old_mapping = *mapping;
        if (regs->rdi > mapping->guest_virtual_address) {
                change.pieces[change.n_pieces] = *mapping;
                change.pieces[change.n_pieces++].size = regs->rdi - mapping->guest_virtual_address;
        }
        if (source_end < mapping_end) {
                change.pieces[change.n_pieces] = *mapping;
                change.pieces[change.n_pieces].host_address = (uint8_t *) mapping->host_address +
                                source_end - mapping->guest_virtual_address;
                change.pieces[change.n_pieces].guest_virtual_address = source_end;
                change.pieces[change.n_pieces].guest_physical_address += source_end -
                                mapping->guest_virtual_address;
                if (change.pieces[change.n_pieces].file_backed)
                        change.pieces[change.n_pieces].file_offset +=
                                source_end - mapping->guest_virtual_address;
                change.pieces[change.n_pieces++].size = mapping_end - source_end;
        }

        change.pieces[change.n_pieces] = *mapping;
        change.pieces[change.n_pieces].host_address = (void *) (uintptr_t) target;
        change.pieces[change.n_pieces].guest_virtual_address = target;
        change.pieces[change.n_pieces].guest_physical_address = destination_gpa;
        if (change.pieces[change.n_pieces].file_backed)
                change.pieces[change.n_pieces].file_offset +=
                        regs->rdi - mapping->guest_virtual_address;
        change.pieces[change.n_pieces++].size = new_length;
        assert(change.n_pieces >= 2 && change.n_pieces <= ELEMENTSOF(change.pieces));

        r = reserve_memslots(h, change.n_pieces - 1, &slot_reservation);
        if (r < 0) {
                *ret = (uint64_t) (r == -ENOSPC ? -ENOMEM : r);
                return 0;
        }
        for (size_t i = 0; i < change.n_pieces; i++)
                change.pieces[i].slot = i == 0 ? mapping->slot : slot_reservation.slots[next_slot++];
        assert(next_slot == slot_reservation.n_slots);

        n_pieces = change.n_pieces;
        new_mappings = new (ExecHypervisorMapping, machine->n_mappings + n_pieces - 1);
        old_pages = old_length / page_size();
        new_pages = new_length / page_size();
        old_entries = new (uint64_t, old_pages);
        if (!new_mappings || !old_entries) {
                *ret = (uint64_t) -ENOMEM;
                return 0;
        }

        mapping_index = mapping - machine->mappings;
        memcpy(new_mappings, machine->mappings, mapping_index * sizeof(new_mappings[0]));
        memcpy(new_mappings + mapping_index, change.pieces, n_pieces * sizeof(new_mappings[0]));
        memcpy(new_mappings + mapping_index + n_pieces,
               machine->mappings + mapping_index + 1,
               (machine->n_mappings - mapping_index - 1) * sizeof(new_mappings[0]));
        n_new_mappings = machine->n_mappings + n_pieces - 1;

        for (size_t i = 0; i < old_pages; i++) {
                uint64_t *source_entry = guest_page_entry(h, regs->rdi + i * page_size());

                if (!source_entry || *source_entry == 0)
                        return -EFAULT;
                old_entries[i] = *source_entry;
        }
        for (size_t i = 0; i < new_pages; i++) {
                uint64_t *target_entry;

                r = ensure_guest_page_entry(h, target + i * page_size(), &target_entry);
                if (r < 0) {
                        *ret = (uint64_t) (r == -ENOSPC ? -ENOMEM : r);
                        return 0;
                }
                if (*target_entry != 0) {
                        *ret = (uint64_t) -EFAULT;
                        return 0;
                }
        }

        reservation = mmap(
                        (void *) (uintptr_t) target,
                        new_length,
                        PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1,
                        0);
        if (reservation == MAP_FAILED) {
                *ret = (uint64_t) (errno == EEXIST ? (fixed ? -ENOSYS : -ENOMEM) : -errno);
                return 0;
        }
        if ((uintptr_t) reservation != target) {
                (void) munmap(reservation, new_length);
                return -EPROTO;
        }
        if (munmap(reservation, new_length) < 0) {
                *ret = (uint64_t) -errno;
                return 0;
        }

        r = remove_mapping_memory_region(h, mapping->slot);
        if (r < 0)
                return r;
        new_address = mremap(
                        (void *) (uintptr_t) regs->rdi,
                        old_length,
                        new_length,
                        MREMAP_MAYMOVE | MREMAP_FIXED,
                        (void *) (uintptr_t) target);
        if (new_address == MAP_FAILED) {
                int error = errno;

                r = set_mapping_memory_region(h, &change.old_mapping);
                if (r < 0)
                        return r;
                *ret = (uint64_t) -error;
                return 0;
        }
        if ((uintptr_t) new_address != target) {
                r = rollback_host_mremap(new_address, new_length, (void *) (uintptr_t) regs->rdi, old_length);
                if (r < 0)
                        return r;
                r = set_mapping_memory_region(h, &change.old_mapping);
                if (r < 0)
                        return r;
                return -EPROTO;
        }

        FOREACH_ARRAY(piece, change.pieces, change.n_pieces) {
                r = set_mapping_memory_region(h, piece);
                if (r < 0) {
                        int error = r;

                        r = rollback_host_mremap(
                                        new_address, new_length, (void *) (uintptr_t) regs->rdi, old_length);
                        if (r < 0)
                                return r;
                        r = rollback_fixed_map_memory_regions(h, &change, 1);
                        return r < 0 ? r : error;
                }
        }

        for (size_t i = 0; i < new_pages; i++) {
                uint64_t *entry = ASSERT_PTR(guest_page_entry(h, target + i * page_size()));

                if (userfault_index != SIZE_MAX && i < old_pages &&
                    FLAGS_SET(old_entries[i], X86_PAGE_SOFTWARE_UFFD_POISON))
                        *entry = (destination_gpa + i * page_size()) |
                                        (old_entries[i] & ~X86_PAGE_ADDRESS_MASK);
                else if (userfault_index != SIZE_MAX && !preserve_userfault_move)
                        *entry = guest_page_value(destination_gpa + i * page_size(), mapping->protection);
                else if (i < old_pages)
                        *entry = (destination_gpa + i * page_size()) |
                                        (old_entries[i] & ~X86_PAGE_ADDRESS_MASK);
                else if (userfault_index != SIZE_MAX) {
                        *entry = guest_page_value(destination_gpa + i * page_size(), mapping->protection);
                        if (FLAGS_SET(old_userfault_range.mode, UFFDIO_REGISTER_MODE_MISSING) ||
                            FLAGS_SET(old_userfault_range.mode, UFFDIO_REGISTER_MODE_MINOR))
                                *entry &= ~X86_PAGE_PRESENT;
                } else
                        *entry = (destination_gpa + i * page_size()) |
                                        (old_entries[old_pages - 1] & ~X86_PAGE_ADDRESS_MASK);
        }
        for (size_t i = 0; i < old_pages; i++)
                unmap_guest_page(h, regs->rdi + i * page_size());
        r = flush_all_guest_tlbs(h);
        if (r < 0)
                _exit(EXIT_FAILURE);
        for (size_t i = 0; i < old_pages; i++)
                reclaim_guest_page_tables(h, regs->rdi + i * page_size());

        if (gpa_reservation.size > 0) {
                r = release_guest_physical(h, moved_source_gpa, old_length);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                gpa_reservation.committed = true;
        }

        if (userfault_index != SIZE_MAX) {
                commit_userfault_range_split(
                                h, userfault_index, regs->rdi, source_end, false, false, old_userfault_range.fd);
                if (preserve_userfault_move) {
                        machine->userfault_ranges[machine->n_userfault_ranges] = old_userfault_range;
                        machine->userfault_ranges[machine->n_userfault_ranges].start = target;
                        machine->userfault_ranges[machine->n_userfault_ranges++].length = old_length;
                        if (new_length > old_length) {
                                machine->userfault_ranges[machine->n_userfault_ranges] = old_userfault_range;
                                machine->userfault_ranges[machine->n_userfault_ranges].start = target +
                                                old_length;
                                machine->userfault_ranges[machine->n_userfault_ranges].length = new_length -
                                                old_length;
                                machine->userfault_ranges[machine->n_userfault_ranges++].write_protected = false;
                        }
                        coalesce_userfault_ranges(h);
                }
        }

        free(machine->mappings);
        machine->mappings = TAKE_PTR(new_mappings);
        machine->n_mappings = n_new_mappings;
        free(machine->dontfork_ranges);
        machine->dontfork_ranges = TAKE_PTR(new_dontfork_ranges);
        machine->n_dontfork_ranges = n_new_dontfork_ranges;
        free(machine->wipeonfork_ranges);
        machine->wipeonfork_ranges = TAKE_PTR(new_wipeonfork_ranges);
        machine->n_wipeonfork_ranges = n_new_wipeonfork_ranges;
        close_unused_mapping_fds(machine);
        slot_reservation.committed = true;
        *ret = target;
        return 0;
}

static int handle_guest_mremap_multi_vma_fixed_shrink(
                ExecHypervisor *h,
                const struct kvm_regs *regs,
                uint64_t old_length,
                uint64_t new_length,
                uint64_t target,
                uint64_t *ret) {

        _cleanup_free_ ExecHypervisorMapping *new_mappings = NULL;
        _cleanup_free_ ExecHypervisorMapping *tail_mappings = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_dontfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_wipeonfork_ranges = NULL;
        _cleanup_free_ uint64_t *old_entries = NULL;
        ExecHypervisorMapping first = {}, moved, old_target_mapping = {};
        ExecHypervisor *machine;
        uint64_t old_end, target_end;
        size_t n_new_mappings = 0, n_staged = 0, n_tail = 0, new_pages,
               target_mapping_index = SIZE_MAX;
        size_t n_new_dontfork_ranges, n_new_wipeonfork_ranges;
        void *new_address, *reservation, *staged_target = MAP_FAILED, *staging;
        bool target_staged = false;
        int error, r;

        assert(h);
        assert(regs);
        assert(old_length > new_length);
        assert(ret);

        machine = exec_hypervisor_machine(h);
        assert_se(ADD_SAFE(&old_end, regs->rdi, old_length));
        assert_se(ADD_SAFE(&target_end, target, new_length));

        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end;

                assert_se(ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size));
                if (regs->rdi >= mapping_end || old_end <= mapping->guest_virtual_address)
                        continue;
                if (!mapping->mutable || mapping->guest_virtual_address < regs->rdi || mapping_end > old_end) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
                if (mapping->guest_virtual_address == regs->rdi) {
                        if (first.size > 0 || mapping->size != new_length) {
                                *ret = (uint64_t) -ENOSYS;
                                return 0;
                        }
                        first = *mapping;
                } else {
                        if (mapping->guest_virtual_address < regs->rdi + new_length) {
                                *ret = (uint64_t) -ENOSYS;
                                return 0;
                        }
                        n_tail++;
                }
        }
        if (first.size == 0 || n_tail == 0) {
                *ret = (uint64_t) -ENOSYS;
                return 0;
        }

        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end;

                assert_se(ADD_SAFE(&mapping_end, mapping->guest_virtual_address, mapping->size));
                if (target < mapping_end && target_end > mapping->guest_virtual_address) {
                        if (target_mapping_index != SIZE_MAX || !mapping->mutable ||
                            mapping->guest_virtual_address != target || mapping->size != new_length) {
                                *ret = (uint64_t) -ENOSYS;
                                return 0;
                        }
                        target_mapping_index = mapping - machine->mappings;
                        old_target_mapping = *mapping;
                }
        }
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if ((regs->rdi < range_end && old_end > range->start) ||
                    (target < range_end && target_end > range->start)) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
        }

        r = prepare_mremap_fork_advice_ranges(
                        machine->dontfork_ranges,
                        machine->n_dontfork_ranges,
                        regs->rdi,
                        old_length,
                        target,
                        new_length,
                        false,
                        &new_dontfork_ranges,
                        &n_new_dontfork_ranges);
        if (r < 0) {
                *ret = (uint64_t) r;
                return 0;
        }
        r = prepare_mremap_fork_advice_ranges(
                        machine->wipeonfork_ranges,
                        machine->n_wipeonfork_ranges,
                        regs->rdi,
                        old_length,
                        target,
                        new_length,
                        false,
                        &new_wipeonfork_ranges,
                        &n_new_wipeonfork_ranges);
        if (r < 0) {
                *ret = (uint64_t) r;
                return 0;
        }

        r = ensure_gpa_release_capacity(h, n_tail + (target_mapping_index != SIZE_MAX));
        if (r < 0) {
                *ret = (uint64_t) r;
                return 0;
        }
        tail_mappings = new (ExecHypervisorMapping, n_tail);
        new_mappings = new (
                        ExecHypervisorMapping,
                        machine->n_mappings - n_tail - (target_mapping_index != SIZE_MAX));
        new_pages = new_length / page_size();
        old_entries = new (uint64_t, new_pages);
        if (!tail_mappings || !new_mappings || !old_entries) {
                *ret = (uint64_t) -ENOMEM;
                return 0;
        }

        size_t tail_index = 0;
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings) {
                uint64_t mapping_end = mapping->guest_virtual_address + mapping->size;

                if ((size_t) (mapping - machine->mappings) == target_mapping_index)
                        continue;
                if (mapping->guest_virtual_address >= regs->rdi + new_length && mapping_end <= old_end) {
                        tail_mappings[tail_index++] = *mapping;
                        continue;
                }
                if (mapping->guest_virtual_address == regs->rdi && mapping->size == new_length) {
                        moved = *mapping;
                        moved.host_address = (void *) (uintptr_t) target;
                        moved.guest_virtual_address = target;
                        new_mappings[n_new_mappings++] = moved;
                } else
                        new_mappings[n_new_mappings++] = *mapping;
        }
        assert(tail_index == n_tail);
        assert(n_new_mappings == machine->n_mappings - n_tail - (target_mapping_index != SIZE_MAX));

        for (size_t i = 0; i < new_pages; i++) {
                uint64_t *source_entry = guest_page_entry(h, regs->rdi + i * page_size());
                uint64_t *target_entry;

                if (!source_entry || *source_entry == 0)
                        return -EFAULT;
                old_entries[i] = *source_entry;
                r = ensure_guest_page_entry(h, target + i * page_size(), &target_entry);
                if (r < 0) {
                        *ret = (uint64_t) (r == -ENOSPC ? -ENOMEM : r);
                        return 0;
                }
                if (*target_entry != 0 && target_mapping_index == SIZE_MAX) {
                        *ret = (uint64_t) -EFAULT;
                        return 0;
                }
        }

        reservation = mmap(
                        target_mapping_index == SIZE_MAX ? (void *) (uintptr_t) target : NULL,
                        new_length,
                        PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS |
                                        (target_mapping_index == SIZE_MAX ? MAP_FIXED_NOREPLACE : 0),
                        -1,
                        0);
        if (reservation == MAP_FAILED) {
                *ret = (uint64_t) (errno == EEXIST ? -ENOSYS : -errno);
                return 0;
        }
        if (target_mapping_index == SIZE_MAX && (uintptr_t) reservation != target) {
                (void) munmap(reservation, new_length);
                return -EPROTO;
        }
        if (target_mapping_index != SIZE_MAX)
                staged_target = reservation;

        staging = mmap(NULL, old_length - new_length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (staging == MAP_FAILED) {
                error = errno;

                (void) munmap(reservation, new_length);
                *ret = (uint64_t) -error;
                return 0;
        }
        if (munmap(staging, old_length - new_length) < 0) {
                error = errno;

                (void) munmap(reservation, new_length);
                *ret = (uint64_t) -error;
                return 0;
        }
        if (munmap(reservation, new_length) < 0) {
                *ret = (uint64_t) -errno;
                return 0;
        }

        if (target_mapping_index != SIZE_MAX) {
                r = remove_mapping_memory_region(h, old_target_mapping.slot);
                if (r < 0)
                        return r;
                new_address = mremap(
                                old_target_mapping.host_address,
                                old_target_mapping.size,
                                old_target_mapping.size,
                                MREMAP_MAYMOVE | MREMAP_FIXED,
                                staged_target);
                if (new_address == MAP_FAILED) {
                        error = errno;
                        r = set_mapping_memory_region(h, &old_target_mapping);
                        if (r < 0)
                                return r;
                        *ret = (uint64_t) -error;
                        return 0;
                }
                if (new_address != staged_target) {
                        r = restore_staged_mremap_target(h, new_address, &old_target_mapping);
                        if (r < 0)
                                return r;
                        return -EPROTO;
                }
                target_staged = true;
        }

        r = remove_mapping_memory_region(h, first.slot);
        if (r < 0) {
                if (!target_staged)
                        return r;
                error = r;
                goto rollback_target;
        }
        FOREACH_ARRAY(mapping, tail_mappings, n_tail) {
                r = remove_mapping_memory_region(h, mapping->slot);
                if (r < 0)
                        goto rollback_regions;
        }

        FOREACH_ARRAY(mapping, tail_mappings, n_tail) {
                void *staged_address = (uint8_t *) staging + mapping->guest_virtual_address - regs->rdi -
                                new_length;

                new_address = mremap(
                                mapping->host_address,
                                mapping->size,
                                mapping->size,
                                MREMAP_MAYMOVE | MREMAP_FIXED,
                                staged_address);
                if (new_address == MAP_FAILED) {
                        r = -errno;
                        goto rollback_host;
                }
                if (new_address != staged_address) {
                        r = -EPROTO;
                        goto rollback_host;
                }
                n_staged++;
        }

        new_address = mremap(
                        first.host_address,
                        first.size,
                        first.size,
                        MREMAP_MAYMOVE | MREMAP_FIXED,
                        (void *) (uintptr_t) target);
        if (new_address == MAP_FAILED) {
                r = -errno;
                goto rollback_host;
        }
        if ((uintptr_t) new_address != target) {
                r = -EPROTO;
                goto rollback_first;
        }

        r = set_mapping_memory_region(h, &moved);
        if (r < 0)
                goto rollback_first;

        for (size_t i = 0; i < new_pages; i++) {
                *ASSERT_PTR(guest_page_entry(h, target + i * page_size())) = old_entries[i];
                unmap_guest_page(h, regs->rdi + i * page_size());
        }
        for (uint64_t page = regs->rdi + new_length; page < old_end; page += page_size())
                unmap_guest_page(h, page);
        r = flush_all_guest_tlbs(h);
        if (r < 0)
                _exit(EXIT_FAILURE);
        for (uint64_t page = regs->rdi; page < old_end; page += page_size())
                reclaim_guest_page_tables(h, page);

        FOREACH_ARRAY(mapping, tail_mappings, n_tail) {
                r = release_guest_physical(h, mapping->guest_physical_address, mapping->size);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                release_memslot(h, mapping->slot);
        }
        if (target_staged) {
                if (munmap(staged_target, old_target_mapping.size) < 0)
                        _exit(EXIT_FAILURE);
                r = release_guest_physical(
                                h, old_target_mapping.guest_physical_address, old_target_mapping.size);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                release_memslot(h, old_target_mapping.slot);
        }
        if (munmap(staging, old_length - new_length) < 0)
                _exit(EXIT_FAILURE);

        free(machine->mappings);
        machine->mappings = TAKE_PTR(new_mappings);
        machine->n_mappings = n_new_mappings;
        free(machine->dontfork_ranges);
        machine->dontfork_ranges = TAKE_PTR(new_dontfork_ranges);
        machine->n_dontfork_ranges = n_new_dontfork_ranges;
        free(machine->wipeonfork_ranges);
        machine->wipeonfork_ranges = TAKE_PTR(new_wipeonfork_ranges);
        machine->n_wipeonfork_ranges = n_new_wipeonfork_ranges;
        FOREACH_ARRAY(context, machine->aio_contexts, machine->n_aio_contexts)
                if (context->mapping_start == regs->rdi && context->mapping_size == old_length) {
                        context->id = target;
                        context->mapping_start = target;
                        context->mapping_size = new_length;
                        break;
                }
        close_unused_mapping_fds(machine);
        *ret = target;
        return 0;

rollback_first:
        if (new_address != MAP_FAILED) {
                int q = rollback_host_mremap(new_address, first.size, first.host_address, first.size);
                if (q < 0)
                        return q;
        }
rollback_host:
        for (size_t i = n_staged; i > 0; i--) {
                ExecHypervisorMapping *mapping = tail_mappings + i - 1;
                void *staged_address = (uint8_t *) staging + mapping->guest_virtual_address - regs->rdi -
                                new_length;
                int q = rollback_host_mremap(
                                staged_address, mapping->size, mapping->host_address, mapping->size);
                if (q < 0)
                        return q;
        }
rollback_regions:
        error = r;
        r = set_mapping_memory_region(h, &first);
        if (r < 0)
                return r;
        FOREACH_ARRAY(mapping, tail_mappings, n_tail) {
                r = set_mapping_memory_region(h, mapping);
                if (r < 0)
                        return r;
        }
rollback_target:
        if (target_staged) {
                r = restore_staged_mremap_target(h, staged_target, &old_target_mapping);
                if (r < 0)
                        return r;
        }
        *ret = (uint64_t) error;
        return 0;
}

static int handle_guest_mremap(ExecHypervisor *h, const struct kvm_regs *regs, uint64_t *ret) {
        _cleanup_(gpa_reservation_done) ExecHypervisorGpaReservation gpa_reservation = {};
        _cleanup_(memslot_reservation_done) ExecHypervisorMemslotReservation slot_reservation = {};
        _cleanup_free_ ExecHypervisorSealedRange *new_dontfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_wipeonfork_ranges = NULL;
        _cleanup_free_ uint64_t *old_entries = NULL;
        ExecHypervisor *machine;
        ExecHypervisorMapping *mapping = NULL, old_mapping, old_target_mapping = {};
        ExecHypervisorUserfaultRange old_userfault_range = {};
        struct kvm_userspace_memory_region region;
        uint64_t end, gpa, old_end, old_length, new_length, target;
        size_t mapping_index, new_pages, old_pages, target_mapping_index = SIZE_MAX,
                                                    userfault_additional = 0, userfault_index = SIZE_MAX;
        size_t n_new_dontfork_ranges, n_new_wipeonfork_ranges;
        void *new_address, *reservation = MAP_FAILED, *staged_target = MAP_FAILED;
        bool dontunmap, fixed, preserve_userfault_move = false, split_dontunmap_userfault_range = false,
                               split_userfault_range = false, target_staged = false;
        int host_flags = 0, r;

        assert(h);
        assert(regs);
        assert(ret);

        machine = exec_hypervisor_machine(h);

        if (regs->rdi % page_size() != 0 || regs->rsi == 0 || regs->rsi > SIZE_MAX - (page_size() - 1) ||
            regs->rdx == 0 || regs->rdx > SIZE_MAX - (page_size() - 1)) {
                *ret = (uint64_t) -EINVAL;
                return 0;
        }
        if ((regs->r10 & ~(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP)) != 0) {
                *ret = (uint64_t) -EINVAL;
                return 0;
        }

        dontunmap = FLAGS_SET(regs->r10, MREMAP_DONTUNMAP);
        fixed = FLAGS_SET(regs->r10, MREMAP_FIXED);
        old_length = PAGE_ALIGN(regs->rsi);
        new_length = PAGE_ALIGN(regs->rdx);
        if (dontunmap && (!FLAGS_SET(regs->r10, MREMAP_MAYMOVE) || old_length != new_length)) {
                *ret = (uint64_t) -EINVAL;
                return 0;
        }
        if (!ADD_SAFE(&old_end, regs->rdi, old_length)) {
                *ret = (uint64_t) -EINVAL;
                return 0;
        }
        target = fixed ? regs->r8 : regs->rdi;
        if (fixed &&
            (!FLAGS_SET(regs->r10, MREMAP_MAYMOVE) || target % page_size() != 0 ||
             !ADD_SAFE(&end, target, new_length) || end > UINT64_C(0x0000800000000000) ||
             (target < old_end && end > regs->rdi))) {
                *ret = (uint64_t) -EINVAL;
                return 0;
        }
        FOREACH_ARRAY(range, machine->sealed_ranges, machine->n_sealed_ranges) {
                uint64_t range_end = range->start + range->length;

                if ((regs->rdi < range_end && old_end > range->start) ||
                    (fixed && target < range_end && end > range->start)) {
                        *ret = (uint64_t) -EPERM;
                        return 0;
                }
        }
        if (!fixed && !dontunmap && new_length < old_length) {
                bool source_mapped = false;
                uint64_t result;

                FOREACH_ARRAY(candidate, machine->mappings, machine->n_mappings) {
                        uint64_t candidate_end;

                        assert_se(ADD_SAFE(&candidate_end, candidate->guest_virtual_address, candidate->size));
                        if (regs->rdi < candidate->guest_virtual_address || regs->rdi >= candidate_end)
                                continue;
                        if (!candidate->mutable) {
                                *ret = (uint64_t) -ENOSYS;
                                return 0;
                        }
                        source_mapped = true;
                        break;
                }
                if (!source_mapped) {
                        *ret = (uint64_t) -EFAULT;
                        return 0;
                }

                result = handle_guest_munmap(h, regs->rdi + new_length, old_length - new_length);
                *ret = result == 0 ? regs->rdi : result;
                return 0;
        }
        FOREACH_ARRAY(candidate, machine->mappings, machine->n_mappings) {
                uint64_t candidate_end;

                assert_se(ADD_SAFE(&candidate_end, candidate->guest_virtual_address, candidate->size));
                if (!candidate->mutable)
                        continue;
                if (dontunmap ? regs->rdi >= candidate->guest_virtual_address && old_end <= candidate_end :
                                candidate->guest_virtual_address == regs->rdi &&
                                                    candidate->size == old_length) {
                        mapping = candidate;
                        break;
                }
        }
        if (!mapping) {
                if (fixed && !dontunmap && new_length < old_length)
                        return handle_guest_mremap_multi_vma_fixed_shrink(
                                        h, regs, old_length, new_length, target, ret);
                if (fixed && !dontunmap && old_length == new_length)
                        return handle_guest_mremap_partial(h, regs, old_length, new_length, target, ret);
                if (!fixed && !dontunmap && FLAGS_SET(regs->r10, MREMAP_MAYMOVE) && new_length > old_length)
                        return handle_guest_mremap_partial(h, regs, old_length, new_length, target, ret);
                if (!fixed && !dontunmap && new_length == old_length)
                        return handle_guest_mremap_partial(h, regs, old_length, new_length, target, ret);
                *ret = (uint64_t) -ENOSYS;
                return 0;
        }
        if (fixed) {
                FOREACH_ARRAY(candidate, machine->mappings, machine->n_mappings) {
                        uint64_t candidate_end;

                        assert_se(ADD_SAFE(&candidate_end, candidate->guest_virtual_address, candidate->size));
                        if (target >= candidate_end || end <= candidate->guest_virtual_address)
                                continue;
                        if (target_mapping_index != SIZE_MAX || !candidate->mutable ||
                            candidate->guest_virtual_address != target || candidate->size != new_length) {
                                *ret = (uint64_t) -ENOSYS;
                                return 0;
                        }
                        target_mapping_index = candidate - machine->mappings;
                        old_target_mapping = *candidate;
                }
                if (target_mapping_index != SIZE_MAX)
                        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges)
                if (target < range->start + range->length && end > range->start) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
        }
        FOREACH_ARRAY(range, machine->userfault_ranges, machine->n_userfault_ranges) {
                uint64_t range_end = range->start + range->length;

                if (regs->rdi >= range_end || regs->rdi + old_length <= range->start)
                        continue;
                if (userfault_index != SIZE_MAX ||
                    (dontunmap ? regs->rdi < range->start || old_end > range_end :
                                 range->start != regs->rdi || range->length != old_length)) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
                userfault_index = range - machine->userfault_ranges;
        }
        if (new_length == old_length && !fixed && !dontunmap) {
                *ret = regs->rdi;
                return 0;
        }
        if (userfault_index != SIZE_MAX &&
            (dontunmap || fixed || (new_length > old_length && FLAGS_SET(regs->r10, MREMAP_MAYMOVE)))) {
                ExecHypervisorUserfaultRange *range = machine->userfault_ranges + userfault_index;

                if (!range->features_known) {
                        *ret = (uint64_t) -ENOSYS;
                        return 0;
                }
                preserve_userfault_move = FLAGS_SET(range->features, UFFD_FEATURE_EVENT_REMAP);
        }
        if (userfault_index != SIZE_MAX && new_length > old_length &&
            (!FLAGS_SET(regs->r10, MREMAP_MAYMOVE) || preserve_userfault_move) &&
            FLAGS_SET(machine->userfault_ranges[userfault_index].mode, UFFDIO_REGISTER_MODE_WP) &&
            machine->userfault_ranges[userfault_index].write_protected) {
                if (!GREEDY_REALLOC0(machine->userfault_ranges, machine->n_userfault_ranges + 1)) {
                        *ret = (uint64_t) -ENOMEM;
                        return 0;
                }
                split_userfault_range = true;
        }

        mapping_index = mapping - machine->mappings;
        old_mapping = *mapping;
        if (dontunmap && userfault_index != SIZE_MAX &&
            !IN_SET(machine->userfault_ranges[userfault_index].mode,
                    UFFDIO_REGISTER_MODE_MISSING,
                    UFFDIO_REGISTER_MODE_WP,
                    UFFDIO_REGISTER_MODE_MINOR,
                    UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP,
                    UFFDIO_REGISTER_MODE_MINOR | UFFDIO_REGISTER_MODE_WP)) {
                *ret = (uint64_t) -ENOSYS;
                return 0;
        }
        if (dontunmap && userfault_index != SIZE_MAX) {
                ExecHypervisorUserfaultRange *range = machine->userfault_ranges + userfault_index;
                uint64_t range_end = range->start + range->length;

                old_userfault_range = *range;
                if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) && range->write_protected) {
                        split_dontunmap_userfault_range = true;
                        userfault_additional += regs->rdi > range->start;
                        userfault_additional += old_end < range_end;
                }
                userfault_additional += preserve_userfault_move;
                if (userfault_additional > 0 &&
                    !GREEDY_REALLOC0(
                                    machine->userfault_ranges,
                                    machine->n_userfault_ranges + userfault_additional)) {
                        *ret = (uint64_t) -ENOMEM;
                        return 0;
                }
        }
        if (dontunmap) {
                if (!GREEDY_REALLOC0(machine->mappings, machine->n_mappings + 1)) {
                        *ret = (uint64_t) -ENOMEM;
                        return 0;
                }
                r = reserve_memslots(h, 1, &slot_reservation);
                if (r < 0) {
                        *ret = (uint64_t) (r == -ENOSPC ? -ENOMEM : r);
                        return 0;
                }
        }
        if (target_mapping_index != SIZE_MAX) {
                r = ensure_gpa_release_capacity(h, 1);
                if (r < 0) {
                        *ret = (uint64_t) r;
                        return 0;
                }
        }
        old_pages = old_length / page_size();
        new_pages = new_length / page_size();
        old_entries = new (uint64_t, old_pages);
        if (!old_entries) {
                *ret = (uint64_t) -ENOMEM;
                return 0;
        }

        for (size_t i = 0; i < old_pages; i++) {
                uint64_t *entry = guest_page_entry(h, regs->rdi + i * page_size());

                if (!entry || *entry == 0)
                        return -EFAULT;
                old_entries[i] = *entry;
        }

        if (fixed) {
                reservation = mmap(
                                target_mapping_index == SIZE_MAX ? (void *) (uintptr_t) target : NULL,
                                new_length,
                                PROT_NONE,
                                MAP_PRIVATE | MAP_ANONYMOUS |
                                                (target_mapping_index == SIZE_MAX ? MAP_FIXED_NOREPLACE : 0),
                                -1,
                                0);
                if (reservation == MAP_FAILED) {
                        *ret = (uint64_t) (errno == EEXIST ? -ENOSYS : -errno);
                        return 0;
                }
                if (target_mapping_index == SIZE_MAX && (uintptr_t) reservation != target) {
                        (void) munmap(reservation, new_length);
                        return -EPROTO;
                }
                if (target_mapping_index != SIZE_MAX)
                        staged_target = reservation;
                if (munmap(reservation, new_length) < 0) {
                        *ret = (uint64_t) -errno;
                        return 0;
                }
                reservation = MAP_FAILED;
                host_flags = MREMAP_MAYMOVE | MREMAP_FIXED | (dontunmap ? MREMAP_DONTUNMAP : 0);
        } else if (dontunmap || (new_length > old_length && FLAGS_SET(regs->r10, MREMAP_MAYMOVE))) {
                reservation = mmap(NULL, new_length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (reservation == MAP_FAILED) {
                        *ret = (uint64_t) -errno;
                        return 0;
                }
                target = (uintptr_t) reservation;
                if (target > UINT64_C(0x00007fffffffffff) ||
                    new_length > UINT64_C(0x0000800000000000) - target) {
                        (void) munmap(reservation, new_length);
                        *ret = (uint64_t) -ENOMEM;
                        return 0;
                }
                if (munmap(reservation, new_length) < 0) {
                        *ret = (uint64_t) -errno;
                        return 0;
                }
                reservation = MAP_FAILED;
                host_flags = MREMAP_MAYMOVE | MREMAP_FIXED | (dontunmap ? MREMAP_DONTUNMAP : 0);
        }

        r = prepare_mremap_fork_advice_ranges(
                        machine->dontfork_ranges,
                        machine->n_dontfork_ranges,
                        regs->rdi,
                        old_length,
                        target,
                        new_length,
                        dontunmap,
                        &new_dontfork_ranges,
                        &n_new_dontfork_ranges);
        if (r < 0) {
                *ret = (uint64_t) r;
                return 0;
        }
        r = prepare_mremap_fork_advice_ranges(
                        machine->wipeonfork_ranges,
                        machine->n_wipeonfork_ranges,
                        regs->rdi,
                        old_length,
                        target,
                        new_length,
                        dontunmap,
                        &new_wipeonfork_ranges,
                        &n_new_wipeonfork_ranges);
        if (r < 0) {
                *ret = (uint64_t) r;
                return 0;
        }

        for (size_t i = 0; i < new_pages; i++) {
                uint64_t *entry;

                r = ensure_guest_page_entry(h, target + i * page_size(), &entry);
                if (r < 0) {
                        *ret = (uint64_t) (r == -ENOSPC ? -ENOMEM : r);
                        return 0;
                }
                if ((target != regs->rdi || i >= old_pages) && *entry != 0 &&
                    target_mapping_index == SIZE_MAX) {
                        *ret = (uint64_t) -EFAULT;
                        return 0;
                }
        }

        r = reserve_guest_physical(h, new_length, &gpa_reservation);
        if (r < 0) {
                *ret = (uint64_t) r;
                return 0;
        }
        gpa = gpa_reservation.address;

        if (target_mapping_index != SIZE_MAX) {
                r = remove_mapping_memory_region(h, old_target_mapping.slot);
                if (r < 0)
                        return r;
                reservation = mremap(
                                old_target_mapping.host_address,
                                old_target_mapping.size,
                                old_target_mapping.size,
                                MREMAP_MAYMOVE | MREMAP_FIXED,
                                staged_target);
                if (reservation == MAP_FAILED) {
                        int error = errno;

                        r = set_mapping_memory_region(h, &old_target_mapping);
                        if (r < 0)
                                return r;
                        *ret = (uint64_t) -error;
                        return 0;
                }
                if (reservation != staged_target) {
                        r = restore_staged_mremap_target(h, reservation, &old_target_mapping);
                        if (r < 0)
                                return r;
                        return -EPROTO;
                }
                target_staged = true;
        }

        region = (struct kvm_userspace_memory_region) {
                .slot = old_mapping.slot,
        };
        if (ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
                r = -errno;
                if (target_staged) {
                        int q = restore_staged_mremap_target(h, staged_target, &old_target_mapping);

                        if (q < 0)
                                return q;
                }
                return r;
        }

        if (host_flags != 0)
                new_address = mremap(
                                (void *) (uintptr_t) regs->rdi,
                                old_length,
                                new_length,
                                host_flags,
                                (void *) (uintptr_t) target);
        else
                new_address = mremap((void *) (uintptr_t) regs->rdi, old_length, new_length, 0);
        if (new_address == MAP_FAILED) {
                int error = errno;

                region = (struct kvm_userspace_memory_region) {
                        .slot = old_mapping.slot,
                        .flags = old_mapping.stage2_writable ? 0 : KVM_MEM_READONLY,
                        .guest_phys_addr = old_mapping.guest_physical_address,
                        .memory_size = old_mapping.size,
                        .userspace_addr = (uintptr_t) old_mapping.host_address,
                };
                if (ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
                        return -errno;

                if (target_staged) {
                        r = restore_staged_mremap_target(h, staged_target, &old_target_mapping);
                        if (r < 0)
                                return r;
                }

                *ret = (uint64_t) -error;
                return 0;
        }
        if ((uintptr_t) new_address != target) {
                r = rollback_host_mremap(new_address, new_length, (void *) (uintptr_t) regs->rdi, old_length);
                if (r < 0)
                        return r;
                r = set_mapping_memory_region(h, &old_mapping);
                if (r < 0)
                        return r;
                if (target_staged) {
                        r = restore_staged_mremap_target(h, staged_target, &old_target_mapping);
                        if (r < 0)
                                return r;
                }
                return -EPROTO;
        }

        if (dontunmap) {
                region = (struct kvm_userspace_memory_region) {
                        .slot = old_mapping.slot,
                        .flags = old_mapping.stage2_writable ? 0 : KVM_MEM_READONLY,
                        .guest_phys_addr = old_mapping.guest_physical_address,
                        .memory_size = old_mapping.size,
                        .userspace_addr = (uintptr_t) old_mapping.host_address,
                };
                r = ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0 ? -errno : 0;
                if (r >= 0) {
                        region = (struct kvm_userspace_memory_region) {
                                .slot = slot_reservation.slots[0],
                                .flags = old_mapping.stage2_writable ? 0 : KVM_MEM_READONLY,
                                .guest_phys_addr = gpa,
                                .memory_size = new_length,
                                .userspace_addr = (uintptr_t) new_address,
                        };
                        r = ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0 ? -errno : 0;
                }
        } else {
                region = (struct kvm_userspace_memory_region) {
                        .slot = old_mapping.slot,
                        .flags = old_mapping.stage2_writable ? 0 : KVM_MEM_READONLY,
                        .guest_phys_addr = gpa,
                        .memory_size = new_length,
                        .userspace_addr = (uintptr_t) new_address,
                };
                r = ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0 ? -errno : 0;
        }
        if (r < 0) {
                int error = r;

                if (dontunmap)
                        (void) remove_mapping_memory_region(h, old_mapping.slot);
                r = rollback_host_mremap(new_address, new_length, (void *) (uintptr_t) regs->rdi, old_length);
                if (r < 0)
                        return r;

                region = (struct kvm_userspace_memory_region) {
                        .slot = old_mapping.slot,
                        .flags = old_mapping.stage2_writable ? 0 : KVM_MEM_READONLY,
                        .guest_phys_addr = old_mapping.guest_physical_address,
                        .memory_size = old_mapping.size,
                        .userspace_addr = (uintptr_t) old_mapping.host_address,
                };
                if (ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
                        return -errno;

                if (target_staged) {
                        r = restore_staged_mremap_target(h, staged_target, &old_target_mapping);
                        if (r < 0)
                                return r;
                }

                return error;
        }

        if (target_staged) {
                if (munmap(staged_target, old_target_mapping.size) < 0)
                        _exit(EXIT_FAILURE);
                r = release_guest_physical(
                                h, old_target_mapping.guest_physical_address, old_target_mapping.size);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                release_memslot(h, old_target_mapping.slot);
        }

        if (!dontunmap)
                for (size_t i = 0; i < old_pages; i++)
                        unmap_guest_page(h, regs->rdi + i * page_size());
        for (size_t i = 0; i < new_pages; i++) {
                uint64_t *entry = ASSERT_PTR(guest_page_entry(h, target + i * page_size()));

                if (i < old_pages && FLAGS_SET(old_entries[i], X86_PAGE_SOFTWARE_UFFD_POISON))
                        *entry = (gpa + i * page_size()) | (old_entries[i] & ~X86_PAGE_ADDRESS_MASK);
                else if (userfault_index != SIZE_MAX && target != regs->rdi && !preserve_userfault_move)
                        *entry = guest_page_value(gpa + i * page_size(), old_mapping.protection);
                else if (i < old_pages)
                        *entry = (gpa + i * page_size()) | (old_entries[i] & ~X86_PAGE_ADDRESS_MASK);
                else if (userfault_index != SIZE_MAX) {
                        ExecHypervisorUserfaultRange *range = machine->userfault_ranges + userfault_index;

                        *entry = guest_page_value(gpa + i * page_size(), old_mapping.protection);
                        if ((range->mode & (UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_MINOR)) != 0)
                                *entry &= ~X86_PAGE_PRESENT;
                } else
                        *entry = (gpa + i * page_size()) |
                                        (old_entries[old_pages - 1] & ~X86_PAGE_ADDRESS_MASK);
        }
        if (dontunmap && userfault_index != SIZE_MAX) {
                ExecHypervisorUserfaultRange *range = machine->userfault_ranges + userfault_index;

                for (size_t i = 0; i < old_pages; i++) {
                        uint64_t *entry = ASSERT_PTR(guest_page_entry(h, regs->rdi + i * page_size()));

                        if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_MISSING) ||
                            FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_MINOR)) {
                                *entry &= ~X86_PAGE_PRESENT;
                                if (FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) &&
                                    FLAGS_SET(old_mapping.protection, PROT_WRITE))
                                        *entry |= X86_PAGE_WRITE;
                        } else {
                                *entry |= X86_PAGE_PRESENT;
                                if (FLAGS_SET(old_mapping.protection, PROT_WRITE))
                                        *entry |= X86_PAGE_WRITE;
                        }
                }
        }

        if (userfault_index != SIZE_MAX) {
                ExecHypervisorUserfaultRange *range = machine->userfault_ranges + userfault_index;

                if (dontunmap) {
                        if (split_dontunmap_userfault_range)
                                commit_userfault_range_split(
                                                h,
                                                userfault_index,
                                                regs->rdi,
                                                old_end,
                                                true,
                                                false,
                                                old_userfault_range.fd);
                        if (preserve_userfault_move) {
                                machine->userfault_ranges[machine->n_userfault_ranges] = old_userfault_range;
                                machine->userfault_ranges[machine->n_userfault_ranges].start = target;
                                machine->userfault_ranges[machine->n_userfault_ranges++].length = new_length;
                        }
                } else if (target != regs->rdi && !preserve_userfault_move) {
                        memmove(range,
                                range + 1,
                                (machine->n_userfault_ranges - userfault_index - 1) * sizeof(*range));
                        machine->n_userfault_ranges--;
                } else if (split_userfault_range) {
                        ExecHypervisorUserfaultRange suffix;

                        range->start = target;
                        range->length = old_length;
                        suffix = *range;
                        suffix.start = target + old_length;
                        suffix.length = new_length - old_length;
                        suffix.write_protected = false;
                        memmove(range + 2,
                                range + 1,
                                (machine->n_userfault_ranges - userfault_index - 1) * sizeof(*range));
                        range[1] = suffix;
                        machine->n_userfault_ranges++;
                } else {
                        range->start = target;
                        range->length = new_length;
                }
        }

        mapping = machine->mappings + mapping_index;
        if (dontunmap) {
                machine->mappings[machine->n_mappings++] = (ExecHypervisorMapping) {
                        .host_address = new_address,
                        .guest_virtual_address = target,
                        .guest_physical_address = gpa,
                        .size = new_length,
                        .protection = old_mapping.protection,
                        .slot = slot_reservation.slots[0],
                        .growdown_id = old_mapping.growdown_id,
                        .mutable = true,
                        .stage2_writable = old_mapping.stage2_writable,
                        .file_backed = old_mapping.file_backed,
                        .shared = old_mapping.shared,
                        .grows_down = old_mapping.grows_down &&
                                regs->rdi == old_mapping.guest_virtual_address,
                        .backing_fd = old_mapping.backing_fd,
                        .file_offset = old_mapping.file_offset +
                                regs->rdi - old_mapping.guest_virtual_address,
                        .backing_device = old_mapping.backing_device,
                        .backing_inode = old_mapping.backing_inode,
                };
                slot_reservation.committed = true;
        } else {
                mapping->host_address = new_address;
                mapping->guest_virtual_address = target;
                mapping->guest_physical_address = gpa;
                mapping->size = new_length;
        }
        if (target_mapping_index != SIZE_MAX) {
                memmove(machine->mappings + target_mapping_index,
                        machine->mappings + target_mapping_index + 1,
                        (machine->n_mappings - target_mapping_index - 1) * sizeof(machine->mappings[0]));
                machine->n_mappings--;
        }
        free(machine->dontfork_ranges);
        machine->dontfork_ranges = TAKE_PTR(new_dontfork_ranges);
        machine->n_dontfork_ranges = n_new_dontfork_ranges;
        free(machine->wipeonfork_ranges);
        machine->wipeonfork_ranges = TAKE_PTR(new_wipeonfork_ranges);
        machine->n_wipeonfork_ranges = n_new_wipeonfork_ranges;
        close_unused_mapping_fds(machine);
        if (!dontunmap && target != regs->rdi) {
                r = restore_shadow_stack_guards_after_unmap(machine, regs->rdi, old_end);
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }
        *ret = target;

        r = flush_all_guest_tlbs(h);
        if (r < 0)
                _exit(EXIT_FAILURE);
        if (!dontunmap) {
                r = release_guest_physical(h, old_mapping.guest_physical_address, old_mapping.size);
                if (r < 0)
                        _exit(EXIT_FAILURE);
        }
        gpa_reservation.committed = true;
        return 0;
}

static ExecHypervisorMapping *find_heap_mapping(ExecHypervisor *h) {
        ExecHypervisor *machine;

        assert(h);

        machine = exec_hypervisor_machine(h);
        FOREACH_ARRAY(mapping, machine->mappings, machine->n_mappings)
                if (mapping->host_address == machine->heap_reservation)
                        return mapping;

        return NULL;
}

static int set_heap_region_size(ExecHypervisor *h, uint64_t size) {
        ExecHypervisor *machine;
        struct kvm_userspace_memory_region region = {
        };

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert(size <= machine->heap_reservation_size);
        region.slot = machine->heap_slot;

        if (size > 0) {
                region.guest_phys_addr = machine->heap_guest_physical_address;
                region.memory_size = size;
                region.userspace_addr = (uintptr_t) machine->heap_reservation;
        }

        if (ioctl(machine->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
                return -errno;

        return 0;
}

static uint64_t handle_guest_brk(ExecHypervisor *h, uint64_t requested) {
        _cleanup_free_ ExecHypervisorSealedRange *new_dontfork_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *new_wipeonfork_ranges = NULL;
        ExecHypervisor *machine;
        ExecHypervisorMapping *mapping;
        uint64_t base, mapped_end, old_mapped_end;
        size_t changed_size, n_mapped_pages = 0, n_new_dontfork_ranges = 0, n_new_wipeonfork_ranges = 0;
        bool shrink;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        assert(machine->heap_reservation);

        if (requested == 0)
                return machine->heap_break;

        base = (uintptr_t) machine->heap_reservation;
        if (requested < base || requested > base + machine->heap_reservation_size)
                return machine->heap_break;

        mapped_end = PAGE_ALIGN(requested);
        old_mapped_end = machine->heap_mapped_end;
        shrink = mapped_end < old_mapped_end;
        if (mapped_end == old_mapped_end) {
                machine->heap_break = requested;
                return machine->heap_break;
        }
        if (shrink)
                FOREACH_ARRAY(range, machine->sealed_ranges, machine->n_sealed_ranges)
                        if (mapped_end < range->start + range->length && old_mapped_end > range->start)
                                return machine->heap_break;
        if (shrink) {
                r = prepare_dontfork_ranges(
                                machine,
                                mapped_end,
                                old_mapped_end,
                                false,
                                &new_dontfork_ranges,
                                &n_new_dontfork_ranges);
                if (r < 0)
                        return machine->heap_break;
                r = prepare_wipeonfork_ranges(
                                machine,
                                mapped_end,
                                old_mapped_end,
                                false,
                                &new_wipeonfork_ranges,
                                &n_new_wipeonfork_ranges);
                if (r < 0)
                        return machine->heap_break;
        }

        mapping = find_heap_mapping(h);
        if (!mapping && !GREEDY_REALLOC0(machine->mappings, machine->n_mappings + 1))
                return machine->heap_break;

        if (mapped_end > old_mapped_end) {
                changed_size = mapped_end - old_mapped_end;

                for (uint64_t page = old_mapped_end; page < mapped_end; page += page_size()) {
                        r = map_guest_page(
                                        h,
                                        page,
                                        machine->heap_guest_physical_address + page - base,
                                        guest_page_flags(PROT_READ|PROT_WRITE));
                        if (r < 0)
                                goto rollback_grow_pages;
                        n_mapped_pages++;
                }

                if (mprotect((void*) (uintptr_t) old_mapped_end, changed_size, PROT_READ|PROT_WRITE) < 0)
                        goto rollback_grow_pages;

                r = set_heap_region_size(h, mapped_end - base);
                if (r < 0) {
                        (void) mprotect((void*) (uintptr_t) old_mapped_end, changed_size, PROT_NONE);
                        goto rollback_grow_pages;
                }

                r = flush_guest_tlb(h);
                if (r < 0) {
                        (void) set_heap_region_size(h, old_mapped_end - base);
                        (void) mprotect((void*) (uintptr_t) old_mapped_end, changed_size, PROT_NONE);
                        goto rollback_grow_pages;
                }
        } else {
                changed_size = old_mapped_end - mapped_end;

                for (uint64_t page = mapped_end; page < old_mapped_end; page += page_size()) {
                        uint64_t *entry = guest_page_entry(h, page);

                        if (!entry)
                                goto rollback_shrink_pages;
                        *entry = 0;
                        n_mapped_pages++;
                }

                r = flush_guest_tlb(h);
                if (r < 0)
                        goto rollback_shrink_pages;

                r = set_heap_region_size(h, mapped_end - base);
                if (r < 0)
                        goto rollback_shrink_pages;

                if (mmap((void*) (uintptr_t) mapped_end,
                         changed_size,
                         PROT_NONE,
                         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                         -1,
                         0) == MAP_FAILED) {
                        (void) set_heap_region_size(h, old_mapped_end - base);
                        goto rollback_shrink_pages;
                }
        }

        if (!mapping) {
                mapping = machine->mappings + machine->n_mappings++;
                *mapping = (ExecHypervisorMapping) {
                        .host_address = machine->heap_reservation,
                        .guest_virtual_address = base,
                        .guest_physical_address = machine->heap_guest_physical_address,
                        .protection = PROT_READ|PROT_WRITE,
                        .slot = machine->heap_slot,
                        .stage2_writable = true,
                };
        }
        mapping->size = mapped_end - base;
        machine->heap_mapped_end = mapped_end;
        machine->heap_break = requested;
        if (shrink) {
                free(machine->dontfork_ranges);
                machine->dontfork_ranges = TAKE_PTR(new_dontfork_ranges);
                machine->n_dontfork_ranges = n_new_dontfork_ranges;
                free(machine->wipeonfork_ranges);
                machine->wipeonfork_ranges = TAKE_PTR(new_wipeonfork_ranges);
                machine->n_wipeonfork_ranges = n_new_wipeonfork_ranges;
        }

        return machine->heap_break;

rollback_grow_pages:
        for (size_t i = 0; i < n_mapped_pages; i++)
                unmap_guest_page(h, old_mapped_end + i * page_size());
        return machine->heap_break;

rollback_shrink_pages:
        for (size_t i = 0; i < n_mapped_pages; i++) {
                uint64_t page = mapped_end + i * page_size();

                *ASSERT_PTR(guest_page_entry(h, page)) =
                        guest_page_value(
                                        machine->heap_guest_physical_address + page - base,
                                        PROT_READ|PROT_WRITE);
        }
        (void) flush_guest_tlb(h);
        return machine->heap_break;
}

static uint64_t handle_guest_mseal(ExecHypervisor *h, const struct kvm_regs *regs) {
        ExecHypervisor *machine;
        uint64_t covered = 0, end, length;
        uint64_t result;

        assert(h);
        assert(regs);

        machine = exec_hypervisor_machine(h);
        if (regs->rdx != 0 || regs->rdi % page_size() != 0 ||
            regs->rsi > SIZE_MAX - (page_size() - 1))
                return (uint64_t) -EINVAL;
        length = PAGE_ALIGN(regs->rsi);
        if (!ADD_SAFE(&end, regs->rdi, length))
                return (uint64_t) -EINVAL;
        if (length == 0) {
                long q = syscall(__NR_mseal, regs->rdi, regs->rsi, regs->rdx);

                return q < 0 ? (uint64_t) -errno : (uint64_t) q;
        }

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
        if (!GREEDY_REALLOC0(machine->sealed_ranges, machine->n_sealed_ranges + 1))
                return (uint64_t) -ENOMEM;

        long q = syscall(__NR_mseal, regs->rdi, regs->rsi, regs->rdx);
        result = q < 0 ? (uint64_t) -errno : (uint64_t) q;
        if ((int64_t) result < 0)
                return result;

        uint64_t merged_start = regs->rdi, merged_end = end;
        for (size_t i = 0; i < machine->n_sealed_ranges;) {
                ExecHypervisorSealedRange *range = machine->sealed_ranges + i;
                uint64_t range_end = range->start + range->length;

                if (merged_end < range->start || merged_start > range_end) {
                        i++;
                        continue;
                }
                merged_start = MIN(merged_start, range->start);
                merged_end = MAX(merged_end, range_end);
                memmove(range,
                        range + 1,
                        (machine->n_sealed_ranges - i - 1) * sizeof(*range));
                machine->n_sealed_ranges--;
        }
        machine->sealed_ranges[machine->n_sealed_ranges++] = (ExecHypervisorSealedRange) {
                .start = merged_start,
                .length = merged_end - merged_start,
        };
        return result;
}

static int allocate_supervisor_page(ExecHypervisor *h, uint64_t flags, uint64_t *ret_gpa, void **ret_host) {
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

static int setup_page_tables(ExecHypervisor *h) {
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

static int exec_hypervisor_open_existing(ExecHypervisor *source, ExecHypervisor **ret) {
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

#if defined(__x86_64__)

static int set_supported_cpuid_fd(ExecHypervisor *h, int vcpu_fd) {
        enum { MAX_CPUID_ENTRIES = 256 };
        _cleanup_free_ struct kvm_cpuid2 *cpuid = NULL;
        struct kvm_cpuid_entry2 *leaf7 = NULL, *leaf80000008 = NULL,
                *xstate0 = NULL, *xstate1 = NULL, *xstate5 = NULL, *xstate6 = NULL, *xstate7 = NULL,
                *xstate11 = NULL, *xstate17 = NULL, *xstate18 = NULL, *tile0 = NULL, *tile1 = NULL;
        uint32_t supported_leaf7_ebx = 0, supported_leaf7_ecx = 0, supported_leaf7_edx = 0,
                supported_leaf80000008_ebx = 0;
        uint64_t supported_xfeatures = 0, supported_xss = 0;
        bool amx = false, avx512 = false, fsgsbase = false, shstk_available = false,
                have_basic_baseline = false, have_extended_baseline = false;

        assert(h);
        assert(h->kvm_fd >= 0);
        assert(vcpu_fd >= 0);

        cpuid = malloc0(offsetof(struct kvm_cpuid2, entries[MAX_CPUID_ENTRIES]));
        if (!cpuid)
                return -ENOMEM;

        cpuid->nent = MAX_CPUID_ENTRIES;
        if (ioctl(h->kvm_fd, KVM_GET_SUPPORTED_CPUID, cpuid) < 0)
                return -errno;

        FOREACH_ARRAY(entry, cpuid->entries, cpuid->nent)
                switch (entry->function) {
                case 1:
                        if ((entry->edx & (CPUID_BIT(0)|CPUID_BIT(24)|CPUID_BIT(26))) !=
                                    (CPUID_BIT(0)|CPUID_BIT(24)|CPUID_BIT(26)) ||
                            (entry->ecx & (CPUID_BIT(26)|CPUID_BIT(28))) !=
                                    (CPUID_BIT(26)|CPUID_BIT(28)))
                                return -EOPNOTSUPP;

                        have_basic_baseline = true;
                        break;

                case 7:
                        if (entry->index == 0) {
                                leaf7 = entry;
                                supported_leaf7_ebx = entry->ebx;
                                supported_leaf7_ecx = entry->ecx;
                                supported_leaf7_edx = entry->edx;
                                fsgsbase = FLAGS_SET(entry->ebx, CPUID_BIT(0));
                                entry->eax = 0; /* Hide all extended-feature subleaves. */
                                entry->ebx &= ~CPUID_7_0_EBX_UNSUPPORTED_STATE;
                                entry->ecx &= ~CPUID_7_0_ECX_UNSUPPORTED_STATE;
                                entry->edx &= ~CPUID_7_0_EDX_UNSUPPORTED_STATE;
                        } else
                                entry->eax = entry->ebx = entry->ecx = entry->edx = 0;
                        break;

                case 0x0d:
                        if (entry->index == 0) {
                                xstate0 = entry;
                                supported_xfeatures = entry->eax | (uint64_t) entry->edx << 32;
                                if ((entry->eax & X86_XFEATURE_MASK_AVX) != X86_XFEATURE_MASK_AVX)
                                        return -EOPNOTSUPP;

                                entry->eax = X86_XFEATURE_MASK_AVX;
                                entry->edx = 0;
                                entry->ecx = X86_AVX_XSAVE_SIZE;
                        } else if (entry->index == 1) {
                                xstate1 = entry;
                                supported_xss = entry->ecx | (uint64_t) entry->edx << 32;
                        } else if (entry->index == 2) {
                                if (entry->eax != X86_YMMH_SIZE || entry->ebx != X86_YMMH_OFFSET)
                                        return -EOPNOTSUPP;

                                entry->ecx = entry->edx = 0;
                        } else if (entry->index == 5)
                                xstate5 = entry;
                        else if (entry->index == 6)
                                xstate6 = entry;
                        else if (entry->index == 7)
                                xstate7 = entry;
                        else if (entry->index == 11)
                                xstate11 = entry;
                        else if (entry->index == 17)
                                xstate17 = entry;
                        else if (entry->index == 18)
                                xstate18 = entry;
                        else
                                entry->eax = entry->ebx = entry->ecx = entry->edx = 0;
                        break;

                case 0x1d:
                        if (entry->index == 0)
                                tile0 = entry;
                        else if (entry->index == 1)
                                tile1 = entry;
                        else
                                entry->eax = entry->ebx = entry->ecx = entry->edx = 0;
                        break;

                case 0x24:
                        entry->eax = entry->ebx = entry->ecx = entry->edx = 0;
                        break;

                case 0x80000001:
                        if ((entry->edx & (CPUID_BIT(11)|CPUID_BIT(20)|CPUID_BIT(29))) !=
                            (CPUID_BIT(11)|CPUID_BIT(20)|CPUID_BIT(29)))
                                return -EOPNOTSUPP;

                        entry->ecx &= ~CPUID_80000001_ECX_UNSUPPORTED_STATE;
                        have_extended_baseline = true;
                        break;

                case 0x80000008:
                        leaf80000008 = entry;
                        supported_leaf80000008_ebx = entry->ebx;
                        entry->ebx &= ~CPUID_80000008_EBX_UNSUPPORTED_SPECULATION;
                        break;
                }

        if (!have_basic_baseline || !have_extended_baseline)
                return -EOPNOTSUPP;

        if (leaf7) {
                if (FLAGS_SET(h->machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_IBRS) &&
                    h->machine->pred_cmd_ibpb_supported)
                        leaf7->edx |= supported_leaf7_edx & CPUID_BIT(26);
                if (FLAGS_SET(h->machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_STIBP))
                        leaf7->edx |= supported_leaf7_edx & CPUID_BIT(27);
                if (FLAGS_SET(h->machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_SSBD))
                        leaf7->edx |= supported_leaf7_edx & CPUID_BIT(31);
                if (h->machine->flush_cmd_l1d_supported)
                        leaf7->edx |= supported_leaf7_edx & CPUID_BIT(28);
        }
        if (leaf80000008) {
                if (h->machine->pred_cmd_ibpb_supported)
                        leaf80000008->ebx |= supported_leaf80000008_ebx & CPUID_BIT(12);
                if (FLAGS_SET(h->machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_IBRS))
                        leaf80000008->ebx |= supported_leaf80000008_ebx & CPUID_BIT(14);
                if (FLAGS_SET(h->machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_STIBP))
                        leaf80000008->ebx |= supported_leaf80000008_ebx & CPUID_BIT(15);
                if (FLAGS_SET(h->machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_SSBD))
                        leaf80000008->ebx |= supported_leaf80000008_ebx & CPUID_BIT(24);
                if (FLAGS_SET(h->machine->virt_spec_ctrl_supported_mask, X86_SPEC_CTRL_SSBD))
                        leaf80000008->ebx |= supported_leaf80000008_ebx & CPUID_BIT(25);
        }

        if (leaf7 && xstate0 && xstate5 && xstate6 && xstate7 &&
                        FLAGS_SET(supported_leaf7_ebx, CPUID_BIT(16)) &&
                        (supported_xfeatures & X86_XFEATURE_MASK_AVX512) == X86_XFEATURE_MASK_AVX512 &&
            xstate5->eax == X86_OPMASK_SIZE && xstate5->ebx == X86_OPMASK_OFFSET &&
            xstate6->eax == X86_ZMM_HI256_SIZE && xstate6->ebx == X86_ZMM_HI256_OFFSET &&
            xstate7->eax == X86_HI16_ZMM_SIZE && xstate7->ebx == X86_HI16_ZMM_OFFSET) {
                avx512 = true;
                xstate0->eax = X86_XFEATURE_MASK_AVX512;
                xstate0->ecx = X86_AVX512_XSAVE_SIZE;
                xstate5->ecx = xstate5->edx = 0;
                xstate6->ecx = xstate6->edx = 0;
                xstate7->ecx = xstate7->edx = 0;

                /* Restore the complete, dependency-safe AVX-512 feature group. */
                const uint32_t avx512_ebx = CPUID_BIT(16)|CPUID_BIT(17)|CPUID_BIT(21)|
                        CPUID_BIT(26)|CPUID_BIT(27)|CPUID_BIT(28)|CPUID_BIT(30)|CPUID_BIT(31);
                const uint32_t avx512_ecx = CPUID_BIT(1)|CPUID_BIT(6)|CPUID_BIT(11)|
                        CPUID_BIT(12)|CPUID_BIT(14);
                const uint32_t avx512_edx = CPUID_BIT(2)|CPUID_BIT(3)|CPUID_BIT(8)|CPUID_BIT(23);

                leaf7->ebx |= supported_leaf7_ebx & avx512_ebx;
                leaf7->ecx |= supported_leaf7_ecx & avx512_ecx;
                leaf7->edx |= supported_leaf7_edx & avx512_edx;
        } else {
                if (xstate5)
                        xstate5->eax = xstate5->ebx = xstate5->ecx = xstate5->edx = 0;
                if (xstate6)
                        xstate6->eax = xstate6->ebx = xstate6->ecx = xstate6->edx = 0;
                if (xstate7)
                        xstate7->eax = xstate7->ebx = xstate7->ecx = xstate7->edx = 0;
        }

        uint64_t xfeatures = avx512 ? X86_XFEATURE_MASK_AVX512 : X86_XFEATURE_MASK_AVX;
        uint64_t xfeatures_default = xfeatures;
        size_t xsave_size = avx512 ? X86_AVX512_XSAVE_SIZE : X86_AVX_XSAVE_SIZE;
        size_t palette_tile_bytes = 0, palette_row_bytes = 0,
                xsave_default_size = xsave_size, xtilecfg_end = 0, xtiledata_end = 0;
        uint32_t bytes_per_row = tile1 ? tile1->ebx & UINT32_C(0xffff) : 0;
        uint32_t bytes_per_tile = tile1 ? tile1->eax >> 16 : 0;
        uint32_t max_rows = tile1 ? tile1->ecx & UINT32_C(0xffff) : 0;
        uint32_t n_tiles = tile1 ? tile1->ebx >> 16 : 0;
        uint32_t total_tile_bytes = tile1 ? tile1->eax & UINT32_C(0xffff) : 0;
        bool palette_valid = tile0 && tile1 && tile0->eax >= 1 &&
                tile0->ebx == 0 && tile0->ecx == 0 && tile0->edx == 0 &&
                tile1->edx == 0 && (tile1->ecx >> 16) == 0 &&
                bytes_per_row >= 64 && bytes_per_tile >= 1024 && max_rows >= 16 && n_tiles >= 8 &&
                MUL_SAFE(&palette_tile_bytes, (size_t) bytes_per_tile, (size_t) n_tiles) &&
                MUL_SAFE(&palette_row_bytes, (size_t) bytes_per_row, (size_t) max_rows) &&
                palette_row_bytes <= bytes_per_tile && palette_tile_bytes == total_tile_bytes;

        size_t cet_user_end = 0, cet_user_offset = 0, cet_user_size = 0;
        shstk_available = leaf7 && xstate1 && xstate11 && FLAGS_SET(supported_leaf7_ecx, CPUID_BIT(7)) &&
                FLAGS_SET(xstate1->eax, CPUID_BIT(3)) &&
                FLAGS_SET(supported_xss, X86_XFEATURE_MASK_CET_USER) &&
                xstate11->eax > 0 && FLAGS_SET(xstate11->ecx, CPUID_BIT(0)) &&
                ADD_SAFE(&cet_user_end, (size_t) xstate11->ebx, (size_t) xstate11->eax) &&
                cet_user_end <= h->machine->kvm_xsave2_size && cet_user_end <= sizeof(X86KvmXsave);
        if (shstk_available) {
                cet_user_offset = xstate11->ebx;
                cet_user_size = xstate11->eax;
        }
        if (xstate11)
                xstate11->eax = xstate11->ebx = xstate11->ecx = xstate11->edx = 0;

        if (h->machine->amx_guest_permission && h->machine->kvm_xsave2_size > 0 &&
            leaf7 && xstate0 && xstate1 && xstate17 && xstate18 && palette_valid &&
            FLAGS_SET(supported_leaf7_edx, CPUID_BIT(24)) &&
            (supported_xfeatures & X86_XFEATURE_MASK_XTILE) == X86_XFEATURE_MASK_XTILE &&
            FLAGS_SET(xstate1->eax, CPUID_BIT(4)) &&
            xstate17->eax > 0 && !FLAGS_SET(xstate17->ecx, CPUID_BIT(0)) &&
            xstate18->eax > 0 && !FLAGS_SET(xstate18->ecx, CPUID_BIT(0)) &&
            FLAGS_SET(xstate18->ecx, CPUID_BIT(2)) &&
            xstate17->eax == 64 && xstate18->eax == total_tile_bytes &&
            ADD_SAFE(&xtilecfg_end, (size_t) xstate17->ebx, (size_t) xstate17->eax) &&
            ADD_SAFE(&xtiledata_end, (size_t) xstate18->ebx, (size_t) xstate18->eax) &&
            xstate17->ebx >= xsave_size && xtilecfg_end <= xstate18->ebx &&
            xtiledata_end <= h->machine->kvm_xsave2_size &&
            xtiledata_end <= sizeof(X86KvmXsave)) {
                amx = true;
                xfeatures |= X86_XFEATURE_MASK_XTILE;
                xfeatures_default |= X86_XFEATURE_MASK_XTILE_CFG;
                xsave_size = xtiledata_end;
                xsave_default_size = MAX(xsave_default_size, xtilecfg_end);

                xstate0->eax = xfeatures;
                xstate0->ebx = xstate0->ecx = xsave_size;
                xstate0->edx = 0;
                xstate1->eax = CPUID_BIT(4);
                xstate1->ebx = xstate1->ecx = xstate1->edx = 0;
                xstate17->ecx &= CPUID_BIT(1);
                xstate17->edx = 0;
                xstate18->ecx &= CPUID_BIT(1)|CPUID_BIT(2);
                xstate18->edx = 0;
                tile0->eax = 1;
                tile0->ebx = tile0->ecx = tile0->edx = 0;
                tile1->ecx &= UINT32_C(0xffff);
                tile1->edx = 0;
                leaf7->edx |= supported_leaf7_edx & (CPUID_BIT(22)|CPUID_BIT(24)|CPUID_BIT(25));
        } else {
                if (xstate1)
                        xstate1->eax = xstate1->ebx = xstate1->ecx = xstate1->edx = 0;
                if (xstate17)
                        xstate17->eax = xstate17->ebx = xstate17->ecx = xstate17->edx = 0;
                if (xstate18)
                        xstate18->eax = xstate18->ebx = xstate18->ecx = xstate18->edx = 0;
                FOREACH_ARRAY(entry, cpuid->entries, cpuid->nent)
                        if (IN_SET(entry->function, 0x1d, 0x1e))
                                entry->eax = entry->ebx = entry->ecx = entry->edx = 0;
        }

        if (!h->machine->xstate_profile_initialized) {
                h->machine->fsgsbase = fsgsbase;
                h->machine->hwcap2 = fsgsbase ? X86_HWCAP2_FSGSBASE : 0;
                h->machine->xfeatures = xfeatures;
                h->machine->xfeatures_default = xfeatures_default;
                h->machine->xfeatures_permitted = xfeatures_default;
                h->machine->xsave_size = xsave_size;
                h->machine->xsave_default_size = xsave_default_size;
                h->machine->xsave_permitted_size = xsave_default_size;
                h->machine->xfeatures_allocated = xfeatures_default;
                h->machine->xsave_frame_size = xsave_default_size;
                h->machine->xfd = amx ? X86_XFEATURE_MASK_XTILE_DATA : 0;
                h->machine->xfd_err = 0;
                h->machine->xtilecfg_offset = amx ? xstate17->ebx : 0;
                h->machine->xtilecfg_size = amx ? xstate17->eax : 0;
                h->machine->xtiledata_offset = amx ? xstate18->ebx : 0;
                h->machine->xtiledata_size = amx ? xstate18->eax : 0;
                h->machine->amx_supported = amx;
                h->machine->shstk_available = shstk_available;
                h->machine->cet_user_offset = cet_user_offset;
                h->machine->cet_user_size = cet_user_size;
                h->machine->xstate_profile_initialized = true;
        } else if (h->machine->fsgsbase != fsgsbase ||
                   h->machine->xfeatures != xfeatures ||
                   h->machine->xfeatures_default != xfeatures_default ||
                   h->machine->xsave_size != xsave_size ||
                   h->machine->xsave_default_size != xsave_default_size ||
                   h->machine->amx_supported != amx ||
                   h->machine->xtilecfg_offset != (amx ? xstate17->ebx : 0) ||
                   h->machine->xtilecfg_size != (amx ? xstate17->eax : 0) ||
                   h->machine->xtiledata_offset != (amx ? xstate18->ebx : 0) ||
                                                 h->machine->xtiledata_size != (amx ? xstate18->eax : 0) ||
                                                 h->machine->shstk_available != shstk_available ||
                                                 h->machine->cet_user_offset != cet_user_offset ||
                                                 h->machine->cet_user_size != cet_user_size)
                return -EPROTO;

        if (ioctl(vcpu_fd, KVM_SET_CPUID2, cpuid) < 0)
                return -errno;

        return 0;
}

static int set_supported_cpuid(ExecHypervisor *h) {
        assert(h);

        return set_supported_cpuid_fd(h, h->vcpu_fd);
}

static struct kvm_segment make_code_segment(uint16_t selector, uint8_t dpl) {
        return (struct kvm_segment) {
                .base = 0,
                .limit = UINT32_MAX,
                .selector = selector,
                .type = 11,
                .present = 1,
                .dpl = dpl,
                .s = 1,
                .l = 1,
                .g = 1,
        };
}

static struct kvm_segment make_data_segment(uint16_t selector, uint8_t dpl) {
        return (struct kvm_segment) {
                .base = 0,
                .limit = UINT32_MAX,
                .selector = selector,
                .type = 3,
                .present = 1,
                .dpl = dpl,
                .db = 1,
                .s = 1,
                .g = 1,
        };
}

static uint64_t initial_instruction_pointer(const ExecHypervisor *h) {
        assert(h);
        assert(h->image);

        if (h->interpreter_image)
                return h->interpreter_load_bias + h->interpreter_image->entry;

        return h->image_load_bias + h->image->entry;
}

static int set_vcpu_syscall_msrs(ExecHypervisor *h, int vcpu_fd) {
        struct {
                uint32_t nmsrs;
                uint32_t pad;
                struct kvm_msr_entry entries[3];
        } msrs = {
                .nmsrs = 3,
                .entries = {
                        { .index = X86_MSR_STAR, .data = (UINT64_C(0x08) << 32) | (UINT64_C(0x10) << 48) },
                        { .index = X86_MSR_LSTAR, .data = h->supervisor_code_gpa },
                        { .index = X86_MSR_FMASK, .data = UINT64_C(1) << 9 },
                },
        };
        int n;

        assert(h);
        assert(vcpu_fd >= 0);

        n = ioctl(vcpu_fd, KVM_SET_MSRS, &msrs);
        if (n < 0)
                return -errno;
        if (n != (int) msrs.nmsrs)
                return -EIO;

        return 0;
}

static int get_vcpu_msr(int vcpu_fd, uint32_t index, uint64_t *ret) {
        struct {
                uint32_t nmsrs;
                uint32_t pad;
                struct kvm_msr_entry entry;
        } msrs = {
                .nmsrs = 1,
                .entry.index = index,
        };
        int n;

        assert(vcpu_fd >= 0);
        assert(ret);

        n = ioctl(vcpu_fd, KVM_GET_MSRS, &msrs);
        if (n < 0)
                return -errno;
        if (n == 0)
                return 0;
        if (n != 1)
                return -EIO;

        *ret = msrs.entry.data;
        return 1;
}

static int set_vcpu_msr(int vcpu_fd, uint32_t index, uint64_t value) {
        struct {
                uint32_t nmsrs;
                uint32_t pad;
                struct kvm_msr_entry entry;
        } msrs = {
                .nmsrs = 1,
                .entry = {
                        .index = index,
                        .data = value,
                },
        };
        int n;

        assert(vcpu_fd >= 0);

        n = ioctl(vcpu_fd, KVM_SET_MSRS, &msrs);
        if (n < 0)
                return -errno;
        if (n == 0)
                return 0;
        if (n != 1)
                return -EIO;

        return 1;
}

static int set_vcpu_xfd_state(ExecHypervisor *h, int vcpu_fd) {
        ExecHypervisor *machine;
        uint64_t value;
        int r;

        assert(h);
        assert(vcpu_fd >= 0);

        machine = exec_hypervisor_machine(h);
        if (!machine->amx_supported)
                return (h->xfd | h->xfd_err) == 0 ? 0 : -EOPNOTSUPP;
        if ((h->xfd | h->xfd_err) & ~X86_XFEATURE_MASK_XTILE_DATA)
                return -EINVAL;

        r = set_vcpu_msr(vcpu_fd, X86_MSR_IA32_XFD_ERR, h->xfd_err);
        if (r <= 0)
                return r < 0 ? r : -EOPNOTSUPP;
        r = get_vcpu_msr(vcpu_fd, X86_MSR_IA32_XFD_ERR, &value);
        if (r <= 0)
                return r < 0 ? r : -EOPNOTSUPP;
        if (value != h->xfd_err)
                return -EPROTO;

        r = set_vcpu_msr(vcpu_fd, X86_MSR_IA32_XFD, h->xfd);
        if (r <= 0)
                return r < 0 ? r : -EOPNOTSUPP;
        r = get_vcpu_msr(vcpu_fd, X86_MSR_IA32_XFD, &value);
        if (r <= 0)
                return r < 0 ? r : -EOPNOTSUPP;
        if (value != h->xfd)
                return -EPROTO;

        return 0;
}

static int get_vcpu_xfd_state(ExecHypervisor *h, int vcpu_fd) {
        ExecHypervisor *machine;
        uint64_t xfd, xfd_err;
        int r;

        assert(h);
        assert(vcpu_fd >= 0);

        machine = exec_hypervisor_machine(h);
        if (!machine->amx_supported)
                return 0;

        r = get_vcpu_msr(vcpu_fd, X86_MSR_IA32_XFD, &xfd);
        if (r <= 0)
                return r < 0 ? r : -EOPNOTSUPP;
        r = get_vcpu_msr(vcpu_fd, X86_MSR_IA32_XFD_ERR, &xfd_err);
        if (r <= 0)
                return r < 0 ? r : -EOPNOTSUPP;
        if ((xfd | xfd_err) & ~X86_XFEATURE_MASK_XTILE_DATA)
                return -EPROTO;

        h->xfd = xfd;
        h->xfd_err = xfd_err;
        return 0;
}

static int set_vcpu_speculation_msrs(ExecHypervisor *h, int vcpu_fd) {
        ExecHypervisor *machine;
        uint64_t value;
        int r;

        assert(h);
        assert(vcpu_fd >= 0);

        machine = exec_hypervisor_machine(h);
        if ((h->spec_ctrl & ~machine->spec_ctrl_supported_mask) != 0 ||
            (h->virt_spec_ctrl & ~machine->virt_spec_ctrl_supported_mask) != 0)
                return -EOPNOTSUPP;

        if (machine->spec_ctrl_supported_mask != 0) {
                r = set_vcpu_msr(vcpu_fd, X86_MSR_IA32_SPEC_CTRL, h->spec_ctrl);
                if (r <= 0)
                        return r < 0 ? r : -EPROTO;
                r = get_vcpu_msr(vcpu_fd, X86_MSR_IA32_SPEC_CTRL, &value);
                if (r <= 0)
                        return r < 0 ? r : -EPROTO;
                if (value != h->spec_ctrl)
                        return -EPROTO;
        }

        if (machine->virt_spec_ctrl_supported_mask != 0) {
                r = set_vcpu_msr(vcpu_fd, X86_MSR_AMD64_VIRT_SPEC_CTRL, h->virt_spec_ctrl);
                if (r <= 0)
                        return r < 0 ? r : -EPROTO;
                r = get_vcpu_msr(vcpu_fd, X86_MSR_AMD64_VIRT_SPEC_CTRL, &value);
                if (r <= 0)
                        return r < 0 ? r : -EPROTO;
                if (value != h->virt_spec_ctrl)
                        return -EPROTO;
        }

        return 0;
}

static bool spec_store_bypass_status_valid(uint64_t status) {
        return IN_SET(status,
                      PR_SPEC_NOT_AFFECTED,
                      PR_SPEC_ENABLE,
                      PR_SPEC_DISABLE,
                      PR_SPEC_PRCTL | PR_SPEC_ENABLE,
                      PR_SPEC_PRCTL | PR_SPEC_DISABLE,
                      PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE,
                      PR_SPEC_PRCTL | PR_SPEC_DISABLE_NOEXEC);
}

static bool spec_store_bypass_disabled(uint64_t status) {
        return (status & (PR_SPEC_DISABLE | PR_SPEC_FORCE_DISABLE | PR_SPEC_DISABLE_NOEXEC)) != 0;
}

static bool spec_indirect_branch_status_valid(uint64_t status) {
        return IN_SET(status,
                      PR_SPEC_NOT_AFFECTED,
                      PR_SPEC_ENABLE,
                      PR_SPEC_DISABLE,
                      PR_SPEC_PRCTL | PR_SPEC_ENABLE,
                      PR_SPEC_PRCTL | PR_SPEC_DISABLE,
                      PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE);
}

static bool spec_indirect_branch_disabled(uint64_t status) {
        return (status & (PR_SPEC_DISABLE | PR_SPEC_FORCE_DISABLE)) != 0;
}

static bool spec_l1d_flush_status_valid(uint64_t status) {
        return IN_SET(status,
                      PR_SPEC_FORCE_DISABLE,
                      PR_SPEC_PRCTL | PR_SPEC_ENABLE,
                      PR_SPEC_PRCTL | PR_SPEC_DISABLE);
}

typedef enum GuestSeccompSpeculationPolicy {
        GUEST_SECCOMP_SPECULATION_NONE            = 0,
        GUEST_SECCOMP_SPECULATION_STORE_BYPASS    = 1 << 0,
        GUEST_SECCOMP_SPECULATION_INDIRECT_BRANCH = 1 << 1,
        _GUEST_SECCOMP_SPECULATION_PROBE_FAILED   = 255,
} GuestSeccompSpeculationPolicy;

static int probe_guest_seccomp_speculation_policy(ExecHypervisor *h) {
        static const struct sock_filter instructions[] = {
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        const struct sock_fprog program = {
                .len = ELEMENTSOF(instructions),
                .filter = (struct sock_filter*) instructions,
        };
        ExecHypervisor *machine;
        pid_t child, waited;
        int status;

        assert(h);

        machine = exec_hypervisor_machine(h);
        child = fork();
        if (child < 0)
                return -errno;
        if (child == 0) {
                long indirect_branch, store_bypass;
                unsigned policy = GUEST_SECCOMP_SPECULATION_NONE;

                if (syscall(__NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
                    syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) < 0)
                        _exit(_GUEST_SECCOMP_SPECULATION_PROBE_FAILED);

                store_bypass = syscall(
                                __NR_prctl,
                                PR_GET_SPECULATION_CTRL,
                                PR_SPEC_STORE_BYPASS,
                                0,
                                0,
                                0);
                indirect_branch = syscall(
                                __NR_prctl,
                                PR_GET_SPECULATION_CTRL,
                                PR_SPEC_INDIRECT_BRANCH,
                                0,
                                0,
                                0);
                if (!spec_store_bypass_status_valid(store_bypass) ||
                    !spec_indirect_branch_status_valid(indirect_branch))
                        _exit(_GUEST_SECCOMP_SPECULATION_PROBE_FAILED);

                if ((uint64_t) store_bypass != h->spec_store_bypass) {
                        if (store_bypass != (PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE))
                                _exit(_GUEST_SECCOMP_SPECULATION_PROBE_FAILED);
                        policy |= GUEST_SECCOMP_SPECULATION_STORE_BYPASS;
                }
                if ((uint64_t) indirect_branch != h->spec_indirect_branch) {
                        if (indirect_branch != (PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE))
                                _exit(_GUEST_SECCOMP_SPECULATION_PROBE_FAILED);
                        policy |= GUEST_SECCOMP_SPECULATION_INDIRECT_BRANCH;
                }
                _exit(policy);
        }

        do
                waited = waitpid(child, &status, 0);
        while (waited < 0 && errno == EINTR);
        if (waited < 0)
                return -errno;
        if (waited != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) == _GUEST_SECCOMP_SPECULATION_PROBE_FAILED)
                return -EPROTO;

        machine->seccomp_forces_store_bypass =
                FLAGS_SET(WEXITSTATUS(status), GUEST_SECCOMP_SPECULATION_STORE_BYPASS);
        machine->seccomp_forces_indirect_branch =
                FLAGS_SET(WEXITSTATUS(status), GUEST_SECCOMP_SPECULATION_INDIRECT_BRANCH);
        if (machine->seccomp_forces_store_bypass &&
            !FLAGS_SET(machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_SSBD) &&
            !FLAGS_SET(machine->virt_spec_ctrl_supported_mask, X86_SPEC_CTRL_SSBD))
                return -EOPNOTSUPP;
        if (machine->seccomp_forces_indirect_branch &&
            !FLAGS_SET(machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_STIBP) &&
            !machine->pred_cmd_ibpb_supported)
                return -EOPNOTSUPP;

        return 0;
}

static int apply_guest_l1d_flush_state(ExecHypervisor *h) {
        unsigned long mode;
        long status;

        assert(h);

        if (!FLAGS_SET(h->spec_l1d_flush, PR_SPEC_PRCTL))
                return 0;

        mode = FLAGS_SET(h->spec_l1d_flush, PR_SPEC_ENABLE) ? PR_SPEC_ENABLE : PR_SPEC_DISABLE;
        if (syscall(__NR_prctl, PR_SET_SPECULATION_CTRL, PR_SPEC_L1D_FLUSH, mode, 0, 0) < 0)
                return -errno;

        status = syscall(__NR_prctl, PR_GET_SPECULATION_CTRL, PR_SPEC_L1D_FLUSH, 0, 0, 0);
        if (status < 0)
                return -errno;
        if (!spec_l1d_flush_status_valid(status) || (uint64_t) status != h->spec_l1d_flush)
                return -EPROTO;

        return 0;
}

static int issue_guest_indirect_branch_barrier(ExecHypervisor *h) {
        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (!spec_indirect_branch_disabled(h->spec_indirect_branch) ||
            !machine->pred_cmd_ibpb_supported)
                return 0;

        r = set_vcpu_msr(h->vcpu_fd, X86_MSR_IA32_PRED_CMD, X86_PRED_CMD_IBPB);
        if (r < 0)
                return r;
        return r > 0 ? 0 : -EPROTO;
}

static int apply_guest_indirect_branch_state(ExecHypervisor *h, bool issue_barrier) {
        ExecHypervisor *machine;
        uint64_t old_spec_ctrl;
        bool disabled;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        disabled = spec_indirect_branch_disabled(h->spec_indirect_branch);
        if ((FLAGS_SET(h->spec_indirect_branch, PR_SPEC_PRCTL) || disabled) &&
            !FLAGS_SET(machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_STIBP) &&
            !machine->pred_cmd_ibpb_supported)
                return -EOPNOTSUPP;

        old_spec_ctrl = h->spec_ctrl;
        h->spec_ctrl &= ~X86_SPEC_CTRL_STIBP;
        if (disabled && FLAGS_SET(machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_STIBP))
                h->spec_ctrl |= X86_SPEC_CTRL_STIBP;

        r = set_vcpu_speculation_msrs(h, h->vcpu_fd);
        if (r >= 0 && issue_barrier)
                r = issue_guest_indirect_branch_barrier(h);
        if (r < 0) {
                h->spec_ctrl = old_spec_ctrl;
                if (set_vcpu_speculation_msrs(h, h->vcpu_fd) < 0)
                        _exit(EXIT_FAILURE);
        }
        return r;
}

static int apply_guest_store_bypass_state(ExecHypervisor *h) {
        ExecHypervisor *machine;
        uint64_t old_spec_ctrl, old_virt_spec_ctrl;
        bool disabled;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        disabled = spec_store_bypass_disabled(h->spec_store_bypass);
        old_spec_ctrl = h->spec_ctrl;
        old_virt_spec_ctrl = h->virt_spec_ctrl;

        h->spec_ctrl &= ~X86_SPEC_CTRL_SSBD;
        h->virt_spec_ctrl &= ~X86_SPEC_CTRL_SSBD;
        if (disabled) {
                if (FLAGS_SET(machine->spec_ctrl_supported_mask, X86_SPEC_CTRL_SSBD))
                        h->spec_ctrl |= X86_SPEC_CTRL_SSBD;
                else if (FLAGS_SET(machine->virt_spec_ctrl_supported_mask, X86_SPEC_CTRL_SSBD))
                        h->virt_spec_ctrl |= X86_SPEC_CTRL_SSBD;
                else {
                        h->spec_ctrl = old_spec_ctrl;
                        h->virt_spec_ctrl = old_virt_spec_ctrl;
                        return -EOPNOTSUPP;
                }
        }

        r = set_vcpu_speculation_msrs(h, h->vcpu_fd);
        if (r < 0) {
                h->spec_ctrl = old_spec_ctrl;
                h->virt_spec_ctrl = old_virt_spec_ctrl;
                if (set_vcpu_speculation_msrs(h, h->vcpu_fd) < 0)
                        _exit(EXIT_FAILURE);
        }
        return r;
}

static int force_guest_seccomp_speculation(ExecHypervisor *h, bool issue_barrier) {
        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (machine->seccomp_forces_store_bypass) {
                h->spec_store_bypass = PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
                r = apply_guest_store_bypass_state(h);
                if (r < 0)
                        return r;
        }
        if (machine->seccomp_forces_indirect_branch) {
                h->spec_indirect_branch = PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
                r = apply_guest_indirect_branch_state(h, issue_barrier);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int commit_guest_seccomp_filter(
                ExecHypervisor *h,
                bool synchronize,
                bool allow_speculation) {

        ExecHypervisor *machine;
        int r;

        assert(h);

        machine = exec_hypervisor_machine(h);
        if (!synchronize) {
                h->seccomp_local_filter = true;
                return allow_speculation ? 0 : force_guest_seccomp_speculation(h, /* issue_barrier= */ true);
        }

        machine->seccomp_local_filter = true;
        if (!allow_speculation) {
                r = force_guest_seccomp_speculation(machine, /* issue_barrier= */ machine == h);
                if (r < 0)
                        return r;
        }
        FOREACH_ARRAY(thread, machine->active_vcpus, machine->n_active_vcpus) {
                (*thread)->seccomp_local_filter = true;
                if (!allow_speculation) {
                        r = force_guest_seccomp_speculation(*thread, /* issue_barrier= */ *thread == h);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int initialize_guest_speculation_policy(ExecHypervisor *h) {
        long indirect_branch, l1d_flush, store_bypass;
        int r;

        assert(h);

        if (h->speculation_policy_initialized) {
                r = set_vcpu_speculation_msrs(h, h->vcpu_fd);
                if (r < 0)
                        return r;
                return apply_guest_l1d_flush_state(h);
        }

        store_bypass = syscall(__NR_prctl, PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);
        if (store_bypass < 0)
                return -errno;
        if (!spec_store_bypass_status_valid(store_bypass))
                return -EPROTO;
        indirect_branch = syscall(__NR_prctl, PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, 0, 0, 0);
        if (indirect_branch < 0)
                return -errno;
        if (!spec_indirect_branch_status_valid(indirect_branch))
                return -EPROTO;
        l1d_flush = syscall(__NR_prctl, PR_GET_SPECULATION_CTRL, PR_SPEC_L1D_FLUSH, 0, 0, 0);
        if (l1d_flush < 0)
                return -errno;
        if (!spec_l1d_flush_status_valid(l1d_flush))
                return -EPROTO;

        h->spec_store_bypass = store_bypass;
        h->spec_indirect_branch = indirect_branch;
        h->spec_l1d_flush = l1d_flush;
        h->speculation_policy_initialized = true;
        r = probe_guest_seccomp_speculation_policy(h);
        if (r < 0)
                return r;
        r = apply_guest_store_bypass_state(h);
        if (r < 0)
                return r;
        r = apply_guest_indirect_branch_state(h, /* issue_barrier= */ true);
        if (r < 0)
                return r;
        return apply_guest_l1d_flush_state(h);
}

static int initialize_guest_keyring_policy(ExecHypervisor *h) {
        long id;

        assert(h);

        if (h->keyring_policy_initialized)
                return 0;
        id = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0, 0, 0);
        if (id < 0)
                return -errno;
        h->session_keyring_id = id;
        h->keyring_policy_initialized = true;
        return 0;
}

static uint64_t handle_guest_store_bypass(ExecHypervisor *h, const struct kvm_regs *regs) {
        uint64_t old_status, status;
        int r;

        assert(h);
        assert(regs);

        if (regs->rdi == PR_GET_SPECULATION_CTRL)
                return h->spec_store_bypass;
        if (!FLAGS_SET(h->spec_store_bypass, PR_SPEC_PRCTL))
                return (uint64_t) -ENXIO;

        old_status = h->spec_store_bypass;
        if (FLAGS_SET(old_status, PR_SPEC_FORCE_DISABLE)) {
                if (IN_SET(regs->rdx, PR_SPEC_ENABLE, PR_SPEC_DISABLE_NOEXEC))
                        return (uint64_t) -EPERM;
                status = PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
        } else
                switch (regs->rdx) {
                case PR_SPEC_ENABLE:
                        status = PR_SPEC_PRCTL | PR_SPEC_ENABLE;
                        break;
                case PR_SPEC_DISABLE:
                        status = PR_SPEC_PRCTL | PR_SPEC_DISABLE;
                        break;
                case PR_SPEC_FORCE_DISABLE:
                        status = PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
                        break;
                case PR_SPEC_DISABLE_NOEXEC:
                        status = PR_SPEC_PRCTL | PR_SPEC_DISABLE_NOEXEC;
                        break;
                default:
                        assert_not_reached();
                }

        h->spec_store_bypass = status;
        r = apply_guest_store_bypass_state(h);
        if (r < 0)
                h->spec_store_bypass = old_status;
        return r < 0 ? (uint64_t) r : 0;
}

static uint64_t handle_guest_indirect_branch(ExecHypervisor *h, const struct kvm_regs *regs) {
        uint64_t old_status, status;
        int r;

        assert(h);
        assert(regs);

        if (regs->rdi == PR_GET_SPECULATION_CTRL)
                return h->spec_indirect_branch;
        if (!FLAGS_SET(h->spec_indirect_branch, PR_SPEC_PRCTL)) {
                if (regs->rdx == PR_SPEC_ENABLE)
                        return h->spec_indirect_branch == PR_SPEC_DISABLE ? (uint64_t) -EPERM : 0;
                return h->spec_indirect_branch == PR_SPEC_DISABLE ? 0 : (uint64_t) -EPERM;
        }

        old_status = h->spec_indirect_branch;
        if (FLAGS_SET(old_status, PR_SPEC_FORCE_DISABLE)) {
                if (regs->rdx == PR_SPEC_ENABLE)
                        return (uint64_t) -EPERM;
                status = PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
        } else
                switch (regs->rdx) {
                case PR_SPEC_ENABLE:
                        status = PR_SPEC_PRCTL | PR_SPEC_ENABLE;
                        break;
                case PR_SPEC_DISABLE:
                        status = PR_SPEC_PRCTL | PR_SPEC_DISABLE;
                        break;
                case PR_SPEC_FORCE_DISABLE:
                        status = PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
                        break;
                default:
                        assert_not_reached();
                }

        h->spec_indirect_branch = status;
        r = apply_guest_indirect_branch_state(h, /* issue_barrier= */ true);
        if (r < 0)
                h->spec_indirect_branch = old_status;
        return r < 0 ? (uint64_t) r : 0;
}

static uint64_t handle_guest_l1d_flush(ExecHypervisor *h, const struct kvm_regs *regs) {
        long status;

        assert(h);
        assert(regs);

        if (regs->rdi == PR_SET_SPECULATION_CTRL &&
            syscall(__NR_prctl, PR_SET_SPECULATION_CTRL, PR_SPEC_L1D_FLUSH, regs->rdx, 0, 0) < 0)
                return (uint64_t) -errno;

        status = syscall(__NR_prctl, PR_GET_SPECULATION_CTRL, PR_SPEC_L1D_FLUSH, 0, 0, 0);
        if (status < 0)
                return (uint64_t) -errno;
        if (!spec_l1d_flush_status_valid(status))
                return (uint64_t) -EPROTO;

        h->spec_l1d_flush = status;
        return regs->rdi == PR_GET_SPECULATION_CTRL ? (uint64_t) status : 0;
}

static int probe_vcpu_speculation_msrs(ExecHypervisor *h, int vcpu_fd) {
        static const uint64_t bits[] = {
                X86_SPEC_CTRL_IBRS,
                X86_SPEC_CTRL_STIBP,
                X86_SPEC_CTRL_SSBD,
        };
        ExecHypervisor *machine;
        uint64_t mask = 0, value;
        int r;

        assert(h);
        assert(vcpu_fd >= 0);

        machine = exec_hypervisor_machine(h);
        FOREACH_ELEMENT(bit, bits) {
                r = set_vcpu_msr(vcpu_fd, X86_MSR_IA32_SPEC_CTRL, *bit);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;
                r = get_vcpu_msr(vcpu_fd, X86_MSR_IA32_SPEC_CTRL, &value);
                if (r <= 0)
                        return r < 0 ? r : -EPROTO;
                if (value != *bit)
                        return -EPROTO;
                mask |= *bit;
        }
        machine->spec_ctrl_supported_mask = mask;

        r = set_vcpu_msr(vcpu_fd, X86_MSR_IA32_PRED_CMD, X86_PRED_CMD_IBPB);
        if (r < 0)
                return r;
        machine->pred_cmd_ibpb_supported = r > 0;

        r = set_vcpu_msr(vcpu_fd, X86_MSR_IA32_FLUSH_CMD, X86_FLUSH_CMD_L1D);
        if (r < 0)
                return r;
        machine->flush_cmd_l1d_supported = r > 0;

        r = set_vcpu_msr(vcpu_fd, X86_MSR_AMD64_VIRT_SPEC_CTRL, X86_SPEC_CTRL_SSBD);
        if (r < 0)
                return r;
        if (r > 0) {
                r = get_vcpu_msr(vcpu_fd, X86_MSR_AMD64_VIRT_SPEC_CTRL, &value);
                if (r <= 0)
                        return r < 0 ? r : -EPROTO;
                if (value != X86_SPEC_CTRL_SSBD)
                        return -EPROTO;
                machine->virt_spec_ctrl_supported_mask = X86_SPEC_CTRL_SSBD;
        }

        r = set_vcpu_speculation_msrs(h, vcpu_fd);
        if (r < 0)
                return r;

        log_debug("KVM speculation controls passed MSR readback: SPEC_CTRL mask=%#" PRIx64
                  ", VIRT_SPEC_CTRL mask=%#" PRIx64 ", IBPB=%s, L1D_FLUSH=%s.",
                  machine->spec_ctrl_supported_mask,
                  machine->virt_spec_ctrl_supported_mask,
                  machine->pred_cmd_ibpb_supported ? "yes" : "no",
                  machine->flush_cmd_l1d_supported ? "yes" : "no");
        return 0;
}

static X86FxsaveArea* xsave_fxsave(X86KvmXsave *xsave) {
        assert(xsave);

        return (X86FxsaveArea*) xsave->region;
}

static const X86FxsaveArea* xsave_fxsave_const(const X86KvmXsave *xsave) {
        assert(xsave);

        return (const X86FxsaveArea*) xsave->region;
}

static const X86XsaveHeader* xsave_header_const(const X86KvmXsave *xsave) {
        assert(xsave);

        return (const X86XsaveHeader*) ((const uint8_t*) xsave->region + sizeof(X86FxsaveArea));
}

static X86XsaveHeader* xsave_header(X86KvmXsave *xsave) {
        assert(xsave);

        return (X86XsaveHeader*) ((uint8_t*) xsave->region + sizeof(X86FxsaveArea));
}

static void reset_dynamic_xsave(ExecHypervisor *h, X86KvmXsave *xsave) {
        ExecHypervisor *machine;

        assert(h);
        assert(xsave);

        machine = exec_hypervisor_machine(h);
        if (!machine->amx_supported)
                return;

        assert(machine->xtiledata_offset <= sizeof(*xsave));
        assert(machine->xtiledata_size <= sizeof(*xsave) - machine->xtiledata_offset);
        memzero((uint8_t*) xsave->region + machine->xtiledata_offset, machine->xtiledata_size);
        xsave_header(xsave)->xfeatures &= ~X86_XFEATURE_MASK_XTILE_DATA;
}

static int get_vcpu_xsave(ExecHypervisor *h, int vcpu_fd, X86KvmXsave *ret) {
        ExecHypervisor *machine;

        assert(h);
        assert(vcpu_fd >= 0);
        assert(ret);

        machine = exec_hypervisor_machine(h);
        memzero(ret, sizeof(*ret));
        if (ioctl(vcpu_fd, machine->kvm_xsave2_size > 0 ? KVM_GET_XSAVE2 : KVM_GET_XSAVE, ret) < 0)
                return -errno;

        return 0;
}

static int set_vcpu_xsave(int vcpu_fd, const X86KvmXsave *xsave) {
        assert(vcpu_fd >= 0);
        assert(xsave);

        if (ioctl(vcpu_fd, KVM_SET_XSAVE, xsave) < 0)
                return -errno;

        return 0;
}

static int set_vcpu_xcr0(ExecHypervisor *h, int vcpu_fd) {
        struct kvm_xcrs xcrs = {
                .nr_xcrs = 1,
                .xcrs[0] = {
                        .xcr = 0,
                },
        };

        assert(h);
        assert(vcpu_fd >= 0);

        xcrs.xcrs[0].value = h->machine->xfeatures;

        if (ioctl(vcpu_fd, KVM_SET_XCRS, &xcrs) < 0)
                return -errno;

        memzero(&xcrs, sizeof(xcrs));
        if (ioctl(vcpu_fd, KVM_GET_XCRS, &xcrs) < 0)
                return -errno;
        if (xcrs.nr_xcrs > KVM_MAX_XCRS)
                return -EPROTO;
        for (unsigned i = 0; i < xcrs.nr_xcrs; i++)
                if (xcrs.xcrs[i].xcr == 0)
                        return xcrs.xcrs[i].value == h->machine->xfeatures ? 0 : -EPROTO;

        return -EPROTO;
}

static int setup_vcpu_state(ExecHypervisor *h) {
        X86KvmXsave xsave;
        struct kvm_regs regs = {
                .rip = initial_instruction_pointer(h),
                .rflags = 2,
        };
        struct kvm_sregs sregs;
        int r;

        assert(h);
        assert(h->vcpu_fd >= 0);

        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;

        sregs.cr0 = X86_CR0_PE|X86_CR0_MP|X86_CR0_ET|X86_CR0_NE|X86_CR0_WP|X86_CR0_PG;
        sregs.cr3 = h->cr3;
        sregs.cr4 = X86_CR4_PAE|X86_CR4_OSFXSR|X86_CR4_OSXMMEXCPT|X86_CR4_OSXSAVE;
        if (h->machine->fsgsbase)
                sregs.cr4 |= X86_CR4_FSGSBASE;
        if (h->tsc_disabled)
                sregs.cr4 |= X86_CR4_TSD;
        sregs.efer = X86_EFER_SCE|X86_EFER_LME|X86_EFER_LMA|X86_EFER_NXE;
        sregs.cs = make_code_segment(0x23, 3);
        sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = make_data_segment(0x1b, 3);
        sregs.gdt.base = h->gdt_gpa;
        sregs.gdt.limit = 7 * sizeof(uint64_t) - 1;
        sregs.idt.base = h->idt_gpa;
        sregs.idt.limit = EXEC_HYPERVISOR_N_EXCEPTIONS * sizeof(X86IdtGate) - 1;
        sregs.tr = (struct kvm_segment) {
                .base = h->tss_gpa,
                .limit = 0x67,
                .selector = 0x28,
                .type = 11,
                .present = 1,
        };
        sregs.ldt.unusable = 1;

        if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                return -errno;

        r = set_vcpu_xcr0(h, h->vcpu_fd);
        if (r < 0)
                return r;

        r = set_vcpu_syscall_msrs(h, h->vcpu_fd);
        if (r < 0)
                return r;

        r = set_vcpu_speculation_msrs(h, h->vcpu_fd);
        if (r < 0)
                return r;

        r = set_vcpu_xfd_state(h, h->vcpu_fd);
        if (r < 0)
                return r;

        r = get_vcpu_xsave(h, h->vcpu_fd, &xsave);
        if (r < 0)
                return r;

        X86FxsaveArea *fxsave = xsave_fxsave(&xsave);
        fxsave->fcw = 0x37f;
        fxsave->mxcsr = 0x1f80;
        if (fxsave->mxcsr_mask == 0)
                fxsave->mxcsr_mask = UINT32_C(0x0000ffff);
        xsave_header(&xsave)->xfeatures |= h->xfeatures_allocated;

        r = set_vcpu_xsave(h->vcpu_fd, &xsave);
        if (r < 0)
                return r;
        if (ioctl(h->vcpu_fd, KVM_SET_REGS, &regs) < 0)
                return -errno;

        return 0;
}

static int validate_translation(
                ExecHypervisor *h,
                uint64_t address,
                bool writeable) {

        struct kvm_translation translation = {
                .linear_address = address,
        };

        assert(h);
        assert(h->vcpu_fd >= 0);

        if (ioctl(h->vcpu_fd, KVM_TRANSLATE, &translation) < 0)
                return -errno;
        if (!translation.valid ||
            (writeable && !translation.writeable))
                return -EPROTO;

        return 0;
}

static int validate_vcpu_state(ExecHypervisor *h) {
        struct kvm_regs regs;
        struct kvm_sregs sregs;
        uint64_t expected_cr0, expected_efer;

        assert(h);
        assert(h->vcpu_fd >= 0);

        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;
        if (ioctl(h->vcpu_fd, KVM_GET_REGS, &regs) < 0)
                return -errno;

        expected_cr0 = X86_CR0_PE|X86_CR0_MP|X86_CR0_ET|X86_CR0_NE|X86_CR0_WP|X86_CR0_PG;
        expected_efer = X86_EFER_SCE|X86_EFER_LME|X86_EFER_LMA|X86_EFER_NXE;
                uint64_t expected_cr4 = X86_CR4_PAE|X86_CR4_OSFXSR|X86_CR4_OSXMMEXCPT|X86_CR4_OSXSAVE;
                if (h->machine->fsgsbase)
                                expected_cr4 |= X86_CR4_FSGSBASE;

        if ((sregs.cr0 & expected_cr0) != expected_cr0 ||
            sregs.cr3 != h->cr3 ||
                        (sregs.cr4 & expected_cr4) != expected_cr4 ||
            (sregs.efer & expected_efer) != expected_efer ||
            sregs.cs.selector != 0x23 ||
            sregs.ss.selector != 0x1b ||
            sregs.gdt.base != h->gdt_gpa ||
            sregs.idt.base != h->idt_gpa ||
            sregs.tr.base != h->tss_gpa ||
            regs.rip != initial_instruction_pointer(h) ||
            regs.rflags != 2)
                return -EPROTO;

        int r;

        r = validate_translation(h, initial_instruction_pointer(h), /* writeable= */ false);
        if (r < 0)
                return r;
        r = validate_translation(h, h->supervisor_code_gpa, /* writeable= */ false);
        if (r < 0)
                return r;
        r = validate_translation(h, h->idt_gpa, /* writeable= */ false);
        if (r < 0)
                return r;
        r = validate_translation(h, h->tss_gpa, /* writeable= */ true);
        if (r < 0)
                return r;
        r = validate_translation(
                        h,
                        h->ring0_stack_gpa + page_size() - sizeof(uint64_t),
                        /* writeable= */ true);
        if (r < 0)
                return r;

        return 0;
}

static void close_hypervisor_machine(ExecHypervisor *h) {
        assert(h);

        h->preserve_shared_fds = h->files_shared;
        FOREACH_ARRAY(thread, h->idle_vcpus, h->n_idle_vcpus)
                exec_hypervisor_free(*thread);
        h->idle_vcpus = mfree(h->idle_vcpus);
        h->n_idle_vcpus = 0;
        h->active_vcpus = mfree(h->active_vcpus);
        h->n_active_vcpus = 0;
        h->exec_caller = NULL;
        h->exec_replacement = exec_hypervisor_free(h->exec_replacement);
        h->exec_request_state = GUEST_EXEC_REQUEST_IDLE;

        if (h->run)
                (void) munmap(h->run, h->run_size);
        h->run = NULL;
        h->run_size = 0;
        if (h->preserve_shared_fds) {
                h->vcpu_fd = -EBADF;
                h->vm_fd = -EBADF;
        } else {
                h->vcpu_fd = safe_close(h->vcpu_fd);
                h->vm_fd = safe_close(h->vm_fd);
        }

        if (h->supervisor_memory)
                (void) munmap(h->supervisor_memory, h->supervisor_memory_size);
        h->supervisor_memory = NULL;
        h->supervisor_memory_size = 0;
        h->free_supervisor_pages = mfree(h->free_supervisor_pages);
        h->n_registered_mappings = 0;
        if (h->free_memslots)
                memzero(h->free_memslots, h->n_memslots * sizeof(bool));
        h->supervisor_slot = UINT_MAX;
        h->n_free_gpa_extents = 0;
        h->userfault_ranges = mfree(h->userfault_ranges);
        h->n_userfault_ranges = 0;
        h->userfault_contexts = mfree(h->userfault_contexts);
        h->n_userfault_contexts = 0;
        h->next_guest_physical_address = 0;
        h->next_page_table_gpa = 0;
        h->cr3 = 0;
        h->supervisor_code_gpa = 0;
        h->gdt_gpa = 0;
        h->idt_gpa = 0;
        h->tss_gpa = 0;
        h->ring0_stack_gpa = 0;
        h->probe_code_gpa = 0;
        h->next_vcpu_id = 0;
        h->n_guest_threads = 0;
        h->vcpu_id = 0;
        h->runner_tid = 0;
        h->owner_tid = 0;
        h->quiesce_generation = 0;
        h->quiesce_scan_generation = 0;
        h->quiesce_acknowledged = 0;
        h->quiesce_expected = 0;
        h->quiesce_owner_tid = 0;
        h->quiesce_requested_generation = 0;
        h->quiesce_seen_generation = 0;
        h->vcpu_in_guest = false;
        h->preserve_shared_fds = false;
}

static int host_page_is_mapped(uint64_t address) {
        unsigned char residency;

        if (mincore((void*) (uintptr_t) address, page_size(), &residency) >= 0)
                return 1;
        if (errno == ENOMEM)
                return 0;
        return -errno;
}

static int reconcile_dontfork_mappings_after_fork(ExecHypervisor *h) {
        _cleanup_free_ ExecHypervisorMapping *mappings = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *sealed_ranges = NULL;
        _cleanup_free_ ExecHypervisorSealedRange *wipeonfork_ranges = NULL;
        size_t n_mappings = 0, n_sealed_ranges = 0, n_wipeonfork_ranges = 0;
        int r;

        assert(h);

        if (h->n_dontfork_ranges == 0) {
                h->aio_contexts = mfree(h->aio_contexts);
                h->n_aio_contexts = 0;
                return 0;
        }

        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings) {
                size_t run_start = SIZE_MAX;

                for (size_t offset = 0; offset <= mapping->size; offset += page_size()) {
                        bool present = false;

                        if (offset < mapping->size) {
                                r = host_page_is_mapped(mapping->guest_virtual_address + offset);
                                if (r < 0)
                                        return r;
                                present = r > 0;
                        }
                        if (present && run_start == SIZE_MAX)
                                run_start = offset;
                        if (present || run_start == SIZE_MAX)
                                continue;

                        if (!GREEDY_REALLOC0(mappings, n_mappings + 1))
                                return -ENOMEM;
                        mappings[n_mappings] = *mapping;
                        mappings[n_mappings].host_address = (uint8_t*) mapping->host_address + run_start;
                        mappings[n_mappings].guest_virtual_address += run_start;
                        mappings[n_mappings].guest_physical_address += run_start;
                        mappings[n_mappings].size = offset - run_start;
                        n_mappings++;
                        run_start = SIZE_MAX;
                }
        }

        FOREACH_ARRAY(range, h->sealed_ranges, h->n_sealed_ranges) {
                size_t run_start = SIZE_MAX;

                for (size_t offset = 0; offset <= range->length; offset += page_size()) {
                        bool present = false;

                        if (offset < range->length) {
                                r = host_page_is_mapped(range->start + offset);
                                if (r < 0)
                                        return r;
                                present = r > 0;
                        }
                        if (present && run_start == SIZE_MAX)
                                run_start = offset;
                        if (present || run_start == SIZE_MAX)
                                continue;

                        if (!GREEDY_REALLOC0(sealed_ranges, n_sealed_ranges + 1))
                                return -ENOMEM;
                        sealed_ranges[n_sealed_ranges++] = (ExecHypervisorSealedRange) {
                                .start = range->start + run_start,
                                .length = offset - run_start,
                        };
                        run_start = SIZE_MAX;
                }
        }

        FOREACH_ARRAY(range, h->wipeonfork_ranges, h->n_wipeonfork_ranges) {
                size_t run_start = SIZE_MAX;

                for (size_t offset = 0; offset <= range->length; offset += page_size()) {
                        bool present = false;

                        if (offset < range->length) {
                                r = host_page_is_mapped(range->start + offset);
                                if (r < 0)
                                        return r;
                                present = r > 0;
                        }
                        if (present && run_start == SIZE_MAX)
                                run_start = offset;
                        if (present || run_start == SIZE_MAX)
                                continue;

                        if (!GREEDY_REALLOC0(wipeonfork_ranges, n_wipeonfork_ranges + 1))
                                return -ENOMEM;
                        wipeonfork_ranges[n_wipeonfork_ranges++] = (ExecHypervisorSealedRange) {
                                .start = range->start + run_start,
                                .length = offset - run_start,
                        };
                        run_start = SIZE_MAX;
                }
        }

        free(h->mappings);
        h->mappings = TAKE_PTR(mappings);
        h->n_mappings = n_mappings;
        free(h->sealed_ranges);
        h->sealed_ranges = TAKE_PTR(sealed_ranges);
        h->n_sealed_ranges = n_sealed_ranges;
        free(h->wipeonfork_ranges);
        h->wipeonfork_ranges = TAKE_PTR(wipeonfork_ranges);
        h->n_wipeonfork_ranges = n_wipeonfork_ranges;
        h->dontfork_ranges = mfree(h->dontfork_ranges);
        h->n_dontfork_ranges = 0;
        h->aio_contexts = mfree(h->aio_contexts);
        h->n_aio_contexts = 0;
        return 0;
}

static int recreate_hypervisor_machine_after_fork(
                ExecHypervisor *h,
                struct kvm_regs *regs,
                const struct kvm_sregs *old_sregs,
                const X86KvmXsave *xsave) {

        _cleanup_free_ uint64_t *page_flags = NULL;
        struct kvm_sregs sregs;
        size_t n_pages = 0, page_index = 0;
        long run_size;
        int r;

        assert(h);
        assert(regs);
        assert(old_sregs);
        assert(xsave);

        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings) {
                size_t mapping_pages;

                mapping_pages = mapping->size / page_size();
                if (!ADD_SAFE(&n_pages, n_pages, mapping_pages))
                        return -EOVERFLOW;
        }
        page_flags = new(uint64_t, n_pages);
        if (!page_flags)
                return -ENOMEM;

        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings)
                for (size_t offset = 0; offset < mapping->size; offset += page_size()) {
                        uint64_t *entry = guest_page_entry(h, mapping->guest_virtual_address + offset);
                        uint64_t address = mapping->guest_virtual_address + offset;
                        uint64_t flags;

                        if (!entry || *entry == 0)
                                return -EFAULT;
                        flags = *entry & ~X86_PAGE_ADDRESS_MASK;
                        FOREACH_ARRAY(range, h->userfault_ranges, h->n_userfault_ranges)
                                if (address >= range->start && address < range->start + range->length) {
                                        if ((range->mode &
                                             (UFFDIO_REGISTER_MODE_MISSING|UFFDIO_REGISTER_MODE_MINOR)) != 0 &&
                                            !FLAGS_SET(flags, X86_PAGE_SOFTWARE_UFFD_POISON))
                                                flags |= X86_PAGE_PRESENT;
                                        if (!FLAGS_SET(flags, X86_PAGE_SOFTWARE_UFFD_POISON) &&
                                            FLAGS_SET(range->mode, UFFDIO_REGISTER_MODE_WP) &&
                                            FLAGS_SET(mapping->protection, PROT_WRITE))
                                                flags |= X86_PAGE_WRITE;
                                        break;
                                }
                        page_flags[page_index++] = flags;
                }
        assert(page_index == n_pages);

        close_hypervisor_machine(h);

        h->vm_fd = ioctl(h->kvm_fd, KVM_CREATE_VM, 0);
        if (h->vm_fd < 0)
                return -errno;

        r = register_image_mappings(h);
        if (r < 0)
                return r;
        r = setup_page_tables(h);
        if (r < 0)
                return r;

        page_index = 0;
        FOREACH_ARRAY(mapping, h->mappings, h->n_mappings)
                for (size_t offset = 0; offset < mapping->size; offset += page_size()) {
                        uint64_t *entry = guest_page_entry(h, mapping->guest_virtual_address + offset);

                        if (!entry)
                                return -EFAULT;
                        *entry = (mapping->guest_physical_address + offset) | page_flags[page_index++];
                }
        assert(page_index == n_pages);

        h->vcpu_fd = ioctl(h->vm_fd, KVM_CREATE_VCPU, 0);
        if (h->vcpu_fd < 0)
                return -errno;
        r = set_supported_cpuid(h);
        if (r < 0)
                return r;

        run_size = ioctl(h->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
        if (run_size < (long) sizeof(struct kvm_run))
                return run_size < 0 ? -errno : -EPROTO;

        h->run_size = run_size;
        h->run = mmap(NULL, h->run_size, PROT_READ|PROT_WRITE, MAP_SHARED, h->vcpu_fd, 0);
        if (h->run == MAP_FAILED) {
                h->run = NULL;
                return -errno;
        }

        r = setup_vcpu_state(h);
        if (r < 0)
                return r;
        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;

        sregs.cs = old_sregs->cs;
        sregs.ds = old_sregs->ds;
        sregs.es = old_sregs->es;
        sregs.fs = old_sregs->fs;
        sregs.gs = old_sregs->gs;
        sregs.ss = old_sregs->ss;
        sregs.cr2 = old_sregs->cr2;
        if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                return -errno;
        r = set_vcpu_xsave(h->vcpu_fd, xsave);
        if (r < 0)
                return r;

        regs->rax = 0;
        regs->rip = h->supervisor_code_gpa + 2;
        if (ioctl(h->vcpu_fd, KVM_SET_REGS, regs) < 0)
                return -errno;

        return validate_translation(h, regs->rcx, /* writeable= */ false);
}

#endif

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

static uint64_t raw_host_syscall(const struct kvm_regs *regs) {
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

static int prepare_dontfork_ranges(
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

static int prepare_wipeonfork_ranges(
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

static int prepare_mremap_fork_advice_ranges(
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

static uint64_t handle_guest_madvise(ExecHypervisor *h, const struct kvm_regs *regs) {
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

static int validate_guest_range(ExecHypervisor *h, uint64_t address, size_t size, bool writeable);
static int userfault_range_is_registered(
                const ExecHypervisorUserfaultRange *range,
                uint64_t start,
                uint64_t length);
static int reconcile_unregistered_userfault_ranges(
                ExecHypervisor *h,
                uint64_t fault_page,
                dev_t device,
                ino_t inode);

static int copy_to_guest(ExecHypervisor *h, uint64_t guest_address, const void *source, size_t size) {
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

static int copy_from_guest(ExecHypervisor *h, void *destination, uint64_t guest_address, size_t size) {
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

static int copy_guest_cstring(ExecHypervisor *h, uint64_t guest_address, size_t *remaining, char **ret) {
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

static int copy_guest_strv(ExecHypervisor *h, uint64_t guest_address, size_t *remaining, char ***ret) {
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

static void coalesce_userfault_ranges(ExecHypervisor *h) {
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

static void commit_userfault_range_split(
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

static uint64_t handle_guest_ioctl(ExecHypervisor *h, const struct kvm_regs *regs) {
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

static uint64_t handle_guest_process_madvise(ExecHypervisor *h, const struct kvm_regs *regs) {
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

static bool guest_ioctl_requires_quiescence(uint64_t request) {
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

typedef enum GuestUserfaultSigbusDisposition {
        GUEST_USERFAULT_SIGBUS_NONE,
        GUEST_USERFAULT_SIGBUS_DELIVER,
        GUEST_USERFAULT_SIGBUS_HANDLED,
} GuestUserfaultSigbusDisposition;

static int guest_userfault_delivers_sigbus(ExecHypervisor *h, uint64_t address, uint64_t error_code) {
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

static int resolve_guest_userfault(ExecHypervisor *h, uint64_t address, uint64_t error_code) {
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

static void clear_guest_tid_address(ExecHypervisor *h, uint64_t clear_tid_address) {
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

static void update_guest_futex_hash_after_thread_clone(ExecHypervisor *machine, unsigned n_threads) {
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

static int abort_guest_rseq_for_signal(ExecHypervisor *h, struct kvm_regs *regs) {
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

static int host_signal_action(
                int signo,
                const GuestSignalAction *action,
                GuestSignalAction *old_action) {

        assert(signo > 0 && signo <= (int) EXEC_HYPERVISOR_N_SIGNALS);

        if (syscall(__NR_rt_sigaction, signo, action, old_action, sizeof(uint64_t)) < 0)
                return -errno;

        return 0;
}

static int get_host_signal_mask(sigset_t *ret) {
        uint64_t mask;

        assert(ret);

        if (syscall(__NR_rt_sigprocmask, SIG_SETMASK, NULL, &mask, sizeof(mask)) < 0)
                return -errno;

        assert_se(sigemptyset(ret) >= 0);
        memcpy(ret, &mask, sizeof(mask));
        return 0;
}

static int set_host_signal_mask(const sigset_t *mask) {
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

static uint64_t handle_guest_masked_wait(ExecHypervisor *h, const struct kvm_regs *regs) {
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

static int initialize_guest_signal_action(ExecHypervisor *h, int signo) {
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

static int set_host_signal_action(ExecHypervisor *h, int signo, const GuestSignalAction *action) {
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

static int reapply_guest_reserved_signal_actions(ExecHypervisor *h) {
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

static uint64_t handle_guest_rt_sigaction(
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

static uint64_t handle_guest_sigaltstack(
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

static uint64_t handle_guest_arch_prctl(ExecHypervisor *h, uint64_t operation, uint64_t address) {
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

static int validate_guest_range(ExecHypervisor *h, uint64_t address, size_t size, bool writeable) {
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

static int deliver_pending_guest_signal(ExecHypervisor *h) {
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

static int handle_guest_exception(ExecHypervisor *h, uint32_t vector, uint64_t fault_address) {
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

static int handle_guest_memory_fault(ExecHypervisor *h, int error) {
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

static int handle_guest_rt_sigreturn(ExecHypervisor *h, struct kvm_regs *regs) {
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

static void notify_vfork_parent(ExecHypervisor *h) {
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

static int install_guest_exec_control_signal(ExecHypervisor *h) {
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

static _noreturn_ void process_guest_exec_request(ExecHypervisor *h) {
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

static uint64_t handle_guest_execve(ExecHypervisor *h, const struct kvm_regs *regs) {
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

static uint64_t handle_guest_execveat(ExecHypervisor *h, const struct kvm_regs *regs) {
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

static int handle_guest_vfork(
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

static int handle_guest_fork(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret) {
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

static int handle_guest_clone(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret) {
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

static int handle_guest_clone3(ExecHypervisor *h, struct kvm_regs *regs, uint64_t *ret) {
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

static bool guest_syscall_should_restart(
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

static int wait_for_guest_threads(ExecHypervisor *h) {
        return wait_for_guest_thread_count(h, 0);
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