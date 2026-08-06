/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-hypervisor-internal.h"

#if defined(__x86_64__)

int set_supported_cpuid_fd(ExecHypervisor *h, int vcpu_fd) {
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

int set_supported_cpuid(ExecHypervisor *h) {
        assert(h);

        return set_supported_cpuid_fd(h, h->vcpu_fd);
}

struct kvm_segment make_code_segment(uint16_t selector, uint8_t dpl) {
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

struct kvm_segment make_data_segment(uint16_t selector, uint8_t dpl) {
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

int set_vcpu_syscall_msrs(ExecHypervisor *h, int vcpu_fd) {
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

int set_vcpu_xfd_state(ExecHypervisor *h, int vcpu_fd) {
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

int get_vcpu_xfd_state(ExecHypervisor *h, int vcpu_fd) {
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

int set_vcpu_speculation_msrs(ExecHypervisor *h, int vcpu_fd) {
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

int issue_guest_indirect_branch_barrier(ExecHypervisor *h) {
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

int commit_guest_seccomp_filter(
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

int initialize_guest_speculation_policy(ExecHypervisor *h) {
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

int initialize_guest_keyring_policy(ExecHypervisor *h) {
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

uint64_t handle_guest_store_bypass(ExecHypervisor *h, const struct kvm_regs *regs) {
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

uint64_t handle_guest_indirect_branch(ExecHypervisor *h, const struct kvm_regs *regs) {
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

uint64_t handle_guest_l1d_flush(ExecHypervisor *h, const struct kvm_regs *regs) {
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

int probe_vcpu_speculation_msrs(ExecHypervisor *h, int vcpu_fd) {
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

X86FxsaveArea* xsave_fxsave(X86KvmXsave *xsave) {
        assert(xsave);

        return (X86FxsaveArea*) xsave->region;
}

const X86FxsaveArea* xsave_fxsave_const(const X86KvmXsave *xsave) {
        assert(xsave);

        return (const X86FxsaveArea*) xsave->region;
}

const X86XsaveHeader* xsave_header_const(const X86KvmXsave *xsave) {
        assert(xsave);

        return (const X86XsaveHeader*) ((const uint8_t*) xsave->region + sizeof(X86FxsaveArea));
}

X86XsaveHeader* xsave_header(X86KvmXsave *xsave) {
        assert(xsave);

        return (X86XsaveHeader*) ((uint8_t*) xsave->region + sizeof(X86FxsaveArea));
}

void reset_dynamic_xsave(ExecHypervisor *h, X86KvmXsave *xsave) {
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

int get_vcpu_xsave(ExecHypervisor *h, int vcpu_fd, X86KvmXsave *ret) {
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

int set_vcpu_xsave(int vcpu_fd, const X86KvmXsave *xsave) {
        assert(vcpu_fd >= 0);
        assert(xsave);

        if (ioctl(vcpu_fd, KVM_SET_XSAVE, xsave) < 0)
                return -errno;

        return 0;
}

int set_vcpu_xcr0(ExecHypervisor *h, int vcpu_fd) {
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

int setup_vcpu_state(ExecHypervisor *h) {
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

int validate_translation(
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

int validate_vcpu_state(ExecHypervisor *h) {
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

int reconcile_dontfork_mappings_after_fork(ExecHypervisor *h) {
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

int recreate_hypervisor_machine_after_fork(
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
