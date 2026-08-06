/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-hypervisor-internal.h"

#if defined(__x86_64__)

int allocate_memslot(ExecHypervisor *h, unsigned *ret_slot) {
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

void release_memslot(ExecHypervisor *h, unsigned slot) {
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

void memslot_reservation_done(ExecHypervisorMemslotReservation *reservation) {
        if (!reservation)
                return;

        if (!reservation->committed)
                for (size_t i = reservation->n_slots; i > 0; i--)
                        release_memslot(reservation->machine, reservation->slots[i - 1]);
        free(reservation->slots);
        *reservation = (ExecHypervisorMemslotReservation) {};
}

int reserve_memslots(
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

int ensure_gpa_release_capacity(ExecHypervisor *h, size_t additional) {
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

int release_guest_physical(ExecHypervisor *h, uint64_t address, uint64_t size) {
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

void gpa_reservation_done(ExecHypervisorGpaReservation *reservation) {
        if (!reservation || reservation->size == 0)
                return;
        if (!reservation->committed)
                assert_se(release_guest_physical(
                                reservation->machine,
                                reservation->address,
                                reservation->size) >= 0);
        *reservation = (ExecHypervisorGpaReservation) {};
}

int reserve_guest_physical(
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

uint64_t* page_table_at(ExecHypervisor *h, uint64_t gpa) {
        ExecHypervisor *machine;

        assert(h);
        assert(gpa % page_size() == 0);

        machine = exec_hypervisor_machine(h);
        assert(machine->supervisor_memory);

        if (gpa >= machine->supervisor_memory_size || page_size() > machine->supervisor_memory_size - gpa)
                return NULL;

        return (uint64_t*) ((uint8_t*) machine->supervisor_memory + gpa);
}

int allocate_page_table(ExecHypervisor *h, uint64_t *ret_gpa) {
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

void reclaim_guest_page_tables(ExecHypervisor *h, uint64_t gva) {
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

int map_guest_page(ExecHypervisor *h, uint64_t gva, uint64_t gpa, uint64_t flags) {
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

void unmap_guest_page(ExecHypervisor *h, uint64_t gva) {
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

uint64_t* guest_page_entry(ExecHypervisor *h, uint64_t gva) {
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

uint64_t guest_page_flags(int protection) {
        uint64_t flags = X86_PAGE_USER;

        if (protection == PROT_NONE)
                flags |= X86_PAGE_SOFTWARE_PROT_NONE;
        if (FLAGS_SET(protection, PROT_WRITE))
                flags |= X86_PAGE_WRITE;
        if (!FLAGS_SET(protection, PROT_EXEC))
                flags |= X86_PAGE_NO_EXECUTE;

        return flags;
}

uint64_t guest_mapping_page_flags(const ExecHypervisorMapping *mapping) {
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

int flush_guest_tlb(ExecHypervisor *h) {
        struct kvm_sregs sregs;

        assert(h);

        if (ioctl(h->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
                return -errno;
        if (ioctl(h->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
                return -errno;

        return 0;
}

int flush_all_guest_tlbs(ExecHypervisor *h) {
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

ExecHypervisorMapping* find_mapping(ExecHypervisor *h, uint64_t address) {
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

int query_host_mapping(uint64_t address, struct procmap_query *ret_query) {
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

int host_mapping_has_vm_flag(uint64_t address, const char *flag, bool *ret) {
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

ExecHypervisorMapping* find_mapping_by_gpa(ExecHypervisor *h, uint64_t gpa, uint64_t size) {
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

int probe_file_mapping_page(const ExecHypervisorMapping *mapping, uint64_t page) {
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

int mark_inaccessible_file_pages(ExecHypervisor *h) {
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

int prepare_userfault_ranges_after_unmap(
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

int prepare_userfault_ranges_after_dontneed(
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

uint64_t handle_guest_mmap(ExecHypervisor *h, const struct kvm_regs *regs) {
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

uint64_t handle_guest_remap_file_pages(ExecHypervisor *h, const struct kvm_regs *regs) {
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

uint64_t handle_guest_mprotect(
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

uint64_t handle_guest_munmap(ExecHypervisor *h, uint64_t address, uint64_t requested_length) {
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

int handle_guest_mremap(ExecHypervisor *h, const struct kvm_regs *regs, uint64_t *ret) {
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

uint64_t handle_guest_brk(ExecHypervisor *h, uint64_t requested) {
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

uint64_t handle_guest_mseal(ExecHypervisor *h, const struct kvm_regs *regs) {
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

#endif

