/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "macro.h"

typedef struct ExecHypervisor ExecHypervisor;

int exec_hypervisor_open_system(ExecHypervisor **ret);
int exec_hypervisor_prepare_image(ExecHypervisor *h, int executable_fd, const char *executable_path);
int exec_hypervisor_create_machine(ExecHypervisor *h);
int exec_hypervisor_run_probe(ExecHypervisor *h);
bool exec_hypervisor_can_run(const ExecHypervisor *h);
void exec_hypervisor_set_secure_exec(ExecHypervisor *h, bool secure_exec);
int exec_hypervisor_prepare_stack(ExecHypervisor *h, char *const argv[], char *const envp[]);
int exec_hypervisor_set_syscall_filter(ExecHypervisor *h, Hashmap *filter, bool allow_list, int errno_or_action);
int exec_hypervisor_run(ExecHypervisor *h, int *ret_status);
int* exec_hypervisor_kvm_fd(ExecHypervisor *h);

ExecHypervisor* exec_hypervisor_free(ExecHypervisor *h);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecHypervisor*, exec_hypervisor_free);