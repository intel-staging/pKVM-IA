/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include <pkvm.h>
#include <vmx/vmx_lib.h>

MODULE_LICENSE("GPL");

struct pkvm_hyp *pkvm;

static void *pkvm_early_alloc_contig(int pages)
{
	return alloc_pages_exact(pages << PAGE_SHIFT, GFP_KERNEL | __GFP_ZERO);
}

static void pkvm_early_free(void *ptr, int pages)
{
	free_pages_exact(ptr, pages << PAGE_SHIFT);
}

static int pkvm_host_check_and_setup_vmx_cap(struct pkvm_hyp *pkvm)
{
	struct vmcs_config *vmcs_config = &pkvm->vmcs_config;
	struct vmx_capability *vmx_cap = &pkvm->vmx_cap;
	int ret = 0;
	struct vmcs_config_setting setting = {
		.cpu_based_exec_ctrl_min =
			CPU_BASED_USE_MSR_BITMAPS |
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
		.cpu_based_exec_ctrl_opt = 0,
		.cpu_based_2nd_exec_ctrl_min =
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_SHADOW_VMCS,
		.cpu_based_2nd_exec_ctrl_opt =
			SECONDARY_EXEC_ENABLE_INVPCID |
			SECONDARY_EXEC_XSAVES |
			SECONDARY_EXEC_ENABLE_RDTSCP |
			SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE,
		.pin_based_exec_ctrl_min = 0,
		.pin_based_exec_ctrl_opt = 0,
		.vmexit_ctrl_min =
			VM_EXIT_HOST_ADDR_SPACE_SIZE |
			VM_EXIT_LOAD_IA32_EFER |
			VM_EXIT_SAVE_IA32_PAT |
			VM_EXIT_SAVE_IA32_EFER |
			VM_EXIT_SAVE_DEBUG_CONTROLS,
		.vmexit_ctrl_opt = 0,
		.vmentry_ctrl_min =
			VM_ENTRY_LOAD_DEBUG_CONTROLS |
			VM_ENTRY_IA32E_MODE |
			VM_ENTRY_LOAD_IA32_EFER |
			VM_ENTRY_LOAD_IA32_PAT,
		.vmentry_ctrl_opt = 0,
		.has_broken_vmx_preemption_timer = false,
		.perf_global_ctrl_workaround = false,
	};

	if (!boot_cpu_has(X86_FEATURE_VMX))
		return -EINVAL;

	if (__setup_vmcs_config(vmcs_config, vmx_cap, &setting) < 0)
		return -EINVAL;

	pr_info("pin_based_exec_ctrl 0x%x\n", vmcs_config->pin_based_exec_ctrl);
	pr_info("cpu_based_exec_ctrl 0x%x\n", vmcs_config->cpu_based_exec_ctrl);
	pr_info("cpu_based_2nd_exec_ctrl 0x%x\n", vmcs_config->cpu_based_2nd_exec_ctrl);
	pr_info("vmexit_ctrl 0x%x\n", vmcs_config->vmexit_ctrl);
	pr_info("vmentry_ctrl 0x%x\n", vmcs_config->vmentry_ctrl);

	return ret;
}

int __init pkvm_init(void)
{
	int ret = 0;

	pkvm = pkvm_early_alloc_contig(PKVM_PAGES);
	if (!pkvm) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = pkvm_host_check_and_setup_vmx_cap(pkvm);
	if (ret)
		goto fail1;

	pkvm->num_cpus = num_possible_cpus();

	return 0;

fail1:
	pkvm_early_free(pkvm, PKVM_PAGES);
fail:
	return ret;
}
