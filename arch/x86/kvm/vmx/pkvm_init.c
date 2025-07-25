// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/kvm_pkvm.h>
#include <pkvm.h>
#include "vmx.h"

MODULE_LICENSE("GPL");

static bool pkvm_init;

u64 hyp_total_reserve_pages(void)
{
	return pkvm_data_struct_pages(PKVM_GLOBAL_PAGES,
				      PKVM_PERCPU_PAGES,
				      num_possible_cpus());
}

static __init int setup_pkvm_host_vmcs_config(struct pkvm_hyp *pkvm)
{
	struct vmcs_config *vmcs_config = &pkvm->vmcs_config;
	struct vmx_capability *vmx_cap = &vmx_capability;
	int ret = 0;
	struct vmcs_config_setting setting = {
		.cpu_based_vm_exec_ctrl_req =
			CPU_BASED_INTR_WINDOW_EXITING |
			CPU_BASED_USE_IO_BITMAPS |
			CPU_BASED_USE_MSR_BITMAPS |
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
		.cpu_based_vm_exec_ctrl_opt = 0,
		.secondary_vm_exec_ctrl_req =
			SECONDARY_EXEC_ENABLE_EPT,
		.secondary_vm_exec_ctrl_opt =
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_INVPCID |
			SECONDARY_EXEC_ENABLE_XSAVES |
			SECONDARY_EXEC_ENABLE_RDTSCP |
			SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE,
		.tertiary_vm_exec_ctrl_opt = 0,
		.pin_based_vm_exec_ctrl_req = 0,
		.pin_based_vm_exec_ctrl_opt = 0,
		.vmexit_ctrl_req =
			VM_EXIT_HOST_ADDR_SPACE_SIZE |
			VM_EXIT_LOAD_IA32_PAT |
			VM_EXIT_LOAD_IA32_EFER |
			VM_EXIT_SAVE_IA32_PAT |
			VM_EXIT_SAVE_IA32_EFER |
			VM_EXIT_SAVE_DEBUG_CONTROLS,
		.vmexit_ctrl_opt = 0,
		.vmentry_ctrl_req =
			VM_ENTRY_LOAD_DEBUG_CONTROLS |
			VM_ENTRY_IA32E_MODE |
			VM_ENTRY_LOAD_IA32_EFER |
			VM_ENTRY_LOAD_IA32_PAT,
		.vmentry_ctrl_opt = 0,
	};

	ret = setup_vmcs_config_common(vmcs_config, vmx_cap, &setting);
	if (ret) {
		pr_err("pkvm: setup host vmcs config failed with ret %d\n", ret);
	} else {
		pr_info("pin_based_exec_ctrl 0x%x\n", vmcs_config->pin_based_exec_ctrl);
		pr_info("cpu_based_exec_ctrl 0x%x\n", vmcs_config->cpu_based_exec_ctrl);
		pr_info("cpu_based_2nd_exec_ctrl 0x%x\n", vmcs_config->cpu_based_2nd_exec_ctrl);
		pr_info("vmexit_ctrl 0x%x\n", vmcs_config->vmexit_ctrl);
		pr_info("vmentry_ctrl 0x%x\n", vmcs_config->vmentry_ctrl);
	}

	return ret;
}

static __init int pkvm_setup_pcpu(struct pkvm_hyp *pkvm, int cpu)
{
	struct pkvm_pcpu *pcpu;

	if (cpu >= CONFIG_NR_CPUS)
		return -ENOMEM;

	pcpu = pkvm_early_alloc_contig(PKVM_PCPU_PAGES);
	if (!pcpu)
		return -ENOMEM;

	pkvm->pcpus[cpu] = pcpu;

	return 0;
}

static __init int pkvm_host_setup_vcpu(struct pkvm_hyp *pkvm, int cpu)
{
	struct pkvm_host_vcpu *hvcpu;

	if (cpu >= CONFIG_NR_CPUS)
		return -ENOMEM;

	hvcpu = pkvm_early_alloc_contig(PKVM_HOST_VCPU_PAGES);
	if (!hvcpu)
		return -ENOMEM;

	hvcpu->pcpu = pkvm->pcpus[cpu];
	hvcpu->vmx.vcpu.cpu = cpu;

	pkvm->host_vm.host_vcpus[cpu] = hvcpu;

	return 0;
}

static __init int pkvm_init_io_emulation(struct pkvm_hyp *pkvm)
{
	pkvm->host_vm.io_bitmap = pkvm_early_alloc_contig(2);

	if (!pkvm->host_vm.io_bitmap) {
		pr_err("pkvm: no memory page for io_bitmap\n");
		return -ENOMEM;
	}

	memset(pkvm->host_vm.io_bitmap, 0, 2 * PAGE_SIZE);

	return 0;
}

int __init vmx_pkvm_init(void)
{
	unsigned long nr_pages;
	struct pkvm_hyp *pkvm;
	int ret, cpu;

	if (cmpxchg(&pkvm_init, 0, 1) != 0) {
		pr_err("pkvm: init is already started\n");
		return -EBUSY;
	}

	if (!hyp_mem_base) {
		pr_err("pkvm: required memory not reserved\n");
		ret = -ENOMEM;
		goto out;
	}

	nr_pages = pkvm_data_struct_pages(PKVM_GLOBAL_PAGES,
					  PKVM_PERCPU_PAGES,
					  num_possible_cpus());
	pkvm_early_alloc_init(__va(hyp_mem_base), nr_pages << PAGE_SHIFT);

	pkvm = pkvm_early_alloc_contig(PKVM_PAGES);
	if (!pkvm) {
		pr_err("pkvm: cannot alloc pkvm_hyp\n");
		ret = -ENOMEM;
		goto out;
	}

	pkvm->num_cpus = num_possible_cpus();

	ret = setup_pkvm_host_vmcs_config(pkvm);
	if (ret)
		goto out;

	for_each_possible_cpu(cpu) {
		ret = pkvm_setup_pcpu(pkvm, cpu);
		if (ret)
			goto out;
		ret = pkvm_host_setup_vcpu(pkvm, cpu);
		if (ret)
			goto out;
	}

	ret = pkvm_init_io_emulation(pkvm);
	if (ret)
		goto out;

	/* FIXME: Should return 0 once pvVMCS is supported */
	return 1;
out:
	pkvm_init = false;
	return ret;
}
