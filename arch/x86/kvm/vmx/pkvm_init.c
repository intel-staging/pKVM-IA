// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pkvm: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/kvm_pkvm.h>
#include <asm/msr.h>
#include "vmx.h"

static int __init early_pkvm_parse_cmdline(char *buf)
{
	return kstrtobool(buf, &enable_pkvm);
}
early_param("kvm-intel.pkvm", early_pkvm_parse_cmdline);

static DEFINE_PER_CPU(struct pkvm_pcpu *, pkvm_pcpu);

unsigned long __init pkvm_vmx_reserve_pages(void)
{
	return pkvm_data_pages();
}

static __init int pkvm_setup_pcpu(int cpu)
{
	struct pkvm_pcpu *pcpu;

	if (cpu >= CONFIG_NR_CPUS) {
		pr_err("setup_pcpu: invalid CPU number %d\n", cpu);
		return -EINVAL;
	}

	pcpu = pkvm_early_alloc_contig(PKVM_PCPU_PAGES);
	if (!pcpu) {
		pr_err("no pcpu memory for CPU%d\n", cpu);
		return -ENOMEM;
	}

	pcpu->cpu = cpu;
	per_cpu(pkvm_pcpu, cpu) = pcpu;

	return 0;
}

int __init vmx_pkvm_init(void)
{
	unsigned long vmx_pages_size;
	int ret = -ENOMEM, cpu;
	struct pkvm_hyp *pkvm;

	if (!enable_pkvm)
		return 0;

	if (!pkvm_mem_base || !pkvm_mem_size) {
		pr_err("required memory not reserved\n");
		goto out;
	}

	vmx_pages_size = pkvm_vmx_reserve_pages() << PAGE_SHIFT;
	if (pkvm_mem_size < vmx_pages_size) {
		pr_err("reserved memory size (0x%llx) is smaller than required (0x%lx)\n",
		       pkvm_mem_size, vmx_pages_size);
		goto out;
	}

	pkvm_early_alloc_init(__va(pkvm_mem_base), vmx_pages_size);

	pkvm = pkvm_early_alloc_contig(PKVM_HYP_PAGES);
	if (!pkvm) {
		pr_err("cannot alloc pkvm_hyp\n");
		goto out;
	}

	pkvm->num_cpus = 0;

	for_each_possible_cpu(cpu) {
		ret = pkvm_setup_pcpu(cpu);
		if (ret)
			goto out;

		pkvm->pcpus[pkvm->num_cpus] = per_cpu(pkvm_pcpu, cpu);
		pkvm->num_cpus++;
	}

	return -EOPNOTSUPP;
out:
	/*
	 * As the reserved memory at the pkvm_mem_base will not be
	 * released back to the host, no need to de-initialize or
	 * free for the early_alloc.
	 */
	enable_pkvm = false;
	return ret;
}

MODULE_LICENSE("GPL");
