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

int __init vmx_pkvm_init(void)
{
	unsigned long nr_pages;
	struct pkvm_hyp *pkvm;
	int ret;

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

	/* FIXME: Should return 0 once pvVMCS is supported */
	return 1;
out:
	pkvm_init = false;
	return ret;
}
