// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/kvm_pkvm.h>
#include <pkvm.h>
#include "vmx.h"

MODULE_LICENSE("GPL");

u64 hyp_total_reserve_pages(void)
{
	return pkvm_data_struct_pages(PKVM_GLOBAL_PAGES,
				      PKVM_PERCPU_PAGES,
				      num_possible_cpus());
}

int __init vmx_pkvm_init(void)
{
	struct pkvm_hyp pkvm;

	pkvm.num_cpus = num_possible_cpus();

	/* FIXME: Should return 0 once pvVMCS is supported */
	return 1;
}
