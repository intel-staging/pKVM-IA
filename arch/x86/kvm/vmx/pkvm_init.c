// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <pkvm.h>
#include "vmx.h"

MODULE_LICENSE("GPL");

int __init vmx_pkvm_init(void)
{
	struct pkvm_hyp pkvm;

	pkvm.num_cpus = num_possible_cpus();

	/* FIXME: Should return 0 once pvVMCS is supported */
	return 1;
}
