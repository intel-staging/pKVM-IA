/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include <pkvm.h>

MODULE_LICENSE("GPL");

struct pkvm_hyp *pkvm;

static void *pkvm_early_alloc_contig(int pages)
{
	return alloc_pages_exact(pages << PAGE_SHIFT, GFP_KERNEL | __GFP_ZERO);
}

int __init pkvm_init(void)
{
	int ret = 0;

	pkvm = pkvm_early_alloc_contig(PKVM_PAGES);
	if (!pkvm) {
		ret = -ENOMEM;
		goto fail;
	}

	pkvm->num_cpus = num_possible_cpus();

	return 0;

fail:
	return ret;
}
