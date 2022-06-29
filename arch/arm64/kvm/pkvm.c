// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_pkvm.h>
#include "hyp_constants.h"

int pkvm_pre_reserve_check(void)
{
	if (!is_hyp_mode_available() || is_kernel_in_hyp_mode())
		return -EINVAL;

	if (kvm_get_mode() != KVM_MODE_PROTECTED)
		return -EINVAL;

	return 0;
}

u64 pkvm_total_reserve_pages(void)
{
	u64 nr_pages, prev, total_pages = 0;

	total_pages += hyp_s1_pgtable_pages();
	total_pages += host_s2_pgtable_pages();

	/*
	 * The hyp_vmemmap needs to be backed by pages, but these pages
	 * themselves need to be present in the vmemmap, so compute the number
	 * of pages needed by looking for a fixed point.
	 */
	nr_pages = 0;
	do {
		prev = nr_pages;
		nr_pages = total_pages + prev;
		nr_pages = DIV_ROUND_UP(nr_pages * STRUCT_HYP_PAGE_SIZE,
					PAGE_SIZE);
		nr_pages += __hyp_pgtable_max_pages(nr_pages);
	} while (nr_pages != prev);
	total_pages += nr_pages;

	return total_pages;
}
