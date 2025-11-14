// SPDX-License-Identifier: GPL-2.0
#include <asm/kvm_pkvm.h>
#include "init_finalize.h"
#include "memory.h"

static void *hyp_pgt_base;

static int divide_memory_pool(phys_addr_t phys, unsigned long size)
{
	unsigned long nr_pages;

	pkvm_early_alloc_init(__pkvm_va(phys), size);

	nr_pages = pkvm_hyp_pgtable_pages();
	hyp_pgt_base = pkvm_early_alloc_contig(nr_pages);
	if (!hyp_pgt_base)
		return -ENOMEM;

	return 0;
}

static int finalize_global(phys_addr_t mem_base, unsigned long mem_size)
{
	if (!PAGE_ALIGNED(mem_base) || !mem_size)
		return -EINVAL;

	return divide_memory_pool(mem_base, mem_size);
}

int pkvm_init_finalize(phys_addr_t mem_base, unsigned long mem_size)
{
	static bool global_finalized;

	if (!global_finalized) {
		int ret = finalize_global(mem_base, mem_size);

		if (ret)
			return ret;

		global_finalized = true;
	}

	return 0;
}
