// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/memblock.h>
#include <linux/sort.h>

#include <asm/kvm_pkvm.h>

static struct memblock_region *_pkvm_memory = pkvm_sym(pkvm_memory);
static unsigned int *pkvm_memblock_nr_ptr = &pkvm_sym(pkvm_memblock_nr);

phys_addr_t pkvm_mem_base;
phys_addr_t pkvm_mem_size;

static int cmp_pkvm_memblock(const void *p1, const void *p2)
{
	const struct memblock_region *r1 = p1;
	const struct memblock_region *r2 = p2;

	return r1->base < r2->base ? -1 : (r1->base > r2->base);
}

static void __init sort_memblock_regions(void)
{
	sort(_pkvm_memory,
	     *pkvm_memblock_nr_ptr,
	     sizeof(struct memblock_region),
	     cmp_pkvm_memblock,
	     NULL);
}

static int __init register_memblock_regions(void)
{
	struct memblock_region *reg;

	for_each_mem_region(reg) {
		if (*pkvm_memblock_nr_ptr >= PKVM_MEMBLOCK_REGIONS)
			return -ENOMEM;

		_pkvm_memory[*pkvm_memblock_nr_ptr] = *reg;
		(*pkvm_memblock_nr_ptr)++;
	}
	sort_memblock_regions();

	return 0;
}

void __init pkvm_reserve(void)
{
	int ret;

	if (pkvm_pre_reserve_check() < 0)
		return;

	ret = register_memblock_regions();
	if (ret) {
		*pkvm_memblock_nr_ptr = 0;
		kvm_err("Failed to register pkvm memblocks: %d\n", ret);
		return;
	}

	/*
	 * Try to allocate a PMD-aligned region to reduce TLB pressure once
	 * this is unmapped from the host stage-2, and fallback to PAGE_SIZE.
	 */
	pkvm_mem_size = pkvm_total_reserve_pages() << PAGE_SHIFT;
	pkvm_mem_base = memblock_phys_alloc(ALIGN(pkvm_mem_size, PMD_SIZE),
					   PMD_SIZE);
	if (!pkvm_mem_base)
		pkvm_mem_base = memblock_phys_alloc(pkvm_mem_size, PAGE_SIZE);
	else
		pkvm_mem_size = ALIGN(pkvm_mem_size, PMD_SIZE);

	if (!pkvm_mem_base) {
		kvm_err("Failed to reserve pkvm memory\n");
		return;
	}

	kvm_info("Reserved %lld MiB at 0x%llx\n", pkvm_mem_size >> 20,
		 pkvm_mem_base);
}
