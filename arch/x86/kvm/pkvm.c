// SPDX-License-Identifier: GPL-2.0
#include <linux/cache.h>
#include <linux/kvm_host.h>
#include <linux/memblock.h>
#include <linux/sort.h>
#include <asm/kvm_pkvm.h>
#include "pkvm_constants.h"

bool __read_mostly enable_pkvm;

static struct memblock_region *pkvm_memory = pkvm_sym(pkvm_memory);
static unsigned int pkvm_memblock_nr;

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
	sort(pkvm_memory,
	     pkvm_memblock_nr,
	     sizeof(struct memblock_region),
	     cmp_pkvm_memblock,
	     NULL);
}

static int __init register_memblock_regions(void)
{
	struct memblock_region *reg;

	for_each_mem_region(reg) {
		if (pkvm_memblock_nr >= PKVM_MEMBLOCK_REGIONS)
			return -ENOMEM;

		pkvm_memory[pkvm_memblock_nr] = *reg;
		pkvm_memblock_nr++;
	}
	sort_memblock_regions();
	pkvm_sym(pkvm_memblock_nr) = pkvm_memblock_nr;

	return 0;
}

static unsigned long __init pkvm_total_reserve_pages(void)
{
	unsigned long (*vendor_pages)(void) = NULL;
	unsigned long total;

#ifdef CONFIG_PKVM_INTEL
	if (cpu_feature_enabled(X86_FEATURE_VMX))
		vendor_pages = pkvm_vmx_reserve_pages;
#endif
	if (!vendor_pages)
		return 0;

	total = vendor_pages();
	total += pkvm_hyp_pgtable_pages();
	total += pkvm_vmemmap_pages(PKVM_VMEMMAP_ENTRY_SIZE);

	return total;
}

void __init pkvm_reserve(void)
{
	int ret;

	if (!enable_pkvm)
		return;

	ret = register_memblock_regions();
	if (ret) {
		kvm_err("Failed to register pkvm memblocks: %d\n", ret);
		goto disable;
	}

	pkvm_mem_size = pkvm_total_reserve_pages() << PAGE_SHIFT;
	if (!pkvm_mem_size)
		goto disable;

	/*
	 * Try to allocate a PMD-aligned region to reduce TLB pressure once
	 * this is unmapped from the host stage-2, and fallback to PAGE_SIZE.
	 */
	pkvm_mem_base = memblock_phys_alloc(ALIGN(pkvm_mem_size, PMD_SIZE),
					   PMD_SIZE);
	if (pkvm_mem_base) {
		pkvm_mem_size = ALIGN(pkvm_mem_size, PMD_SIZE);
	} else {
		pkvm_mem_base = memblock_phys_alloc(pkvm_mem_size, PAGE_SIZE);
		if (!pkvm_mem_base) {
			kvm_err("Failed to reserve pkvm memory\n");
			goto disable;
		}
	}

	kvm_info("Reserved %llu MiB at 0x%llx for pkvm\n", pkvm_mem_size >> 20,
		 pkvm_mem_base);

	return;

disable:
	pkvm_mem_size = 0;
	enable_pkvm = false;
}
