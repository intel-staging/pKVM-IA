// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */
#ifndef __ARM64_KVM_PKVM_H__
#define __ARM64_KVM_PKVM_H__

#include <linux/memblock.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_mmu.h>

#define PKVM_MEMBLOCK_REGIONS 128

#define __hyp_va(phys)	((void *)((phys_addr_t)(phys) - hyp_physvirt_offset))

static inline void *hyp_phys_to_virt(phys_addr_t phys)
{
	return __hyp_va(phys);
}

static inline phys_addr_t hyp_virt_to_phys(void *addr)
{
	return __hyp_pa(addr);
}

#define __pkvm_pa __hyp_pa
#define __pkvm_va __hyp_va

#define pkvm_sym kvm_nvhe_sym

extern struct memblock_region kvm_nvhe_sym(pkvm_memory)[];
extern unsigned int kvm_nvhe_sym(pkvm_memblock_nr);

int pkvm_pre_reserve_check(void);
u64 pkvm_total_reserve_pages(void);

static inline unsigned long __hyp_pgtable_max_pages(unsigned long nr_pages)
{
	unsigned long total = 0, i;

	/* Provision the worst case scenario */
	for (i = 0; i < KVM_PGTABLE_MAX_LEVELS; i++) {
		nr_pages = DIV_ROUND_UP(nr_pages, PTRS_PER_PTE);
		total += nr_pages;
	}

	return total;
}

static inline unsigned long __hyp_pgtable_total_pages(void)
{
	unsigned long res = 0, i;

	/* Cover all of memory with page-granularity */
	for (i = 0; i < kvm_nvhe_sym(pkvm_memblock_nr); i++) {
		struct memblock_region *reg = &kvm_nvhe_sym(pkvm_memory)[i];
		res += __hyp_pgtable_max_pages(reg->size >> PAGE_SHIFT);
	}

	return res;
}

static inline unsigned long hyp_s1_pgtable_pages(void)
{
	unsigned long res;

	res = __hyp_pgtable_total_pages();

	/* Allow 1 GiB for private mappings */
	res += __hyp_pgtable_max_pages(SZ_1G >> PAGE_SHIFT);

	return res;
}

static inline unsigned long host_s2_pgtable_pages(void)
{
	unsigned long res;

	/*
	 * Include an extra 16 pages to safely upper-bound the worst case of
	 * concatenated pgds.
	 */
	res = __hyp_pgtable_total_pages() + 16;

	/* Allow 1 GiB for MMIO mappings */
	res += __hyp_pgtable_max_pages(SZ_1G >> PAGE_SHIFT);

	return res;
}

#endif	/* __ARM64_KVM_PKVM_H__ */
