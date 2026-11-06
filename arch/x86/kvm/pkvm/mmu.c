// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>
#include <linux/pgtable.h>
#include <asm/invpcid.h>
#include <asm/kvm_pkvm.h>
#include <asm/tlbflush.h>
#include "early_alloc.h"
#include "mmu.h"
#include "pgtable.h"

static struct pkvm_pgtable hyp_mmu;
static bool hyp_mmu_in_use;

static bool hyp_mmu_pte_present(void *ptep)
{
	return *(u64 *)ptep & _PAGE_PRESENT;
}

static bool hyp_mmu_pte_huge(void *ptep)
{
	return *(u64 *)ptep & _PAGE_PSE;
}

static void hyp_mmu_pte_mkhuge(void *ptep)
{
	*(u64 *)ptep |= _PAGE_PSE;
}

static unsigned long hyp_mmu_pte_to_phys(void *ptep)
{
	return *(u64 *)ptep & PTE_PFN_MASK;
}

static u64 hyp_mmu_pte_to_prot(void *ptep)
{
	u64 prot = *(u64 *)ptep & PTE_FLAGS_MASK;

	return prot & ~_PAGE_PSE;
}

static int hyp_mmu_vaddr_to_index(unsigned long vaddr, int level)
{
	return (vaddr >> page_level_shift(level)) & ((1UL << PTE_SHIFT) - 1);
}

static unsigned long hyp_mmu_level_to_size(int level)
{
	return page_level_size(level);
}

static u64 hyp_mmu_level_to_mask(int level)
{
	return page_level_mask(level);
}

static bool hyp_mmu_pte_is_leaf(void *ptep, int level)
{
	return level == PG_LEVEL_4K || !hyp_mmu_pte_present(ptep) || hyp_mmu_pte_huge(ptep);
}

static int hyp_mmu_pte_size(int level)
{
	return PAGE_SIZE / PTRS_PER_PTE;
}

static int hyp_mmu_pte_count(int level)
{
	return PTRS_PER_PTE;
}

static void hyp_mmu_pte_set(void *ptep, u64 pte)
{
	WRITE_ONCE(*(u64 *)ptep, pte);
}

static u64 hyp_mmu_pte_get(void *ptep)
{
	return READ_ONCE(*(u64 *)ptep);
}

static void hyp_mmu_flush_tlb(struct pkvm_pgtable *pgt,
			      unsigned long vaddr, unsigned long size)
{
	/*
	 * Before the hypervisor's MMU is loaded on any CPU, no CPU can have
	 * TLB entries for it, so there is nothing to flush.
	 */
	if (!READ_ONCE(hyp_mmu_in_use))
		return;

	/*
	 * The pKVM hypervisor will map all valid memory in its MMU during the
	 * init phase and won't change or unmap at runtime. So there is no
	 * usages to change a present leaf in the hyp_mmu at runtime. Put a BUG
	 * here in case anything is missed.
	 */
	BUG();
}

static const struct pkvm_pgtable_ops hyp_mmu_pgt_ops = {
	.pte_present = hyp_mmu_pte_present,
	.pte_huge = hyp_mmu_pte_huge,
	.pte_mkhuge = hyp_mmu_pte_mkhuge,
	.pte_to_phys = hyp_mmu_pte_to_phys,
	.pte_to_prot = hyp_mmu_pte_to_prot,
	.vaddr_to_index = hyp_mmu_vaddr_to_index,
	.level_to_size = hyp_mmu_level_to_size,
	.level_to_mask = hyp_mmu_level_to_mask,
	.pte_is_leaf = hyp_mmu_pte_is_leaf,
	.pte_size = hyp_mmu_pte_size,
	.pte_count = hyp_mmu_pte_count,
	.pte_set = hyp_mmu_pte_set,
	.pte_get = hyp_mmu_pte_get,
	.flush_tlb = hyp_mmu_flush_tlb,
};

int pkvm_hyp_mmu_init(void *pool_base, unsigned long pool_pages)
{
	struct pkvm_pgtable_cap cap = {
		.level = pgtable_l5_enabled() ? 5 : 4,
		.allowed_pgsz = (1 << PG_LEVEL_2M) | (1 << PG_LEVEL_4K),
		.table_prot = (u64)_KERNPG_TABLE_NOENC,
	};

	if (boot_cpu_has(X86_FEATURE_GBPAGES))
		cap.allowed_pgsz |= 1 << PG_LEVEL_1G;

	pkvm_early_alloc_init(pool_base, pool_pages << PAGE_SHIFT);

	return pkvm_pgtable_init(&hyp_mmu, cap, &pkvm_early_alloc_mm_ops, &hyp_mmu_pgt_ops);
}

void pkvm_hyp_mmu_load(void)
{
	native_write_cr3(hyp_mmu.root_pa);

	/*
	 * Writing CR3 doesn't invalidate the TLB entries for global pages.
	 * In case there are such TLB entries, flush all the TLB entries,
	 * like native_flush_tlb_global() does, so that this CPU only uses
	 * translations from the hypervisor's MMU.
	 */
	if (cpu_feature_enabled(X86_FEATURE_INVPCID))
		invpcid_flush_all();
	else
		__native_tlb_flush_global(native_read_cr4());

	if (!READ_ONCE(hyp_mmu_in_use))
		WRITE_ONCE(hyp_mmu_in_use, true);
}

int pkvm_hyp_mmu_map(unsigned long vaddr, unsigned long phys,
		     unsigned long size, u64 prot)
{
	if (WARN_ON(!__is_canonical_address(vaddr, boot_cpu_data.x86_virt_bits)))
		return -EINVAL;

	vaddr &= (1ULL << boot_cpu_data.x86_virt_bits) - 1;

	return pkvm_pgtable_map(&hyp_mmu, vaddr, phys, size, prot);
}
