/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef _ASM_X86_KVM_PKVM_H
#define _ASM_X86_KVM_PKVM_H

#include <linux/kvm_host.h>

#ifdef CONFIG_PKVM_INTEL

#include <linux/memblock.h>
#include <asm/pkvm_image.h>
#include <asm/pkvm.h>

#define PKVM_MEMBLOCK_REGIONS   128
#define PKVM_PGTABLE_MAX_LEVELS		5U

extern struct memblock_region pkvm_sym(pkvm_memory)[];
extern unsigned int pkvm_sym(pkvm_memblock_nr);

void *pkvm_phys_to_virt(unsigned long phys);
unsigned long pkvm_virt_to_phys(void *virt);

#define __pkvm_pa(virt)	pkvm_virt_to_phys((void *)(virt))
#define __pkvm_va(phys)	pkvm_phys_to_virt((unsigned long)(phys))

extern phys_addr_t pkvm_mem_base;
extern phys_addr_t pkvm_mem_size;

void __init pkvm_reserve(void);

static inline unsigned long __pkvm_pgtable_max_pages(unsigned long nr_pages)
{
	unsigned long total = 0, i;

	/* Provision the worst case */
	for (i = 0; i < PKVM_PGTABLE_MAX_LEVELS; i++) {
		nr_pages = DIV_ROUND_UP(nr_pages, PTRS_PER_PTE);
		total += nr_pages;
	}

	return total;
}

static inline unsigned long __pkvm_pgtable_total_pages(void)
{
	unsigned long total = 0, i;

	for (i = 0; i < pkvm_sym(pkvm_memblock_nr); i++) {
		struct memblock_region *reg = &pkvm_sym(pkvm_memory)[i];
		total += __pkvm_pgtable_max_pages(reg->size >> PAGE_SHIFT);
	}

	return total;
}

static inline unsigned long host_ept_pgtable_pages(void)
{
	unsigned long res;

	/*
	 * Include an extra 16 pages to safely upper-bound the worst case of
	 * concatenated pgds.
	 */
	res = __pkvm_pgtable_total_pages() + 16;

	/* Allow 1 GiB for MMIO mappings */
	 res += __pkvm_pgtable_max_pages(SZ_1G >> PAGE_SHIFT);

	return res;
}

static inline unsigned long pkvm_mmu_pgtable_pages(void)
{
	unsigned long res;

	res = __pkvm_pgtable_total_pages();

	return res;
}

static inline unsigned long pkvm_vmemmap_memblock_size(struct memblock_region *reg,
		size_t vmemmap_entry_size)
{
	unsigned long nr_pages = reg->size >> PAGE_SHIFT;
	unsigned long start, end;

	/* Translate the pfn to the vmemmap entry */
	start = (reg->base >> PAGE_SHIFT) * vmemmap_entry_size;
	end = start + nr_pages * vmemmap_entry_size;
	start = ALIGN_DOWN(start, PAGE_SIZE);
	end = ALIGN(end, PAGE_SIZE);

	return end - start;
}

static inline unsigned long pkvm_vmemmap_pages(size_t vmemmap_entry_size)
{
	unsigned long total_size = 0, i;

	for (i = 0; i < pkvm_sym(pkvm_memblock_nr); i++) {
		total_size += pkvm_vmemmap_memblock_size(&pkvm_sym(pkvm_memory)[i],
							 vmemmap_entry_size);
	}

	return total_size >> PAGE_SHIFT;
}

static inline unsigned long pkvm_data_struct_pages(unsigned long global_pgs,
		unsigned long percpu_pgs, int num_cpus)
{
	return (percpu_pgs * num_cpus + global_pgs);
}

static inline int pkvm_pre_reserve_check(void)
{
	/* no necessary check yet*/
	return 0;
}

/* Calculate the total pages for Scalable IOMMU */
static inline unsigned long pkvm_iommu_pages(int max_pasid, int nr_pasid_pdev,
					     int nr_pdev, int nr_iommu, int qidesc_sz,
					     int qidesc_status_sz, int num_cpus)
{
	unsigned long res = 0;

	/* PASID page table pages for each PASID capable pdev */
	res += ((max_pasid >> 6) + (max_pasid >> 15)) * nr_pasid_pdev;
	/* PASID page table pages (PASID dir + PASID table) for each normal pdev */
	res += 2 * nr_pdev;
	/*
	 * Context table page count is the minimal value of
	 * total pdev number and 256 bus * 2 (in scalable mode).
	 * Each pdev may require a context page if its bdf is
	 * discrete enough.
	 */
	res += min(256 * 2, nr_pasid_pdev + nr_pdev);
	/* Root pages for each IOMMU */
	res += nr_iommu;
	/* Desc and desc_status pages for each IOMMU */
	res += nr_iommu * ((1 << get_order(qidesc_sz)) + (1 << get_order(qidesc_status_sz)));
	/*
	 * Reserve more IQ descriptor page. The size is calculated according to
	 * the IOMMU QI descriptor size(excludes the QI descriptor status as
	 * this is not needed to bunch requests) and the CPU number. Each CPU can
	 * have its own reserved QI descriptor page so that multiple CPUs can
	 * bunch the QI requests at the same time.
	 */
	res += num_cpus * (1 << get_order(qidesc_sz));

	return res;
}

/*
 * Calculate the total pages for shadow EPT. The assumptions are that:
 * 1. There is no shared memory between normal VMs or between secure VMs.
 * 2. The normal VM or secure VM memory size is no larger than the platform
 * memory size.
 * 3. The virtual MMIO range for each VM is no larger than 1G.
 * With these assumptions, we can reserve enough memory for normal VMs and
 * secure VMs.
 * 4. Each VM only has one shadow EPT. This will make vSMM mode and non-vSMM
 * mode share the same shadow EPT for a VM, which brings security weakness for
 * the vSMM mode.
 */
static inline unsigned long pkvm_shadow_ept_pgtable_pages(int nr_vm)
{
	unsigned long pgtable_pages = __pkvm_pgtable_total_pages();
	unsigned long res;

	/*
	 * Reserve enough pages to map all the platform memory in shadow
	 * EPT. With assumption#1 and assumption#4, these pages are enough
	 * for all VMs.
	 */
	res = pgtable_pages;

	/*
	 * There are multiple VMs. Although the total pages can be calculated
	 * through __pkvm_pgtable_total_pages() to map all the memory, this is
	 * enough to satisfy the level1 page table pages for all VMs but not
	 * enough to satisfy the level2:level5 page table pages. Each VM will
	 * require its own level2:level5 pages. Because __pkvm_pgtable_total_pages
	 * has already allocated 1 level2:level5, we just minus 1 from the total
	 * number of VMs, and multiply it by 2 considering SMM mode.
	 */
	res += __pkvm_pgtable_max_pages(pgtable_pages) * (nr_vm - 1) * 2;

	/* Allow 1 GiB for MMIO mappings for each VM */
	 res += __pkvm_pgtable_max_pages(SZ_1G >> PAGE_SHIFT) * nr_vm;

	 /*
	  * Each shadow VM has two page tables. One is used to manage page state
	  * and reused as IOMMU second-level pagetable for passthrough device in
	  * protected VM. Another one is used as shadow EPT.
	  */
	return (res * 2);
}

u64 pkvm_total_reserve_pages(void);

int pkvm_init_shadow_vm(struct kvm *kvm);
void pkvm_teardown_shadow_vm(struct kvm *kvm);
int pkvm_init_shadow_vcpu(struct kvm_vcpu *vcpu);
void pkvm_teardown_shadow_vcpu(struct kvm_vcpu *vcpu);
int pkvm_tlb_remote_flush(struct kvm *kvm);
int pkvm_tlb_remote_flush_with_range(struct kvm *kvm,
				     struct kvm_tlb_range *range);
int pkvm_set_mmio_ve(struct kvm_vcpu *vcpu, unsigned long gfn);
#else
static inline void pkvm_reserve(void) {}
static inline int pkvm_init_shadow_vm(struct kvm *kvm) { return 0; }
static inline void pkvm_teardown_shadow_vm(struct kvm *kvm) {}
static inline int pkvm_init_shadow_vcpu(struct kvm_vcpu *vcpu) { return 0; }
static inline void pkvm_teardown_shadow_vcpu(struct kvm_vcpu *vcpu) {}
static inline int pkvm_set_mmio_ve(struct kvm_vcpu *vcpu, unsigned long gfn) { return 0; }
#endif

#endif

