/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#include <linux/types.h>
#include <linux/list.h>
#include <linux/dmar.h>
#include <../drivers/iommu/intel/iommu.h>
#include <linux/pci.h>

#include <pkvm.h>
#include <asm/pkvm_spinlock.h>
#include "gfp.h"
#include "debug.h"
#include "memory.h"
#include "pgtable.h"
#include "ept.h"
#include "pkvm_hyp.h"
#include "iommu_internal.h"

#define PASID_PTE_MASK			0x3F

struct tbl_walk {
	u16 bus;
	u16 devfn;
	u32 pasid;
	struct root_entry *rt_entry;
	struct context_entry *ctx_entry;
	struct pasid_entry *pasid_tbl_entry;
};

#define PASID_PDE_SHIFT			6
#define PASID_TBL_ENTRIES               BIT(PASID_PDE_SHIFT)
#define get_pasid_dir_size(entry)      (1 << ((((entry)->lo >> 9) & 0x7) + 7))

static inline struct pasid_dir_entry *context_entry_present(struct context_entry *ce)
{
	if (!(READ_ONCE(ce->lo) & 1))
		return NULL;

	return pkvm_phys_to_virt(READ_ONCE(ce->lo) & VTD_PAGE_MASK);
}

/* Get PRESENT bit of a PASID directory entry. */
static inline bool pasid_pde_is_present(struct pasid_dir_entry *pde)
{
	return READ_ONCE(pde->val) & 1;
}

/* Get PASID table from a PASID directory entry. */
static inline struct pasid_entry *
get_pasid_table_from_pde(struct pasid_dir_entry *pde)
{
	if (!pasid_pde_is_present(pde))
		return NULL;

	return pkvm_phys_to_virt(READ_ONCE(pde->val) & VTD_PAGE_MASK);
}

static struct context_entry *context_addr(struct pkvm_iommu *iommu, u8 bus, u8 devfn)
{
	struct root_entry *root_entry = pkvm_phys_to_virt(iommu->pgt.root_pa);
	struct root_entry *root = &root_entry[bus];
	struct context_entry *context;
	u64 *entry;

	entry = &root->lo;
	if (ecap_smts(iommu->iommu.ecap)) {
		if (devfn >= 0x80) {
			devfn -= 0x80;
			entry = &root->hi;
		}
		devfn *= 2;
	}

	if (*entry & 1)
		context = pkvm_phys_to_virt(*entry & VTD_PAGE_MASK);
	else
		return NULL;

	return &context[devfn];
}

static inline void print_tbl_walk(struct tbl_walk *tbl_wlk)
{
	/*
	 * A legacy mode DMAR doesn't support PASID, hence default it to -1
	 * indicating that it's invalid. Also, default all PASID related fields
	 * to 0.
	 */
	if (!tbl_wlk->pasid_tbl_entry)
		pkvm_dbg("%02x:%02x.%x\t0x%016llx:0x%016llx\t0x%016llx:0x%016llx\t%-6d\t0x%016llx:0x%016llx:0x%016llx\n",
			   tbl_wlk->bus, PCI_SLOT(tbl_wlk->devfn),
			   PCI_FUNC(tbl_wlk->devfn), tbl_wlk->rt_entry->hi,
			   tbl_wlk->rt_entry->lo, tbl_wlk->ctx_entry->hi,
			   tbl_wlk->ctx_entry->lo, -1,
			   (u64)0, (u64)0, (u64)0);
	else
		pkvm_dbg("%02x:%02x.%x\t0x%016llx:0x%016llx\t0x%016llx:0x%016llx\t%-6d\t0x%016llx:0x%016llx:0x%016llx\n",
			   tbl_wlk->bus, PCI_SLOT(tbl_wlk->devfn),
			   PCI_FUNC(tbl_wlk->devfn), tbl_wlk->rt_entry->hi,
			   tbl_wlk->rt_entry->lo, tbl_wlk->ctx_entry->hi,
			   tbl_wlk->ctx_entry->lo, tbl_wlk->pasid,
			   tbl_wlk->pasid_tbl_entry->val[2],
			   tbl_wlk->pasid_tbl_entry->val[1],
			   tbl_wlk->pasid_tbl_entry->val[0]);
}

static void pasid_tbl_walk(struct tbl_walk *tbl_wlk, struct pasid_entry *tbl_entry, u16 dir_idx)
{
	u8 tbl_idx;

	for (tbl_idx = 0; tbl_idx < PASID_TBL_ENTRIES; tbl_idx++) {
		if (pasid_pte_is_present(tbl_entry)) {
			tbl_wlk->pasid_tbl_entry = tbl_entry;
			tbl_wlk->pasid = (dir_idx << PASID_PDE_SHIFT) + tbl_idx;
			print_tbl_walk(tbl_wlk);
		}

		tbl_entry++;
	}
}

static void pasid_dir_walk(struct tbl_walk *tbl_wlk, u64 pasid_dir_ptr,
			   u16 pasid_dir_size)
{
	struct pasid_dir_entry *dir_entry = pkvm_phys_to_virt(pasid_dir_ptr);
	struct pasid_entry *pasid_tbl;
	u16 dir_idx;

	for (dir_idx = 0; dir_idx < pasid_dir_size; dir_idx++) {
		pasid_tbl = get_pasid_table_from_pde(dir_entry);
		if (pasid_tbl)
			pasid_tbl_walk(tbl_wlk, pasid_tbl, dir_idx);

		dir_entry++;
	}
}

static void ctx_tbl_walk(struct pkvm_iommu *iommu, u16 bus)
{
	struct root_entry *root_entry = pkvm_phys_to_virt(iommu->pgt.root_pa);
	struct context_entry *context;
	u16 devfn, pasid_dir_size;
	u64 pasid_dir_ptr;

	for (devfn = 0; devfn < 256; devfn++) {
		struct tbl_walk tbl_wlk = {0};

		/*
		 * Scalable mode root entry points to upper scalable mode
		 * context table and lower scalable mode context table. Each
		 * scalable mode context table has 128 context entries where as
		 * legacy mode context table has 256 context entries. So in
		 * scalable mode, the context entries for former 128 devices are
		 * in the lower scalable mode context table, while the latter
		 * 128 devices are in the upper scalable mode context table.
		 * In scalable mode, when devfn > 127, iommu_context_addr()
		 * automatically refers to upper scalable mode context table and
		 * hence the caller doesn't have to worry about differences
		 * between scalable mode and non scalable mode.
		 */
		context = context_addr(iommu, bus, devfn);
		if (!context)
			return;

		if (!context_entry_present(context))
			continue;

		tbl_wlk.bus = bus;
		tbl_wlk.devfn = devfn;
		tbl_wlk.rt_entry = &root_entry[bus];
		tbl_wlk.ctx_entry = context;

		if (ecap_smts(iommu->iommu.ecap)) {
			pasid_dir_ptr = context->lo & VTD_PAGE_MASK;
			pasid_dir_size = get_pasid_dir_size(context);
			pasid_dir_walk(&tbl_wlk, pasid_dir_ptr, pasid_dir_size);
			continue;
		}

		print_tbl_walk(&tbl_wlk);
	}
}

void root_tbl_walk(struct pkvm_iommu *iommu)
{
	u16 bus;

	pkvm_dbg("IOMMU %d: Root Table Address: 0x%llx\n",
		 iommu->iommu.seq_id, (u64)iommu->pgt.root_pa);
	pkvm_dbg("B.D.F\tRoot_entry\t\t\t\tContext_entry\t\t\t\tPASID\tPASID_table_entry\n");

	/*
	 * No need to check if the root entry is present or not because
	 * iommu_context_addr() performs the same check before returning
	 * context entry.
	 */
	for (bus = 0; bus < 256; bus++)
		ctx_tbl_walk(iommu, bus);
}

static inline unsigned long level_to_directory_size(int level)
{
	return BIT_ULL(VTD_PAGE_SHIFT + VTD_STRIDE_SHIFT * (level - 1));
}

static inline void
dump_page_info(unsigned long iova, u64 *path)
{
	pkvm_dbg("0x%013lx | 0x%016llx 0x%016llx 0x%016llx 0x%016llx 0x%016llx",
		   iova >> VTD_PAGE_SHIFT, path[5], path[4], path[3], path[2], path[1]);
}
static void pgtable_walk_level(struct dma_pte *pde,
			       int level, unsigned long start,
			       u64 *path)
{
	int i;

	if (level > 5 || level < 1)
		return;

	for (i = 0; i < BIT_ULL(VTD_STRIDE_SHIFT);
			i++, pde++, start += level_to_directory_size(level)) {
		if (!dma_pte_present(pde))
			continue;

		path[level] = pde->val;
		if (dma_pte_superpage(pde) || level == 1)
			dump_page_info(start, path);
		else
			pgtable_walk_level(pkvm_phys_to_virt(dma_pte_addr(pde)),
					   level - 1, start, path);
		path[level] = 0;
	}
}

void domain_translation_struct_show(struct pkvm_iommu *iommu, u16 bdf, u32 pasid)
{
	struct viommu_reg *vreg = &iommu->viommu.vreg;
	struct context_entry *context;
	u16 devfn, bus;
	u64 pgd, path[6] = { 0 };
	u32 agaw;
	bool scalable;

	bus = (bdf >> 8) & 0xff;
	devfn = bdf & 0xff;

	if (!(vreg->gsts & DMA_GSTS_TES)) {
		pkvm_dbg("DMA Remapping is not enabled on %s\n",
				   iommu->iommu.name);
		return;
	}

	if (ecap_smts(iommu->iommu.ecap)) {
		scalable = true;
	} else {
		scalable = false;
	}


	pkvm_spin_lock(&iommu->lock);

	context = context_addr(iommu, bus, devfn);
	if (!context || !context_present(context))
		goto iommu_unlock;

	if (scalable) {	/* scalable mode */
		struct pasid_entry *pasid_tbl, *pasid_tbl_entry;
		struct pasid_dir_entry *dir_tbl, *dir_entry;
		u16 dir_idx, tbl_idx, pgtt;
		u64 pasid_dir_ptr;

		pasid_dir_ptr = context->lo & VTD_PAGE_MASK;

		/* Dump specified device domain mappings with PASID. */
		dir_idx = pasid >> PASID_PDE_SHIFT;
		tbl_idx = pasid & PASID_PTE_MASK;

		dir_tbl = pkvm_phys_to_virt(pasid_dir_ptr);
		dir_entry = &dir_tbl[dir_idx];

		pasid_tbl = get_pasid_table_from_pde(dir_entry);
		if (!pasid_tbl)
			goto iommu_unlock;

		pasid_tbl_entry = &pasid_tbl[tbl_idx];
		if (!pasid_pte_is_present(pasid_tbl_entry))
			goto iommu_unlock;

		/*
		 * According to PASID Granular Translation Type(PGTT),
		 * get the page table pointer.
		 */
		pgtt = (u16)(pasid_tbl_entry->val[0] & GENMASK_ULL(8, 6)) >> 6;
		agaw = (u8)(pasid_tbl_entry->val[0] & GENMASK_ULL(4, 2)) >> 2;

		switch (pgtt) {
		case PASID_ENTRY_PGTT_FL_ONLY:
			pgd = pasid_tbl_entry->val[2];
			break;
		case PASID_ENTRY_PGTT_SL_ONLY:
		case PASID_ENTRY_PGTT_NESTED:
			pgd = pasid_tbl_entry->val[0];
			break;
		default:
			goto iommu_unlock;
		}
		pgd &= VTD_PAGE_MASK;
	} else { /* legacy mode */
		pgd = context->lo & VTD_PAGE_MASK;
		agaw = context->hi & 7;
	}

	pkvm_dbg("Device %04x:%02x:%02x.%x ",
			   iommu->iommu.segment, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

	if (scalable)
		pkvm_dbg("with pasid %x @0x%llx\n", pasid, pgd);
	else
		pkvm_dbg("@0x%llx\n", pgd);

	if (!pgd) {
		pkvm_dbg("Device configured for pass through!\n");
	} else {
		pkvm_dbg("%-17s\t%-18s\t%-18s\t%-18s\t%-18s\t%-s\n",
		   "IOVA_PFN", "PML5E", "PML4E", "PDPE", "PDE", "PTE");
		pgtable_walk_level(pkvm_phys_to_virt(pgd), agaw + 2, 0, path);
	}

iommu_unlock:
	pkvm_spin_unlock(&iommu->lock);
}
