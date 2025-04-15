/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2025 Google
 */
#include <../drivers/iommu/intel/iommu.h>
#include <asm/pkvm_spinlock.h>
#include <pkvm.h>
#include "pkvm_hyp.h"
#include "gfp.h"
#include "memory.h"
#include "mmu.h"
#include "ept.h"
#include "pgtable.h"
#include "pci.h"
#include "iommu_internal.h"
#include "debug.h"
#include "ptdev.h"
#include "mem_protect.h"
#include "iommu_spgt.h"
#include "bug.h"
#include "iommu.h"

int initialize_iommu_pgt(struct pkvm_iommu *iommu)
{
	/*
	 * This is a nop as pv iommu implementation do not use
	 * iommu->pgt except for iommu-pgt.root_pa and that is
	 * initialized elsewhere.
	 */
	return 0;
}

unsigned long pkvm_iommu_set_rta(unsigned long phys, unsigned long rta_phys)
{
	struct pkvm_iommu *iommu = find_iommu_by_reg_phys(phys);
	struct viommu_reg *vreg = &iommu->viommu.vreg;
	unsigned long old_rta_phys = iommu->pgt.root_pa;

	pkvm_spin_lock(&iommu->lock);
	vreg->gsts &= ~DMA_GSTS_RTPS;

	pkvm_dbg("pkvm: %s: rta_phys: %lx\n", __func__, rta_phys);

	/*
	 * Host has the pages identity mapped. So not converting from host gpa to hpa.
	 */
	iommu->pgt.root_pa = rta_phys;
	vreg->rta = rta_phys;

	if (!iommu->activated) {
		if (activate_iommu(iommu)) {
			pkvm_dbg("pkvm: %s: iommu%d failed to activate\n", __func__, iommu->iommu.seq_id);
		}
	} else if (vreg->gsts & DMA_GSTS_TES) {
		flush_context_cache(iommu, 0, 0, 0, DMA_CCMD_GLOBAL_INVL);
		flush_iotlb(iommu, 0, 0, 0, DMA_TLB_GLOBAL_FLUSH);
	}

	vreg->gsts |= DMA_GSTS_RTPS;
	pkvm_spin_unlock(&iommu->lock);

	/*
	 * Remove the mapping for the root table page so that host
	 * will not be able to directly access it.
	 */
	if (old_rta_phys != rta_phys) {
		if (old_rta_phys) {
			pkvm_dbg("pkvm: %s: mapping prev root_table page[0x%lx] back to host\n",
					__func__, old_rta_phys);
			__pkvm_hyp_donate_host(old_rta_phys, PAGE_SIZE);
		}
		pkvm_dbg("pkvm: %s: unmapping root_table page[0x%lx] from host\n",
				__func__, rta_phys);
		__pkvm_host_donate_hyp(rta_phys, PAGE_SIZE);
	}

	root_tbl_walk(iommu);
	return 0;
}

unsigned long pkvm_iommu_update_ce(unsigned long phys, unsigned long rte,
		unsigned long ce_hi, unsigned long ce_lo)
{
	struct context_entry *context = pkvm_phys_to_virt(rte & VTD_PAGE_MASK);
	struct pkvm_iommu *iommu = find_iommu_by_reg_phys(phys);
	struct root_entry *root_entry = pkvm_phys_to_virt(iommu->pgt.root_pa);
	struct context_entry *ce;
	struct root_entry *root;
	unsigned long old_rte;
	u16 bdf = (ce_hi >> 32) & 0xFFFF;
	u8 bus = PCI_BUS_NUM(bdf);
	u8 devfn = PCI_DEV_FN(bdf);
	u16 did;

	pkvm_spin_lock(&iommu->lock);

	root = &root_entry[bus];
	ce = &context[devfn];
	ce_hi &= 0xFFFFFFFF;
	did = context_domain_id(ce);
	pkvm_dbg("pkvm: %s: did: %d, old_rte=%llx, new_rte: %lx, old_ce: (%llx:%llx), new_ce: (%lx:%lx)\n",
			__func__, did, root->lo, rte, ce->hi, ce->lo, ce_hi, ce_lo);
	old_rte = root->lo & VTD_PAGE_MASK;
	root->lo = rte;
	ce->hi = ce_hi;
	ce->lo = ce_lo;

	/*
	 * TODO: Revisit the cache flushing and optimize for cases like present to non-present
	 * and non-present-to-present.
	 */
	if (!iommu_coherency(iommu->iommu.ecap)) {
		pkvm_clflush_cache_range(root, sizeof(*root));
		pkvm_clflush_cache_range(ce, sizeof(*ce));
	}
	flush_context_cache(iommu, 0, bdf, DMA_CCMD_MASK_NOBIT, DMA_CCMD_DEVICE_INVL);
	flush_iotlb(iommu, did, 0, 0, DMA_TLB_DSI_FLUSH);

	pkvm_spin_unlock(&iommu->lock);

	/*
	 * Remove the mapping for the context table page so that host
	 * will not be able to directly access it.
	 */
	rte &= VTD_PAGE_MASK;
	if (old_rte != rte) {
		if (old_rte) {
			pkvm_dbg("pkvm: %s: mapping prev context_table page[0x%lx] back to host\n",
					__func__, old_rte);
			__pkvm_hyp_donate_host(old_rte, PAGE_SIZE);
		}
		if (rte) {
			pkvm_dbg("pkvm: %s: unmapping context_table page[0x%lx] from host\n",
				__func__, rte);
			__pkvm_host_donate_hyp(rte, PAGE_SIZE);
		}
	}

	return 0;
}
