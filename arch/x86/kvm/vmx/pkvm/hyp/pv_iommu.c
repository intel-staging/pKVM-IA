// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Google
 */
#include <../drivers/iommu/intel/iommu.h>
#include <asm/pkvm_spinlock.h>
#include <linux/pci.h>
#include <pkvm.h>
#include "pkvm_hyp.h"
#include "gfp.h"
#include "memory.h"
#include "mmu.h"
#include "ept.h"
#include "pgtable.h"
#include "mem_protect.h"
#include "iommu_internal.h"
#include "debug.h"
#include "iommu_spgt.h"
#include "bug.h"
#include "iommu.h"

static void __set_lm_context(struct context_entry *context, u16 did, u8 aw, u8 tt, u64 slptr)
{
	context_clear_entry(context);

	context_set_domain_id(context, did);

	context_set_address_root(context, slptr);
	context_set_address_width(context, aw);
	context_set_translation_type(context, tt);
	context_set_fault_enable(context);
	context_set_present(context);
}

/*
 * Copied from drivers/iommu/intel/iommu.c:iommu_context_addr()
 */
struct context_entry *pkvm_iommu_context_addr(struct intel_iommu *iommu, u8 bus,
					      u8 devfn, u64 *context_phys)
{
	struct context_entry *context;
	struct root_entry *root;
	u64 *entry;
	int ret;

	if (WARN_ON_ONCE(!iommu->root_entry))
		return NULL;

	root = &iommu->root_entry[bus];
	entry = &root->lo;
	if (sm_supported(iommu)) {
		if (devfn >= 0x80) {
			devfn -= 0x80;
			entry = &root->hi;
		}
		devfn *= 2;
	}
	if (*entry & 1)
		context = pkvm_phys_to_virt(*entry & VTD_PAGE_MASK);
	else {
		if (!context_phys || !*context_phys)
			return NULL;

		context = (struct context_entry *)host_gpa2hva(*context_phys);
		if (!context)
			return NULL;

		pkvm_dbg("pkvm: %s: write protecting lm context table: %llx\n",
			 __func__, pkvm_virt_to_phys(context));
		ret = __pkvm_host_donate_hyp_share_ro(pkvm_virt_to_phys(context), VTD_PAGE_SIZE);
		if (ret) {
			pkvm_err("pkvm: %s: failed to write protect context table Page(err=%d)!\n",
				 __func__, ret);
			return NULL;
		}
		memset(context, 0, VTD_PAGE_SIZE);

		__pkvm_iommu_flush_cache(iommu, context, VTD_PAGE_SIZE);
		*entry = host_gpa2hpa(*context_phys) | 1;
		__pkvm_iommu_flush_cache(iommu, entry, sizeof(*entry));

		/*
		 * Unset the context_phys to let host driver know that pkvm has
		 * used the donated page for context table.
		 */
		*context_phys = 0;
	}
	return &context[devfn];
}

/*
 * Cache invalidations after change in a context table entry that was present
 * according to the Spec 6.5.3.3 (Guidance to Software for Invalidations).
 * This helper can only be used when IOMMU is working in the legacy mode or
 * IOMMU is in scalable mode but all PASID table entries of the device are
 * non-present.
 *  Copied from drivers/iommu/inte/iommu.c:intel_context_flush_no_pasid() (6.18)
 *              drivers/iommu/inte/iommu.c:intel_context_flush_present() (6.12)
 */
static void context_flush_present_no_pasid(struct pkvm_iommu *hyp_iommu, u16 did,
					   u16 bdf, u8 ats_qdep)
{
	u16 pfsid = 0;

	flush_context_cache(hyp_iommu, did, bdf,
			    DMA_CCMD_MASK_NOBIT, DMA_CCMD_DEVICE_INVL);

	if (!sm_supported(&hyp_iommu->iommu))
		flush_iotlb(hyp_iommu, did, 0, 0, DMA_TLB_DSI_FLUSH);

	if (is_dev_in_satc(bdf)) {
		/*
		 * Device is in SATC and optimistically assuming that a well crafted SATC
		 * would contain only physical functions, its safe to set pfsid = bdf.
		 * TODO: We should probably be verifying SATC for existence of only
		 * physical functions during pkvm initialization.
		 */
		if (ecap_dit(hyp_iommu->iommu.ecap))
			pfsid = bdf;

		flush_dev_iotlb(hyp_iommu, bdf, pfsid, ats_qdep, 0, MAX_AGAW_PFN_WIDTH);

		/*
		 * NOTE:
		 * There are devices(QAT: PCI device IDs ranging from 0x4940 to 0x4943)
		 * which doesn't perform devtlb flush correctly and needs an extra flush
		 * operation from the driver side.
		 *
		 * Since these devices are not concerning to pkvm and we don't trust host
		 * to pass this information correctly(if the host is compromised), we don't
		 * do the second flush.
		 */
	}
}

int pkvm_iommu_clear_ce(u64 param_va)
{
	struct pkvm_clear_translation_param param, *param_ptr;
	struct context_entry *context;
	struct pkvm_iommu *hyp_iommu;
	struct intel_iommu *iommu;
	struct pasid_dir_entry *pasid_dir;
	u64 pasid_dir_sz;
	u16 did = 0;
	int ret = 0;
	bool sm;

	if (!param_va)
		return -EINVAL;

	param_ptr = (struct pkvm_clear_translation_param *)kern_pkvm_va((void *)param_va);
	if (WARN_ON_ONCE(copy_pv_param_from_host(clear_translation_param, param_ptr, param)))
		return -EINVAL;

	if (param.ats_qdep > PCI_ATS_MAX_QDEP)
		return -EINVAL;

	hyp_iommu = find_iommu_by_reg_phys(param.phys);
	if (!hyp_iommu)
		return -EINVAL;

	iommu = &hyp_iommu->iommu;
	sm = sm_supported(iommu);

	pkvm_spin_lock(&hyp_iommu->lock);
	context = pkvm_iommu_context_addr(iommu, PCI_BUS_NUM(param.bdf),
					  PCI_DEV_FN(param.bdf), NULL);

	if (!context || !context_present(context)) {
		pkvm_spin_unlock(&hyp_iommu->lock);
		return 0;
	}

	if (sm) {
		pasid_dir = pkvm_phys_to_virt(context->lo & VTD_PAGE_MASK);
		pasid_dir_sz = get_pasid_dir_size(context);
	} else {
		did = context_domain_id(context);
	}
	pkvm_dbg("pkvm: %s: [%s]: dev[%x] did: %u\n", __func__,
		 sm ? "SM" : "LM", param.bdf, did);

	context_clear_entry(context);
	__pkvm_iommu_flush_cache(iommu, context, sizeof(*context));
	pkvm_spin_unlock(&hyp_iommu->lock);

	context_flush_present_no_pasid(hyp_iommu, did, param.bdf, param.ats_qdep);

	if (sm)
		ret = pkvm_pasid_free_table(pasid_dir, pasid_dir_sz);

	return ret;
}

/* Copied from drivers/iommu/intel/iommu.c:context_present_cache_flush() */
static void context_present_cache_flush(struct pkvm_iommu *iommu, u16 bdf, u16 did)
{
	if (cap_caching_mode(iommu->iommu.cap)) {
		flush_context_cache(iommu, 0, bdf, DMA_CCMD_MASK_NOBIT, DMA_CCMD_DEVICE_INVL);
		flush_iotlb(iommu, did, 0, 0, DMA_TLB_DSI_FLUSH);
	}
}

unsigned long set_context_entry(struct pkvm_iommu *hyp_iommu,
				struct pkvm_lm_context_param *param, u16 agaw)
{
	struct intel_iommu *iommu = &hyp_iommu->iommu;
	u8 bus = PCI_BUS_NUM(param->bdf);
	u8 devfn = PCI_DEV_FN(param->bdf);
	struct context_entry *context;
	u8 tt = CONTEXT_TT_MULTI_LEVEL;

	if (param->ats_supported) {
		if (!is_dev_in_satc(param->bdf)) {
			pkvm_err("pkvm: device[%x]: host reports ats supported, but not in satc\n",
				 param->bdf);
			return -EPERM;
		}

		tt = CONTEXT_TT_DEV_IOTLB;
	}

	context = pkvm_iommu_context_addr(iommu, bus, devfn, &param->context_gpa);
	if (!context)
		return -ENOMEM;

	if (context_present(context))
		return 0;

	__set_lm_context(context, param->did, agaw, tt, param->domain_pgd_gpa);

	__pkvm_iommu_flush_cache(iommu, context, sizeof(*context));
	context_present_cache_flush(hyp_iommu, param->bdf, param->did);

	return 0;
}

int pkvm_iommu_set_lm_ce(u64 param_va)
{
	struct pkvm_lm_context_param param, *param_ptr;
	struct pkvm_iommu *hyp_iommu;
	struct intel_iommu *iommu;
	u16 agaw;
	int ret;

	if (!param_va)
		return -EINVAL;

	param_ptr = (struct pkvm_lm_context_param *)kern_pkvm_va((void *)param_va);
	if (WARN_ON_ONCE(copy_pv_param_from_host(lm_context_param, param_ptr, param)))
		return -EINVAL;

	hyp_iommu = find_iommu_by_reg_phys(param.phys);
	if (!hyp_iommu)
		return -EINVAL;

	pkvm_spin_lock(&hyp_iommu->lock);
	iommu = &hyp_iommu->iommu;

	if (param.did == FLPT_DEFAULT_DID) {
		/*
		 * Passthrough will break pkvm security guarantees as
		 * device would be able to access the whole physical
		 * memory range. Use Second stage translation with host ept
		 * as second stage pagetable so as to limit device access
		 * to host memory..
		 */
		agaw = level_to_agaw(pkvm_host_ept_level());
		param.domain_pgd_gpa = pkvm_host_ept_pgd();
	} else {
		agaw = iommu->agaw;
		param.domain_pgd_gpa = host_gpa2hpa(param.domain_pgd_gpa);
	}
	pkvm_dbg("pkvm: %s: dev[%x] did:%u, agaw: %u, pgd: %llx\n",
		 __func__, param.bdf, param.did, agaw, param.domain_pgd_gpa);

	ret = set_context_entry(hyp_iommu, &param, agaw);

	pkvm_spin_unlock(&hyp_iommu->lock);

	if (!ret)
		copy_pv_param_to_host(lm_context_param, param_ptr, param);
	return ret;
}

/*
 * Calculate PDTS(PASID Directory Size) for scalable mode context entry.
 * Value of X in the PDTS field of a scalable mode context entry
 * indicates PASID directory with 2^(X + 7) entries.
 *
 * Copied from drivers/iommu/intel/pasid.c:context_get_sm_pds()
 */
static unsigned long context_get_sm_pds(u32 max_pasid)
{
	unsigned long pds, max_pde;

	max_pde = max_pasid >> PASIDDIR_SHIFT;
	pds = find_first_bit(&max_pde, MAX_NR_PASID_BITS);
	if (pds < 7)
		return 0;

	return pds - 7;
}

/*
 * Size of pasid directory in bytes, given the max pasid number
 * A pasid directory entry can address 64 pasids and a pasid
 * directory page holds 512 entries, hence one pasid dir page can
 * address (64 * 512) entries.
 * So pasid_dir_size = (max_pasid / (64 * 512)) * PAGE_SIZE
 *                   = (max_pasid >> 15) << PAGE_SHIFT
 */
#define pasid_dir_size(max_pasid) ((max_pasid) >> (15 - PAGE_SHIFT))

int pkvm_iommu_set_sm_ce(u64 param_va)
{
	struct pkvm_sm_context_param param, *param_ptr;
	u64 pasid_dir_pa, pasid_dir_sz;
	struct context_entry *context;
	struct pkvm_iommu *hyp_iommu;
	struct intel_iommu *iommu;
	unsigned long pds;
	void *pasid_dir;
	u8 bus, devfn;
	int ret;

	if (!param_va)
		return -EINVAL;

	param_ptr = (struct pkvm_sm_context_param *)kern_pkvm_va((void *)param_va);
	if (WARN_ON_ONCE(copy_pv_param_from_host(sm_context_param, param_ptr, param)))
		return -EINVAL;

	hyp_iommu = find_iommu_by_reg_phys(param.phys);
	if (!hyp_iommu)
		return -EINVAL;

	if (!param.pasid_dir_gpa)
		return -EINVAL;

	if (param.ats_supported && !is_dev_in_satc(param.bdf)) {
		pkvm_err("pkvm: device[%x]: host reports ats supported, but not in satc\n",
			 param.bdf);
		return -EPERM;
	}

	iommu = &hyp_iommu->iommu;
	if (!sm_supported(iommu)) {
		pkvm_err("pkvm: %s: iommu%d doesn't support scalable mode!\n",
			 __func__, iommu->seq_id);
		return -EINVAL;
	};

	pkvm_dbg("pkvm: %s: dev[%x] max_pasid: %u, pasid_dir: %llx\n",
		 __func__, param.bdf, param.max_pasid, param.pasid_dir_gpa);

	pkvm_spin_lock(&hyp_iommu->lock);
	bus = PCI_BUS_NUM(param.bdf);
	devfn = PCI_DEV_FN(param.bdf);
	context = pkvm_iommu_context_addr(iommu, bus, devfn, &param.context_gpa);
	if (!context) {
		pkvm_spin_unlock(&hyp_iommu->lock);
		return -ENOMEM;
	}

	if (context_present(context)) {
		pkvm_spin_unlock(&hyp_iommu->lock);
		return 0;
	}

	pasid_dir_pa = host_gpa2hpa(param.pasid_dir_gpa);
	pasid_dir_sz = pasid_dir_size(param.max_pasid);
	pasid_dir = pkvm_phys_to_virt(pasid_dir_pa);
	ret = __pkvm_host_donate_hyp_share_ro(pasid_dir_pa, pasid_dir_sz);
	if (ret) {
		pkvm_spin_unlock(&hyp_iommu->lock);
		pkvm_err("pkvm: %s: failed to write protect pasid dir pages(err=%d)\n",
			 __func__, ret);
		return ret;
	}
	memset(pasid_dir, 0, pasid_dir_sz);
	__pkvm_iommu_flush_cache(iommu, pasid_dir, pasid_dir_sz);

	context_clear_entry(context);

	pds = context_get_sm_pds(param.max_pasid);
	context->lo = pasid_dir_pa | context_pdts(pds);
	context_set_sm_rid2pasid(context, IOMMU_NO_PASID);

	if (param.ats_supported)
		context_set_sm_dte(context);
	if (ecap_pasid(iommu->ecap))
		context_set_pasid(context);

	context_set_fault_enable(context);
	context_set_present(context);

	__pkvm_iommu_flush_cache(iommu, context, sizeof(*context));
	pkvm_spin_unlock(&hyp_iommu->lock);

	/*
	 * It's a non-present to present mapping. If hardware doesn't cache
	 * non-present entry we don't need to flush the caches. If it does
	 * cache non-present entries, then it does so in the special
	 * domain #0, which we have to flush:
	 */
	if (cap_caching_mode(iommu->cap)) {
		flush_context_cache(hyp_iommu, 0, param.bdf,
				    DMA_CCMD_MASK_NOBIT, DMA_CCMD_DEVICE_INVL);
		flush_iotlb(hyp_iommu, 0, 0, 0, DMA_TLB_DSI_FLUSH);
	}

	copy_pv_param_to_host(sm_context_param, param_ptr, param);
	return 0;
}
