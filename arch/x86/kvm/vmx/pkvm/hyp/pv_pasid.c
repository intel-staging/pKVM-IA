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
#include "iommu_domain.h"

static void __pasid_setup_fl(struct intel_iommu *iommu, struct pasid_entry *pe, u64 flptr,
			     u16 did, bool force_snoop)
{
	pasid_clear_entry(pe);
	pasid_set_flptr(pe, flptr);

	if (agaw_to_level(iommu->agaw) == 5 && cap_fl5lp_support(iommu->cap))
		pasid_set_flpm(pe, 1);

	if (force_snoop)
		pasid_set_pgsnp(pe);

	pasid_set_domain_id(pe, did);
	pasid_set_address_width(pe, iommu->agaw);
	pasid_set_page_snoop(pe, !!ecap_smpwc(iommu->ecap));
	pasid_set_translation_type(pe, PASID_ENTRY_PGTT_FL_ONLY);

	pasid_set_present(pe);
}

static void __pasid_setup_sl(struct intel_iommu *iommu, struct pasid_entry *pe, u64 slptr,
			     u16 did, u8 agaw, bool dirty_tracking)
{
	pasid_clear_entry(pe);
	pasid_set_domain_id(pe, did);
	pasid_set_slptr(pe, slptr);
	pasid_set_address_width(pe, agaw);
	pasid_set_translation_type(pe, PASID_ENTRY_PGTT_SL_ONLY);
	pasid_set_fault_enable(pe);
	pasid_set_page_snoop(pe, !!ecap_smpwc(iommu->ecap));
	pasid_set_ssade(pe, dirty_tracking);

	pasid_set_present(pe);
}

int pkvm_pasid_free_table(struct pasid_dir_entry *dir, int max_pde)
{
	struct pasid_entry *table;
	int i, ret = 0, _ret;

	for (i = 0; i < max_pde; i++) {
		table = get_pasid_table_from_pde(&dir[i]);
		if (!table)
			continue;
		_ret = __pkvm_hyp_donate_host_unshare_ro(pkvm_virt_to_phys(table), VTD_PAGE_SIZE);
		if (_ret) {
			pkvm_err("pkvm: %s: failed to remove write protect pasid entry: %llx (err=%d)\n",
				  __func__, pkvm_virt_to_phys(table), _ret);
			ret = _ret;
		}
	}

	_ret = __pkvm_hyp_donate_host_unshare_ro(pkvm_virt_to_phys(dir),
						 ALIGN(max_pde * 8, VTD_PAGE_SIZE));
	if (_ret) {
		pkvm_err("pkvm: %s: failed to remove write protect pasid dir: %llx (err=%d)\n",
			 __func__, pkvm_virt_to_phys(dir), _ret);
		ret = _ret;
	}

	return ret;
}

static int pkvm_pasid_get_entry(struct intel_iommu *iommu, u32 pasid, u16 bdf,
				u64 *ptable_gpa, struct pasid_entry **pte)
{
	struct pasid_dir_entry *dir;
	struct pasid_entry *entries;
	struct context_entry *context;
	u8 bus, devfn;
	int dir_index, index;
	u32 pds, max_pasid;

	bus = PCI_BUS_NUM(bdf);
	devfn = PCI_DEV_FN(bdf);
	context = pkvm_iommu_context_addr(iommu, bus, devfn, NULL);
	if (!context || !context_present(context)) {
		pkvm_err("pkvm: %s: pasid directory table not found: device=%x\n",
			 __func__, bdf);
		return -EINVAL;
	}

	pds = get_pasid_dir_size(context);
	max_pasid = pds << PASIDDIR_SHIFT;
	if (pasid >= max_pasid) {
		pkvm_err("pkvm: %s: unexpected pasid:  device[%x] pasid=%u, max_pasid=%u\n",
			 __func__, bdf, pasid, max_pasid);
		return -EINVAL;
	}

	dir = pkvm_phys_to_virt(context->lo & VTD_PAGE_MASK);
	dir_index = pasid >> PASIDDIR_SHIFT;
	index = pasid & PASID_PTE_MASK;

retry:
	entries = get_pasid_table_from_pde(&dir[dir_index]);
	if (!entries) {
		u64 ptable_hpa;
		u64 tmp;
		int ret;

		if (!ptable_gpa || !*ptable_gpa)
			return -ENOMEM;

		ptable_hpa = host_gpa2hpa(*ptable_gpa);
		entries = host_gpa2hva(*ptable_gpa);

		pkvm_dbg("pkvm: %s: write protecting pasid table: %llx\n",
			 __func__, pkvm_virt_to_phys(entries));
		ret = __pkvm_host_donate_hyp_share_ro(ptable_hpa, VTD_PAGE_SIZE);
		if (ret) {
			pkvm_err("pkvm: %s: write protect pasid table page failed(err=%d)\n",
				 __func__, ret);
			return ret;
		}
		memset(entries, 0, VTD_PAGE_SIZE);
		__pkvm_iommu_flush_cache(iommu, entries, VTD_PAGE_SIZE);

		/*
		 * The pasid directory table entry won't be freed after
		 * allocation. No worry about the race with free and
		 * clear. However, this entry might be populated by others
		 * while we are preparing it. Use theirs with a retry.
		 */
		tmp = 0ULL;
		if (!try_cmpxchg64(&dir[dir_index].val, &tmp,
				   (u64)ptable_hpa | PASID_PTE_PRESENT)) {
			ret = __pkvm_hyp_donate_host_unshare_ro(ptable_hpa, VTD_PAGE_SIZE);
			if (ret) {
				pkvm_err("pkvm: %s: undonate pasid table page failed(err=%d)\n",
					 __func__, ret);
				return ret;
			}
			goto retry;
		}
		__pkvm_iommu_flush_cache(iommu, &dir[dir_index].val, sizeof(*dir));

		/*
		 * Let the host driver know that pkvm used the donated page
		 * for pasid table.
		 */
		*ptable_gpa = 0;
	}

	*pte = &entries[index];
	return 0;
}

/*
 * This function flushes cache for a newly setup pasid table entry.
 * Caller of it should not modify the in-use pasid table entries.
 *
 * Copied from drivers/iommu/intel/pasid.c:pasid_flush_caches()
 */
static void pkvm_pasid_flush_caches(struct pkvm_iommu *hyp_iommu,
				    struct pasid_entry *pte,
				    u32 pasid, u16 did)
{
	struct intel_iommu *iommu = &hyp_iommu->iommu;

	__pkvm_iommu_flush_cache(iommu, pte, sizeof(*pte));

	if (cap_caching_mode(iommu->cap)) {
		flush_pasid_cache(hyp_iommu, did, QI_PC_PASID_SEL, pasid);
		flush_piotlb(hyp_iommu, did, pasid, 0, -1, 0);
	}
}

static bool __context_devtlb_enabled(struct intel_iommu *iommu, u16 bdf)
{
	struct context_entry *context = pkvm_iommu_context_addr(iommu,
							PCI_BUS_NUM(bdf),
							PCI_DEV_FN(bdf), NULL);

	if (WARN_ON(!context || !context_present(context)))
		return false;
	return context_get_sm_dte(context);
}

int pkvm_iommu_clear_pasid_entry(u64 param_va)
{
	struct pkvm_clear_translation_param param, *param_ptr;
	struct pkvm_iommu_domain *domain;
	struct pkvm_iommu *hyp_iommu;
	struct intel_iommu *iommu;
	struct pasid_entry *pte;
	u64 pgd_pa = 0;
	u16 did, pgtt;
	int ret;

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

	pkvm_spin_lock(&hyp_iommu->lock);
	iommu = &hyp_iommu->iommu;
	ret = pkvm_pasid_get_entry(iommu, param.pasid, param.bdf, NULL, &pte);
	if (ret) {
		pkvm_err("pkvm: %s: failed to get pasid table entry for device[%x] (err=%d)\n",
			 __func__, param.bdf, ret);
		goto out_unlock;
	}
	if (!pasid_pte_is_present(pte)) {
		pkvm_err("pkvm: %s: pte for teardown not present!\n", __func__);
		ret = -ENODEV;
		goto out_unlock;
	}

	did = pasid_get_domain_id(pte);
	pgtt = pasid_get_translation_type(pte);
	if (pgtt == PASID_ENTRY_PGTT_FL_ONLY)
		pgd_pa = pasid_get_flptr(pte);
	else if (pgtt == PASID_ENTRY_PGTT_SL_ONLY)
		pgd_pa = pasid_get_slptr(pte);

	if (did != FLPT_DEFAULT_DID) {
		/*
		 * We are guaranteed to have a reference on domain
		 * if the domain exists. So get the domain without
		 * incrementing reference count. We are retrieving
		 * the domain to decrement its reference count we
		 * took during pasid entry update.
		 */
		domain = pkvm_get_iommu_domain_noref(pgd_pa);
		if (WARN_ON(!domain)) {
			ret = -EFAULT;
			goto out_unlock;
		}
	}
	pkvm_dbg("pkvm: %s: dev[%x] pasid: %u, did: %u, pgd: %llx\n",
		 __func__, param.bdf, param.pasid, did, pgd_pa);

	pasid_clear_entry(pte);
	ret = 0;

out_unlock:
	pkvm_spin_unlock(&hyp_iommu->lock);

	if (ret)
		return ret;

	__pkvm_iommu_flush_cache(iommu, pte, sizeof(*pte));

	flush_pasid_cache(hyp_iommu, did, QI_PC_PASID_SEL, param.pasid);

	if (pgtt == PASID_ENTRY_PGTT_PT || pgtt == PASID_ENTRY_PGTT_FL_ONLY)
		flush_piotlb(hyp_iommu, did, param.pasid, 0, -1, 0);
	else
		flush_iotlb(hyp_iommu, did, 0, 0, DMA_TLB_DSI_FLUSH);

	/* Copied from drivers/iommu/intel/pasid.c:devtlb_invalidation_with_pasid() */
	if (is_dev_in_satc(param.bdf)) {
		u16 pfsid = 0;

		if (ecap_dit(iommu->ecap))
			pfsid = param.bdf;
		if (param.pasid == IOMMU_NO_PASID)
			flush_dev_iotlb(hyp_iommu, param.bdf, pfsid,
					param.ats_qdep, 0, 64 - VTD_PAGE_SHIFT);
		else
			flush_dev_iotlb_pasid(hyp_iommu, param.bdf, pfsid, param.pasid,
					param.ats_qdep, 0, 64 - VTD_PAGE_SHIFT);
	}

	if (did == FLPT_DEFAULT_DID) {
		atomic_dec(&hyp_iommu->pt_cnt);
	} else {
		pkvm_iommu_cache_unassign_domain(hyp_iommu, domain, did, param.bdf, param.pasid,
						 __context_devtlb_enabled(iommu, param.bdf));

		pkvm_put_iommu_domain(domain);
	}

	return 0;
}

/* Set up the scalable mode pasid table entry for first only translation type. */
int pkvm_iommu_set_pasid_fl(u64 param_va)
{
	struct pkvm_pasid_table_param param, *param_ptr;
	struct pkvm_iommu_domain *domain;
	struct pkvm_iommu *hyp_iommu;
	struct intel_iommu *iommu;
	struct pasid_entry *pte;
	u64 pgd_pa;
	int ret;

	if (!param_va)
		return -EINVAL;

	param_ptr = (struct pkvm_pasid_table_param *)kern_pkvm_va((void *)param_va);
	if (WARN_ON_ONCE(copy_pv_param_from_host(pasid_table_param, param_ptr, param)))
		return -EINVAL;

	hyp_iommu = find_iommu_by_reg_phys(param.phys);
	if (!hyp_iommu)
		return -EINVAL;
	iommu = &hyp_iommu->iommu;
	if (!ecap_flts(iommu->ecap)) {
		pr_err("pkvm: %s: No first level translation support on iommu%d\n",
		       __func__, iommu->seq_id);
		return -EOPNOTSUPP;
	}

	pgd_pa = host_gpa2hpa(param.domain_pgd_gpa);
	pkvm_dbg("pkvm: %s: dev[%x] pasid: %x, did: %u, flptr: %llx\n",
		 __func__, param.bdf, param.pasid,
		 param.did, pgd_pa);

	pkvm_spin_lock(&hyp_iommu->lock);
	ret = pkvm_pasid_get_entry(iommu, param.pasid, param.bdf,
				   &param.pasid_table_gpa, &pte);
	if (ret)
		goto out_unlock;

	if (pasid_pte_is_present(pte)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	/* Verify the domain is present and take a reference. */
	domain = pkvm_get_iommu_domain(pgd_pa);
	if (!domain) {
		pkvm_err("pkvm: %s: Failed to locate domain with pgd: %llx\n",
			 __func__, pgd_pa);
		ret = -EFAULT;
		goto out_unlock;
	}

	ret = pkvm_iommu_cache_assign_domain(hyp_iommu, domain, param.did,
					     param.bdf, param.ats_qdep, param.pasid,
					     __context_devtlb_enabled(iommu, param.bdf));
	if (ret) {
		pkvm_put_iommu_domain(domain);
		goto out_unlock;
	}

	/*
	 * force snoop in host is done currently only by vfio and iommufd.
	 * pkvm doesn't support those yet.
	 */
	__pasid_setup_fl(iommu, pte, pgd_pa,
			 param.did, false /* force snoop */);

out_unlock:
	pkvm_spin_unlock(&hyp_iommu->lock);

	if (!ret) {
		pkvm_pasid_flush_caches(hyp_iommu, pte, param.pasid, param.did);
		copy_pv_param_to_host(pasid_table_param, param_ptr, param);
	}

	return ret;
}

int pkvm_iommu_set_pasid_sl(u64 param_va)
{
	struct pkvm_pasid_table_param param, *param_ptr;
	struct pkvm_iommu *hyp_iommu;
	struct intel_iommu *iommu;
	struct pasid_entry *pte;
	u64 pgd_pa;
	u16 agaw;
	int ret;

	if (!param_va)
		return -EINVAL;

	param_ptr = (struct pkvm_pasid_table_param *)kern_pkvm_va((void *)param_va);
	if (WARN_ON_ONCE(copy_pv_param_from_host(pasid_table_param, param_ptr, param)))
		return -EINVAL;

	hyp_iommu = find_iommu_by_reg_phys(param.phys);
	if (!hyp_iommu)
		return -EINVAL;
	iommu = &hyp_iommu->iommu;
	if (!ecap_slts(iommu->ecap)) {
		pkvm_err("pkvm: %s: No second level translation support on iommu%d\n",
		       __func__, iommu->seq_id);
		return -EOPNOTSUPP;
	}

	pkvm_dbg("pkvm: %s: dev[%x] pasid: %x, did: %u, slptr: %llx\n",
		 __func__, param.bdf, param.pasid,
		 param.did, param.domain_pgd_gpa);

	pkvm_spin_lock(&hyp_iommu->lock);
	ret = pkvm_pasid_get_entry(iommu, param.pasid, param.bdf,
				   &param.pasid_table_gpa, &pte);
	if (ret)
		goto out_unlock;

	if (pasid_pte_is_present(pte)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	if (param.did == FLPT_DEFAULT_DID) {
		atomic_inc(&hyp_iommu->pt_cnt);

		/*
		 * Passthrough will break pkvm security guarantees as
		 * device would be able to access the whole physical
		 * memory range. Use Second stage translation with
		 * host ept as second stage pagetable so as to limit
		 * device access to host memory.
		 */
		agaw = level_to_agaw(pkvm_host_ept_level());
		pgd_pa = pkvm_host_ept_pgd();
	} else {
		struct pkvm_iommu_domain *domain;

		agaw = iommu->agaw;
		pgd_pa = host_gpa2hpa(param.domain_pgd_gpa);

		/* Verify the domain is present and take a reference. */
		domain = pkvm_get_iommu_domain(pgd_pa);
		if (!domain) {
			pkvm_err("pkvm: %s: Failed to locate domain with pgd: %llx\n",
				 __func__, pgd_pa);
			ret = -EFAULT;
			goto out_unlock;
		}

		ret = pkvm_iommu_cache_assign_domain(hyp_iommu, domain, param.did,
						     param.bdf, param.ats_qdep, param.pasid,
						     __context_devtlb_enabled(iommu, param.bdf));
		if (ret) {
			pkvm_put_iommu_domain(domain);
			goto out_unlock;
		}
	}
	__pasid_setup_sl(iommu, pte, pgd_pa, param.did,
			 agaw, param.dirty_tracking);

out_unlock:
	pkvm_spin_unlock(&hyp_iommu->lock);

	if (!ret) {
		pkvm_pasid_flush_caches(hyp_iommu, pte, param.pasid,
					param.did);
		copy_pv_param_to_host(pasid_table_param, param_ptr, param);
	}

	return ret;
}
