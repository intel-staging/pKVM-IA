// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Intel Corporation
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
#include "iommu_internal.h"
#include "debug.h"
#include "ptdev.h"
#include "iommu_spgt.h"
#include "bug.h"
#include "iommu.h"

/* Used in legacy mode only. */
struct shadow_pgt_sync_data {
	unsigned long vaddr;
	unsigned long vaddr_end;
};

/*
 * Guest root/context/pasid table (hereinafter "id table") walking parameter.
 * pkvm IOMMU driver walks the guest page table when syncing
 * with the shadow id table.
 */
struct id_sync_walk_data {
	struct pkvm_iommu *iommu;
	/*
	 * Used to hold shadow id table physical address
	 * which is used for sync shadow entries at each
	 * id table level.
	 */
	u64 shadow_pa[IOMMU_SM_LEVEL_NUM];
	/*
	 * Used when just syncing a part of shadow
	 * id table entries which match with this did if
	 * it is set as a non-zero did value.
	 */
	u16 did;
	/*
	 * Used in legacy mode when just syncing a specific
	 * range of pages in shadow page tables.
	 */
	struct shadow_pgt_sync_data *spgt_data;
};

#define DEFINE_ID_SYNC_WALK_DATA(name, _iommu, domain_id, _spgt_data)	\
	struct id_sync_walk_data (name) = {				\
		.iommu = (_iommu),					\
		.shadow_pa = {0},					\
		.did = (domain_id),					\
		.spgt_data = (_spgt_data),				\
	}

/*
 * Used to config a shadow id table entry in root/context/pasid
 * level.
 */
struct id_sync_data {
	union {
		u64 root_entry;
		struct context_entry ct_entry;
		struct pasid_dir_entry pd_entry;
		struct pasid_entry p_entry;
	};
	void *guest_ptep;
	void *shadow_ptep;
	int level;
	u64 iommu_ecap;
	u64 shadow_pa;
	struct pkvm_pgtable *shadow_id;
	unsigned long vaddr;
	struct shadow_pgt_sync_data *spgt_data;
};

static const struct pkvm_mm_ops viommu_mm_ops = {
	.phys_to_virt = host_gpa2hva,
};

static bool iommu_id_entry_present(void *ptep)
{
	u64 val;

	val = *(u64 *)ptep;
	return !!(val & 1);
}

static unsigned long iommu_id_entry_to_phys(void *ptep)
{
	u64 val = *(u64 *)ptep;

	return val & VTD_PAGE_MASK;
}

static int iommu_sm_id_entry_to_index(unsigned long vaddr, int level)
{
	switch (level) {
	case IOMMU_PASID_TABLE:
		return vaddr & (BIT(PASIDDIR_BITS) - 1);
	case IOMMU_PASID_DIR:
		return (vaddr >> PASIDDIR_SHIFT) & (BIT(PASIDDIR_BITS) - 1);
	case IOMMU_SM_CONTEXT:
		return (vaddr >> DEVFN_SHIFT) & (BIT(SM_DEVFN_BITS) - 1);
	case IOMMU_SM_ROOT:
		return (vaddr >> SM_BUS_SHIFT) & (BIT(SM_BUS_BITS) - 1);
	default:
		break;
	}

	return -EINVAL;
}

static bool iommu_id_entry_is_leaf(void *ptep, int level)
{
	if (LAST_LEVEL(level) ||
		!iommu_id_entry_present(ptep))
		return true;

	return false;
}

static int iommu_sm_id_level_entry_size(int level)
{
	switch (level) {
	case IOMMU_PASID_TABLE:
		return sizeof(struct pasid_entry);
	case IOMMU_PASID_DIR:
		return sizeof(struct pasid_dir_entry);
	case IOMMU_SM_CONTEXT:
		/* scalable mode requires 32bytes for context */
		return sizeof(struct context_entry) * 2;
	case IOMMU_SM_ROOT:
		return sizeof(u64);
	default:
		break;
	}

	return -EINVAL;
}

static int iommu_sm_id_level_to_entries(int level)
{
	switch (level) {
	case IOMMU_PASID_TABLE:
		return 1 << PASIDTAB_BITS;
	case IOMMU_PASID_DIR:
		return 1 << PASIDDIR_BITS;
	case IOMMU_SM_CONTEXT:
		return 1 << SM_DEVFN_BITS;
	case IOMMU_SM_ROOT:
		return 1 << SM_BUS_BITS;
	default:
		break;
	}

	return -EINVAL;
}

static unsigned long iommu_sm_id_level_to_size(int level)
{
	switch (level) {
	case IOMMU_PASID_TABLE:
		return 1;
	case IOMMU_PASID_DIR:
		return 1 << PASIDDIR_SHIFT;
	case IOMMU_SM_CONTEXT:
		return 1 << DEVFN_SHIFT;
	case IOMMU_SM_ROOT:
		return 1 << SM_BUS_SHIFT;
	default:
		break;
	}

	return 0;
}

const struct pkvm_pgtable_ops iommu_sm_id_ops = {
	.pgt_entry_present = iommu_id_entry_present,
	.pgt_entry_to_phys = iommu_id_entry_to_phys,
	.pgt_entry_to_index = iommu_sm_id_entry_to_index,
	.pgt_entry_is_leaf = iommu_id_entry_is_leaf,
	.pgt_level_entry_size = iommu_sm_id_level_entry_size,
	.pgt_level_to_entries = iommu_sm_id_level_to_entries,
	.pgt_level_to_size = iommu_sm_id_level_to_size,
};

static int iommu_lm_id_entry_to_index(unsigned long vaddr, int level)
{
	switch (level) {
	case IOMMU_LM_CONTEXT:
		return (vaddr >> LM_DEVFN_SHIFT) & (BIT(LM_DEVFN_BITS) - 1);
	case IOMMU_LM_ROOT:
		return (vaddr >> LM_BUS_SHIFT) & (BIT(LM_BUS_BITS) - 1);
	default:
		break;
	}

	return -EINVAL;
}

static int iommu_lm_id_level_entry_size(int level)
{
	switch (level) {
	case IOMMU_LM_CONTEXT:
		return sizeof(struct context_entry);
	case IOMMU_LM_ROOT:
		return sizeof(struct root_entry);
	default:
		break;
	}

	return -EINVAL;
}

static int iommu_lm_id_level_to_entries(int level)
{
	switch (level) {
	case IOMMU_LM_CONTEXT:
		return 1 << LM_DEVFN_BITS;
	case IOMMU_LM_ROOT:
		return 1 << LM_BUS_BITS;
	default:
		break;
	}

	return -EINVAL;
}

static unsigned long iommu_lm_id_level_to_size(int level)
{
	switch (level) {
	case IOMMU_LM_CONTEXT:
		return 1 << LM_DEVFN_SHIFT;
	case IOMMU_LM_ROOT:
		return 1 << LM_BUS_SHIFT;
	default:
		break;
	}

	return 0;
}

const struct pkvm_pgtable_ops iommu_lm_id_ops = {
	.pgt_entry_present = iommu_id_entry_present,
	.pgt_entry_to_phys = iommu_id_entry_to_phys,
	.pgt_entry_to_index = iommu_lm_id_entry_to_index,
	.pgt_entry_is_leaf = iommu_id_entry_is_leaf,
	.pgt_level_entry_size = iommu_lm_id_level_entry_size,
	.pgt_level_to_entries = iommu_lm_id_level_to_entries,
	.pgt_level_to_size = iommu_lm_id_level_to_size,
};

static int iommu_pgtable_walk(struct pkvm_pgtable *pgt, unsigned long vaddr,
		       unsigned long vaddr_end, struct pkvm_pgtable_walker *walker)
{
	if (!pgt->root_pa)
		return 0;

	return pgtable_walk(pgt, vaddr, vaddr_end - vaddr, false, walker);
}

static struct pkvm_ptdev *iommu_find_ptdev(struct pkvm_iommu *iommu, u16 bdf, u32 pasid)
{
	struct pkvm_ptdev *p;

	list_for_each_entry(p, &iommu->ptdev_head, iommu_node) {
		if (match_ptdev(p, bdf, pasid))
			return p;
	}

	return NULL;
}

static struct pkvm_ptdev *iommu_add_ptdev(struct pkvm_iommu *iommu, u16 bdf, u32 pasid)
{
	struct pkvm_ptdev *ptdev = pkvm_get_ptdev(bdf, pasid);

	if (!ptdev) {
		ptdev = pkvm_alloc_ptdev(bdf, pasid, iommu_coherency(&iommu->iommu));
		if (!ptdev)
			return NULL;
	}

	list_add_tail(&ptdev->iommu_node, &iommu->ptdev_head);
	return ptdev;
}

static void iommu_del_ptdev(struct pkvm_iommu *iommu, struct pkvm_ptdev *ptdev)
{
	list_del_init(&ptdev->iommu_node);
	pkvm_put_ptdev(ptdev);
}

static int iommu_audit_did(struct pkvm_iommu *iommu, u16 did, int shadow_vm_handle)
{
	struct pkvm_ptdev *tmp;
	int ret = 0;

	list_for_each_entry(tmp, &iommu->ptdev_head, iommu_node) {
		if (tmp->shadow_vm_handle != shadow_vm_handle) {
			if (tmp->did == did) {
				/*
				 * The devices belong to different VMs but behind
				 * the same IOMMU, cannot use the same did.
				 */
				ret = -EPERM;
				break;
			}
		}
	}

	return ret;
}

static int shadow_pgt_map_leaf(struct pkvm_pgtable *pgt, unsigned long vaddr, int level,
			       void *ptep, struct pgt_flush_data *flush_data, void *arg)
{
	struct pkvm_pgtable_map_data *data = arg;
	const struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	struct hyp_page *old_page = NULL, *new_page = NULL;
	unsigned long map_phys;
	int ret = 0;
	u64 old, new, phys;

	host_ept_lock();

	pkvm_host_ept_lookup(data->phys, &map_phys, NULL, NULL);
	if (map_phys == INVALID_ADDR) {
		pkvm_err("pkvm: phys addr 0x%lx not mapped in host ept\n", data->phys);
		goto out;
	}

	old = *(u64 *)ptep;
	ret = pgtable_map_leaf(pgt, vaddr, level, ptep, flush_data, arg);
	new = *(u64 *)ptep;

	if (pgt_ops->pgt_entry_present(&old)) {
		phys = pgt_ops->pgt_entry_to_phys(&old);
		old_page = hyp_phys_to_page_safe(phys);
	}

	if (pgt_ops->pgt_entry_present(&new)) {
		phys = pgt_ops->pgt_entry_to_phys(&new);
		new_page = hyp_phys_to_page_safe(phys);
	}

	if (new_page == old_page)
		goto out;

	if (old_page)
		hyp_page_ref_dec(old_page);

	if (new_page)
		hyp_page_ref_inc(new_page);

out:
	host_ept_unlock();
	return ret;
}

static int shadow_pgt_unmap_leaf(struct pkvm_pgtable *pgt, unsigned long vaddr,
			      int level, void *ptep, struct pgt_flush_data *flush_data,
			      void *const arg)
{
	struct hyp_page *page;
	u64 phys;

	if (pgt->pgt_ops->pgt_entry_present(ptep)) {
		phys = pgt->pgt_ops->pgt_entry_to_phys(ptep);
		page = hyp_phys_to_page_safe(phys);
		if (page)
			hyp_page_ref_dec(page);
	}

	pgtable_unmap_leaf(pgt, vaddr, level, ptep, flush_data, arg);
	return 0;
}

/* used in legacy mode only */
static void sync_shadow_pgt(struct pkvm_ptdev *ptdev, struct shadow_pgt_sync_data *sdata)
{
	struct pkvm_pgtable *spgt;
	int ret;

	PKVM_ASSERT(is_pgt_ops_ept(&ptdev->vpgt));

	/*
	 * ptdev->pgt should be already set to this shadow iommu pgtable.
	 * However, ptdev->pgt could change in the meantime due to ptdev
	 * attach to a VM. So to avoid race, do not use ptdev->pgt directly
	 * but get the same shadow iommu pgtable on our own.
	 */
	spgt = pkvm_get_host_iommu_spgt(ptdev->vpgt.root_pa, ptdev->iommu_coherency);
	PKVM_ASSERT(spgt);

	if (sdata)
		ret = pkvm_pgtable_sync_map_range(&ptdev->vpgt, spgt,
						  sdata->vaddr,
						  sdata->vaddr_end - sdata->vaddr,
						  NULL, shadow_pgt_map_leaf, shadow_pgt_unmap_leaf);
	else
		ret = pkvm_pgtable_sync_map(&ptdev->vpgt, spgt,
					    NULL, shadow_pgt_map_leaf, shadow_pgt_unmap_leaf);
	PKVM_ASSERT(ret == 0);

	pkvm_put_host_iommu_spgt(spgt, ptdev->iommu_coherency);
}

/* present root entry when shadow_pa valid, otherwise un-present it */
static bool sync_root_entry(struct id_sync_data *sdata)
{
	u64 *sre = sdata->shadow_ptep;
	u64 sre_val = sdata->shadow_pa ? (sdata->shadow_pa | 1) : 0;

	if (READ_ONCE(*sre) != sre_val) {
		WRITE_ONCE(*sre, sre_val);
		return true;
	}

	return false;
}

/* sync context entry when guest_ptep & shadow_pa valid, otherwise un-present it */
static bool sync_shadow_context_entry(struct id_sync_data *sdata)
{
	struct context_entry *shadow_ce = sdata->shadow_ptep, tmp = {0};
	struct context_entry *guest_ce = sdata->guest_ptep;
	struct pkvm_iommu *iommu = pgt_to_pkvm_iommu(sdata->shadow_id);
	struct pkvm_ptdev *ptdev;
	struct pkvm_pgtable_cap cap;
	bool updated = false;
	u8 tt, aw;
	u16 bdf, did;

	if (sm_supported(&iommu->iommu)) {
		if (sdata->guest_ptep && sdata->shadow_pa) {
			bdf = sdata->vaddr >> DEVFN_SHIFT;
			tmp.hi = guest_ce->hi;
			tmp.lo = sdata->shadow_pa | (guest_ce->lo & 0xfff);

			/*
			 * Make sure device TLB is disabled for security, unless
			 * the device is explicitly trusted to use it.
			 */
			if (!is_dev_in_satc(bdf))
				context_sm_clear_dte(&tmp);
		}
	} else {
		/*
		 * In legacy mode, a context entry is a leaf entry responsible for
		 * configuring the actual address translation for the given ptdev,
		 * much like a PASID table entry in scalable mode. So the below logic
		 * is quite similar to the logic in sync_shadow_pasid_table_entry()
		 * for scalable mode.
		 */
		bdf = sdata->vaddr >> LM_DEVFN_SHIFT;
		ptdev = iommu_find_ptdev(iommu, bdf, 0);

		if (!ptdev) {
			ptdev = iommu_add_ptdev(iommu, bdf, 0);
			if (!ptdev)
				return false;
		}

		if (!sdata->guest_ptep) {
			if (context_lm_is_present(shadow_ce)) {
				pkvm_setup_ptdev_vpgt(ptdev, 0, NULL, NULL, NULL, false);
				pkvm_setup_ptdev_did(ptdev, 0);
				iommu_del_ptdev(iommu, ptdev);

				goto update_shadow_ce;
			}
			return false;
		}

		tt = context_lm_get_tt(guest_ce);
		switch (tt) {
		case CONTEXT_TT_MULTI_LEVEL:
		case CONTEXT_TT_DEV_IOTLB:
			aw = context_lm_get_aw(guest_ce);
			if (aw != 1 && aw != 2 && aw != 3) {
				pkvm_err("pkvm: unsupported address width %u\n", aw);

				pkvm_setup_ptdev_vpgt(ptdev, 0, NULL, NULL, NULL, false);
				pkvm_setup_ptdev_did(ptdev, 0);

				/*
				 * TODO: our error reporting to the host for invalid
				 * values of aw or tt is not good: the host will see
				 * translation fault reason "present bit is clear"
				 * instead of "invalid entry".
				 */
				goto update_shadow_ce;
			}
			cap.level = (aw == 1) ? 3 :
				    (aw == 2) ? 4 : 5;
			cap.allowed_pgsz = pkvm_hyp->ept_cap.allowed_pgsz;
			pkvm_setup_ptdev_vpgt(ptdev, context_lm_get_slptr(guest_ce),
					      &viommu_mm_ops, &ept_ops, &cap, true);

			if (!ptdev_attached_to_vm(ptdev))
				sync_shadow_pgt(ptdev, sdata->spgt_data);

			break;
		case CONTEXT_TT_PASS_THROUGH:
			/*
			 * When host IOMMU driver is using pass-through mode, pkvm
			 * IOMMU will actually use the address translation
			 * (CONTEXT_TT_MULTI_LEVEL) with the primary VM's EPT
			 * to guarantee the protection.
			 */
			break;
		default:
			pkvm_err("pkvm: unsupported translation type %u\n", tt);

			pkvm_setup_ptdev_vpgt(ptdev, 0, NULL, NULL, NULL, false);
			pkvm_setup_ptdev_did(ptdev, 0);
			goto update_shadow_ce;
		}

		did = context_lm_get_did(guest_ce);
		if (iommu_audit_did(iommu, did, ptdev->shadow_vm_handle))
			return false;

		pkvm_setup_ptdev_did(ptdev, did);

		if (!is_pgt_ops_ept(ptdev->pgt))
			return false;

		tmp = *guest_ce;

		/*
		 * Always set translation type to MULTI_LEVEL to ensure address
		 * translation and to disable device TLB for security.
		 */
		context_lm_set_tt(&tmp, CONTEXT_TT_MULTI_LEVEL);
		context_lm_set_slptr(&tmp, ptdev->pgt->root_pa);
		aw = (ptdev->pgt->level == 3) ? 1 :
		     (ptdev->pgt->level == 4) ? 2 : 3;
		context_lm_set_aw(&tmp, aw);
	}

update_shadow_ce:
	if (READ_ONCE(shadow_ce->hi) != tmp.hi) {
		WRITE_ONCE(shadow_ce->hi, tmp.hi);
		updated = true;
	}

	if (READ_ONCE(shadow_ce->lo) != tmp.lo) {
		WRITE_ONCE(shadow_ce->lo, tmp.lo);
		updated = true;
	}

	return updated;
}

/* sync pasid dir entry when guest_ptep & shadow_pa valid, otherwise un-present it */
static bool sync_shadow_pasid_dir_entry(struct id_sync_data *sdata)
{
	struct pasid_dir_entry *shadow_pde = sdata->shadow_ptep;
	u64 val = 0;

	if (sdata->guest_ptep && sdata->shadow_pa) {
		struct pasid_dir_entry *guest_pde = sdata->guest_ptep;

		val = guest_pde->val & (PASID_PTE_FPD | PASID_PTE_PRESENT);
		val |= sdata->shadow_pa;
	}

	if (READ_ONCE(shadow_pde->val) != val) {
		WRITE_ONCE(shadow_pde->val, val);
		return true;
	}

	return false;
}

/* sync pasid table entry when guest_ptep valid, otherwise un-present it */
static bool sync_shadow_pasid_table_entry(struct id_sync_data *sdata)
{
	u16 bdf = sdata->vaddr >> DEVFN_SHIFT;
	u32 pasid = sdata->vaddr & ((1UL << MAX_NR_PASID_BITS) - 1);
	struct pkvm_iommu *iommu = pgt_to_pkvm_iommu(sdata->shadow_id);
	struct pkvm_ptdev *ptdev = iommu_find_ptdev(iommu, bdf, pasid);
	struct pasid_entry *shadow_pte = sdata->shadow_ptep, tmp_pte = {0};
	struct pasid_entry *guest_pte;
	bool synced = false;
	u64 type, aw;

	if (!ptdev) {
		ptdev = iommu_add_ptdev(iommu, bdf, pasid);
		if (!ptdev)
			return false;
	}

	if (!sdata->guest_ptep) {
		if (pasid_pte_is_present(shadow_pte)) {
			/*
			 * Making a pasid entry not present needs to remove
			 * the corresponding ptdev from IOMMU. It also means
			 * a ptdev's vpgt/did should be reset as well as
			 * deleting ptdev from this iommu.
			 */
			pkvm_setup_ptdev_vpgt(ptdev, 0, NULL, NULL, NULL, false);
			pkvm_setup_ptdev_did(ptdev, 0);
			iommu_del_ptdev(iommu, ptdev);

			synced = pasid_copy_entry(shadow_pte, &tmp_pte);
		}
		return synced;
	}

	guest_pte = sdata->guest_ptep;
	type = pasid_pte_get_pgtt(guest_pte);
	if (type == PASID_ENTRY_PGTT_FL_ONLY) {
		struct pkvm_pgtable_cap cap;

		if (ptdev_attached_to_vm(ptdev))
			/*
			 * For the attached ptdev, use SL Only mode with
			 * using ptdev->pgt so that the translation is
			 * totally controlled by pkvm.
			 */
			type = PASID_ENTRY_PGTT_SL_ONLY;
		else
			/*
			 * For the other ptdev, pkvm IOMMU will use nested
			 * translation to add one more layer translation to
			 * guarantee the protection. This one more layer is the
			 * primary VM's EPT.
			 */
			type = PASID_ENTRY_PGTT_NESTED;

		/* ptdev vpgt can be initialized with flptr */
		cap.level = pasid_get_flpm(guest_pte) == 0 ? 4 : 5;
		cap.allowed_pgsz = pkvm_hyp->mmu_cap.allowed_pgsz;
		pkvm_setup_ptdev_vpgt(ptdev, pasid_get_flptr(guest_pte),
				      &viommu_mm_ops, &mmu_ops, &cap, false);
	} else if (type == PASID_ENTRY_PGTT_PT) {
		/*
		 * When host IOMMU driver is using pass-through mode, pkvm
		 * IOMMU will actually use the second-level only translation
		 * to guarantee the protection. This second-level is als
		 * the EPT.
		 */
		type = PASID_ENTRY_PGTT_SL_ONLY;
	} else {
		/*
		 * As the host IOMMU driver in the pkvm enabled kernel has
		 * already been configured to use first-level only or
		 * pass-through mode, it will not use any other mode. But
		 * in case this has happened, reset the ptdev vpgt/did while
		 * keep ptdev linked to this IOMMU, and clear the shadow entry
		 * so that not to support it.
		 */
		pkvm_setup_ptdev_vpgt(ptdev, 0, NULL, NULL, NULL, false);
		pkvm_setup_ptdev_did(ptdev, 0);

		pkvm_err("pkvm: unsupported pasid type %lld\n", type);

		return pasid_copy_entry(shadow_pte, &tmp_pte);
	}

	pkvm_setup_ptdev_did(ptdev, pasid_get_domain_id(guest_pte));

	if (iommu_audit_did(iommu, ptdev->did, ptdev->shadow_vm_handle))
		/*
		 * It is possible that this ptdev will be attached to a protected
		 * VM so primary VM allocates the same did used by this protected
		 * VM and did a TLB flush. But at this moment, this ptdev is not
		 * attached yet so audit is failed. For this case, can skip the sync
		 * of this pasid table entry and it will be synced again when this
		 * ptdev is attached.
		 *
		 * It is also possible that this ptdev is just detached from a
		 * protected VM but still using the previous did due to primary VM
		 * has not configured this ptdev yet. In this case, the did of this
		 * ptdev is still the same as the did used by other ptdevs not
		 * detached yet. For this case, can skip the sync of this pasid
		 * table entry and it will be synced again when primary VM configures
		 * this ptdev.
		 *
		 * If not the above cases but primary VM does this by purpose, also
		 * not sync the pasid table entry to guarantee the isolation.
		 */
		return false;

	/*
	 * ptdev->pgt will be used as second-level translation table
	 * which should be EPT format.
	 */
	if (!is_pgt_ops_ept(ptdev->pgt))
		return false;

	/*
	 * Copy all the bits from guest_pte. As the translation type will
	 * be re-configured in below, even some bits inherit from guest_pte
	 * but hardware will ignore those bits according to the translation
	 * type.
	 */
	memcpy(&tmp_pte, guest_pte, sizeof(struct pasid_entry));

	pasid_set_page_snoop(&tmp_pte, !!ecap_smpwc(sdata->iommu_ecap));
	if (ecap_sc_support(sdata->iommu_ecap))
		pasid_set_pgsnp(&tmp_pte);

	/*
	 * Modify the second-level related bits:
	 * Set PGTT/SLPTR/AW.
	 * Clear SLADE/SLEE
	 * Reuse FPD/P
	 */
	pasid_set_translation_type(&tmp_pte, type);
	pasid_set_slptr(&tmp_pte, ptdev->pgt->root_pa);
	aw = (ptdev->pgt->level == 4) ? 2 : 3;
	pasid_set_address_width(&tmp_pte, aw);
	pasid_set_ssade(&tmp_pte, 0);
	pasid_set_ssee(&tmp_pte, 0);

	return pasid_copy_entry(shadow_pte, &tmp_pte);
}

static bool iommu_id_sync_entry(struct id_sync_data *sdata)
{
	bool ret = false;
	struct pkvm_pgtable *shadow_id = sdata->shadow_id;
	struct pkvm_iommu *iommu = pgt_to_pkvm_iommu(shadow_id);

	if (sm_supported(&iommu->iommu)) {
		switch (sdata->level) {
		case IOMMU_PASID_TABLE:
			ret = sync_shadow_pasid_table_entry(sdata);
			break;
		case IOMMU_PASID_DIR:
			ret = sync_shadow_pasid_dir_entry(sdata);
			break;
		case IOMMU_SM_CONTEXT:
			ret = sync_shadow_context_entry(sdata);
			break;
		case IOMMU_SM_ROOT:
			ret = sync_root_entry(sdata);
			break;
		default:
			break;
		}
	} else {
		switch (sdata->level) {
		case IOMMU_LM_CONTEXT:
			ret = sync_shadow_context_entry(sdata);
			break;
		case IOMMU_LM_ROOT:
			ret = sync_root_entry(sdata);
			break;
		default:
			break;
		}
	}

	if (ret) {
		int entry_size = shadow_id->pgt_ops->pgt_level_entry_size(sdata->level);

		if (entry_size && shadow_id->mm_ops->flush_cache)
			shadow_id->mm_ops->flush_cache(sdata->shadow_ptep, entry_size);
	}

	return ret;
}

int initialize_iommu_pgt(struct pkvm_iommu *iommu)
{
	struct pkvm_pgtable *pgt = &iommu->pgt;
	struct pkvm_pgtable *vpgt = &iommu->viommu.pgt;
	static const struct pkvm_mm_ops *iommu_mm_ops;
	const struct pkvm_pgtable_ops *iommu_ops;
	struct pkvm_pgtable_cap cap;
	int ret;

	if (sm_supported(&iommu->iommu)) {
		cap.level = IOMMU_SM_ROOT;
		iommu_ops = &iommu_sm_id_ops;
	} else {
		cap.level = IOMMU_LM_ROOT;
		iommu_ops = &iommu_lm_id_ops;
	}

	ret = pkvm_pgtable_init(vpgt, &viommu_mm_ops, iommu_ops, &cap, false);
	if (ret)
		return ret;

	/*
	 * For the IOMMU without Page-Walk Coherency, should use
	 * iommu_pw_noncoherency_mm_ops to flush CPU cache when
	 * modifying any remapping structure entry.
	 *
	 * For the IOMMU with Page-Walk Coherency, can use
	 * iommu_pw_coherency_mm_ops to skip the CPU cache flushing.
	 */
	if (!ecap_coherent(iommu->iommu.ecap))
		iommu_mm_ops = &iommu_pw_noncoherency_mm_ops;
	else
		iommu_mm_ops = &iommu_pw_coherency_mm_ops;

	ret = pkvm_pgtable_init(pgt, iommu_mm_ops, iommu_ops, &cap, true);
	if (!ret) {
		/*
		 * Hold additional reference count to make
		 * sure root page won't be freed
		 */
		void *root = pgt->mm_ops->phys_to_virt(pgt->root_pa);

		pgt->mm_ops->get_page(root);
	}
	return ret;
}

static int free_shadow_id_cb(struct pkvm_pgtable *pgt, unsigned long vaddr,
			  unsigned long vaddr_end, int level, void *ptep,
			  unsigned long flags, struct pgt_flush_data *flush_data,
			  void *const arg)
{
	const struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	const struct pkvm_mm_ops *mm_ops = pgt->mm_ops;
	struct id_sync_data sync_data = {0};
	struct pkvm_iommu *iommu = pgt_to_pkvm_iommu(pgt);
	void *child_ptep;

	/* Doesn't need to do anything if the shadow entry is not present */
	if (!pgt_ops->pgt_entry_present(ptep))
		return 0;

	sync_data.shadow_ptep = ptep;
	sync_data.level = level;
	sync_data.shadow_id = pgt;
	sync_data.iommu_ecap = iommu->iommu.ecap;
	sync_data.vaddr = vaddr;

	/* Un-present a present PASID Table entry */
	if (LAST_LEVEL(level)) {
		if (iommu_id_sync_entry(&sync_data))
			mm_ops->put_page(ptep);
		return 0;
	}

	/*
	 * it's a present entry for PASID DIR, context or root.
	 * its child ptep shall already be freed (the refcnt == 1), if so, we
	 * can un-present itself as well now.
	 */
	child_ptep = mm_ops->phys_to_virt(pgt_ops->pgt_entry_to_phys(ptep));
	if (mm_ops->page_count(child_ptep) == 1) {
		if (iommu_id_sync_entry(&sync_data)) {
			mm_ops->put_page(ptep);
			mm_ops->put_page(child_ptep);
		}
	}

	return 0;
}

/* sync_data != NULL, data != NULL */
static int init_sync_id_data(struct id_sync_data *sync_data,
		struct id_sync_walk_data *data,
		struct pkvm_iommu *iommu, void *guest_ptep,
		unsigned long vaddr, int level)
{
	struct pkvm_pgtable *shadow_id = &iommu->pgt;
	int idx = shadow_id->pgt_ops->pgt_entry_to_index(vaddr, level);
	int entry_size = shadow_id->pgt_ops->pgt_level_entry_size(level);

	if (sm_supported(&iommu->iommu)) {
		switch (level) {
		case IOMMU_PASID_TABLE:
			sync_data->p_entry = *((struct pasid_entry *)guest_ptep);
			sync_data->guest_ptep = &sync_data->p_entry;
			break;
		case IOMMU_PASID_DIR:
			sync_data->pd_entry = *((struct pasid_dir_entry *)guest_ptep);
			sync_data->guest_ptep = &sync_data->pd_entry;
			break;
		case IOMMU_SM_CONTEXT:
			sync_data->ct_entry = *((struct context_entry *)guest_ptep);
			sync_data->guest_ptep = &sync_data->ct_entry;
			break;
		case IOMMU_SM_ROOT:
			sync_data->root_entry = *((u64 *)guest_ptep);
			sync_data->guest_ptep = &sync_data->root_entry;
			break;
		default:
			return -EINVAL;
		}
	} else {
		switch (level) {
		case IOMMU_LM_CONTEXT:
			sync_data->ct_entry = *((struct context_entry *)guest_ptep);
			sync_data->guest_ptep = &sync_data->ct_entry;
			break;
		case IOMMU_LM_ROOT:
			sync_data->root_entry = *((u64 *)guest_ptep);
			sync_data->guest_ptep = &sync_data->root_entry;
			break;
		default:
			return -EINVAL;
		}
	}

	/* shadow_pa of current level must be there */
	if (!data->shadow_pa[level])
		return -EINVAL;

	/* get current shadow_ptep */
	sync_data->shadow_ptep = shadow_id->mm_ops->phys_to_virt(data->shadow_pa[level]);
	sync_data->shadow_ptep += idx * entry_size;

	sync_data->level = level;
	sync_data->shadow_id = shadow_id;
	sync_data->iommu_ecap = iommu->iommu.ecap;
	sync_data->shadow_pa = 0;
	sync_data->vaddr = vaddr;
	sync_data->spgt_data = data->spgt_data;

	return 0;
}

int free_shadow_id(struct pkvm_iommu *iommu, unsigned long vaddr,
		       unsigned long vaddr_end);
static int sync_shadow_id_cb(struct pkvm_pgtable *vpgt, unsigned long vaddr,
			  unsigned long vaddr_end, int level, void *ptep,
			  unsigned long flags, struct pgt_flush_data *flush_data,
			  void *const arg)
{
	const struct pkvm_pgtable_ops *vpgt_ops = vpgt->pgt_ops;
	struct id_sync_walk_data *data = arg;
	struct pkvm_iommu *iommu = data->iommu;
	struct pkvm_pgtable *shadow_id = &iommu->pgt;
	struct id_sync_data sync_data;
	void *shadow_ptep, *guest_ptep;
	bool shadow_p, guest_p;
	int ret = init_sync_id_data(&sync_data, data, iommu, ptep, vaddr, level);

	if (ret < 0)
		return ret;

	guest_ptep = sync_data.guest_ptep;
	shadow_ptep = sync_data.shadow_ptep;

	/*
	 * WALK_TABLE_PRE is for non leaf, WALK_LEAF is for leaf
	 * if not match, it means guest changed it, return -EAGAIN
	 * to re-walk the page table.
	 */
	if ((flags == PKVM_PGTABLE_WALK_TABLE_PRE &&
		vpgt_ops->pgt_entry_is_leaf(guest_ptep, level)) ||
		(flags == PKVM_PGTABLE_WALK_LEAF &&
		!vpgt_ops->pgt_entry_is_leaf(guest_ptep, level)))
		return -EAGAIN;

	shadow_p = shadow_id->pgt_ops->pgt_entry_present(shadow_ptep);
	guest_p = vpgt_ops->pgt_entry_present(guest_ptep);
	if (!guest_p) {
		if (shadow_p) {
			/*
			 * For the case that guest not present but shadow present, just
			 * simply free the shadow to make them consistent.
			 */
			unsigned long new_vaddr_end = shadow_id->pgt_ops->pgt_level_to_size(level) +
						      vaddr;
			/*
			 * Get a reference count before free to make sure the current page
			 * of this level and the pages of its parent levels won't be freed.
			 * As here we only want to free its specific sub-level.
			 */
			shadow_id->mm_ops->get_page(shadow_ptep);
			free_shadow_id(iommu, vaddr, new_vaddr_end);
			shadow_id->mm_ops->put_page(shadow_ptep);
		}
		/*
		 * As now both guest and shadow are not
		 * present, don't need to do anything more.
		 */
		return ret;
	}

	if (LAST_LEVEL(level)) {
		/*
		 * Cache invalidation may want to sync specific PASID entries
		 * (in scalable mode) or context entries (in legacy mode) with
		 * DID matched. In such case we only need to sync the entries
		 * with the matching DID.
		 *
		 * According to vt-d spec 6.2.2.1 and 6.2.3.1, software must
		 * not use domain-id value of 0 when programming entries on
		 * implementations reporting CM=1 in the Capability register.
		 * So non-zero DID means a real DID from host software.
		 */
		if (data->did) {
			u16 did = sm_supported(&iommu->iommu)
				? pasid_get_domain_id(guest_ptep)
				: context_lm_get_did(guest_ptep);

			if (did != data->did)
				return ret;
		}

		/*
		 * For a leaf entry, the physical address of its child level
		 * is determined by the pgt used by the corresponding ptdev.
		 * So no need to set sync_data.shadow_pa.
		 */
	} else if (!shadow_p) {
		/*
		 * For a non-present non-leaf (which may be root/context/pasid
		 * dir) entry, needs to allocate a new page to make this entry
		 * present. Root and context page are always one page with 4K
		 * size. As we fixed the pasid only support 15bits, which makes
		 * the pasid dir is also one page with 4K size.
		 */
		void *shadow = shadow_id->mm_ops->zalloc_page(NULL);

		if (!shadow)
			return -ENOMEM;
		/* Get the shadow id physical address of the child level */
		sync_data.shadow_pa = shadow_id->mm_ops->virt_to_phys(shadow);
	} else
		/*
		 * For a present non-leaf (which is probably root/context/pasid dir)
		 * entry, get the shadow id physical address of its child level.
		 */
		sync_data.shadow_pa = shadow_id->pgt_ops->pgt_entry_to_phys(shadow_ptep);

	if (iommu_id_sync_entry(&sync_data)) {
		if (!shadow_p)
			/*
			 * A non-present to present changing require to get
			 * a new reference count for the shadow id page.
			 */
			shadow_id->mm_ops->get_page(shadow_ptep);
	}

	if ((flags == PKVM_PGTABLE_WALK_TABLE_PRE) && (!LAST_LEVEL(level))) {
		/*
		 * As guest page table walking will go to the child level, pass
		 * the shadow id physical address of the child level to sync.
		 */
		data->shadow_pa[level - 1] = sync_data.shadow_pa;
	}

	return ret;
}

int free_shadow_id(struct pkvm_iommu *iommu, unsigned long vaddr,
		       unsigned long vaddr_end)
{
	struct pkvm_pgtable_walker walker = {
		.cb = free_shadow_id_cb,
		.flags = PKVM_PGTABLE_WALK_LEAF |
			 PKVM_PGTABLE_WALK_TABLE_POST,
	};

	/*
	 * To free the shadow IOMMU page table, walks the shadow IOMMU
	 * page table.
	 */
	if (!(iommu->viommu.vreg.gsts & DMA_GSTS_TES))
		return 0;

	return iommu_pgtable_walk(&iommu->pgt, vaddr, vaddr_end, &walker);
}

static int __sync_shadow_id(struct pkvm_iommu *iommu, unsigned long vaddr,
		       unsigned long vaddr_end, u16 did,
		       struct shadow_pgt_sync_data *spgt_data)
{
	DEFINE_ID_SYNC_WALK_DATA(arg, iommu, did, spgt_data);
	struct pkvm_pgtable_walker walker = {
		.cb = sync_shadow_id_cb,
		.flags = PKVM_PGTABLE_WALK_TABLE_PRE |
			 PKVM_PGTABLE_WALK_LEAF,
		.arg = &arg,
	};
	int ret, retry_cnt = 0;

	if (!(iommu->viommu.vreg.gsts & DMA_GSTS_TES))
		return 0;

retry:
	if (sm_supported(&iommu->iommu))
		arg.shadow_pa[IOMMU_SM_ROOT] = iommu->pgt.root_pa;
	else
		arg.shadow_pa[IOMMU_LM_ROOT] = iommu->pgt.root_pa;
	/*
	 * To sync the shadow IOMMU page table, walks the guest IOMMU
	 * page table
	 */
	ret = iommu_pgtable_walk(&iommu->viommu.pgt, vaddr, vaddr_end, &walker);
	if ((ret == -EAGAIN) && (retry_cnt++ < 5))
		goto retry;

	return ret;
}

int sync_shadow_id(struct pkvm_iommu *iommu, unsigned long vaddr,
		       unsigned long vaddr_end, u16 did)
{
	return __sync_shadow_id(iommu, vaddr, vaddr_end, did, NULL);
}

static int context_cache_invalidate(struct pkvm_iommu *iommu, struct qi_desc *desc)
{
	u16 sid = QI_DESC_CC_SID(desc->qw0);
	u16 did = sm_supported(&iommu->iommu) ? 0 : QI_DESC_CC_DID(desc->qw0);
	u64 granu = QI_DESC_CC_GRANU(desc->qw0) << DMA_CCMD_INVL_GRANU_OFFSET;
	unsigned long start, end;
	int ret;

	switch (granu) {
	case DMA_CCMD_GLOBAL_INVL:
		start = 0;
		end = MAX_NUM_OF_ADDRESS_SPACE(iommu);
		pkvm_dbg("pkvm: %s: iommu%d: global\n", __func__, iommu->iommu.seq_id);
		ret = sync_shadow_id(iommu, start, end, 0);
		break;
	case DMA_CCMD_DOMAIN_INVL:
		/*
		 * Domain selective invalidation which is processed by
		 * hardware as global invalidations for scalable mode
		 * according to spec 6.5.2.1
		 */
		start = 0;
		end = MAX_NUM_OF_ADDRESS_SPACE(iommu);
		pkvm_dbg("pkvm: %s: iommu%d: domain selective\n",
			 __func__, iommu->iommu.seq_id);
		ret = sync_shadow_id(iommu, start, end, did);
		break;
	case DMA_CCMD_DEVICE_INVL:
		if (sm_supported(&iommu->iommu)) {
			start = (unsigned long)sid << DEVFN_SHIFT;
			end = ((unsigned long)sid + 1) << DEVFN_SHIFT;
		} else {
			start = (unsigned long)sid << LM_DEVFN_SHIFT;
			end = ((unsigned long)sid + 1) << LM_DEVFN_SHIFT;
		}
		pkvm_dbg("pkvm: %s: iommu%d: device selective sid 0x%x\n",
			 __func__, iommu->iommu.seq_id, sid);
		ret = sync_shadow_id(iommu, start, end, did);
		break;
	default:
		pkvm_err("pkvm: %s: iommu%d: invalidate granu %lld\n",
			__func__, iommu->iommu.seq_id, granu >> DMA_CCMD_INVL_GRANU_OFFSET);
		ret = -EINVAL;
		break;
	}

	if (ret)
		pkvm_err("pkvm: %s: iommu%d: granularity %lld failed with ret %d\n",
			__func__, iommu->iommu.seq_id, granu >> DMA_CCMD_INVL_GRANU_OFFSET, ret);
	return ret;
}

static int pasid_cache_invalidate(struct pkvm_iommu *iommu, struct qi_desc *desc)
{
	int pasid = QI_DESC_PC_PASID(desc->qw0);
	u16 did = QI_DESC_PC_DID(desc->qw0);
	int granu = QI_DESC_PC_GRANU(desc->qw0);
	unsigned long start, end;
	int ret;

	switch (granu) {
	case QI_PC_ALL_PASIDS:
		/*
		 * This is more like a global invalidation but to check
		 * if matching with a specific DID.
		 */
		pkvm_dbg("pkvm: %s: iommu%d: ALL_PASID did %d\n",
			 __func__, iommu->iommu.seq_id, did);
		start = 0;
		end = IOMMU_MAX_VADDR;
		ret = sync_shadow_id(iommu, start, end, did);
		break;
	case QI_PC_PASID_SEL: {
		/*
		 * Sync specific PASID entry for all contexts
		 */
		u64 bdf, end_bdf = 0x10000;

		pkvm_dbg("pkvm: %s: iommu%d: PASID_SEL did %d pasid 0x%x\n",
			 __func__, iommu->iommu.seq_id, did, pasid);
		for (bdf = 0; bdf < end_bdf; bdf++) {
			start = (bdf << DEVFN_SHIFT) + pasid;
			end = start + 1;
			ret = sync_shadow_id(iommu, start, end, did);
			if (ret)
				break;
		}
		break;
	}
	case QI_PC_GLOBAL:
		start = 0;
		end = IOMMU_MAX_VADDR;
		pkvm_dbg("pkvm: %s: iommu%d: global\n", __func__, iommu->iommu.seq_id);
		ret = sync_shadow_id(iommu, start, end, 0);
		break;
	default:
		pkvm_err("pkvm: %s: iommu%d: invalid granularity %d 0x%llx\n",
			 __func__, iommu->iommu.seq_id, granu, desc->qw0);
		ret = -EINVAL;
		break;
	}

	if (ret)
		pkvm_err("pkvm: %s: iommu%d: granularity %d failed with ret %d\n",
			 __func__, iommu->iommu.seq_id, granu, ret);

	return ret;
}

static int iotlb_lm_invalidate(struct pkvm_iommu *iommu, struct qi_desc *desc)
{
	u16 did = QI_DESC_IOTLB_DID(desc->qw0);
	u64 granu = QI_DESC_IOTLB_GRANU(desc->qw0) << DMA_TLB_FLUSH_GRANU_OFFSET;
	u64 addr = QI_DESC_IOTLB_ADDR(desc->qw1);
	u64 mask = ((u64)-1) << (VTD_PAGE_SHIFT + QI_DESC_IOTLB_AM(desc->qw1));
	struct shadow_pgt_sync_data data;
	struct pkvm_ptdev *p;
	int ret = 0;

	switch (granu) {
	case DMA_TLB_GLOBAL_FLUSH:
		pkvm_dbg("pkvm: %s: iommu%d: global\n", __func__, iommu->iommu.seq_id);
		ret = sync_shadow_id(iommu, 0, IOMMU_LM_MAX_VADDR, 0);
		break;
	case DMA_TLB_DSI_FLUSH:
		pkvm_dbg("pkvm: %s: iommu%d: domain selective did %u\n",
			 __func__, iommu->iommu.seq_id, did);

		/* optimization: walk just the needed devices, not the entire bdf space */
		list_for_each_entry(p, &iommu->ptdev_head, iommu_node)
			if (p->did == did) {
				ret = sync_shadow_id(iommu, p->bdf, p->bdf + 1, did);
				if (ret)
					break;
			}
		break;
	case DMA_TLB_PSI_FLUSH:
		data.vaddr = addr & mask;
		data.vaddr_end = (addr | ~mask) + 1;
		pkvm_dbg("pkvm: %s: iommu%d: page selective did %u start 0x%lx end 0x%lx\n",
			 __func__, iommu->iommu.seq_id, did, data.vaddr, data.vaddr_end);

		/* optimization: walk just the needed devices, not the entire bdf space */
		list_for_each_entry(p, &iommu->ptdev_head, iommu_node)
			if (p->did == did) {
				ret = __sync_shadow_id(iommu, p->bdf, p->bdf + 1, did, &data);
				if (ret)
					break;
			}
		break;
	default:
		pkvm_err("pkvm: %s: iommu%d: invalid granularity %lld\n",
			__func__, iommu->iommu.seq_id, granu >> DMA_TLB_FLUSH_GRANU_OFFSET);
		ret = -EINVAL;
		break;
	}

	if (ret)
		pkvm_err("pkvm: %s: iommu%d: granularity %lld failed with ret %d\n",
			__func__, iommu->iommu.seq_id, granu >> DMA_TLB_FLUSH_GRANU_OFFSET, ret);

	return ret;
}

int handle_descriptor(struct pkvm_iommu *iommu, struct qi_desc *desc)
{
	int type = QI_DESC_TYPE(desc->qw0);
	int ret = 0;

	switch (type) {
	/*
	 * TODO: is it necessary to intercept the
	 * PGRP_RESP & PSTRM_RESP?
	 */
	case QI_PGRP_RESP_TYPE:
	case QI_PSTRM_RESP_TYPE:
	case QI_DIOTLB_TYPE:
	case QI_DEIOTLB_TYPE:
	case QI_IEC_TYPE:
	case QI_IWD_TYPE:
	case QI_EIOTLB_TYPE:
		break;
	case QI_CC_TYPE:
		ret = context_cache_invalidate(iommu, desc);
		break;
	case QI_PC_TYPE:
		ret = pasid_cache_invalidate(iommu, desc);
		break;
	case QI_IOTLB_TYPE:
		if (!sm_supported(&iommu->iommu))
			ret = iotlb_lm_invalidate(iommu, desc);
		break;
	default:
		pkvm_err("pkvm: %s: iommu%d: invalid type %d desc addr 0x%llx val 0x%llx\n",
			 __func__, iommu->iommu.seq_id, type, (u64)desc, desc->qw0);
		ret = -EINVAL;
		break;
	}

	return ret;
}
