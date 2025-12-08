// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Google. */

#include <linux/pci.h>
#include <../drivers/iommu/intel/iommu.h>
#include <asm/pkvm_spinlock.h>
#include <pkvm.h>
#include <linux/bits.h>
#include "iommu_internal.h"
#include "iommu_domain.h"
#include "memory.h"
#include "debug.h"

#define MAX_CACHETAG_NUM 1024
static DECLARE_BITMAP(cache_tag_bitmap, MAX_CACHETAG_NUM);
static struct pkvm_cache_tag cache_tags[MAX_CACHETAG_NUM];
static pkvm_spinlock_t cache_tag_lock = __PKVM_SPINLOCK_UNLOCKED;

static struct pkvm_cache_tag *pkvm_alloc_cache_tag(void)
{
	struct pkvm_cache_tag *cache_tag = NULL;
	unsigned long index;

	pkvm_spin_lock(&cache_tag_lock);
	index = find_first_zero_bit(cache_tag_bitmap, MAX_CACHETAG_NUM);
	if (index < MAX_CACHETAG_NUM) {
		__set_bit(index, cache_tag_bitmap);
		cache_tag = &cache_tags[index];
		cache_tag->index = index;
		INIT_LIST_HEAD(&cache_tag->node);
	}
	pkvm_spin_unlock(&cache_tag_lock);

	return cache_tag;
}

static void pkvm_free_cache_tag(struct pkvm_cache_tag *cache_tag)
{
	pkvm_spin_lock(&cache_tag_lock);
	__clear_bit(cache_tag->index, cache_tag_bitmap);
	memset(cache_tag, 0, sizeof(struct pkvm_cache_tag));
	pkvm_spin_unlock(&cache_tag_lock);
}

/*
 * Copied from drivers/iommu/intel/cache.c:qi_batch_flush_descs()
 */
static void qi_batch_flush_descs(struct pkvm_iommu *iommu, struct qi_batch *batch)
{
	if (!iommu || !batch->index)
		return;

	submit_qi(iommu, batch->descs, batch->index);

	/* Reset the index value and clean the whole batch buffer. */
	memset(batch, 0, sizeof(*batch));
}

/*
 * Copied from drivers/iommu/intel/cache.c:qi_batch_increment_index()
 */
static void qi_batch_increment_index(struct pkvm_iommu *iommu, struct qi_batch *batch)
{
	if (++batch->index == QI_MAX_BATCHED_DESC_COUNT)
		qi_batch_flush_descs(iommu, batch);
}

/*
 * Copied from drivers/iommu/intel/cache.c:qi_batch_add_iotlb()
 */
static void qi_batch_add_iotlb(struct pkvm_iommu *iommu, u16 did, u64 addr,
			       unsigned int size_order, u64 type,
			       struct qi_batch *batch)
{
	setup_iotlb_qi_desc(iommu, &batch->descs[batch->index], did, addr, size_order, type);
	qi_batch_increment_index(iommu, batch);
}

/*
 * Copied from drivers/iommu/intel/cache.c:qi_batch_add_piotlb()
 */
static void qi_batch_add_piotlb(struct pkvm_iommu *iommu, u16 did, u32 pasid,
				u64 addr, unsigned long npages, bool ih,
				struct qi_batch *batch)
{
	/*
	 * npages == -1 means a PASID-selective invalidation, otherwise,
	 * a positive value for Page-selective-within-PASID invalidation.
	 * 0 is not a valid input.
	 */
	if (!npages)
		return;

	qi_desc_piotlb(did, pasid, addr, npages, ih, &batch->descs[batch->index]);
	qi_batch_increment_index(iommu, batch);
}


/*
 * Copied from drivers/iommu/intel/cache.c:cache_tag_flush_iotlb()
 */
static void cache_tag_flush_iotlb(struct pkvm_iommu_domain *domain, struct pkvm_cache_tag *tag,
				  unsigned long addr, unsigned long pages,
				  unsigned long mask, int ih)
{
	struct pkvm_iommu *iommu = tag->iommu;
	u64 type = DMA_TLB_PSI_FLUSH;

	if (domain->use_first_level) {
		qi_batch_add_piotlb(iommu, tag->domain_id, tag->pasid, addr,
				    pages, ih, &domain->qi_batch);
		return;
	}

	/*
	 * Fallback to domain selective flush if no PSI support or the size
	 * is too big.
	 */
	if (!cap_pgsel_inv(iommu->iommu.cap) ||
	    mask > cap_max_amask_val(iommu->iommu.cap) || pages == -1) {
		addr = 0;
		mask = 0;
		ih = 0;
		type = DMA_TLB_DSI_FLUSH;
	}

	qi_batch_add_iotlb(iommu, tag->domain_id, addr | ih, mask, type,
			   &domain->qi_batch);
}

/*
 * Copied from drivers/iommu/intel/cache.c:calculate_psi_aligned_address()
 */
static unsigned long calculate_psi_aligned_address(unsigned long start,
						   unsigned long end,
						   unsigned long *_pages,
						   unsigned long *_mask)
{
	unsigned long pages = aligned_nrpages(start, end - start + 1);
	unsigned long aligned_pages = __roundup_pow_of_two(pages);
	unsigned long bitmask = aligned_pages - 1;
	unsigned long mask = ilog2(aligned_pages);
	unsigned long pfn = IOVA_PFN(start);

	/*
	 * PSI masks the low order bits of the base address. If the
	 * address isn't aligned to the mask, then compute a mask value
	 * needed to ensure the target range is flushed.
	 */
	if (unlikely(bitmask & pfn)) {
		unsigned long end_pfn = pfn + pages - 1, shared_bits;

		/*
		 * Since end_pfn <= pfn + bitmask, the only way bits
		 * higher than bitmask can differ in pfn and end_pfn is
		 * by carrying. This means after masking out bitmask,
		 * high bits starting with the first set bit in
		 * shared_bits are all equal in both pfn and end_pfn.
		 */
		shared_bits = ~(pfn ^ end_pfn) & ~bitmask;
		mask = shared_bits ? __ffs(shared_bits) : MAX_AGAW_PFN_WIDTH;
		aligned_pages = 1UL << mask;
	}

	*_pages = aligned_pages;
	*_mask = mask;

	return ALIGN_DOWN(start, VTD_PAGE_SIZE << mask);
}

/*
 * Copied from drivers/iommu/intel/cache.c:qi_batch_add_dev_iotlb()
 */
static void qi_batch_add_dev_iotlb(struct pkvm_iommu *iommu, u16 sid, u16 pfsid,
				   u16 qdep, u64 addr, unsigned int mask,
				   struct qi_batch *batch)
{
	qi_desc_dev_iotlb(sid, pfsid, qdep, addr, mask, &batch->descs[batch->index]);
	qi_batch_increment_index(iommu, batch);
}

/*
 * Copied from drivers/iommu/intel/cache.c:qi_batch_add_pasid_dev_iotlb()
 */
static void qi_batch_add_pasid_dev_iotlb(struct pkvm_iommu *iommu, u16 sid, u16 pfsid,
					 u32 pasid,  u16 qdep, u64 addr,
					 unsigned int size_order, struct qi_batch *batch)
{
	qi_desc_dev_iotlb_pasid(sid, pfsid, pasid, qdep, addr, size_order,
				&batch->descs[batch->index]);
	qi_batch_increment_index(iommu, batch);
}

/*
 * Copied from drivers/iommu/intel/cache.c:cache_tag_flush_devtlb_psi()
 */
static void cache_tag_flush_devtlb_psi(struct pkvm_iommu_domain *domain, struct pkvm_cache_tag *tag,
				       unsigned long addr, unsigned long mask)
{
	struct pkvm_iommu *iommu = tag->iommu;
	u16 sid;

	sid = PCI_DEVID(tag->bus, tag->devfn);

	if (tag->pasid == IOMMU_NO_PASID) {
		qi_batch_add_dev_iotlb(iommu, sid, tag->pfsid, tag->ats_qdep,
				       addr, mask, &domain->qi_batch);
		return;
	}

	qi_batch_add_pasid_dev_iotlb(iommu, sid, tag->pfsid, tag->pasid,
				     tag->ats_qdep, addr, mask, &domain->qi_batch);
}


/*
 * Invalidates a range of IOVA from @start (inclusive) to @end (inclusive)
 * when the memory mappings in the target domain have been modified.
 *
 * Copied from drivers/iommu/intel/cache.c:cache_tag_flush_range()
 */
void pkvm_cache_tag_flush_range(struct pkvm_iommu_domain *domain, unsigned long start,
				unsigned long end, int ih)
{
	struct pkvm_iommu *iommu = NULL;
	unsigned long pages, mask, addr;
	struct pkvm_cache_tag *tag;

	addr = calculate_psi_aligned_address(start, end, &pages, &mask);

	pkvm_spin_lock(&domain->cache_lock);
	list_for_each_entry(tag, &domain->cache_tags, node) {
		if (iommu && iommu != tag->iommu)
			qi_batch_flush_descs(iommu, &domain->qi_batch);
		iommu = tag->iommu;

		switch (tag->type) {
		case CACHE_TAG_IOTLB:
		case CACHE_TAG_NESTING_IOTLB:
			cache_tag_flush_iotlb(domain, tag, addr, pages, mask, ih);
			break;
		case CACHE_TAG_NESTING_DEVTLB:
			/*
			 * Address translation cache in device side caches the
			 * result of nested translation. There is no easy way
			 * to identify the exact set of nested translations
			 * affected by a change in S2. So just flush the entire
			 * device cache.
			 */
			addr = 0;
			mask = MAX_AGAW_PFN_WIDTH;
			fallthrough;
		case CACHE_TAG_DEVTLB:
			cache_tag_flush_devtlb_psi(domain, tag, addr, mask);
			break;
		}

	}
	qi_batch_flush_descs(iommu, &domain->qi_batch);
	pkvm_spin_unlock(&domain->cache_lock);
}

/*
 * Invalidate a range of IOVA when new mappings are created in the target
 * domain.
 *
 * - VT-d spec, Section 6.1 Caching Mode: When the CM field is reported as
 *   Set, any software updates to remapping structures other than first-
 *   stage mapping requires explicit invalidation of the caches.
 * - VT-d spec, Section 6.8 Write Buffer Flushing: For hardware that requires
 *   write buffer flushing, software must explicitly perform write-buffer
 *   flushing, if cache invalidation is not required.
 *
 * Copied from drivers/iommu/intel/cache.c:cache_tag_flush_range_np()
 */
void pkvm_cache_tag_flush_range_np(struct pkvm_iommu_domain *domain, unsigned long start,
				   unsigned long end)
{
	struct pkvm_iommu *iommu = NULL;
	unsigned long pages, mask, addr;
	struct pkvm_cache_tag *tag;

	addr = calculate_psi_aligned_address(start, end, &pages, &mask);

	pkvm_spin_lock(&domain->cache_lock);
	list_for_each_entry(tag, &domain->cache_tags, node) {
		if (iommu && iommu != tag->iommu)
			qi_batch_flush_descs(iommu, &domain->qi_batch);
		iommu = tag->iommu;

		if (!cap_caching_mode(iommu->iommu.cap) || domain->use_first_level)
			continue;

		if (tag->type == CACHE_TAG_IOTLB ||
		    tag->type == CACHE_TAG_NESTING_IOTLB)
			cache_tag_flush_iotlb(domain, tag, addr, pages, mask, 0);

	}
	qi_batch_flush_descs(iommu, &domain->qi_batch);
	pkvm_spin_unlock(&domain->cache_lock);
}

/*
 * Copied from drivers/iommu/intel/cache.c:cache_tage_match()
 */
static bool cache_tag_match(struct pkvm_cache_tag *tag, u16 domain_id,
			     struct pkvm_iommu *iommu, u8 bus, u8 devfn,
			     u32 pasid, enum cache_tag_type type)
{
	if (tag->type != type)
		return false;

	if (tag->domain_id != domain_id || tag->pasid != pasid)
		return false;

	if (type == CACHE_TAG_IOTLB)
		return tag->iommu == iommu;

	if (type == CACHE_TAG_DEVTLB)
		return tag->bus == bus && tag->devfn == devfn;

	return false;
}

static unsigned long iommu_cache_assign(struct pkvm_iommu *iommu,
					struct pkvm_iommu_domain *domain,
					u16 did, u16 bdf, u8 ats_qdep,
					ioasid_t pasid, enum cache_tag_type type)
{
	struct pkvm_cache_tag *cache_tag, *temp;
	u8 bus = PCI_BUS_NUM(bdf);
	u8 devfn = PCI_DEV_FN(bdf);

	if (ats_qdep > PCI_ATS_MAX_QDEP)
		return -EINVAL;

	cache_tag = pkvm_alloc_cache_tag();
	if (!cache_tag)
		return -ENOMEM;

	cache_tag->type = type;
	cache_tag->iommu = iommu;
	cache_tag->domain_id = did;
	cache_tag->pasid = pasid;
	cache_tag->users = 1;

	if (type == CACHE_TAG_DEVTLB) {
		cache_tag->bus = bus;
		cache_tag->devfn = devfn;
		/*
		 * Only devices in SATC are allowed to have ats enabled, and
		 * assuming a well crafted SATC would contain only physical
		 * functions, it's safe to set pfsid = bdf.
		 */
		cache_tag->pfsid = bdf;
		cache_tag->ats_qdep = ats_qdep;
	}

	pkvm_spin_lock(&domain->cache_lock);
	list_for_each_entry(temp, &domain->cache_tags, node) {
		if (cache_tag_match(temp, did, iommu, bus, devfn, pasid, type)) {
			temp->users++;
			pkvm_free_cache_tag(cache_tag);
			goto out;
		}
	}
	pkvm_dbg("pkvm: %s: dev[%x] did:%u, pasid: %u, ats_qdep: %u, type: %s\n",
		 __func__, PCI_DEVID(bus, devfn), did, pasid, cache_tag->ats_qdep,
		 type == CACHE_TAG_IOTLB ? "IOTLB" : "DEVTLB");
	list_add_tail(&cache_tag->node, &domain->cache_tags);

out:
	pkvm_spin_unlock(&domain->cache_lock);
	return 0;
}

static void iommu_cache_unassign(struct pkvm_iommu *iommu, struct pkvm_iommu_domain *domain,
				 u16 did, u16 bdf, ioasid_t pasid, enum cache_tag_type type)
{
	struct pkvm_cache_tag *cache_tag;
	u8 bus = PCI_BUS_NUM(bdf);
	u8 devfn = PCI_DEV_FN(bdf);

	pkvm_spin_lock(&domain->cache_lock);
	list_for_each_entry(cache_tag, &domain->cache_tags, node) {
		if (cache_tag_match(cache_tag, did, iommu, bus, devfn, pasid, type)) {
			if (--cache_tag->users == 0) {
				pkvm_dbg("pkvm: %s: dev[%x] did:%u, pasid: %u, type: %s\n",
					 __func__, PCI_DEVID(bus, devfn), did, pasid,
					 type == CACHE_TAG_IOTLB ? "IOTLB" : "DEVTLB");
				list_del(&cache_tag->node);
				pkvm_free_cache_tag(cache_tag);
			}
			break;
		}
	}
	pkvm_spin_unlock(&domain->cache_lock);
}

int pkvm_iommu_cache_assign_domain(struct pkvm_iommu *iommu, struct pkvm_iommu_domain *domain,
				   u16 did, u16 bdf, u8 ats_qdep, ioasid_t pasid, bool dte)
{
	int ret = iommu_cache_assign(iommu, domain, did, bdf, ats_qdep, pasid, CACHE_TAG_IOTLB);

	if (!ret && dte) {
		ret = iommu_cache_assign(iommu, domain, did, bdf, ats_qdep,
					 pasid, CACHE_TAG_DEVTLB);
		if (ret)
			iommu_cache_unassign(iommu, domain, did, bdf, pasid, CACHE_TAG_IOTLB);
	}

	return ret;
}

void pkvm_iommu_cache_unassign_domain(struct pkvm_iommu *iommu, struct pkvm_iommu_domain *domain,
				      u16 did, u16 bdf, ioasid_t pasid, bool dte)
{
	iommu_cache_unassign(iommu, domain, did, bdf, pasid, CACHE_TAG_IOTLB);
	if (dte)
		iommu_cache_unassign(iommu, domain, did, bdf, pasid, CACHE_TAG_DEVTLB);
}
