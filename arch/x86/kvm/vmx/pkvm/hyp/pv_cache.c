// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Google. */

#include <linux/pci.h>
#include <../drivers/iommu/intel/iommu.h>
#include "iommu_internal.h"
#include "iommu_domain.h"

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
