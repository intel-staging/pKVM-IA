// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Google. */

#include <../drivers/iommu/intel/iommu.h>
#include <linux/hashtable.h>
#include <asm/pkvm_spinlock.h>
#include <pkvm.h>
#include "pkvm_hyp.h"
#include "debug.h"
#include "iommu_internal.h"
#include "iommu.h"
#include "iommu_domain.h"
#include "mem_protect.h"
#include "bug.h"

/*
 * TODO: Make this a dynamic value.
 */
#define MAX_IOMMU_DOMAIN_NUM	128
static DEFINE_HASHTABLE(iommu_domain_hasht, 8);
static DECLARE_BITMAP(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM);
static struct pkvm_iommu_domain iommu_domains[MAX_IOMMU_DOMAIN_NUM];
static pkvm_spinlock_t iommu_domain_lock = __PKVM_SPINLOCK_UNLOCKED;

static inline struct pkvm_iommu_domain *__pkvm_get_iommu_domain_locked(u64 pgd, bool inc_ref)
{
	struct pkvm_iommu_domain *domain;

	hash_for_each_possible(iommu_domain_hasht, domain, hnode, pgd) {
		if (domain->pgd != pgd)
			continue;

		if (inc_ref && WARN_ON_ONCE(!atomic_inc_not_zero(&domain->refcount)))
			return NULL;

		return domain;
	}

	return NULL;
}

struct pkvm_iommu_domain *pkvm_get_iommu_domain(u64 pgd)
{
	struct pkvm_iommu_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, true);
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

/*
 * Retrieve the domain without incrementing refcount.
 * This api is useful when there is a refcount on the domain
 * and refcount is guaranteed to be not dropped.
 */
struct pkvm_iommu_domain *pkvm_get_iommu_domain_noref(u64 pgd)
{
	struct pkvm_iommu_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

void pkvm_put_iommu_domain(struct pkvm_iommu_domain *domain)
{
	WARN_ON_ONCE(atomic_dec_and_test(&domain->refcount));
}

/*
 * memcache helper functions.
 */

static void *admit_host_page(void *arg)
{
	struct pkvm_memcache *host_mc = arg;

	if (!host_mc->nr_pages)
		return NULL;

	if (WARN_ON(__pkvm_host_donate_hyp_share_ro(host_mc->head, VTD_PAGE_SIZE)))
		return NULL;

	return pop_pkvm_memcache(host_mc, hyp_phys_to_virt);
}

static int refill_domain_memcache(struct pkvm_iommu_domain *domain, struct pkvm_memcache *host_mc)
{
	struct pkvm_memcache *mc = &domain->mc;
	unsigned long min_pages;
	int ret;

	/*
	 * Host expects pKVM to drain the memcache fully as it is
	 * not persistent. Host makes the hypercall without memcache
	 * the first time and passes memcache next time only if the
	 * initial hypercall failed with ENOMEM.
	 */
	min_pages = mc->nr_pages + host_mc->nr_pages;
	ret =  __topup_pkvm_memcache(mc, min_pages, admit_host_page,
				     hyp_virt_to_phys, host_mc);

	return ret;
}

static void free_domain_memcache(struct pkvm_iommu_domain *domain,
				 struct pkvm_memcache *teardown_mc)
{
	struct pkvm_memcache *mc = &domain->mc;

	while (mc->nr_pages) {
		void *addr = pop_pkvm_memcache(mc, hyp_phys_to_virt);

		push_pkvm_memcache(teardown_mc, addr, hyp_virt_to_phys);
		WARN_ON(__pkvm_hyp_donate_host_unshare_ro(pkvm_virt_to_phys(addr), VTD_PAGE_SIZE));
	}
}

static void domain_unmap(struct pkvm_iommu_domain *domain, unsigned long start_pfn,
			 unsigned long last_pfn);
int pkvm_free_iommu_domain(struct pkvm_iommu_domain *domain, struct pkvm_memcache *teardown_mc)
{
	u64 pgd = domain->pgd;

	if (atomic_cmpxchg(&domain->refcount, 1, 0) != 1) {
		pkvm_err("%s: domain[pgd:%llx] has users, refcount %d\n",
			 __func__, domain->pgd, atomic_read(&domain->refcount));
		return -EBUSY;
	}

	/* Unmap any remaining mappings. */
	domain_unmap(domain, 0, DOMAIN_MAX_PFN(domain->gaw));
	free_domain_memcache(domain, teardown_mc);
	/*
	 * pgd was not allocated through memcache, but its safe to return to
	 * memcache as the teardown mc frees it the same way host driver frees
	 * the pages.
	 */
	pkvm_dbg("pkvm: %s: remove write protect pgd: %llx\n", __func__, pgd);
	push_pkvm_memcache(teardown_mc, pkvm_phys_to_virt(pgd), hyp_virt_to_phys);
	WARN_ON(__pkvm_hyp_donate_host_unshare_ro(pgd, VTD_PAGE_SIZE));

	pkvm_dbg("pkvm: %s: freeing domain[pgd: %llx], freed pages: %lu\n",
		 __func__, pgd, teardown_mc->nr_pages);

	pkvm_spin_lock(&iommu_domain_lock);
	hash_del(&domain->hnode);
	__clear_bit(domain->index, iommu_domains_bitmap);
	memset(domain, 0, sizeof(struct pkvm_iommu_domain));
	pkvm_spin_unlock(&iommu_domain_lock);

	return 0;
}

struct pkvm_iommu_domain *pkvm_alloc_iommu_domain(struct pkvm_domain_param *param,
						  bool need_iotlb_sync_map)
{
	u64 pgd = host_gpa2hpa(param->pgd_gpa);
	struct pkvm_iommu_domain *domain;
	unsigned long index;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	if (unlikely(domain)) {
		pkvm_spin_unlock(&iommu_domain_lock);
		return ERR_PTR(-EEXIST);
	}

	index = find_first_zero_bit(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM);
	if (index < MAX_IOMMU_DOMAIN_NUM) {
		__set_bit(index, iommu_domains_bitmap);
		domain = &iommu_domains[index];
		INIT_LIST_HEAD(&domain->cache_tags);
		domain->pgd = pgd;
		domain->use_first_level = param->use_first_level;
		domain->iommu_superpage = param->iommu_superpage;
		domain->iommu_coherency = param->iommu_coherency;
		domain->need_iotlb_sync_map = need_iotlb_sync_map;
		domain->agaw = param->agaw;
		domain->gaw = param->gaw;
		domain->max_addr = param->max_addr;
		domain->index = index;
		atomic_set(&domain->refcount, 1);
		pkvm_spin_lock_init(&domain->lock);
		pkvm_spin_lock_init(&domain->cache_lock);
		hash_add(iommu_domain_hasht, &domain->hnode, pgd);
		pkvm_dbg("pkvm: %s: allocated domain pgd: %llx\n", __func__, pgd);
	} else {
		domain = ERR_PTR(-ENOMEM);
	}
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

/*
 * Following code handles iommu map/unmap and is copied
 * from drivers/iommu/intel/iommu.c almost verbatim. The
 * only notable change is the page allocation. Instead of
 * allocating pages, we use the page donated by the host.
 */

/* Copied from drivers/iommu/intel/iommu.c:domain_flush_cache() */
static void domain_flush_cache(struct pkvm_iommu_domain *domain,
			       void *addr, int size)
{
	if (!domain->iommu_coherency)
		pkvm_clflush_cache_range(addr, size);
}

/* Copied from drivers/iommu/intel/iommu.c:domain_pfn_supported() */
static int domain_pfn_supported(struct pkvm_iommu_domain *domain, unsigned long pfn)
{
	int addr_width = agaw_to_width(domain->agaw) - VTD_PAGE_SHIFT;

	return !(addr_width < BITS_PER_LONG && pfn >> addr_width);
}

/* Copied from drivers/iommu/intel/iommu.c:hardware_largepage_caps() */
/* Return largest possible superpage level for a given mapping */
static int hardware_largepage_caps(struct pkvm_iommu_domain *domain, unsigned long iov_pfn,
				   unsigned long phy_pfn, unsigned long pages)
{
	int support, level = 1;
	unsigned long pfnmerge;

	support = domain->iommu_superpage;

	/*
	 * To use a large page, the virtual *and* physical addresses
	 * must be aligned to 2MiB/1GiB/etc. Lower bits set in either
	 * of them will mean we have to use smaller pages. So just
	 * merge them and check both at once.
	 */
	pfnmerge = iov_pfn | phy_pfn;

	while (support && !(pfnmerge & ~VTD_STRIDE_MASK)) {
		pages >>= VTD_STRIDE_SHIFT;
		if (!pages)
			break;
		pfnmerge >>= VTD_STRIDE_SHIFT;
		level++;
		support--;
	}
	return level;
}

/* Copied from drivers/iommu/intel/iommu.c:pfn_to_dma_pte() */
static struct dma_pte *pfn_to_dma_pte(struct pkvm_iommu_domain *domain,
				      unsigned long pfn, int *target_level)
{
	struct dma_pte *parent, *pte;
	int level = agaw_to_level(domain->agaw);
	int offset;

	parent = (struct dma_pte *)pkvm_phys_to_virt(domain->pgd);

	while (1) {
		void *tmp_page;

		offset = pfn_level_offset(pfn, level);
		pte = &parent[offset];
		if (!*target_level && (dma_pte_superpage(pte) || !dma_pte_present(pte)))
			break;
		if (level == *target_level)
			break;

		if (!dma_pte_present(pte)) {
			uint64_t pteval, tmp;

			tmp_page = pop_pkvm_memcache(&domain->mc, hyp_phys_to_virt);
			if (!tmp_page)
				return NULL;

			memset(tmp_page, 0, VTD_PAGE_SIZE);
			domain_flush_cache(domain, tmp_page, VTD_PAGE_SIZE);
			pteval = pkvm_virt_to_phys(tmp_page) | DMA_PTE_READ | DMA_PTE_WRITE;
			pteval |= DMA_PTE_MAPPED;
			if (domain->use_first_level)
				pteval |= DMA_FL_PTE_US | DMA_FL_PTE_ACCESS;

			tmp = 0ULL;
			if (!try_cmpxchg64(&pte->val, &tmp, pteval))
				/* Someone else set it while we were thinking; use theirs. */
				push_pkvm_memcache(&domain->mc, tmp_page, hyp_virt_to_phys);
			else
				domain_flush_cache(domain, pte, sizeof(*pte));
		}
		if (level == 1)
			break;

		parent = pkvm_phys_to_virt(dma_pte_addr(pte));
		level--;
	}

	if (!*target_level)
		*target_level = level;

	return pte;
}

/* Copied from drivers/iommu/intel/iommu.c:dma_pfn_level_pte() */
/* return address's pte at specific level */
static struct dma_pte *dma_pfn_level_pte(struct pkvm_iommu_domain *domain,
					 unsigned long pfn,
					 int level, int *large_page)
{
	struct dma_pte *parent, *pte;
	int total = agaw_to_level(domain->agaw);
	int offset;

	parent = (struct dma_pte *)pkvm_phys_to_virt(domain->pgd);
	while (level <= total) {
		offset = pfn_level_offset(pfn, total);
		pte = &parent[offset];
		if (level == total)
			return pte;

		if (!dma_pte_present(pte)) {
			*large_page = total;
			break;
		}

		if (dma_pte_superpage(pte)) {
			*large_page = total;
			return pte;
		}

		parent = pkvm_phys_to_virt(dma_pte_addr(pte));
		total--;
	}
	return NULL;
}

/* Copied from drivers/iommu/intel/iommu.c:dma_pte_clear_range() */
/* clear last level pte, a tlb flush should be followed */
static void dma_pte_clear_range(struct pkvm_iommu_domain *domain,
				unsigned long start_pfn,
				unsigned long last_pfn)
{
	unsigned int large_page;
	struct dma_pte *first_pte, *pte;

	if (WARN_ON(!domain_pfn_supported(domain, last_pfn)) ||
	    WARN_ON(start_pfn > last_pfn))
		return;

	/* we don't need lock here; nobody else touches the iova range */
	do {
		large_page = 1;
		first_pte = pte = dma_pfn_level_pte(domain, start_pfn, 1, &large_page);
		if (!pte) {
			start_pfn = align_to_level(start_pfn + 1, large_page + 1);
			continue;
		}
		do {
			dma_clear_pte(pte);
			start_pfn += lvl_to_nr_pages(large_page);
			pte++;
		} while (start_pfn <= last_pfn && !first_pte_in_page(pte));

		domain_flush_cache(domain, first_pte, (void *)pte - (void *)first_pte);

	} while (start_pfn && start_pfn <= last_pfn);
}

/* Copied from drivers/iommu/intel/iommu.c:dma_pte_free_level() */
static void dma_pte_free_level(struct pkvm_iommu_domain *domain,
			       int level,
			       int retain_level, struct dma_pte *pte,
			       unsigned long pfn, unsigned long start_pfn,
			       unsigned long last_pfn)
{
	pfn = max(start_pfn, pfn);
	pte = &pte[pfn_level_offset(pfn, level)];

	do {
		unsigned long level_pfn;
		struct dma_pte *level_pte;

		if (!dma_pte_present(pte) || dma_pte_superpage(pte))
			goto next;

		level_pfn = pfn & level_mask(level);
		level_pte = pkvm_phys_to_virt(dma_pte_addr(pte));

		if (level > 2) {
			dma_pte_free_level(domain, level - 1, retain_level,
					   level_pte, level_pfn, start_pfn,
					   last_pfn);
		}

		/*
		 * Free the page table if we're below the level we want to
		 * retain and the range covers the entire table.
		 */
		if (level < retain_level && !(start_pfn > level_pfn ||
		      last_pfn < level_pfn + level_size(level) - 1)) {
			dma_clear_pte(pte);
			domain_flush_cache(domain, pte, sizeof(*pte));
			push_pkvm_memcache(&domain->mc, (phys_addr_t *)level_pte,
					   hyp_virt_to_phys);
		}
next:
		pfn += level_size(level);
	} while (!first_pte_in_page(++pte) && pfn <= last_pfn);
}

/* Copied from drivers/iommu/intel/iommu.c:dma_pte_free_pagetable() */
/*
 * clear last level (leaf) ptes and free page table pages below the
 * level we wish to keep intact.
 */
static void dma_pte_free_pagetable(struct pkvm_iommu_domain *domain,
				   unsigned long start_pfn,
				   unsigned long last_pfn,
				   int retain_level)
{
	struct dma_pte *pgd = (struct dma_pte *)pkvm_phys_to_virt(domain->pgd);

	dma_pte_clear_range(domain, start_pfn, last_pfn);

	/* We don't need lock here; nobody else touches the iova range */
	dma_pte_free_level(domain, agaw_to_level(domain->agaw), retain_level,
			   pgd, 0, start_pfn, last_pfn);
}

/* Copied from drivers/iommu/intel/iommu.c:switch_to_super_page() */
/*
 * Ensure that old small page tables are removed to make room for superpage(s).
 * We're going to add new large pages, so make sure we don't remove their parent
 * tables. The IOTLB/devTLBs should be flushed if any PDE/PTEs are cleared.
 */
static void switch_to_super_page(struct pkvm_iommu_domain *domain,
				 unsigned long start_pfn,
				 unsigned long end_pfn, int level)
{
	unsigned long lvl_pages = lvl_to_nr_pages(level);
	struct dma_pte *pte = NULL;

	while (start_pfn <= end_pfn) {
		if (!pte)
			pte = pfn_to_dma_pte(domain, start_pfn, &level);

		if (dma_pte_present(pte)) {
			dma_pte_free_pagetable(domain, start_pfn,
					       start_pfn + lvl_pages - 1,
					       level + 1);
			pkvm_cache_tag_flush_range(domain, start_pfn << VTD_PAGE_SHIFT,
					end_pfn << VTD_PAGE_SHIFT, 0);
		}

		pte++;
		start_pfn += lvl_pages;
		if (first_pte_in_page(pte))
			pte = NULL;
	}
}

/* Copied from drivers/iommu/intel/iommu.c:__domain_mapping() */
static int domain_map(struct pkvm_iommu_domain *domain, struct pkvm_iommu_map_param *param)
{
	struct dma_pte *first_pte = NULL, *pte = NULL;
	unsigned long iov_pfn = param->iov_pfn;
	unsigned long phys_pfn = param->phys_pfn;
	unsigned long nr_pages = param->nr_pages;
	int prot = param->prot;
	unsigned int largepage_lvl = 0;
	unsigned long lvl_pages = 0;
	phys_addr_t pteval;
	u64 attr;
	int ret;

	if (unlikely(!domain_pfn_supported(domain, iov_pfn + nr_pages - 1)))
		return -EINVAL;

	if ((prot & (DMA_PTE_READ|DMA_PTE_WRITE)) == 0)
		return -EINVAL;

	ret = __pkvm_use_dma(phys_pfn << VTD_PAGE_SHIFT, nr_pages * VTD_PAGE_SIZE);
	if (ret)
		return ret;

	attr = prot & (DMA_PTE_READ | DMA_PTE_WRITE | DMA_PTE_SNP);
	attr |= DMA_FL_PTE_PRESENT;
	attr |= DMA_PTE_MAPPED;

	if (domain->use_first_level) {
		attr |= DMA_FL_PTE_US | DMA_FL_PTE_ACCESS;
		if (prot & DMA_PTE_WRITE)
			attr |= DMA_FL_PTE_DIRTY;
	}

	pteval = ((phys_addr_t)phys_pfn << VTD_PAGE_SHIFT) | attr;

	while (nr_pages > 0) {
		uint64_t tmp;

		if (!pte) {
			largepage_lvl = hardware_largepage_caps(domain, iov_pfn,
					phys_pfn, nr_pages);

			pte = pfn_to_dma_pte(domain, iov_pfn, &largepage_lvl);
			if (!pte) {
				ret = -ENOMEM;
				goto out;
			}

			first_pte = pte;

			lvl_pages = lvl_to_nr_pages(largepage_lvl);

			/* It is large page */
			if (largepage_lvl > 1) {
				unsigned long end_pfn;
				unsigned long pages_to_remove;

				pteval |= DMA_PTE_LARGE_PAGE;
				pages_to_remove = min_t(unsigned long, nr_pages,
							nr_pte_to_next_page(pte) * lvl_pages);
				end_pfn = iov_pfn + pages_to_remove - 1;
				switch_to_super_page(domain, iov_pfn, end_pfn, largepage_lvl);
			} else {
				pteval &= ~(uint64_t)DMA_PTE_LARGE_PAGE;
			}

		}
		/* We don't need lock here, nobody else touches the iova range. */
		tmp = 0ULL;
		if (!try_cmpxchg64_local(&pte->val, &tmp, pteval)) {
			if (tmp == pteval) {
				__pkvm_unuse_dma(dma_pte_addr(pte), VTD_PAGE_SIZE);
			} else {
				pkvm_err("ERROR: DMA PTE for vPFN 0x%lx already set (to %llx not %llx)\n",
					 iov_pfn, tmp, (unsigned long long)pteval);
			}
		}

		nr_pages -= lvl_pages;
		iov_pfn += lvl_pages;
		phys_pfn += lvl_pages;
		pteval += lvl_pages * VTD_PAGE_SIZE;

		/*
		 * If the next PTE would be the first in a new page, then we
		 * need to flush the cache on the entries we've just written.
		 * And then we'll need to recalculate 'pte', so clear it and
		 * let it get set again in the if (!pte) block above.
		 *
		 * If we're done (!nr_pages) we need to flush the cache too.
		 *
		 * Also if we've been setting superpages, we may need to
		 * recalculate 'pte' and switch back to smaller pages for the
		 * end of the mapping, if the trailing size is not enough to
		 * use another superpage (i.e. nr_pages < lvl_pages).
		 */
		pte++;
		if (!nr_pages || first_pte_in_page(pte) ||
		    (largepage_lvl > 1 && nr_pages < lvl_pages)) {
			domain_flush_cache(domain, first_pte,
					   (void *)pte - (void *)first_pte);
			pte = NULL;
		}
	}

out:
	if (unlikely(nr_pages))
		__pkvm_unuse_dma(phys_pfn << VTD_PAGE_SHIFT, nr_pages * VTD_PAGE_SIZE);

	return ret;
}

int pkvm_iommu_domain_map(unsigned long param_va)
{
	struct pkvm_iommu_map_param param, *param_ptr;
	struct pkvm_iommu_domain *domain;
	u64 size;
	int ret;

	if (!param_va)
		return -EINVAL;

	param_ptr = (struct pkvm_iommu_map_param *)kern_pkvm_va((void *)param_va);
	if (WARN_ON_ONCE(copy_pv_param_from_host(iommu_map_param, param_ptr, param)))
		return -EINVAL;

	/* Check for possible overfows that may have security implications */
	if (check_mul_overflow(param.nr_pages, VTD_PAGE_SIZE, &size))
		return -EINVAL;
	if (param.iov_pfn + param.nr_pages < param.iov_pfn)
		return -EINVAL;
	if ((param.iov_pfn << VTD_PAGE_SHIFT) < param.iov_pfn)
		return -EINVAL;
	if ((param.iov_pfn << VTD_PAGE_SHIFT) + size < param.iov_pfn)
		return -EINVAL;
	if ((param.phys_pfn << VTD_PAGE_SHIFT) < param.phys_pfn)
		return -EINVAL;
	if ((param.phys_pfn << VTD_PAGE_SHIFT) + size < param.phys_pfn)
		return -EINVAL;

	domain = pkvm_get_iommu_domain(host_gpa2hpa(param.pgd_gpa));
	if (!domain) {
		pkvm_err("pkvm: %s, failed to get the domain [pgd:%llx]\n",
				__func__, param.pgd_gpa);
		return -EINVAL;
	}

	pkvm_spin_lock(&domain->lock);
	if (param.mc.nr_pages) {
		ret = refill_domain_memcache(domain, &param.mc);
		if (ret) {
			pkvm_err("pkvm: %s: failed to refill memcache for domain[pgd: %llx] (err=%d)\n",
				 __func__, domain->pgd, ret);
			goto out_unlock;
		}
	}
	if (domain->mc.nr_pages < __pkvm_pgtable_max_pages(param.nr_pages)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	ret = domain_map(domain, &param);
	if (!ret && domain->need_iotlb_sync_map)
		pkvm_cache_tag_flush_range_np(domain, param.iov_pfn << VTD_PAGE_SHIFT,
				(param.iov_pfn + param.nr_pages - 1) << VTD_PAGE_SHIFT);

out_unlock:
	pkvm_spin_unlock(&domain->lock);
	pkvm_put_iommu_domain(domain);

	copy_pv_param_to_host(iommu_map_param, param_ptr, param);
	return ret;
}

static inline void dma_unpresent_pte(struct dma_pte *pte)
{
	u64 unpresent = READ_ONCE(pte->val) & ~(DMA_PTE_READ | DMA_PTE_WRITE);

	WRITE_ONCE(pte->val, unpresent);
}

/* Adapted from drivers/iommu/intel/iommu.c:dma_pte_clear_level() */
static bool dma_pte_clear_level(struct pkvm_iommu_domain *domain, int level,
				struct dma_pte *pte, unsigned long pfn,
				unsigned long start_pfn, unsigned long last_pfn)
{
	struct dma_pte *first_pte = NULL, *last_pte = NULL;
	bool leaf_ptes_only = true;

	pfn = max(start_pfn, pfn);
	pte = &pte[pfn_level_offset(pfn, level)];

	do {
		unsigned long level_pfn = pfn & level_mask(level);

		if (!dma_pte_present(pte))
			goto next;

		/* If range covers entire pagetable, free it */
		if (start_pfn <= level_pfn &&
		    last_pfn >= level_pfn + level_size(level) - 1) {
			/*
			 * These suborbinate page tables are going away entirely. Don't
			 *  bother to clear them; we're just going to *free* them.
			 */
			if (level > 1 && !dma_pte_superpage(pte))
				leaf_ptes_only = false;

			dma_unpresent_pte(pte);
			if (!first_pte)
				first_pte = pte;
			last_pte = pte;
		} else if (level > 1) {
			/* Recurse down into a level that isn't *entirely* obsolete */
			leaf_ptes_only = dma_pte_clear_level(domain, level - 1,
					    pkvm_phys_to_virt(dma_pte_addr(pte)),
					    level_pfn, start_pfn, last_pfn);
		}
next:
		pfn = level_pfn + level_size(level);
	} while (!first_pte_in_page(++pte) && pfn <= last_pfn);

	if (first_pte)
		domain_flush_cache(domain, first_pte,
				   (void *)(++last_pte) - (void *)first_pte);

	return leaf_ptes_only;
}

/*
 * Release(unpin) physical pages reachable by pte that were previously
 * mapped for DMA. Free the page if all PTEs in the page is released.
 */
static void dma_unuse_pte(struct pkvm_iommu_domain *domain,
			  int level, struct dma_pte *pte)
{
	void *pte_addr = pkvm_phys_to_virt(dma_pte_addr(pte));

	/* First PTE in the page */
	pte = (struct dma_pte *)pte_addr;
	if (level == 1) {
		do {
			if (dma_pte_mapped(pte)) {
				__pkvm_unuse_dma(dma_pte_addr(pte), VTD_PAGE_SIZE);
				dma_clear_pte(pte);
			}
			pte++;
		} while (!first_pte_in_page(pte));
	} else {
		do {
			if (dma_pte_mapped(pte)) {
				if (!dma_pte_superpage(pte))
					dma_unuse_pte(domain, level - 1, pte);
				else
					__pkvm_unuse_dma(dma_pte_addr(pte),
							 level_size(level) * VTD_PAGE_SIZE);
				dma_clear_pte(pte);
			}
			pte++;
		} while (!first_pte_in_page(pte));
	}
	push_pkvm_memcache(&domain->mc, pte_addr, hyp_virt_to_phys);
}

/*
 * Walk the IOVA range and release(unpin) physical pages mapped in
 * the range and free the entries in the page table. Free the pages
 * in the page table if all the entries are released as part of this
 * process.
 */
static void dma_unuse_range(struct pkvm_iommu_domain *domain, int level,
			    struct dma_pte *pte, unsigned long pfn,
			    unsigned long start_pfn, unsigned long last_pfn)
{
	struct dma_pte *first_pte = NULL, *last_pte = NULL;

	pfn = max(start_pfn, pfn);
	pte = &pte[pfn_level_offset(pfn, level)];

	do {
		unsigned long level_pfn = pfn & level_mask(level);

		if (!dma_pte_mapped(pte))
			goto next;

		if (start_pfn <= level_pfn &&
		    last_pfn >= level_pfn + level_size(level) - 1) {
			if (level > 1 && !dma_pte_superpage(pte))
				dma_unuse_pte(domain, level - 1, pte);
			else
				__pkvm_unuse_dma(dma_pte_addr(pte),
						 level_size(level) * VTD_PAGE_SIZE);

			dma_clear_pte(pte);
			if (!first_pte)
				first_pte = pte;
			last_pte = pte;
		} else if (level > 1) {
			dma_unuse_range(domain, level - 1,
					pkvm_phys_to_virt(dma_pte_addr(pte)),
					level_pfn, start_pfn, last_pfn);
		}
next:
		pfn = level_pfn + level_size(level);
	} while (!first_pte_in_page(++pte) && pfn <= last_pfn);

	if (first_pte)
		domain_flush_cache(domain, first_pte,
				   (void *)(++last_pte) - (void *)first_pte);
}

/* Copied from drivers/iommu/intel/iommu.c:domain_unmap() */
/*
 * We can't just free the pages because the IOMMU may still be walking
 * the page tables, and may have cached the intermediate levels. The
 * pages can only be freed after the IOTLB flush has been done.
 */
static void domain_unmap(struct pkvm_iommu_domain *domain, unsigned long start_pfn,
			 unsigned long last_pfn)
{
	unsigned long start = start_pfn << VTD_PAGE_SHIFT;
	unsigned long end = last_pfn << VTD_PAGE_SHIFT;
	bool leaf_ptes_only;

	if (WARN_ON(!domain_pfn_supported(domain, last_pfn)) ||
	    WARN_ON(start_pfn > last_pfn))
		return;

	/* we don't need lock here; nobody else touches the iova range */
	leaf_ptes_only = dma_pte_clear_level(domain, agaw_to_level(domain->agaw),
					     pkvm_phys_to_virt(domain->pgd),
					     0, start_pfn, last_pfn);

	/*
	 * Regardless of the DMA mode used by host, we perform iotlb flush on
	 * unmap. Unmapped pages may be donated to a pvm and pvm could use
	 * it to store sensitve data. Until a flush happens, stale entries in
	 * cache could enable a device to read those pages which might contain
	 * sensitive data. So perform flush unconditionally.
	 */
	pkvm_cache_tag_flush_range(domain, start, end, leaf_ptes_only);

	dma_unuse_range(domain, agaw_to_level(domain->agaw),
			pkvm_phys_to_virt(domain->pgd), 0, start_pfn, last_pfn);
}

int pkvm_iommu_domain_unmap(unsigned long pgd_gpa, unsigned long start_pfn, unsigned long last_pfn)
{
	struct pkvm_iommu_domain *domain;

	domain = pkvm_get_iommu_domain(host_gpa2hpa(pgd_gpa));
	if (!domain) {
		pkvm_err("pkvm: %s, failed to get the domain [pgd:%lx]\n",
				__func__, pgd_gpa);
		return -EINVAL;
	}

	pkvm_spin_lock(&domain->lock);
	domain_unmap(domain, start_pfn, last_pfn);
	pkvm_spin_unlock(&domain->lock);

	pkvm_put_iommu_domain(domain);

	return 0;
}
