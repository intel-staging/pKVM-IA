// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. */
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
#include "memory.h"
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


static inline struct pkvm_iommu_domain *__pkvm_get_iommu_domain_locked(u64 pgd)
{
	struct pkvm_iommu_domain *domain = NULL, *tmp;

	hash_for_each_possible(iommu_domain_hasht, tmp, hnode, pgd) {
		if (tmp->pgd == pgd) {
			domain = atomic_inc_not_zero(&tmp->refcount) ? tmp : NULL;
			if (domain)
				break;
		}
	}

	return domain;
}

struct pkvm_iommu_domain *pkvm_get_iommu_domain(u64 pgd)
{
	struct pkvm_iommu_domain *domain;
	pkvm_spin_lock(&iommu_domain_lock);

	domain = __pkvm_get_iommu_domain_locked(pgd);

	pkvm_spin_unlock(&iommu_domain_lock);
	if (domain)
		pkvm_dbg("pkvm: %s acquire iommu domain pgd: %llx\n", __func__, domain->pgd);

	return domain;
}

void pkvm_put_iommu_domain(struct pkvm_iommu_domain *domain)
{
	if (!atomic_dec_and_test(&domain->refcount))
		return;

	pkvm_dbg("pkvm: %s release iommu domain pgd: %llx\n", __func__, domain->pgd);
	pkvm_spin_lock(&iommu_domain_lock);

	hlist_del(&domain->hnode);

	__clear_bit(domain->index, iommu_domains_bitmap);

	memset(domain, 0, sizeof(struct pkvm_iommu_domain));

	pkvm_spin_unlock(&iommu_domain_lock);
}

struct pkvm_iommu_domain *pkvm_alloc_iommu_domain(u64 pgd)
{
	struct pkvm_iommu_domain *domain = NULL;
	unsigned long index;

	pkvm_spin_lock(&iommu_domain_lock);

	domain = __pkvm_get_iommu_domain_locked(pgd);
	if (domain)
		goto out;

	index = find_next_zero_bit(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM, 0);
	if (index < MAX_IOMMU_DOMAIN_NUM) {
		__set_bit(index, iommu_domains_bitmap);
		domain = &iommu_domains[index];
		INIT_LIST_HEAD(&domain->iommu_head);
		domain->pgd = pgd;
		domain->index = index;
		atomic_set(&domain->refcount, 1);
		pkvm_spin_lock_init(&domain->lock);
		hash_add(iommu_domain_hasht, &domain->hnode, pgd);
	}

out:
	pkvm_spin_unlock(&iommu_domain_lock);
	pkvm_dbg("pkvm: %s alloc iommu domain pgd: %llx\n", __func__, domain->pgd);

	return domain;
}

/*
 * Attach an IOMMU to the domain and maintain reference count.
 */
int pkvm_domain_attach_iommu(struct pkvm_iommu_domain *domain, struct pkvm_iommu *iommu)
{
	int ret = 0;

	pkvm_spin_lock(&iommu->lock);
	if (!iommu->domain) {
		iommu->domain = domain;
		pkvm_spin_lock(&domain->lock);
		list_add_tail(&iommu->domain_node, &domain->iommu_head);
		pkvm_spin_unlock(&domain->lock);
		pkvm_dbg("pkvm: %s attached iommu[%d] to domain[pgd: %llx]\n",
				__func__, iommu->iommu.seq_id, domain->pgd);
	} else if (iommu->domain != domain) {
		/*
		 * IOMMU is part of a different domain.
		 */
		ret = -EINVAL;
		goto out;
	}
	iommu->domain_refcount++;
	pkvm_dbg("pkvm: %s iommu[%d] incremented refcount: %d\n",
			__func__, iommu->iommu.seq_id, iommu->domain_refcount);

out:
	pkvm_spin_unlock(&iommu->lock);
	return ret;
}

/*
 * Detach an IOMMU from the domain and maintain reference count.
 */
void pkvm_domain_detach_iommu(struct pkvm_iommu_domain *domain, struct pkvm_iommu *iommu)
{
	PKVM_ASSERT(iommu->domain && iommu->domain == domain);

	pkvm_spin_lock(&iommu->lock);
	PKVM_ASSERT(iommu->domain_refcount > 0);
	iommu->domain_refcount--;
	pkvm_dbg("pkvm: %s iommu[%d] decremented refcount: %d\n",
			__func__, iommu->iommu.seq_id, iommu->domain_refcount);
	if (!iommu->domain_refcount) {
		pkvm_spin_lock(&domain->lock);
		list_del_init(&iommu->domain_node);
		pkvm_spin_unlock(&domain->lock);
		iommu->domain = NULL;
		pkvm_dbg("pkvm: %s detached iommu[%d] from domain[pgd: %llx]\n",
				__func__, iommu->iommu.seq_id, domain->pgd);
	}

	pkvm_spin_unlock(&iommu->lock);
}

void pkvm_domain_flush_iotlb_range(struct pkvm_iommu_domain *domain, unsigned long addr, int size)
{
	int size_order = ilog2(__roundup_pow_of_two(size >> VTD_PAGE_SHIFT));
	struct pkvm_iommu *iommu;
	struct iotlb_flush_data data = {
		.desired_root_pa = domain->pgd,
		.addr = ALIGN_DOWN(addr, (1ULL << (VTD_PAGE_SHIFT + size_order))),
		.size_order = size_order,
	};

	data.desc = iommu_zalloc_pages(PKVM_QI_DESC_ALIGNED_SIZE);
	if (data.desc)
		/* Reserve space for one wait desc and one desc between head and tail */
		data.desc_max_index = PKVM_QI_DESC_ALIGNED_SIZE / sizeof(struct qi_desc) - 2;

	list_for_each_entry(iommu, &domain->iommu_head, domain_node) {
		memset(data.desc, 0, PKVM_QI_DESC_ALIGNED_SIZE);
		pkvm_spin_lock(&iommu->lock);
		iommu_flush_iotlb(iommu, &data);
		pkvm_spin_unlock(&iommu->lock);

	}
	if (data.desc)
		iommu_put_page(data.desc);
}

/*
 * =============================================================================
 * Following code is taken mostly as it is from iommu/intel/iommu.c
 * TODO: See if we can refactor the common code to a single location.
 * =============================================================================
 */

static void domain_flush_cache(struct pkvm_iommu_domain *domain,
			       void *addr, int size)
{
	if (!domain->iommu_coherency)
		iommu_flush_cache(addr, size);
}

static int domain_pfn_supported(struct pkvm_iommu_domain *domain, unsigned long pfn)
{
	int addr_width = agaw_to_width(domain->agaw) - VTD_PAGE_SHIFT;

	return !(addr_width < BITS_PER_LONG && pfn >> addr_width);
}

/* Return largest possible superpage level for a given mapping */
static int hardware_largepage_caps(struct pkvm_iommu_domain *domain, unsigned long iov_pfn,
				   unsigned long phy_pfn, unsigned long pages)
{
	int support, level = 1;
	unsigned long pfnmerge;

	support = domain->iommu_superpage;

	/* To use a large page, the virtual *and* physical addresses
	   must be aligned to 2MiB/1GiB/etc. Lower bits set in either
	   of them will mean we have to use smaller pages. So just
	   merge them and check both at once. */
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

static struct dma_pte *pfn_to_dma_pte(struct pkvm_iommu_domain *domain,
				      struct pkvm_iommu_page_donation *donation,
				      unsigned long pfn, int *target_level)
{
	struct dma_pte *parent, *pte;
	int level = agaw_to_level(domain->agaw);
	int offset;

	if (!domain_pfn_supported(domain, pfn))
		/* Address beyond IOMMU's addressing capabilities. */
		return NULL;

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

			donation->nr_pages--;
			if (donation->nr_pages < 0) {
				/*
				 * Not enough pages donated by host.
				 * Ask for more and restart the hypercall.
				 */
				return NULL;
			}
			__pkvm_host_donate_hyp(donation->pages[donation->nr_pages], PAGE_SIZE);
			tmp_page = pkvm_phys_to_virt(donation->pages[donation->nr_pages]);

			domain_flush_cache(domain, tmp_page, VTD_PAGE_SIZE);
			pteval = pkvm_virt_to_phys(tmp_page) | DMA_PTE_READ | DMA_PTE_WRITE;

			tmp = 0ULL;
			if (!try_cmpxchg64(&pte->val, &tmp, pteval)) {
				/* Someone else set it while we were thinking; use theirs. */
				donation->nr_pages++;
			} else {
				domain_flush_cache(domain, pte, sizeof(*pte));
			}
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

static void dma_pte_free_level(struct pkvm_iommu_domain *domain,
			       struct pkvm_iommu_page_donation *donation,
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
			dma_pte_free_level(domain, donation, level - 1, retain_level,
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
			donation->pages[donation->nr_pages++] = pkvm_virt_to_phys(level_pte);
			__pkvm_hyp_donate_host(pkvm_virt_to_phys(level_pte), PAGE_SIZE);
		}
next:
		pfn += level_size(level);
	} while (!first_pte_in_page(++pte) && pfn <= last_pfn);
}

/*
 * clear last level (leaf) ptes and free page table pages below the
 * level we wish to keep intact.
 */
static void dma_pte_free_pagetable(struct pkvm_iommu_domain *domain,
				   struct pkvm_iommu_page_donation *donation,
				   unsigned long start_pfn,
				   unsigned long last_pfn,
				   int retain_level)
{
	struct dma_pte *pgd = (struct dma_pte *)pkvm_phys_to_virt(domain->pgd);
	dma_pte_clear_range(domain, start_pfn, last_pfn);

	/* We don't need lock here; nobody else touches the iova range */
	dma_pte_free_level(domain, donation, agaw_to_level(domain->agaw), retain_level,
			   pgd, 0, start_pfn, last_pfn);

	/* free pgd */
	if (start_pfn == 0 && last_pfn == DOMAIN_MAX_PFN(domain->gaw)) {
		donation->pages[donation->nr_pages++] = domain->pgd;
		__pkvm_hyp_donate_host(domain->pgd, PAGE_SIZE);
		domain->pgd = 0ULL;
	}
}

/*
 * Ensure that old small page tables are removed to make room for superpage(s).
 * We're going to add new large pages, so make sure we don't remove their parent
 * tables. The IOTLB/devTLBs should be flushed if any PDE/PTEs are cleared.
 */
static void switch_to_super_page(struct pkvm_iommu_domain *domain,
				 struct pkvm_iommu_page_donation *donation,
				 unsigned long start_pfn,
				 unsigned long end_pfn, int level)
{
	unsigned long lvl_pages = lvl_to_nr_pages(level);
	struct dma_pte *pte = NULL;

	while (start_pfn <= end_pfn) {
		if (!pte)
			pte = pfn_to_dma_pte(domain, donation, start_pfn, &level);

		if (dma_pte_present(pte)) {
			dma_pte_free_pagetable(domain, donation, start_pfn,
					       start_pfn + lvl_pages - 1,
					       level + 1);

			pkvm_domain_flush_iotlb_range(domain, start_pfn << VTD_PAGE_SHIFT,
					end_pfn << VTD_PAGE_SHIFT);
		}

		pte++;
		start_pfn += lvl_pages;
		if (first_pte_in_page(pte))
			pte = NULL;
	}
}

static int
domain_map(struct pkvm_iommu_domain *domain, struct pkvm_iommu_map_param *param,
		struct pkvm_iommu_page_donation *donation)
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

	if (unlikely(!domain_pfn_supported(domain, iov_pfn + nr_pages - 1)))
		return -EINVAL;

	if ((prot & (DMA_PTE_READ|DMA_PTE_WRITE)) == 0)
		return -EINVAL;

	attr = prot & (DMA_PTE_READ | DMA_PTE_WRITE | DMA_PTE_SNP);
	attr |= DMA_FL_PTE_PRESENT;

	pteval = ((phys_addr_t)phys_pfn << VTD_PAGE_SHIFT) | attr;

	while (nr_pages > 0) {
		uint64_t tmp;

		if (!pte) {
			largepage_lvl = hardware_largepage_caps(domain, iov_pfn,
					phys_pfn, nr_pages);

			pte = pfn_to_dma_pte(domain, donation, iov_pfn, &largepage_lvl);
			if (!pte)
				return -ENOMEM;
			first_pte = pte;

			lvl_pages = lvl_to_nr_pages(largepage_lvl);

			/* It is large page*/
			if (largepage_lvl > 1) {
				unsigned long end_pfn;
				unsigned long pages_to_remove;

				pteval |= DMA_PTE_LARGE_PAGE;
				pages_to_remove = min_t(unsigned long, nr_pages,
							nr_pte_to_next_page(pte) * lvl_pages);
				end_pfn = iov_pfn + pages_to_remove - 1;
				switch_to_super_page(domain, donation,
						iov_pfn, end_pfn, largepage_lvl);
			} else {
				pteval &= ~(uint64_t)DMA_PTE_LARGE_PAGE;
			}

		}
		/* We don't need lock here, nobody else
		 * touches the iova range
		 */
		tmp = 0ULL;
		if (!try_cmpxchg64_local(&pte->val, &tmp, pteval)) {
			pkvm_err("ERROR: DMA PTE for vPFN 0x%lx already set (to %llx not %llx)\n",
				iov_pfn, tmp, (unsigned long long)pteval);
		}

		nr_pages -= lvl_pages;
		iov_pfn += lvl_pages;
		phys_pfn += lvl_pages;
		pteval += lvl_pages * VTD_PAGE_SIZE;

		/* If the next PTE would be the first in a new page, then we
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
			iommu_flush_cache(first_pte, (void *)pte - (void *)first_pte);
			pte = NULL;
		}
	}

	return 0;
}

unsigned long pkvm_iommu_domain_map(struct kvm_vcpu *hvcpu,
		unsigned long param_gva, unsigned long donation_gva)
{
	struct pkvm_iommu_page_donation donation = { 0 };
	struct pkvm_iommu_map_param param = { 0 };
	struct pkvm_iommu_domain *domain;
	struct x86_exception e;
	unsigned long ret = 0;

	ret = read_gva(hvcpu, param_gva, &param, sizeof(struct pkvm_iommu_map_param), &e);
	if (ret < 0) {
		pkvm_err("pkvm: %s Failed to read update_ce_param(gva: %lx) from host!\n",
				__func__, param_gva);
		return ret;
	}
	ret = read_gva(hvcpu, donation_gva, &donation, sizeof(struct pkvm_iommu_page_donation), &e);
	if (ret < 0) {
		pkvm_err("pkvm: %s Failed to read donation (gva: %lx) from host!\n",
				__func__, donation_gva);
		return ret;
	}

	domain = pkvm_get_iommu_domain(host_gpa2hpa(param.pgd_gpa));
	if (!domain) {
		pkvm_dbg("pkvm: %s, failed to get the domain [pgd:%llx]\n",
				__func__, param.pgd_gpa);
		return -EINVAL;
	} else {
		pkvm_dbg("pkvm: %s, retrieved domain[pgd: %llx] for domain mapping!\n",
				__func__, domain->pgd);
	}
	pkvm_spin_lock(&domain->lock);
	ret = domain_map(domain, &param, &donation);
	pkvm_spin_unlock(&domain->lock);
	pkvm_put_iommu_domain(domain);

	ret = write_gva(hvcpu, donation_gva, &donation, sizeof(struct pkvm_iommu_page_donation), &e);
	if (ret < 0) {
		pkvm_err("pkvm: %s Failed to write donation(gva: %lx) to host!\n",
				__func__, donation_gva);
		return ret;
	}
	return ret;
}

/* When a page at a given level is being unlinked from its parent, we don't
   need to *modify* it at all. All we need to do is make a list of all the
   pages which can be freed just as soon as we've flushed the IOTLB and we
   know the hardware page-walk will no longer touch them.
   The 'pte' argument is the *parent* PTE, pointing to the page that is to
   be freed. */
static void dma_pte_list_pagetables(struct pkvm_iommu_domain *domain,
				    int level, struct dma_pte *pte,
				    struct pkvm_iommu_page_donation *donation)
{
	/*
	 * TODO: check again if this logic is correct.
	 */
	donation->pages[donation->nr_pages++] = dma_pte_addr(pte);
	__pkvm_hyp_donate_host(dma_pte_addr(pte), PAGE_SIZE);

	if (level == 1)
		return;

	pte = pkvm_phys_to_virt(dma_pte_addr(pte));
	do {
		if (dma_pte_present(pte) && !dma_pte_superpage(pte))
			dma_pte_list_pagetables(domain, level - 1, pte, donation);
		pte++;
	} while (!first_pte_in_page(pte));
}

static void dma_pte_clear_level(struct pkvm_iommu_domain *domain, int level,
				struct dma_pte *pte, unsigned long pfn,
				unsigned long start_pfn, unsigned long last_pfn,
				struct pkvm_iommu_page_donation *donation)
{
	struct dma_pte *first_pte = NULL, *last_pte = NULL;

	pfn = max(start_pfn, pfn);
	pte = &pte[pfn_level_offset(pfn, level)];

	do {
		unsigned long level_pfn = pfn & level_mask(level);

		if (!dma_pte_present(pte))
			goto next;

		/* If range covers entire pagetable, free it */
		if (start_pfn <= level_pfn &&
		    last_pfn >= level_pfn + level_size(level) - 1) {
			/* These suborbinate page tables are going away entirely. Don't
			   bother to clear them; we're just going to *free* them. */
			if (level > 1 && !dma_pte_superpage(pte))
				dma_pte_list_pagetables(domain, level - 1, pte, donation);

			dma_clear_pte(pte);
			if (!first_pte)
				first_pte = pte;
			last_pte = pte;
		} else if (level > 1) {
			/* Recurse down into a level that isn't *entirely* obsolete */
			dma_pte_clear_level(domain, level - 1,
					    pkvm_phys_to_virt(dma_pte_addr(pte)),
					    level_pfn, start_pfn, last_pfn,
					    donation);
		}
next:
		pfn = level_pfn + level_size(level);
	} while (!first_pte_in_page(++pte) && pfn <= last_pfn);

	if (first_pte)
		domain_flush_cache(domain, first_pte,
				   (void *)++last_pte - (void *)first_pte);
}

/* We can't just free the pages because the IOMMU may still be walking
   the page tables, and may have cached the intermediate levels. The
   pages can only be freed after the IOTLB flush has been done. */
static void domain_unmap(struct pkvm_iommu_domain *domain, unsigned long start_pfn,
			 unsigned long last_pfn, struct pkvm_iommu_page_donation *donation)
{
	if (WARN_ON(!domain_pfn_supported(domain, last_pfn)) ||
	    WARN_ON(start_pfn > last_pfn))
		return;

	/* we don't need lock here; nobody else touches the iova range */
	dma_pte_clear_level(domain, agaw_to_level(domain->agaw),
			    pkvm_phys_to_virt(domain->pgd), 0, start_pfn, last_pfn, donation);

	/* free pgd */
	if (start_pfn == 0 && last_pfn == DOMAIN_MAX_PFN(domain->gaw)) {
		pkvm_dbg("pkvm: %s freeing pgd: %llx\n", __func__, domain->pgd);
		donation->pages[donation->nr_pages++] = domain->pgd;
		__pkvm_hyp_donate_host(domain->pgd, PAGE_SIZE);
		domain->pgd = 0ULL;
	}
}

unsigned long pkvm_iommu_domain_unmap(struct kvm_vcpu *hvcpu, unsigned long pgd_gpa,
		unsigned long start_pfn, unsigned long last_pfn, unsigned long donation_gva)
{
	struct pkvm_iommu_page_donation donation = { 0 };
	struct pkvm_iommu_domain *domain;
	struct x86_exception e;
	unsigned long ret = 0;

	ret = read_gva(hvcpu, donation_gva, &donation, sizeof(struct pkvm_iommu_page_donation), &e);
	if (ret < 0) {
		pkvm_err("pkvm: %s Failed to read donation (gva: %lx) from host!\n",
				__func__, donation_gva);
		return ret;
	}

	domain = pkvm_get_iommu_domain(host_gpa2hpa(pgd_gpa));
	if (!domain) {
		pkvm_dbg("pkvm: %s, failed to get the domain [pgd:%lx]\n",
				__func__, pgd_gpa);
		return -EINVAL;
	} else {
		pkvm_dbg("pkvm: %s, retrieved domain[pgd: %llx] for domain unmap!\n",
				__func__, domain->pgd);
	}
	pkvm_spin_lock(&domain->lock);
	domain_unmap(domain, start_pfn, last_pfn, &donation);
	pkvm_spin_unlock(&domain->lock);
	pkvm_put_iommu_domain(domain);

	pkvm_dbg("pkvm: %s unused %d pages\n", __func__, donation.nr_pages);
	ret = write_gva(hvcpu, donation_gva, &donation, sizeof(struct pkvm_iommu_page_donation), &e);
	if (ret < 0) {
		pkvm_err("pkvm: %s Failed to write donation(gva: %lx) to host!\n",
				__func__, donation_gva);
		return ret;
	}
	return 0;
}

unsigned long pkvm_iommu_domain_iova_to_phys(struct kvm_vcpu *hvcpu, unsigned long param_gva)
{
	struct pkvm_iommu_page_donation donation = { 0 };
	struct pkvm_iommu_iova2phys_param param = { 0 };
	struct pkvm_iommu_domain *domain;
	struct x86_exception e;
	unsigned long phys = 0;
	unsigned long ret = 0;
	struct dma_pte *pte;
	int level = 0;

	ret = read_gva(hvcpu, param_gva, &param, sizeof(struct pkvm_iommu_iova2phys_param), &e);
	if (ret < 0) {
		pkvm_err("pkvm: %s Failed to read iova2phys_param (gva: %lx) from host!\n",
				__func__, param_gva);
		return ret;
	}

	domain = pkvm_get_iommu_domain(host_gpa2hpa(param.pgd_gpa));
	if (!domain) {
		pkvm_dbg("pkvm: %s, failed to get the domain [pgd:%llx]\n",
				__func__, param.pgd_gpa);
		return -EINVAL;
	} else {
		pkvm_dbg("pkvm: %s, retrieved domain[pgd: %llx] for iova2phys!\n",
				__func__, domain->pgd);
	}
	pkvm_spin_lock(&domain->lock);
	pte = pfn_to_dma_pte(domain, &donation, param.iova >> VTD_PAGE_SHIFT, &level);
	if (pte && dma_pte_present(pte))
		phys = dma_pte_addr(pte) +
			(param.iova & (BIT_MASK(level_to_offset_bits(level) +
					  VTD_PAGE_SHIFT) - 1));
	pkvm_spin_unlock(&domain->lock);
	pkvm_put_iommu_domain(domain);
	pkvm_dbg("pkvm: %s, iova=%llx, phys=%lx, level=%d\n", __func__, param.iova, phys, level);

	param.phys = phys;
	param.level = level;
	ret = write_gva(hvcpu, param_gva, &param, sizeof(struct pkvm_iommu_iova2phys_param), &e);
	if (ret < 0) {
		pkvm_err("pkvm: %s Failed to write iova2phys_param (gva: %lx) tp host!\n",
				__func__, param_gva);
		return ret;
	}

	return ret;
}
