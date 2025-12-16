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

static int domain_map(struct pkvm_iommu_domain *domain, struct pkvm_iommu_map_param *param)
{
	/* TODO: Implement map functionality */
	return -EOPNOTSUPP;
}

int pkvm_iommu_domain_map(unsigned long param_va)
{
	struct pkvm_iommu_map_param param, *param_ptr;
	struct pkvm_iommu_domain *domain;
	int ret;

	if (!param_va)
		return -EINVAL;

	param_ptr = (struct pkvm_iommu_map_param *)kern_pkvm_va((void *)param_va);
	if (WARN_ON_ONCE(copy_pv_param_from_host(iommu_map_param, param_ptr, param)))
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

static void domain_unmap(struct pkvm_iommu_domain *domain, unsigned long start_pfn,
			 unsigned long last_pfn)
{
	unsigned long start = start_pfn << VTD_PAGE_SHIFT;
	unsigned long end = last_pfn << VTD_PAGE_SHIFT;
	unsigned long nr_pages = domain->mc.nr_pages;

	/* TODO: Implement unmap functionality */

	/*
	 * Regardless of the DMA mode used by host, we perform iotlb flush on
	 * unmap. Unmapped pages may be donated to a pvm and pvm could use
	 * it to store sensitve data. Until a flush happens, stale entries in
	 * cache could enable a device to read those pages which might contain
	 * sensitive data. So perform flush unconditionally.
	 */
	/*
	 * No new pages released during unmap implies only the leaf
	 * PTEs were updated. Set IH=1(Invalidation Hint) in that case.
	 */
	pkvm_cache_tag_flush_range(domain, start, end,
				   nr_pages == domain->mc.nr_pages);
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
