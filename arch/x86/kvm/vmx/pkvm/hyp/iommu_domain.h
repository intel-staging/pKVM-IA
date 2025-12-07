/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2025 Google. */

#ifndef _PKVM_IOMMU_DOMAIN_H_
#define _PKVM_IOMMU_DOMAIN_H_

#include "pkvm_hyp.h"

/*
 * Represents a host iommu_domain/dmar_domain
 * Main function is to manage IO page tables.
 */
struct pkvm_iommu_domain {
	atomic_t refcount;
	unsigned long index;
	u64 pgd;
	u64 max_addr;
	u8 iommu_superpage: 4;
	u8 iommu_coherency: 1;
	u8 use_first_level: 1;
	u16 gaw;
	u8 agaw;

	/*
	 * Lock to protect the mapping operations
	 * on this domain.
	 */
	pkvm_spinlock_t lock;

	struct hlist_node hnode;
};

struct pkvm_iommu_domain *pkvm_alloc_iommu_domain(u64 pgd);
struct pkvm_iommu_domain *pkvm_get_iommu_domain(u64 pgd);
struct pkvm_iommu_domain *pkvm_get_iommu_domain_noref(u64 pgd);
void pkvm_put_iommu_domain(struct pkvm_iommu_domain *domain);
int pkvm_free_iommu_domain(struct pkvm_iommu_domain *domain);
#endif
