/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 Intel Corporation. */

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
	bool iommu_coherency;
	u64 pgd;
	int iommu_superpage;
	int gaw;
	int agaw;

	/*
	 * List of IOMMUs attached to this domain.
	 */
	struct list_head iommu_head;

	/*
	 * Lock to protect the mapping operations
	 * on this domain.
	 */
	pkvm_spinlock_t lock;

	struct hlist_node hnode;
};

struct pkvm_iommu_domain *pkvm_alloc_iommu_domain(u64 pgd);
struct pkvm_iommu_domain *pkvm_get_iommu_domain(u64 pgd);
void pkvm_put_iommu_domain(struct pkvm_iommu_domain *iommu_domain);

int pkvm_domain_attach_iommu(struct pkvm_iommu_domain *domain, struct pkvm_iommu *iommu);
void pkvm_domain_detach_iommu(struct pkvm_iommu_domain *domain, struct pkvm_iommu *iommu);
#endif
