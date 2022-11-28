/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 Intel Corporation. */

#ifndef _PKVM_PTDEV_H_
#define _PKVM_PTDEV_H_

#include "pgtable.h"

struct pkvm_ptdev {
	struct hlist_node hnode;
	u16 did;
	u16 bdf;
	u32 pasid;
	unsigned long index;
	struct list_head iommu_node;

	/* Represents the page table maintained by primary VM */
	struct pkvm_pgtable vpgt;
	/* Represents the page table maintained by pKVM */
	struct pkvm_pgtable *pgt;
};

struct pkvm_ptdev *pkvm_get_ptdev(u16 bdf, u32 pasid);
void pkvm_put_ptdev(struct pkvm_ptdev *ptdev);
void pkvm_setup_ptdev_vpgt(struct pkvm_ptdev *ptdev, unsigned long root_gpa,
			   struct pkvm_mm_ops *mm_ops, struct pkvm_pgtable_ops *paging_ops,
			   struct pkvm_pgtable_cap *cap);
void pkvm_setup_ptdev_did(struct pkvm_ptdev *ptdev, u16 did);

static inline bool match_ptdev(struct pkvm_ptdev *ptdev, u16 bdf, u32 pasid)
{
	return ptdev && (ptdev->bdf == bdf) && (ptdev->pasid == pasid);
}
#endif
