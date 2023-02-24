/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kbuild.h>
#include <pkvm.h>
#include <buddy_memory.h>
#include "hyp/pkvm_hyp.h"
#include "hyp/iommu_internal.h"

int main(void)
{
	DEFINE(PKVM_PERCPU_PAGES, PKVM_PCPU_PAGES + PKVM_HOST_VCPU_PAGES + PKVM_VMCS_PAGES);
	DEFINE(PKVM_GLOBAL_PAGES, PKVM_PAGES);
	DEFINE(PKVM_VMEMMAP_ENTRY_SIZE, sizeof(struct pkvm_page));
	DEFINE(PKVM_SHADOW_VM_SIZE, sizeof(struct pkvm_shadow_vm) + pkvm_shadow_vcpu_array_size());
	DEFINE(PKVM_SHADOW_VCPU_STATE_SIZE, sizeof(struct shadow_vcpu_state));
	DEFINE(PKVM_IOMMU_NUM, PKVM_MAX_IOMMU_NUM);
	DEFINE(PKVM_PASIDDEV_NUM, PKVM_MAX_PASID_PDEV_NUM);
	DEFINE(PKVM_PDEV_NUM, PKVM_MAX_PDEV_NUM);
	DEFINE(PKVM_IOMMU_QI_DESC_SIZE, PKVM_QI_DESC_ALIGNED_SIZE);
	DEFINE(PKVM_IOMMU_QI_DESC_STATUS_SIZE, PKVM_QI_DESC_STATUS_ALIGNED_SIZE);
	DEFINE(PKVM_MAX_VM_NUM, PKVM_MAX_NORMAL_VM_NUM + PKVM_MAX_SECURE_VM_NUM);
	return 0;
}
