/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2026 Google
 */

#ifndef _PKVM_INTEL_IOMMU_HC_H_
#define _PKVM_INTEL_IOMMU_HC_H_

#include <asm/kvm_pkvm.h>

enum iommu_hc_num {
	qi_submit,
};

struct qi_submit_data {
	u64 phys;
	u64 desc_gpa;
	u32 options;
	u32 count;
};

struct iommu_hc_data {
	union {
		struct qi_submit_data qi_submit;
	};
	u8 hc_num;
};
static_assert(sizeof(struct iommu_hc_data) <= PKVM_HC_DATA_MAX_NUM * sizeof(u64));

int pkvm_iommu_qi_submit(struct qi_submit_data *data);
#endif /* _PKVM_INTEL_IOMMU_HC_H_ */
