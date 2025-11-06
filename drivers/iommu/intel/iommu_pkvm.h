/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2025, Google.
 */

#ifndef _INTEL_IOMMU_PKVM_H_
#define _INTEL_IOMMU_PKVM_H_

#include <asm/kvm_pkvm.h>

static inline int pkvm_hc_qi_iec_flush(unsigned long reg_phys, bool global, unsigned long index,
		unsigned int mask)
{
	return pkvm_hypercall(iommu_iec_flush, reg_phys, global, index, mask);
}
#endif
