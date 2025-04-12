/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2025 Google
 */
#include <../drivers/iommu/intel/iommu.h>
#include <asm/pkvm_spinlock.h>
#include <pkvm.h>
#include "pkvm_hyp.h"
#include "gfp.h"
#include "memory.h"
#include "mmu.h"
#include "ept.h"
#include "pgtable.h"
#include "iommu_internal.h"
#include "debug.h"
#include "ptdev.h"
#include "iommu_spgt.h"
#include "bug.h"
#include "iommu.h"

int initialize_iommu_pgt(struct pkvm_iommu *iommu)
{
	/*
	 * This is a nop as pv iommu implementation do not use
	 * iommu->pgt except for iommu-pgt.root_pa and that is
	 * initialized elsewhere.
	 */
	return 0;
}
