/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#include <../drivers/iommu/intel/iommu.h>
#include <pkvm.h>
#include "pkvm_hyp.h"
#include "memory.h"
#include "mmu.h"

struct pkvm_iommu {
	struct intel_iommu iommu;
};

static struct pkvm_iommu iommus[PKVM_MAX_IOMMU_NUM];

int pkvm_init_iommu(void)
{
	struct pkvm_iommu_info *info = &pkvm_hyp->iommu_infos[0];
	struct pkvm_iommu *piommu = &iommus[0];
	int i, ret;

	for (i = 0; i < PKVM_MAX_IOMMU_NUM; piommu++, info++, i++) {
		if (!info->reg_phys)
			break;

		piommu->iommu.reg_phys = info->reg_phys;
		piommu->iommu.reg_size = info->reg_size;
		piommu->iommu.reg = pkvm_iophys_to_virt(info->reg_phys);
		if ((unsigned long)piommu->iommu.reg == INVALID_ADDR)
			return -ENOMEM;
		piommu->iommu.seq_id = i;

		ret = pkvm_mmu_map((unsigned long)piommu->iommu.reg,
				   (unsigned long)info->reg_phys,
				   info->reg_size, 1 << PG_LEVEL_4K,
				   PKVM_PAGE_IO_NOCACHE);
		if (ret)
			return ret;

		piommu->iommu.cap = readq(piommu->iommu.reg + DMAR_CAP_REG);
		piommu->iommu.ecap = readq(piommu->iommu.reg + DMAR_ECAP_REG);
	}

	return 0;
}
