/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef _PKVM_IOMMU_H_
#define _PKVM_IOMMU_H_

int pkvm_init_iommu(unsigned long mem_base, unsigned long nr_pages);
unsigned long pkvm_access_iommu(bool is_read, int len, unsigned long reg, unsigned long val);
bool is_mem_range_overlap_iommu(unsigned long start, unsigned long end);
int pkvm_iommu_sync(u16 bdf, u32 pasid);
bool pkvm_iommu_coherency(u16 bdf, u32 pasid);
void pkvm_iommu_flush_iotlb(unsigned long pgd, unsigned long addr, unsigned long size);

#ifdef CONFIG_PKVM_INTEL_PVIOMMU
unsigned long pkvm_iommu_set_rta(unsigned long phys,unsigned long rta_phys);
unsigned long pkvm_iommu_update_ce(struct kvm_vcpu *hvcpu, unsigned long phys, unsigned long param_gva);
#endif
#endif
