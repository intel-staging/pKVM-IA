/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef __PKVM_VMX_H
#define __PKVM_VMX_H

static inline u64 pkvm_construct_eptp(unsigned long root_hpa,
		struct vmx_capability *vmx_cap)
{
	u64 eptp = 0;

	if (vmx_cap->ept & VMX_EPT_PAGE_WALK_4_BIT)
		eptp = VMX_EPTP_PWL_4;
	else if (vmx_cap->ept & VMX_EPT_PAGE_WALK_5_BIT)
		eptp = VMX_EPTP_PWL_5;

	if (vmx_cap->ept & VMX_EPTP_WB_BIT)
		eptp |= VMX_EPTP_MT_WB;

	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

static inline void vmcs_load_track(struct vcpu_vmx *vmx, struct vmcs *vmcs)
{
	struct pkvm_host_vcpu *pkvm_host_vcpu = vmx_to_pkvm_hvcpu(vmx);

	pkvm_host_vcpu->current_vmcs = vmcs;
	barrier();
	vmcs_load(vmcs);
}

static inline void vmcs_clear_track(struct vcpu_vmx *vmx, struct vmcs *vmcs)
{
	struct pkvm_host_vcpu *pkvm_host_vcpu = vmx_to_pkvm_hvcpu(vmx);

	/* vmcs_clear might clear none current vmcs */
	if (pkvm_host_vcpu->current_vmcs == vmcs)
		pkvm_host_vcpu->current_vmcs = NULL;

	barrier();
	vmcs_clear(vmcs);
}

void init_contant_host_state_area(struct pkvm_pcpu *pcpu, int cpu);
#endif
