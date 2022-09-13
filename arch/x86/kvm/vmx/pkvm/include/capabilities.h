/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef _PKVM_CAPS_H_
#define _PKVM_CAPS_H_

#ifdef __PKVM_HYP__
#define PKVM_HYP pkvm_hyp
#else
#define PKVM_HYP pkvm_sym(pkvm_hyp)
#endif

static inline bool vmx_vpid_capability_check(u32 bit)
{
	struct vmx_capability *vmx_cap = &PKVM_HYP->vmx_cap;

	return vmx_cap->vpid & bit;
}

static inline bool vmx_has_invvpid(void)
{
	return vmx_vpid_capability_check(VMX_VPID_INVVPID_BIT);
}

static inline bool vmx_has_invvpid_single(void)
{
	return vmx_vpid_capability_check(VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT);
}

static inline bool vmx_has_invvpid_global(void)
{
	return vmx_vpid_capability_check(VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT);
}

#endif
