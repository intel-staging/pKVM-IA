/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kbuild.h>
#include <pkvm.h>
#include <buddy_memory.h>
#include "hyp/pkvm_hyp.h"

int main(void)
{
	DEFINE(PKVM_PERCPU_PAGES, PKVM_PCPU_PAGES + PKVM_HOST_VCPU_PAGES + PKVM_VMCS_PAGES);
	DEFINE(PKVM_GLOBAL_PAGES, PKVM_PAGES);
	DEFINE(PKVM_VMEMMAP_ENTRY_SIZE, sizeof(struct pkvm_page));
	DEFINE(PKVM_SHADOW_VM_SIZE, sizeof(struct pkvm_shadow_vm));
	DEFINE(PKVM_SHADOW_VCPU_STATE_SIZE, sizeof(struct shadow_vcpu_state));
	return 0;
}
