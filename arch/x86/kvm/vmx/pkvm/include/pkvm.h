// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef _PKVM_H_
#define _PKVM_H_

#include <vmx/vmx.h>

struct pkvm_hyp {
	int num_cpus;

	struct vmx_capability vmx_cap;
	struct vmcs_config vmcs_config;
};

#define PKVM_PAGES (ALIGN(sizeof(struct pkvm_hyp), PAGE_SIZE) >> PAGE_SHIFT)

#endif
