/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kbuild.h>
#include <pkvm.h>

int main(void)
{
	DEFINE(PKVM_PERCPU_PAGES, PKVM_PCPU_PAGES + PKVM_HOST_VCPU_PAGES);
	DEFINE(PKVM_GLOBAL_PAGES, PKVM_PAGES);
	return 0;
}
