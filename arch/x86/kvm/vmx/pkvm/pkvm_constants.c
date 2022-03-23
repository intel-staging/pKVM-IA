// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kbuild.h>
#include <linux/bug.h>
#include <vdso/limits.h>
#include <buddy_memory.h>

int main(void)
{
	DEFINE(PKVM_VMEMMAP_ENTRY_SIZE, sizeof(struct hyp_page));
	return 0;
}
