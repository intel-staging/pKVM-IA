// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */

#include <pkvm.h>
#include "debug.h"

#define TMP_SECTION_SZ	16UL
int __pkvm_init_finalise(struct kvm_vcpu *vcpu, struct pkvm_section sections[],
			 int section_sz)
{
	int i, ret = 0;
	static bool pkvm_init;
	struct pkvm_section tmp_sections[TMP_SECTION_SZ];
	phys_addr_t hyp_mem_base;
	unsigned long hyp_mem_size = 0;

	if (pkvm_init)
		goto switch_pgt;

	if (section_sz > TMP_SECTION_SZ) {
		pkvm_err("pkvm: no enough space to save sections[] array parameters!");
		ret = -ENOMEM;
		goto out;
	}

	/* kernel may use VMAP_STACK, which could make the parameter's vaddr
	 * not-valid after we switch new CR3 later, so copy parameter sections
	 * array from host space to pkvm space
	 */
	for (i = 0; i < section_sz; i++) {
		tmp_sections[i] = sections[i];
		if (sections[i].type == PKVM_RESERVED_MEMORY) {
			hyp_mem_base = sections[i].addr;
			hyp_mem_size = sections[i].size;
		}
	}
	if (hyp_mem_size == 0) {
		pkvm_err("pkvm: no pkvm reserve memory!");
		ret = -ENOTSUPP;
	}

	/* TODO: setup MMU & host EPT page tables */

	pkvm_init = true;

switch_pgt:
	/* TODO: switch MMU & EPT */

out:
	return ret;
}
