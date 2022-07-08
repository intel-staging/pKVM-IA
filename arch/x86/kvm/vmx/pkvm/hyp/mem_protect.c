/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#include <linux/bitfield.h>
#include <pkvm.h>
#include "pkvm_hyp.h"
#include "mem_protect.h"
#include "pgtable.h"
#include "ept.h"

static u64 pkvm_init_invalid_leaf_owner(pkvm_id owner_id)
{
	/* the page owned by others also means NOPAGE in page state */
	return FIELD_PREP(PKVM_INVALID_PTE_OWNER_MASK, owner_id) |
		FIELD_PREP(PKVM_PAGE_STATE_PROT_MASK, PKVM_NOPAGE);
}

int host_ept_set_owner_locked(phys_addr_t addr, u64 size, pkvm_id owner_id)
{
	u64 annotation = pkvm_init_invalid_leaf_owner(owner_id);
	int ret;


	/*
	 * The memory [addr, addr + size) will be unmaped from host ept. At the
	 * same time, the annotation with a NOPAGE flag will be put in the
	 * invalid pte that has been unmaped. And these information record that
	 * the page has been used by some guest and it's id can be read from
	 * annotation. Also when later these page back to host, the annotation
	 * will help to check the right page transition.
	 */
	ret = pkvm_pgtable_annotate(pkvm_hyp->host_vm.ept, addr, size, annotation);

	return ret;
}

int host_ept_set_owner(phys_addr_t addr, u64 size, pkvm_id owner_id)
{
	int ret;

	host_ept_lock();
	ret = host_ept_set_owner_locked(addr, size, owner_id);
	host_ept_unlock();

	return ret;
}
