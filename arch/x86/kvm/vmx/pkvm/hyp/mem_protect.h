/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef __PKVM_MEM_PROTECT_H__
#define __PKVM_MEM_PROTECT_H__

/* use 20 bits[12~31] - not conflict w/ low 12 bits pte prot */
#define PKVM_INVALID_PTE_OWNER_MASK	GENMASK(31, 12)

typedef u32 pkvm_id;
static const pkvm_id pkvm_hyp_id = 0;

int host_ept_set_owner(phys_addr_t addr, u64 size, pkvm_id owner_id);

#endif
