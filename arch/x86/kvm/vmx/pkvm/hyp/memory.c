// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/types.h>
#include <asm/kvm_pkvm.h>

unsigned long __page_base_offset;
unsigned long __symbol_base_offset;

unsigned int hyp_memblock_nr;
struct memblock_region hyp_memory[HYP_MEMBLOCK_REGIONS];

void *pkvm_phys_to_virt(unsigned long phys)
{
	return (void *)__page_base_offset + phys;
}

unsigned long pkvm_virt_to_phys(void *virt)
{
	return (unsigned long)virt - __page_base_offset;
}

unsigned long pkvm_virt_to_symbol_phys(void *virt)
{
	return (unsigned long)virt - __symbol_base_offset;
}
