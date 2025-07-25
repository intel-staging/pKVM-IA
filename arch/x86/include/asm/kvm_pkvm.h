/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_PKVM_H
#define _ASM_X86_KVM_PKVM_H

#include <linux/init.h>

#ifdef CONFIG_PKVM_INTEL

#define HYP_MEMBLOCK_REGIONS		128

extern phys_addr_t hyp_mem_base;
extern phys_addr_t hyp_mem_size;

void __init kvm_hyp_reserve(void);
u64 hyp_total_reserve_pages(void);

static inline unsigned long pkvm_data_struct_pages(unsigned long global_pgs,
						   unsigned long percpu_pgs,
						   int num_cpus)
{
	return (percpu_pgs * num_cpus + global_pgs);
}

#else
static inline void __init kvm_hyp_reserve(void) {}
#endif

#endif
