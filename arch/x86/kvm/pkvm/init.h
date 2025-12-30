/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_INIT_H
#define __PKVM_X86_INIT_H

#include <asm/kvm_pkvm.h>
#include "pgtable.h"

typedef int (*hyp_mmu_finalize_fn_t)(struct pkvm_pgtable *pgt);
typedef int (*host_mmu_init_fn_t)(struct pkvm_pgtable *pgt, void *pool_base,
				  unsigned long pool_pages);
typedef int (*host_mmu_finalize_fn_t)(struct pkvm_pgtable *pgt);
typedef int (*hyp_global_init_fn_t)(void);

/**
 * pkvm_init_ops - The platform vendor specific pKVM init operations used by the
 *		   pkvm_init. Some operation could be NULL if it is not necessary.
 *
 * @hyp_mmu_finalize:	Finalize the hypervisor mmu.
 * @host_mmu_init:	Initialize the host mmu.
 * @host_mmu_finalize:	Finalize the host mmu.
 * @hyp_global_init:	Initialize the hypervisor globally.
 */
struct pkvm_init_ops {
	hyp_mmu_finalize_fn_t		hyp_mmu_finalize;
	host_mmu_init_fn_t		host_mmu_init;
	host_mmu_finalize_fn_t		host_mmu_finalize;
	hyp_global_init_fn_t		hyp_global_init;
};

int pkvm_init(struct pkvm_mem_info infos[], int nr_info, struct pkvm_init_ops *init_ops);

#endif /* __PKVM_X86_INIT_H */
