/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_INIT_FINALIZE_H
#define __PKVM_X86_INIT_FINALIZE_H

#include <asm/kvm_pkvm.h>
#include "pgtable.h"

typedef int (*hyp_mmu_finalize_fn_t)(struct pkvm_pgtable *pgt);

/**
 * pkvm_init_ops - The platform vendor specific pKVM finalize operations used by
 *		   the pkvm_init_finalize. Some operation could be NULL if it is
 *		   not necessary.
 *
 * @hyp_mmu_finalize:	Finalize the hypervisor mmu.
 */
struct pkvm_init_ops {
	hyp_mmu_finalize_fn_t		hyp_mmu_finalize;
};

int pkvm_init_finalize(struct pkvm_mem_info infos[], int nr_info,
		       struct pkvm_init_ops *init_ops);

#endif /* __PKVM_X86_INIT_FINALIZE_H */
