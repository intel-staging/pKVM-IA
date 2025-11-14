/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_INIT_FINALIZE_H
#define __PKVM_X86_INIT_FINALIZE_H

#include <asm/kvm_pkvm.h>

/**
 * pkvm_init_ops - The platform vendor specific pKVM finalize operations used by
 *		   the pkvm_init_finalize.
 */
struct pkvm_init_ops {};

int pkvm_init_finalize(struct pkvm_mem_info infos[], int nr_info,
		       struct pkvm_init_ops *init_ops);

#endif /* __PKVM_X86_INIT_FINALIZE_H */
