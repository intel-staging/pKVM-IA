/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_FPU_H
#define __PKVM_X86_FPU_H

#include <asm/fpu/types.h>

void pkvm_init_percpu_fpu(void);
void pkvm_init_guest_fpu(struct fpu_guest *gfpu);
void pkvm_reset_host_fpu(bool init_event);

#endif /* __PKVM_X86_FPU_H */
