/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/frame.h>
#include <asm/asm.h>
#include <asm/bitsperlong.h>
#include <asm/unwind_hints.h>
#include <asm/nospec-branch.h>
#include "vmenter.h"

/*
 * pkvm_host_vmexit_entry - Handle a VM-Exit event from the deprivileged
 * host in pkvm.
 *
 * The pKVM stack starts from fixed address, which is pkvm_sp_top
 * configured in VMCS.HOST_RSP.
 *
 * pkvm_sp_top = pcpu->stack + PKVM_STACK_SIZE - PKVM_STACK_TOP_RESV
 * pkvm_sp_top[0] --> pointer to vcpu->arch.regs
 * pkvm_sp_top[1] --> struct vcpu_vmx *vmx
 *
 */
SYM_FUNC_START(pkvm_host_vmexit_entry)
	UNWIND_HINT_END_OF_STACK
	ENDBR
	push %_ASM_BX
	mov WORD_SIZE*1(%_ASM_SP), %_ASM_BX

	STORE_REGS %_ASM_BX, 0, \
		   %_ASM_AX, %_ASM_CX, %_ASM_DX, %_ASM_SI, %_ASM_DI, %_ASM_BP
	STORE_REGS %_ASM_BX, 0, \
		   %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15
	POP_REGS   %_ASM_BX, 0, %_ASM_BX

	/*
	 * Clear all general purpose registers except RSP and RBX to prevent
	 * speculative use of the guest's values, even those that are reloaded
	 * via the stack. See the analogous comment in vmx/vmenter.S.
	 */
	CLEAR_REGS %eax, %ecx, %edx, %ebp, %esi, %edi
	CLEAR_REGS %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d

	/* RDI: point to vcpu_vmx */
	mov WORD_SIZE*1(%_ASM_SP), %_ASM_DI

	/* pKVM never enables interrupts */
	call pkvm_host_vmexit_main

	/*
	 * Restore registers to reflect the vm-exit handling/emulation result
	 * before vmresume.
	 */
	LOAD_REGS %_ASM_BX, 0, \
		  %_ASM_AX, %_ASM_CX, %_ASM_DX, %_ASM_SI, %_ASM_DI, %_ASM_BP
	LOAD_REGS %_ASM_BX, 0, \
		  %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15
	LOAD_REGS %_ASM_BX, 0, %_ASM_BX

	/*
	 * The first time of entering guest is in local_deprivilege_cpu() which
	 * requires vmlaunch. This code path is called after that, hence only
	 * vmresume required.
	 */
	vmresume

	/* should not come here */
	mov $0x4400, %_ASM_CX
	vmread %_ASM_CX, %_ASM_AX
failed:
	jmp failed			/* should never come here */
SYM_FUNC_END(pkvm_host_vmexit_entry)
STACK_FRAME_NON_STANDARD(pkvm_host_vmexit_entry);
