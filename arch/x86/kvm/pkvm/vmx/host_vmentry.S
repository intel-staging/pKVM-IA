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
	UNWIND_HINT_ENTRY
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

	/*
	 * Untrain the return predictor before any CALL or RET in the
	 * hypervisor. UNTRAIN_RET has three parts:
	 *
	 * 1) VALIDATE_UNRET_END: an objtool annotation (no runtime effect)
	 *    that satisfies objtool's UNRET validation.  UNWIND_HINT_ENTRY
	 *    above emits VALIDATE_UNRET_BEGIN which starts the validation walk;
	 *    VALIDATE_UNRET_END here marks the point where the walk succeeds,
	 *    preventing "RET before UNTRAIN" errors for subsequent CALLs.
	 *
	 * 2) CALL_UNTRAIN_RET: flushes the AMD return predictor state to
	 *    prevent the deprivileged host from using poisoned return predictor
	 *    entries to hijack speculative execution (AMD UNRET/SRSO).  Active
	 *    only when X86_FEATURE_UNRET or X86_FEATURE_SRSO_ALIAS is set;
	 *    NOPs on Intel.
	 *
	 * 3) ALTERNATIVE_2: either write_ibpb (gated on X86_FEATURE_ENTRY_IBPB
	 *    for IBPB-based retbleed mitigation) or RESET_CALL_DEPTH (gated on
	 *    X86_FEATURE_CALL_DEPTH, resets the call depth counter to
	 *    RET_DEPTH_INIT for correct RSB stuffing).
	 *
	 * On Intel platforms with eIBRS (required by pKVM), all three runtime
	 * alternatives are NOPs — eIBRS hardware handles return predictor
	 * protection on vmexit, IBPB is not required, and call depth tracking
	 * is inactive. UNTRAIN_RET is still required here solely for the
	 * VALIDATE_UNRET_END objtool annotation, and must precede the first
	 * CALL (vmx_spec_ctrl_restore_host).
	 *
	 * But in case the host kernel boots with retbleed=stuff which sets
	 * X86_FEATURE_CALL_DEPTH, RESET_CALL_DEPTH will become active to reset
	 * the call depth counter, ensuring RSB stuffing fires only when call
	 * depth tracking indicates the RSB may be exhausted.
	 */
	UNTRAIN_RET

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
