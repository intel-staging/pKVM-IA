// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/unwind_hints.h>

.macro save_frame
	push %r15
	push %r14
	push %r13
	push %r12
	push %r11
	push %r10
	push %r9
	push %r8
	push %_ASM_DI
	push %_ASM_SI
	push %_ASM_BP
	push %_ASM_SP
	push %_ASM_DX
	push %_ASM_CX
	push %_ASM_BX
	push %_ASM_AX
.endm

.macro restore_frame
	pop %_ASM_AX
	pop %_ASM_BX
	pop %_ASM_CX
	pop %_ASM_DX
	pop %_ASM_SP
	pop %_ASM_BP
	pop %_ASM_SI
	pop %_ASM_DI
	pop %r8
	pop %r9
	pop %r10
	pop %r11
	pop %r12
	pop %r13
	pop %r14
	pop %r15
.endm

SYM_CODE_START(noop_handler)
	UNWIND_HINT_UNDEFINED
	save_frame

	call handle_noop

	restore_frame

	iretq
SYM_CODE_END(noop_handler)

SYM_CODE_START(nmi_handler)
	UNWIND_HINT_UNDEFINED
	save_frame

	call handle_nmi

	restore_frame

	iretq
SYM_CODE_END(nmi_handler)
