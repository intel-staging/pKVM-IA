/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2002 Andi Kleen */

#include <linux/linkage.h>

/*
 * memcpy - Copy a memory block.
 *
 * Input:
 *  rdi destination
 *  rsi source
 *  rdx count
 *
 * Output:
 * rax original destination
 *
 * This is enhanced fast string memcpy. It is faster and
 * simpler than old memcpy.
 */

SYM_FUNC_START(memcpy)
	movq %rdi, %rax
	movq %rdx, %rcx
	rep movsb
	RET
SYM_FUNC_END(memcpy)
