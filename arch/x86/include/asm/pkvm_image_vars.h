/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_PKVM_IMAGE_VARS_H
#define _ASM_X86_PKVM_IMAGE_VARS_H

#ifdef CONFIG_PKVM_X86_DEBUG

#include <asm/pkvm_image.h>
/*
 * Defines a linker script alias of a kernel-proper symbol referenced by
 * PKVM code.
 */
#define PKVM_ALIAS(sym)  pkvm_sym(sym) = sym;

#ifdef CONFIG_PRINTK
PKVM_ALIAS(_printk);
PKVM_ALIAS(mem_dump_obj);
#endif

#ifdef CONFIG_BUG
PKVM_ALIAS(__warn_printk);
/*
 * WARN() on x86 dispatches through a static call (static_call_mod(WARN_trap),
 * see <asm/bug.h>), which references the generated static-call trampoline and
 * key symbols. Alias them to the kernel-proper definitions from
 * DEFINE_STATIC_CALL(WARN_trap, ...) in arch/x86/kernel/traps.c.
 */
PKVM_ALIAS(__SCT__WARN_trap);
PKVM_ALIAS(__SCK__WARN_trap);
#endif

#ifdef CONFIG_TRACING
PKVM_ALIAS(__trace_bputs);
PKVM_ALIAS(__trace_bprintk);
#endif

#ifdef CONFIG_DYNAMIC_DEBUG_CORE
PKVM_ALIAS(__dynamic_pr_debug);
#endif

PKVM_ALIAS(___ratelimit);
PKVM_ALIAS(vmalloc_base);
#endif /* CONFIG_PKVM_X86_DEBUG */

#endif /* _ASM_X86_PKVM_IMAGE_VARS_H */
