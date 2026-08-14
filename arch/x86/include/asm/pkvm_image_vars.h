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
PKVM_ALIAS(get_cpu_entry_area);
#endif /* CONFIG_PKVM_X86_DEBUG */

#endif /* _ASM_X86_PKVM_IMAGE_VARS_H */
