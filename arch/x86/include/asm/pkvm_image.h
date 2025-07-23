/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_PKVM_IMAGE_H
#define _ASM_X86_PKVM_IMAGE_H

#include <linux/types.h>

#if defined(__PKVM_HYP__)
/*
 * For the pkvm hypervisor code to use the pkvm hypervisor symbols.
 * There is no need to manually add the suffix as the Makefile will
 * automatically do this for symbols in the pkvm hypervisor
 * text.
 */
#define PKVM_DECLARE(type, f, params)	type f params
#define pkvm_sym(sym)			sym
#else
/*
 * For the host code to use the pkvm hypervisor symbols which has
 * the __pkvm suffix added by the Makefile. It is necessary to manually
 * add the suffix as the Makefile will not do this for symbols in the
 * host text.
 */
#define PKVM_DECLARE(type, f, params)	type f##__pkvm params
#define pkvm_sym(sym)			sym##__pkvm
#endif

#ifdef LINKER_SCRIPT

#define __PKVM_CONCAT(a, b)	a ## b
#define PKVM_CONCAT(a, b)	__PKVM_CONCAT(a, b)

#define PKVM_SECTION_NAME(NAME)	.pkvm##NAME

#define PKVM_SECTION_SYMBOL_NAME(NAME) \
	PKVM_CONCAT(__pkvm_section_, PKVM_SECTION_NAME(NAME))

#define BEGIN_PKVM_SECTION(NAME)			\
	PKVM_SECTION_NAME(NAME) : {			\
		PKVM_SECTION_SYMBOL_NAME(NAME) = .;

#define END_PKVM_SECTION				\
	}

#define PKVM_SECTION(NAME)			\
	BEGIN_PKVM_SECTION(NAME)		\
		*(NAME NAME##.*)		\
	END_PKVM_SECTION

#endif /* LINKER_SCRIPT */

#ifndef __ASSEMBLER__

#ifdef CONFIG_PKVM_X86
extern char __pkvm_text_start[], __pkvm_text_end[];
static inline bool is_pkvm_text(void *addr)
{
	return addr >= (void *)__pkvm_text_start && addr < (void *)__pkvm_text_end;
}
#else
static inline bool is_pkvm_text(void *addr) { return false; }
#endif

#endif

#endif /* _ASM_X86_PKVM_IMAGE_H */
