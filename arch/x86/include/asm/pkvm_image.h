/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_PKVM_IMAGE_H
#define _ASM_X86_PKVM_IMAGE_H

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

#endif /* _ASM_X86_PKVM_IMAGE_H */
