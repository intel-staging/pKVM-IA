/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/pkvm_image.h>
#include <asm-generic/vmlinux.lds.h>
#include <asm/cache.h>
#include <asm/page.h>

SECTIONS {
	PKVM_SECTION(.text)
	PKVM_SECTION(.noinstr.text)
	PKVM_SECTION(.rodata)
	/*
	 * .pkvm.data..ro_after_init needs to be defined before .data section
	 * as .pkvm.data section will include all sections started with .data
	 * which will include .data..ro_after_init as well.
	 */
	PKVM_SECTION(.data..ro_after_init)
	PKVM_SECTION(.data)
	PKVM_SECTION(.bss)
}
