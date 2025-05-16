/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/pkvm_image.h>
#include <asm-generic/vmlinux.lds.h>
#include <asm/cache.h>
#include <asm/page.h>

SECTIONS {
	PKVM_SECTION(.text)
	PKVM_SECTION(.noinstr.text)
	PKVM_SECTION(.init.text)
	PKVM_SECTION(.rodata)
	/*
	 * .pkvm.data..percpu needs to be defined before .data section
	 * as .pkvm.data section will include all sections started with
	 * .data which will include .data..percpu as well.
	 *
	 * .pkvm.data..percpu also needs to be page aligned to maintain
	 * the same alignment for when linking into vmlinux.
	 */
	. = ALIGN(PAGE_SIZE);
	BEGIN_PKVM_SECTION(.data..percpu)
		PERCPU_INPUT(INTERNODE_CACHE_BYTES)
	END_PKVM_SECTION
	PKVM_SECTION(.data)
	PKVM_SECTION(.init.data)
	PKVM_SECTION(.bss)
	__ex_table : { KEEP(*(__ex_table)) }
	.smp_locks : { KEEP(*(.smp_locks)) }
	.altinstructions : { KEEP(*(.altinstructions)) }
	__bug_table : { KEEP(*(__bug_table)) }
	__jump_table : { KEEP(*(__jump_table)) }
	.altinstr_replacement : { KEEP(*(.altinstr_replacement)) }
	.discard.reachable : { KEEP(*(.discard.reachable)) }
	.discard.unwind_hints : { KEEP(*(.discard.unwind_hints)) }
	.discard.intra_function_calls : { KEEP(*(.discard.intra_function_calls)) }
	.discard.noendbr : { KEEP(*(.discard.noendbr)) }
	.discard.retpoline_safe : { KEEP(*(.discard.retpoline_safe)) }
	.altinstr_aux : { *(.altinstr_aux*) }
	.altinstructions : { *(.altinstructions*) }
}
