/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/pkvm_image.h>

SECTIONS {
	PKVM_SECTION(.text)
	PKVM_SECTION(.rodata)
	PKVM_SECTION(.data)
	PKVM_SECTION(.bss)
}
