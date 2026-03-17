/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_CPU_H
#define __PKVM_X86_CPU_H

#define PKVM_WRITE_CR(crnum, val) \
static inline void __pkvm_write_cr##crnum(unsigned long val) \
{							\
	asm volatile("mov %0,%%cr" #crnum : "+r" (val) : : "memory"); \
}

PKVM_WRITE_CR(0, val)
PKVM_WRITE_CR(3, val)
PKVM_WRITE_CR(4, val)

#endif /* __PKVM_X86_CPU_H */
