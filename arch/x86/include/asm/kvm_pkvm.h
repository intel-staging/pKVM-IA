/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_PKVM_H
#define _ASM_X86_KVM_PKVM_H

#ifdef CONFIG_PKVM_X86

#define PKVM_MEMBLOCK_REGIONS		128

void *pkvm_early_alloc_contig(unsigned int nr_pages);
void pkvm_early_alloc_init(void *virt, unsigned long size);

#ifdef CONFIG_PKVM_INTEL
unsigned long __init pkvm_vmx_reserve_pages(void);
#endif

#endif /* CONFIG_PKVM_X86 */

#endif /* _ASM_X86_KVM_PKVM_H */
