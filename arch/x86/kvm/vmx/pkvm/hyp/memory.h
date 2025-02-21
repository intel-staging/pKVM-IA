/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef _PKVM_MEMORY_H_
#define _PKVM_MEMORY_H_

#include <asm/kvm_pkvm.h>

#define INVALID_ADDR (~(unsigned long)0)

/*
 * simply define IOVA offset from bit 43 to avoid
 * canonical addressing check for the linear address
 * as max linear address bits usually >= 47
 */
#define PKVM_IOVA_OFFSET	0x0000080000000000

/* MMU entry property bits for UC. Can be used to map MMIO. */
#define PKVM_PAGE_IO_NOCACHE	((u64)(__PAGE_KERNEL | _PAGE_PWT | _PAGE_PCD))

unsigned long pkvm_virt_to_symbol_phys(void *virt);
#define __pkvm_pa_symbol(x) pkvm_virt_to_symbol_phys((void *)x)

void *pkvm_iophys_to_virt(unsigned long phys);

#include <linux/kvm_host.h>
void *host_gpa2hva(unsigned long gpa);
unsigned long host_gpa2hpa(unsigned long gpa);
void *host_mmio2hva(unsigned long gpa);
int gva2gpa(struct kvm_vcpu *vcpu, gva_t gva, gpa_t *gpa,
		u32 access, struct x86_exception *exception);
int read_gva(struct kvm_vcpu *vcpu, gva_t gva, void *addr,
		unsigned int bytes, struct x86_exception *exception);
int write_gva(struct kvm_vcpu *vcpu, gva_t gva, void *addr,
		unsigned int bytes, struct x86_exception *exception);
int read_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr, unsigned int bytes);
int write_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr, unsigned int bytes);

struct mem_range {
	unsigned long start;
	unsigned long end;
};

bool find_mem_range(unsigned long addr, struct mem_range *range);
bool mem_range_included(struct mem_range *child, struct mem_range *parent);

void pkvm_clflush_cache_range(void *vaddr, unsigned int size);

u64 get_max_physaddr_bits(void);
#endif
