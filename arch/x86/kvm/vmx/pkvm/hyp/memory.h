// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef _PKVM_MEMORY_H_
#define _PKVM_MEMORY_H_

#include <asm/kvm_pkvm.h>

#define INVALID_ADDR (~0UL)

unsigned long pkvm_virt_to_symbol_phys(void *virt);
#define __pkvm_pa_symbol(x) pkvm_virt_to_symbol_phys((void *)x)

struct mem_range {
	unsigned long start;
	unsigned long end;
};

bool find_mem_range(unsigned long addr, struct mem_range *range);
bool mem_range_included(struct mem_range *child, struct mem_range *parent);

#include <linux/kvm_host.h>
void *host_gpa2hva(unsigned long gpa);
unsigned long host_gpa2hpa(unsigned long gpa);
int gva2gpa(struct kvm_vcpu *vcpu, gva_t gva, gpa_t *gpa,
		u32 access, struct x86_exception *exception);
int read_gva(struct kvm_vcpu *vcpu, gva_t gva, void *addr,
		unsigned int bytes, struct x86_exception *exception);
int write_gva(struct kvm_vcpu *vcpu, gva_t gva, void *addr,
		unsigned int bytes, struct x86_exception *exception);
int read_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr, unsigned int bytes);
int write_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr, unsigned int bytes);

#endif
