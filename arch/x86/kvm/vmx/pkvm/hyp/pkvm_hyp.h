// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef __PKVM_HYP_H
#define __PKVM_HYP_H

#include "pkvm_hyp_types.h"

#define SHADOW_VM_HANDLE_SHIFT		32
#define SHADOW_VCPU_INDEX_MASK		((1UL << SHADOW_VM_HANDLE_SHIFT) - 1)
#define to_shadow_vcpu_handle(vm_handle, vcpu_idx)		\
		(((s64)(vm_handle) << SHADOW_VM_HANDLE_SHIFT) | \
		 ((vcpu_idx) & SHADOW_VCPU_INDEX_MASK))

#define sept_to_shadow_ept_desc(_sept)	container_of(_sept, struct shadow_ept_desc, sept)

#define sept_desc_to_shadow_vm(desc) container_of(desc, struct pkvm_shadow_vm, sept_desc)

#define sept_to_shadow_vm(_sept) sept_desc_to_shadow_vm(sept_to_shadow_ept_desc(_sept))

#define pgstate_pgt_to_shadow_vm(_pgt) container_of(_pgt, struct pkvm_shadow_vm, pgstate_pgt)

int __pkvm_init_shadow_vm(struct kvm_vcpu *hvcpu, unsigned long kvm_va,
			  unsigned long shadow_pa,  size_t shadow_size);
unsigned long __pkvm_teardown_shadow_vm(int shadow_vm_handle);
struct pkvm_shadow_vm *get_shadow_vm(int shadow_vm_handle);
void put_shadow_vm(int shadow_vm_handle);
void pkvm_shadow_vm_link_ptdev(struct pkvm_shadow_vm *vm,
			       struct list_head *node, bool coherency);
void pkvm_shadow_vm_unlink_ptdev(struct pkvm_shadow_vm *vm,
				 struct list_head *node, bool coherency);
s64 __pkvm_init_shadow_vcpu(struct kvm_vcpu *hvcpu, int shadow_vm_handle,
			    unsigned long vcpu_va, unsigned long shadow_pa,
			    size_t shadow_size);
unsigned long __pkvm_teardown_shadow_vcpu(s64 shadow_vcpu_handle);
struct shadow_vcpu_state *get_shadow_vcpu(s64 shadow_vcpu_handle);
void put_shadow_vcpu(s64 shadow_vcpu_handle);
s64 find_shadow_vcpu_handle_by_vmcs(unsigned long vmcs12_pa);
void pkvm_kick_vcpu(struct kvm_vcpu *vcpu);
int pkvm_add_ptdev(int shadow_vm_handle, u16 bdf, u32 pasid);

#define PKVM_REQ_TLB_FLUSH_HOST_EPT			KVM_ARCH_REQ(0)
#define PKVM_REQ_TLB_FLUSH_SHADOW_EPT			KVM_ARCH_REQ(1)

extern struct pkvm_hyp *pkvm_hyp;

static inline bool shadow_vm_is_protected(struct pkvm_shadow_vm *vm)
{
	return vm->vm_type == KVM_X86_PKVM_PROTECTED_VM;
}

static inline bool shadow_vcpu_is_protected(struct shadow_vcpu_state *shadow_vcpu)
{
	return shadow_vm_is_protected(shadow_vcpu->vm);
}

#endif
