/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef __PKVM_HYP_H
#define __PKVM_HYP_H

#include "pkvm_spinlock.h"

/*
 *  * A container for the vcpu state that hyp needs to maintain for protected VMs.
 *   */
struct shadow_vcpu_state {
	/*
	 * A unique id to the shadow vcpu, which is combined by
	 * shadow_vm_handle and shadow_vcpu index in the arrary.
	 * As shadow_vm_handle is in the high end and it is a
	 * int, so define the shadow_vcpu_handle as a s64.
	 */
	s64 shadow_vcpu_handle;

	struct pkvm_shadow_vm *vm;

	struct vcpu_vmx vmx;
} __aligned(PAGE_SIZE);

#define SHADOW_VM_HANDLE_SHIFT		32
#define SHADOW_VCPU_INDEX_MASK		((1UL << SHADOW_VM_HANDLE_SHIFT) - 1)
#define to_shadow_vcpu_handle(vm_handle, vcpu_idx)		\
		(((s64)(vm_handle) << SHADOW_VM_HANDLE_SHIFT) | \
		 ((vcpu_idx) & SHADOW_VCPU_INDEX_MASK))

/*
 *  * Holds the relevant data for running a protected vm.
 *   */
struct pkvm_shadow_vm {
	/* A unique id to the shadow structs in the hyp shadow area. */
	int shadow_vm_handle;

	/* Number of vcpus for the vm. */
	int created_vcpus;

	/* The host's kvm va. */
	unsigned long host_kvm_va;

	pkvm_spinlock_t lock;

	/* Array of the shadow state per vcpu. */
	struct shadow_vcpu_state *shadow_vcpus[KVM_MAX_VCPUS];
} __aligned(PAGE_SIZE);

int __pkvm_init_shadow_vm(unsigned long kvm_va, unsigned long shadow_pa,
			  size_t shadow_size);
unsigned long __pkvm_teardown_shadow_vm(int shadow_vm_handle);
s64 __pkvm_init_shadow_vcpu(struct kvm_vcpu *hvcpu, int shadow_vm_handle,
			    unsigned long vcpu_va, unsigned long shadow_pa,
			    size_t shadow_size);
unsigned long __pkvm_teardown_shadow_vcpu(s64 shadow_vcpu_handle);

extern struct pkvm_hyp *pkvm_hyp;

#endif
