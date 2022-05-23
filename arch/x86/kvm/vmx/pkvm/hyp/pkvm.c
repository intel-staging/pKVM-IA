/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <pkvm.h>

#include "pkvm_hyp.h"

struct pkvm_hyp *pkvm_hyp;

#define MAX_SHADOW_VMS	255
#define HANDLE_OFFSET 1

#define to_shadow_vm_handle(vcpu_handle)	((s64)(vcpu_handle) >> SHADOW_VM_HANDLE_SHIFT)
#define to_shadow_vcpu_idx(vcpu_handle)		((s64)(vcpu_handle) & SHADOW_VCPU_INDEX_MASK)

static DECLARE_BITMAP(shadow_vms_bitmap, MAX_SHADOW_VMS);
static pkvm_spinlock_t shadow_vms_lock = { __ARCH_PKVM_SPINLOCK_UNLOCKED };
static struct pkvm_shadow_vm *shadow_vms[MAX_SHADOW_VMS];

static int allocate_shadow_vm_handle(struct pkvm_shadow_vm *vm)
{
	int handle;

	/* The shadow_vm_handle is a int so cannot exceed the INT_MAX */
	BUILD_BUG_ON(MAX_SHADOW_VMS > INT_MAX);

	pkvm_spin_lock(&shadow_vms_lock);

	handle = find_next_zero_bit(shadow_vms_bitmap, MAX_SHADOW_VMS,
				    HANDLE_OFFSET);
	if (handle < MAX_SHADOW_VMS) {
		__set_bit(handle, shadow_vms_bitmap);
		shadow_vms[handle] = vm;
		vm->shadow_vm_handle = handle;
	} else
		handle = -ENOMEM;

	pkvm_spin_unlock(&shadow_vms_lock);

	return handle;
}

static struct pkvm_shadow_vm *free_shadow_vm_handle(int handle)
{
	struct pkvm_shadow_vm *vm = NULL;

	pkvm_spin_lock(&shadow_vms_lock);
	if (test_bit(handle, shadow_vms_bitmap)) {
		vm = shadow_vms[handle];
		shadow_vms[handle] = NULL;
		__clear_bit(handle, shadow_vms_bitmap);
	}
	pkvm_spin_unlock(&shadow_vms_lock);

	return vm;
}

static struct pkvm_shadow_vm *get_shadow_vm(int handle)
{
	struct pkvm_shadow_vm *vm = NULL;

	pkvm_spin_lock(&shadow_vms_lock);
	if (test_bit(handle, shadow_vms_bitmap))
		vm = shadow_vms[handle];
	pkvm_spin_unlock(&shadow_vms_lock);

	return vm;
}

int __pkvm_init_shadow_vm(unsigned long kvm_va,
			  unsigned long shadow_pa,
			  size_t shadow_size)
{
	struct pkvm_shadow_vm *vm;

	if (!PAGE_ALIGNED(shadow_pa) ||
		!PAGE_ALIGNED(shadow_size) ||
		(shadow_size != PAGE_ALIGN(sizeof(struct pkvm_shadow_vm))))
		return -EINVAL;

	vm = pkvm_phys_to_virt(shadow_pa);

	memset(vm, 0, shadow_size);
	pkvm_spinlock_init(&vm->lock);

	vm->host_kvm_va = kvm_va;
	return allocate_shadow_vm_handle(vm);
}

unsigned long __pkvm_teardown_shadow_vm(int shadow_vm_handle)
{
	struct pkvm_shadow_vm *vm = free_shadow_vm_handle(shadow_vm_handle);

	if (!vm)
		return 0;

	memset(vm, 0, sizeof(*vm));

	return pkvm_virt_to_phys(vm);
}

static s64 attach_shadow_vcpu_to_vm(struct pkvm_shadow_vm *vm,
				    struct shadow_vcpu_state *shadow_vcpu)
{
	u32 vcpu_idx;

	/*
	 * Shadow_vcpu_handle is a s64 value combined with shadow_vm_handle
	 * and shadow_vcpu index from the arrary. So the array size cannot be
	 * larger than the shadow_vcpu index mask.
	 */
	BUILD_BUG_ON(KVM_MAX_VCPUS > SHADOW_VCPU_INDEX_MASK);

	shadow_vcpu->vm = vm;

	pkvm_spin_lock(&vm->lock);

	if (vm->created_vcpus == KVM_MAX_VCPUS) {
		pkvm_spin_unlock(&vm->lock);
		return -EINVAL;
	}

	vcpu_idx = vm->created_vcpus;
	shadow_vcpu->shadow_vcpu_handle =
		to_shadow_vcpu_handle(vm->shadow_vm_handle, vcpu_idx);
	vm->shadow_vcpus[vcpu_idx] = shadow_vcpu;
	vm->created_vcpus++;

	pkvm_spin_unlock(&vm->lock);

	return shadow_vcpu->shadow_vcpu_handle;
}

static struct shadow_vcpu_state *
detach_shadow_vcpu_from_vm(struct pkvm_shadow_vm *vm, s64 shadow_vcpu_handle)
{
	u32 vcpu_idx = to_shadow_vcpu_idx(shadow_vcpu_handle);
	struct shadow_vcpu_state *shadow_vcpu;

	if (vcpu_idx >= KVM_MAX_VCPUS)
		return NULL;

	pkvm_spin_lock(&vm->lock);
	shadow_vcpu = vm->shadow_vcpus[vcpu_idx];
	pkvm_spin_unlock(&vm->lock);

	return shadow_vcpu;
}

s64 __pkvm_init_shadow_vcpu(struct kvm_vcpu *hvcpu, int shadow_vm_handle,
			    unsigned long vcpu_va, unsigned long shadow_pa,
			    size_t shadow_size)
{
	struct pkvm_shadow_vm *vm;
	struct shadow_vcpu_state *shadow_vcpu;
	struct x86_exception e;
	int ret;

	if (!PAGE_ALIGNED(shadow_pa) || !PAGE_ALIGNED(shadow_size) ||
		(shadow_size != PAGE_ALIGN(sizeof(struct shadow_vcpu_state))) ||
		(pkvm_hyp->vmcs_config.size > PAGE_SIZE))
		return -EINVAL;

	shadow_vcpu = pkvm_phys_to_virt(shadow_pa);
	memset(shadow_vcpu, 0, shadow_size);

	ret = read_gva(hvcpu, vcpu_va, &shadow_vcpu->vmx, sizeof(struct vcpu_vmx), &e);
	if (ret < 0)
		return -EINVAL;

	vm = get_shadow_vm(shadow_vm_handle);
	if (!vm)
		return -EINVAL;

	return attach_shadow_vcpu_to_vm(vm, shadow_vcpu);
}

unsigned long __pkvm_teardown_shadow_vcpu(s64 shadow_vcpu_handle)
{
	int shadow_vm_handle = to_shadow_vm_handle(shadow_vcpu_handle);
	struct shadow_vcpu_state *shadow_vcpu;
	struct pkvm_shadow_vm *vm = get_shadow_vm(shadow_vm_handle);

	if (!vm)
		return 0;

	shadow_vcpu = detach_shadow_vcpu_from_vm(vm, shadow_vcpu_handle);
	if (!shadow_vcpu)
		return 0;

	memset(shadow_vcpu, 0, sizeof(struct shadow_vcpu_state));
	return pkvm_virt_to_phys(shadow_vcpu);
}
