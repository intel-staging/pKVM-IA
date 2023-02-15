// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <linux/mutex.h>

#include <asm/kvm_pkvm.h>

#include "hyp_constants.h"

int hyp_pre_reserve_check(void)
{
	if (!is_hyp_mode_available() || is_kernel_in_hyp_mode())
		return -EINVAL;

	if (kvm_get_mode() != KVM_MODE_PROTECTED)
		return -EINVAL;

	return 0;
}

u64 hyp_total_reserve_pages(void)
{
	u64 hyp_mem_pages = 0;

	hyp_mem_pages += hyp_s1_pgtable_pages();
	hyp_mem_pages += host_s2_pgtable_pages();
	hyp_mem_pages += hyp_vm_table_pages();
	hyp_mem_pages += hyp_vmemmap_pages(STRUCT_HYP_PAGE_SIZE);

	return hyp_mem_pages;
}

/*
 * Allocates and donates memory for hypervisor VM structs at EL2.
 *
 * Allocates space for the VM state, which includes the hyp vm as well as
 * the hyp vcpus.
 *
 * Stores an opaque handler in the kvm struct for future reference.
 *
 * Return 0 on success, negative error code on failure.
 */
static int __pkvm_create_hyp_vm(struct kvm *host_kvm)
{
	size_t pgd_sz, hyp_vm_sz, hyp_vcpu_sz;
	struct kvm_vcpu *host_vcpu;
	pkvm_handle_t handle;
	void *pgd, *hyp_vm;
	unsigned long idx;
	int ret;

	if (host_kvm->created_vcpus < 1)
		return -EINVAL;

	pgd_sz = kvm_pgtable_stage2_pgd_size(host_kvm->arch.vtcr);

	/*
	 * The PGD pages will be reclaimed using a hyp_memcache which implies
	 * page granularity. So, use alloc_pages_exact() to get individual
	 * refcounts.
	 */
	pgd = alloc_pages_exact(pgd_sz, GFP_KERNEL_ACCOUNT);
	if (!pgd)
		return -ENOMEM;

	/* Allocate memory to donate to hyp for vm and vcpu pointers. */
	hyp_vm_sz = PAGE_ALIGN(size_add(PKVM_HYP_VM_SIZE,
					size_mul(sizeof(void *),
						 host_kvm->created_vcpus)));
	hyp_vm = alloc_pages_exact(hyp_vm_sz, GFP_KERNEL_ACCOUNT);
	if (!hyp_vm) {
		ret = -ENOMEM;
		goto free_pgd;
	}

	/* Donate the VM memory to hyp and let hyp initialize it. */
	ret = kvm_call_hyp_nvhe(__pkvm_init_vm, host_kvm, hyp_vm, pgd);
	if (ret < 0)
		goto free_vm;

	handle = ret;

	host_kvm->arch.pkvm.handle = handle;

	/* Donate memory for the vcpus at hyp and initialize it. */
	hyp_vcpu_sz = PAGE_ALIGN(PKVM_HYP_VCPU_SIZE);
	kvm_for_each_vcpu(idx, host_vcpu, host_kvm) {
		void *hyp_vcpu;

		/* Indexing of the vcpus to be sequential starting at 0. */
		if (WARN_ON(host_vcpu->vcpu_idx != idx)) {
			ret = -EINVAL;
			goto destroy_vm;
		}

		hyp_vcpu = alloc_pages_exact(hyp_vcpu_sz, GFP_KERNEL_ACCOUNT);
		if (!hyp_vcpu) {
			ret = -ENOMEM;
			goto destroy_vm;
		}

		ret = kvm_call_hyp_nvhe(__pkvm_init_vcpu, handle, host_vcpu,
					hyp_vcpu);
		if (ret) {
			free_pages_exact(hyp_vcpu, hyp_vcpu_sz);
			goto destroy_vm;
		}
	}

	return 0;

destroy_vm:
	pkvm_destroy_hyp_vm(host_kvm);
	return ret;
free_vm:
	free_pages_exact(hyp_vm, hyp_vm_sz);
free_pgd:
	free_pages_exact(pgd, pgd_sz);
	return ret;
}

int pkvm_create_hyp_vm(struct kvm *host_kvm)
{
	int ret = 0;

	mutex_lock(&host_kvm->lock);
	if (!host_kvm->arch.pkvm.handle)
		ret = __pkvm_create_hyp_vm(host_kvm);
	mutex_unlock(&host_kvm->lock);

	return ret;
}

void pkvm_destroy_hyp_vm(struct kvm *host_kvm)
{
	if (host_kvm->arch.pkvm.handle) {
		WARN_ON(kvm_call_hyp_nvhe(__pkvm_teardown_vm,
					  host_kvm->arch.pkvm.handle));
	}

	host_kvm->arch.pkvm.handle = 0;
	free_hyp_memcache(&host_kvm->arch.pkvm.teardown_mc);
}

int pkvm_init_host_vm(struct kvm *host_kvm)
{
	mutex_init(&host_kvm->lock);
	return 0;
}
