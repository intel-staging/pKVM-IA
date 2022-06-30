/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/types.h>
#include <asm/kvm_pkvm.h>

#include <pkvm.h>
#include "pgtable.h"
#include "pkvm_hyp.h"

unsigned long __page_base_offset;
unsigned long __symbol_base_offset;

unsigned int pkvm_memblock_nr;
struct memblock_region pkvm_memory[PKVM_MEMBLOCK_REGIONS];

void *pkvm_phys_to_virt(unsigned long phys)
{
	return (void *)__page_base_offset + phys;
}

unsigned long pkvm_virt_to_phys(void *virt)
{
	return (unsigned long)virt - __page_base_offset;
}

unsigned long pkvm_virt_to_symbol_phys(void *virt)
{
	return (unsigned long)virt - __symbol_base_offset;
}

void *host_gpa2hva(unsigned long gpa)
{
	/* host gpa = hpa */
	return pkvm_phys_to_virt(gpa);
}

extern struct pkvm_pgtable_ops mmu_ops;
static struct pkvm_mm_ops mm_ops = {
	.phys_to_virt = host_gpa2hva,
};

static int check_translation(struct kvm_vcpu *vcpu, gpa_t gpa,
		u64 prot, u32 access, struct x86_exception *exception)
{
	/* TODO: exception for #PF */
	return 0;
}

int gva2gpa(struct kvm_vcpu *vcpu, gva_t gva, gpa_t *gpa,
		u32 access, struct x86_exception *exception)
{
	struct pkvm_pgtable guest_mmu;
	gpa_t _gpa;
	u64 prot;
	int pg_level;

	/* caller should ensure exception is not NULL */
	WARN_ON(exception == NULL);

	memset(exception, 0, sizeof(*exception));

	/*TODO: support other paging mode beside long mode */
	guest_mmu.root_pa = vcpu->arch.cr3 & PAGE_MASK;
	pkvm_pgtable_init(&guest_mmu, &mm_ops, &mmu_ops, &pkvm_hyp->mmu_cap, false);
	pkvm_pgtable_lookup(&guest_mmu, (unsigned long)gva,
			(unsigned long *)&_gpa, &prot, &pg_level);
	*gpa = _gpa;
	if (_gpa == INVALID_ADDR)
		return -EFAULT;

	return check_translation(vcpu, _gpa, prot, access, exception);
}

/* only support host VM now */
static int copy_gva(struct kvm_vcpu *vcpu, gva_t gva, void *addr,
		unsigned int bytes, struct x86_exception *exception, bool from_guest)
{
	u32 access = VMX_AR_DPL(vmcs_read32(GUEST_SS_AR_BYTES)) == 3 ? PFERR_USER_MASK : 0;
	gpa_t gpa;
	void *hva;
	int ret;

	/*FIXME: need check the gva per page granularity */
	ret = gva2gpa(vcpu, gva, &gpa, access, exception);
	if (ret)
		return ret;

	hva = host_gpa2hva(gpa);
	if (from_guest)
		memcpy(addr, hva, bytes);
	else
		memcpy(hva, addr, bytes);

	return bytes;
}

int read_gva(struct kvm_vcpu *vcpu, gva_t gva, void *addr,
		unsigned int bytes, struct x86_exception *exception)
{
	return copy_gva(vcpu, gva, addr, bytes, exception, true);
}

int write_gva(struct kvm_vcpu *vcpu, gva_t gva, void *addr,
		unsigned int bytes, struct x86_exception *exception)
{
	return copy_gva(vcpu, gva, addr, bytes, exception, false);
}

/* only support host VM now */
static int copy_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr,
		unsigned int bytes, bool from_guest)
{
	void *hva;

	hva = host_gpa2hva(gpa);
	if (from_guest)
		memcpy(addr, hva, bytes);
	else
		memcpy(hva, addr, bytes);

	return bytes;
}

int read_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr, unsigned int bytes)
{
	return copy_gpa(vcpu, gpa, addr, bytes, true);
}

int write_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr, unsigned int bytes)
{
	return copy_gpa(vcpu, gpa, addr, bytes, false);
}
