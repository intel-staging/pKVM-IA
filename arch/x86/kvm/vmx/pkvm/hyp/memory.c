// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/types.h>
#include <asm/kvm_pkvm.h>

#include <pkvm.h>
#include "memory.h"
#include "pgtable.h"
#include "pkvm_hyp.h"

unsigned long __page_base_offset;
unsigned long __symbol_base_offset;

unsigned int hyp_memblock_nr;
struct memblock_region hyp_memory[HYP_MEMBLOCK_REGIONS];

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

bool find_mem_range(unsigned long addr, struct mem_range *range)
{
	int cur, left = 0, right = hyp_memblock_nr;
	struct memblock_region *reg;
	unsigned long end;

	range->start = 0;
	range->end = ULONG_MAX;

	/* The list of memblock regions is sorted, binary search it */
	while (left < right) {
		cur = (left + right) >> 1;
		reg = &hyp_memory[cur];
		end = reg->base + reg->size;
		if (addr < reg->base) {
			right = cur;
			range->end = reg->base;
		} else if (addr >= end) {
			left = cur + 1;
			range->start = end;
		} else {
			range->start = reg->base;
			range->end = end;
			return true;
		}
	}

	return false;
}

bool mem_range_included(struct mem_range *child, struct mem_range *parent)
{
	return parent->start <= child->start && child->end <= parent->end;
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

static int check_translation(struct kvm_vcpu *vcpu, gva_t gva, gpa_t gpa,
		u64 prot, u32 access, struct x86_exception *exception)
{
	u16 errcode = 0;
	bool page_rw_flags_on = true;
	bool user_mode_addr = true;
	const int user_mode_access = access & PFERR_USER_MASK;
	const int write_access = access & PFERR_WRITE_MASK;
	bool cr4_smap = vmcs_readl(GUEST_CR4) & X86_CR4_SMAP;
	bool cr0_wp = vmcs_readl(GUEST_CR0) & X86_CR0_WP;

	/*
	 * As pkvm hypervisor will not do instruction emulation, here we do not
	 * expect guest memory access for instruction fetch.
	 */
	WARN_ON(access & PFERR_FETCH_MASK);

	/* pte is not present */
	if (gpa == INVALID_ADDR) {
		goto check_fault;
	} else {
		errcode |= PFERR_PRESENT_MASK;

		/*TODO: check reserved bits and PK */

		/* check for R/W */
		if ((prot & _PAGE_RW) == 0) {
			if (write_access && (user_mode_access || cr0_wp))
				/*
				 * case 1: Supermode and wp is 1
				 * case 2: Usermode
				 */
				goto check_fault;
			page_rw_flags_on = false;
		}

		/* check for U/S */
		if ((prot & _PAGE_USER) == 0) {
			user_mode_addr = false;
			if (user_mode_access)
				goto check_fault;
		}

		/*
		 * When SMAP is on, we only need to apply check when address is
		 * user-mode address.
		 *
		 * Also SMAP only impacts the supervisor-mode access.
		 */
		/* if SMAP is enabled and supervisor-mode access */
		if (cr4_smap && (!user_mode_access) && user_mode_addr) {
			bool acflag = vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_AC;

			/* read from user mode address, eflags.ac = 0 */
			if ((!write_access) && (!acflag)) {
				goto check_fault;
			} else if (write_access) {
				/* write to user mode address */

				/* cr0.wp = 0, eflags.ac = 0 */
				if ((!cr0_wp) && (!acflag))
					goto check_fault;

				/*
				 * cr0.wp = 1, eflags.ac = 1, r/w flag is 0
				 * on any paging structure entry
				 */
				if (cr0_wp && acflag && (!page_rw_flags_on))
					goto check_fault;

				/* cr0.wp = 1, eflags.ac = 0 */
				if (cr0_wp && (!acflag))
					goto check_fault;
			} else {
				/* do nothing */
			}
		}
	}

	return 0;

check_fault:
	errcode |= write_access | user_mode_access;
	exception->error_code = errcode;
	exception->vector = PF_VECTOR;
	exception->error_code_valid = true;
	exception->address = gva;
	exception->nested_page_fault = false;
	exception->async_page_fault = false;
	return -EFAULT;

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

	return check_translation(vcpu, gva, _gpa, prot, access, exception);
}

static inline int __copy_gpa(struct kvm_vcpu *vcpu, void *addr, gpa_t gpa,
			     unsigned int size, unsigned int pg_size,
			     bool from_guest)
{
	unsigned int len, offset_in_pg;
	void *hva;

	offset_in_pg = (unsigned int)gpa & (pg_size - 1);
	len = (size > (pg_size - offset_in_pg)) ? (pg_size - offset_in_pg) : size;

	hva = host_gpa2hva(gpa);
	if (from_guest)
		memcpy(addr, hva, len);
	else
		memcpy(hva, addr, len);

	return len;
}

/* only support host VM now */
static int copy_gva(struct kvm_vcpu *vcpu, gva_t gva, void *addr,
		unsigned int bytes, struct x86_exception *exception, bool from_guest)
{
	u32 access = VMX_AR_DPL(vmcs_read32(GUEST_SS_AR_BYTES)) == 3 ? PFERR_USER_MASK : 0;
	gpa_t gpa;
	unsigned int len;
	int ret = 0;

	if (!from_guest)
		access |= PFERR_WRITE_MASK;

	while ((bytes > 0) && (ret == 0)) {
		ret = gva2gpa(vcpu, gva, &gpa, access, exception);
		if (ret >= 0) {
			len = __copy_gpa(vcpu, addr, gpa, bytes, PAGE_SIZE, from_guest);
			if (len == 0)
				return -EINVAL;
			gva += len;
			addr += len;
			bytes -= len;
		}
	}

	return ret;
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
	unsigned int len;

	while (bytes > 0) {
		len = __copy_gpa(vcpu, addr, gpa, bytes, PAGE_SIZE, from_guest);
		if (len == 0)
			return -EINVAL;
		gpa += len;
		addr += len;
		bytes -= len;
	}

	return 0;
}

int read_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr, unsigned int bytes)
{
	return copy_gpa(vcpu, gpa, addr, bytes, true);
}

int write_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, void *addr, unsigned int bytes)
{
	return copy_gpa(vcpu, gpa, addr, bytes, false);
}
