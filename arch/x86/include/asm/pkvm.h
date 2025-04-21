/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef _ASM_X86_PKVM_H
#define _ASM_X86_PKVM_H

#include <asm/kvm_para.h>
#include <asm/io.h>
#include <asm/coco.h>
#include <asm/virt_exception.h>

/* PKVM Hypercalls */
#define PKVM_HC_KVM_CALL		0
#define PKVM_HC_INIT_FINALISE		1
#define PKVM_HC_FINALIZE_SHADOW_VM	4
#define PKVM_HC_MMIO_ACCESS		7
#define PKVM_HC_IOMMU_SET_RTA		8
#define PKVM_HC_IOMMU_UPDATE_CE		9
#define PKVM_HC_IOMMU_MAP_PAGES		10
#define PKVM_HC_IOMMU_UNMAP_PAGES	11
#define PKVM_HC_IOMMU_IOVA2PHYS		12
#define PKVM_HC_TLB_REMOTE_FLUSH_RANGE	13
#define PKVM_HC_SET_MMIO_VE		14
#define PKVM_HC_ADD_PTDEV		15

#define PKVM_HC_DUMP_DMAR_TR_STRUCT	20
#define PKVM_HC_DUMP_DOMAIN_PGT		21


/*
 * 15bits for PASID, DO NOT change it, based on it,
 * the size of PASID DIR table can kept as one page
 */
#define PKVM_MAX_PASID_BITS	15
#define PKVM_MAX_PASID		(1 << PKVM_MAX_PASID_BITS)

#ifdef CONFIG_PKVM_INTEL

#ifndef __PKVM_HYP__
extern bool __read_mostly enable_pkvm;	/* kernel command-line flag */

extern struct static_key_false pkvm_ia_enabled_key;

#define pkvm_ia_enabled() (bool)static_branch_likely(&pkvm_ia_enabled_key)

struct pkvm_iommu_driver {
	int (*init_driver)(void);
	void (*remove_driver)(void);
};

int pkvm_iommu_register_driver(struct pkvm_iommu_driver *kern_ops);
#endif

DECLARE_PER_CPU_READ_MOSTLY(bool, pkvm_enabled);

static inline long pkvm_dump_dmar_translation_struct(void)
{
	if (likely(this_cpu_read(pkvm_enabled)))
		return kvm_hypercall0(PKVM_HC_DUMP_DMAR_TR_STRUCT);
	return 0;
}

static inline long pkvm_dump_domain_translation_struct(
		unsigned long phys, unsigned long bdf, unsigned long pasid)
{
	if (likely(this_cpu_read(pkvm_enabled)))
		return kvm_hypercall3(PKVM_HC_DUMP_DOMAIN_PGT, phys, bdf, pasid);
	return 0;
}

static inline u64 pkvm_readq(void __iomem *reg, unsigned long reg_phys,
			     unsigned long offset)
{
	if (likely(this_cpu_read(pkvm_enabled)))
		return (u64)kvm_hypercall3(PKVM_HC_MMIO_ACCESS, true,
					   sizeof(u64), reg_phys + offset);
	else
		return readq(reg + offset);
}

static inline u32 pkvm_readl(void __iomem *reg, unsigned long reg_phys,
			     unsigned long offset)
{
	if (likely(this_cpu_read(pkvm_enabled)))
		return (u32)kvm_hypercall3(PKVM_HC_MMIO_ACCESS, true,
					   sizeof(u32), reg_phys + offset);
	else
		return readl(reg + offset);
}

static inline void pkvm_writeq(void __iomem *reg, unsigned long reg_phys,
			       unsigned long offset, u64 val)
{
	if (likely(this_cpu_read(pkvm_enabled)))
		kvm_hypercall4(PKVM_HC_MMIO_ACCESS, false, sizeof(u64),
			       reg_phys + offset, val);
	else
		writeq(val, reg + offset);
}

static inline void pkvm_writel(void __iomem *reg, unsigned long reg_phys,
			       unsigned long offset, u32 val)
{
	if (likely(this_cpu_read(pkvm_enabled)))
		kvm_hypercall4(PKVM_HC_MMIO_ACCESS, false, sizeof(u32),
			       reg_phys + offset, (u64)val);
	else
		writel(val, reg + offset);
}

static inline long pkvm_set_iommu_root(unsigned long reg_phys, unsigned long root_addr)
{
	long ret = 0;
	if (likely(this_cpu_read(pkvm_enabled)))
		ret = kvm_hypercall2(PKVM_HC_IOMMU_SET_RTA, reg_phys, root_addr);

	return ret;
}

/*
 * Parameters passed by the host for UPDATE_CE hypercall.
 */
struct pkvm_update_ce_param {
	u16 bdf;
	u16 domain_gaw;
	u16 domain_agaw;
	u8 iommu_coherency;
	u8 iommu_superpage;
	u64 rte;
	u64 ce_lo;
	u64 ce_hi;
};

static inline long pkvm_update_context_entry(unsigned long reg_phys, struct pkvm_update_ce_param *param)
{
	long ret = 0;
	if (likely(this_cpu_read(pkvm_enabled))) {
		ret = kvm_hypercall2(PKVM_HC_IOMMU_UPDATE_CE, reg_phys, (unsigned long)param);
	}

	return ret;
}

#define PKVM_MAX_IOMMU_PAGE_DONATION	16
/*
 * For managing IOMMU page tables, pkvm would need free pages and host
 * donates the pages as needed. This avoids static allocation of pages
 * in pkvm during boot. map and unmap hypercalls use this structure as
 * a two-way communication mechanism to manage page donation. Host
 * allocates pages and updates nr_donated for the map hypercall. pkvm
 * updates nr_returned with the pages not used or freed during map/unmap
 * hypercalls.
 */
struct pkvm_iommu_page_donation {
	u32 nr_pages;
	u64 pages[PKVM_MAX_IOMMU_PAGE_DONATION]; /* page gpa */
};

/*
 * parameters passed by host for MAP_PAGE hypercall.
 */
struct pkvm_iommu_map_param {
	u64 pgd_gpa;
	u64 iov_pfn;
	u64 phys_pfn;
	u64 nr_pages;
	u64 prot;
};

static inline long pkvm_iommu_map_pages(struct pkvm_iommu_map_param *param,
		struct pkvm_iommu_page_donation *donation)
{
	long ret = 0;
	if (likely(this_cpu_read(pkvm_enabled))) {
		ret = kvm_hypercall2(PKVM_HC_IOMMU_MAP_PAGES,
				(unsigned long)param, (unsigned long)donation);
	}
	return ret;
}

static inline long pkvm_iommu_unmap_pages(unsigned long pgd_gpa, unsigned long start_pfn,
		unsigned long last_pfn, struct pkvm_iommu_page_donation *donation)
{
	long ret = 0;
	if (likely(this_cpu_read(pkvm_enabled))) {
		ret = kvm_hypercall4(PKVM_HC_IOMMU_UNMAP_PAGES, pgd_gpa, start_pfn, last_pfn,
				(unsigned long)donation);
	}
	return ret;
}

struct pkvm_iommu_iova2phys_param {
	u64 pgd_gpa;
	u64 iova;
	u64 phys;
	u64 level;
};
static inline long pkvm_iommu_iova_to_phys(struct pkvm_iommu_iova2phys_param *param)
{
	long ret = 0;
	if (likely(this_cpu_read(pkvm_enabled))) {
		ret = kvm_hypercall1(PKVM_HC_IOMMU_IOVA2PHYS, (unsigned long)param);
	}
	return ret;
}

static inline void pkvm_update_iommu_virtual_caps(u64 *cap, u64 *ecap)
{
#ifndef __PKVM_HYP__
	if (!enable_pkvm)
		return;
#endif

	if (cap)
		/*
		 * Set caching mode as linux OS will runs in a VM
		 * with controlling a virtual IOMMU device emulated
		 * by pkvm.
		 */
		*cap |= 1 << 7;

	if (ecap) {
		u64 tmp;

		/*
		 * Some IOMMU capabilities cannot be directly used by the linux
		 * IOMMU driver after the linux is deprivileged, which is because after
		 * deprivileging, pkvm IOMMU driver will control the physical IOMMU and
		 * it is designed to use physical IOMMU in two ways for better performance
		 * and simpler implementation:
		 * 1. using nested translation with the first-level from the deprivileged
		 * linux IOMMU driver and EPT as second-level.
		 * 2. using second-level only translation with EPT.
		 * The linux IOMMU driver then uses an virtual IOMMU device emulated by
		 * pkvm IOMMU driver.
		 *
		 * Way#1 and way#2 can only support the linux IOMMU driver works in
		 * first-level translation mode or HW pass-through mode. To guarantee
		 * this, let linux IOMMU driver to pick up the supported capabilities
		 * when running at the bare metal if pkvm is enabled, to make it as a
		 * pkvm-awared IOMMU kernel driver.
		 *
		 * So disable SLTS and Nest.
		 */
		*ecap &= ~((1UL << 46) | (1UL << 26));

		/* limit PASID to reduce the memory consumptions */
		tmp = min_t(u64, (PKVM_MAX_PASID_BITS - 1),
			    (*ecap & GENMASK_ULL(39, 35)) >> 35);
		*ecap = (*ecap & ~GENMASK_ULL(39, 35)) | (tmp << 35);

		/*
		 * Disable Device TLB capability for security.
		 *
		 * ATS is only enabled for trusted device by the host OS.
		 * However with pkvm, the host OS including the device driver
		 * is treated as untrusted software. A malicious software in
		 * host OS may enable ATS for untrusted device so that the
		 * untrusted device can still exploit the ATS weekness to bypass
		 * VT-d's translation protection and access the isolated memory.
		 *
		 * To resolve this, tell the host IOMMU driver not to enable
		 * any device's ATS as pkvm controls IOMMU not to enable the
		 * device TLB.
		 */
		*ecap &= ~(1UL << 2);
	}
}
#else
static inline bool pkvm_ia_enabled(void)
{
	return false;
}
#endif

#ifdef CONFIG_PKVM_GUEST

void pkvm_guest_init_coco(void);
bool pkvm_is_protected_guest(void);
int pkvm_set_mem_host_visibility(unsigned long addr, int numpages, bool enc);

u64 __pkvm_module_call(u64 fn, struct tdx_module_args *out);

#else

static inline void pkvm_guest_init_coco(void) { }
static inline bool pkvm_is_protected_guest(void) { return false; }
static inline int
pkvm_set_mem_host_visibility(unsigned long addr, int numpages, bool enc) { return 0; }

#endif

#endif
