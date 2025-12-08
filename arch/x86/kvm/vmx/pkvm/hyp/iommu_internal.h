/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef __PKVM_IOMMU_INTERNAL_H
#define __PKVM_IOMMU_INTERNAL_H

#include <../drivers/iommu/intel/iommu.h>
#include <asm/pkvm.h>
#include <asm/pkvm_spinlock.h>
#include "pgtable.h"
#include "pkvm_iommu_types.h"
#include "pv_pasid.h"
#include "iommu_domain.h"

struct viommu_reg {
	u64 cap;
	u64 ecap;
	u32 gsts;
	u64 rta;
	u64 iq_head;
	u64 iq_tail;
	u64 iqa;
};

struct pkvm_viommu {
	struct pkvm_pgtable pgt;
	struct viommu_reg vreg;
	u64 iqa;
};

struct pkvm_iommu {
	struct intel_iommu iommu;
	pkvm_spinlock_t lock;
	bool activated;
	struct pkvm_pgtable pgt;
	struct pkvm_viommu viommu;

	struct q_inval qi;
	pkvm_spinlock_t qi_lock;
	u64 piommu_iqa;

	/* Link ptdev information of this IOMMU */
	struct list_head ptdev_head;

	/*
	 * Number of Context/Pasid entries configured
	 * in pass-through mode from the host perspective
	 */
	atomic_t pt_cnt;
};

struct pkvm_cache_tag {
	unsigned int index;
	struct list_head node;
	enum cache_tag_type type;
	struct pkvm_iommu *iommu;
	u8 bus;
	u8 devfn;
	u16 pfsid;
	u8 ats_qdep;
	u16 domain_id;
	ioasid_t pasid;
	unsigned int users;
};

enum lm_level {
	IOMMU_LM_CONTEXT = 1,
	IOMMU_LM_ROOT,
};

enum sm_level {
	IOMMU_PASID_TABLE = 1,
	IOMMU_PASID_DIR,
	IOMMU_SM_CONTEXT,
	IOMMU_SM_ROOT,
	IOMMU_SM_LEVEL_NUM,
};

/*
 * Simple wrapper to get devfn from bdf.
 * This is not the appropriate place to park.
 * Temporarily parking it here as it is used
 * only by iommu code.
 */
#define PCI_DEV_FN(x) ((x) & 0xff)

extern const struct pkvm_mm_ops iommu_pw_coherency_mm_ops;
extern const struct pkvm_mm_ops iommu_pw_noncoherency_mm_ops;

static inline u16 level_to_agaw(int level)
{
	return (level == 3) ? 1 : (level == 4) ? 2 : 3;
}

#define __DOMAIN_MAX_ADDR(gaw) ((((uint64_t)1) << (gaw)) - 1)

#define LAST_LEVEL(level)	\
	(((level) == 1) ? true : false)

#define LM_DEVFN_BITS	8
#define LM_DEVFN_SHIFT	0

#define LM_BUS_BITS		8
#define LM_BUS_SHIFT	8
#define IOMMU_LM_MAX_VADDR         BIT(16)

#define DEVFN_BITS		8
#define DEVFN_SHIFT		(PASIDDIR_SHIFT + PASIDDIR_BITS)

#define BUS_BITS		8
#define BUS_SHIFT		(DEVFN_SHIFT + DEVFN_BITS)

/* Used to calculate the level-to-index */
#define SM_DEVFN_BITS		7
#define SM_BUS_BITS		9
#define SM_BUS_SHIFT		(DEVFN_SHIFT + SM_DEVFN_BITS)

#define IOMMU_MAX_VADDR_LEN	(BUS_SHIFT + BUS_BITS)
#define IOMMU_MAX_VADDR		BIT(IOMMU_MAX_VADDR_LEN)

#define MAX_NUM_OF_ADDRESS_SPACE(_iommu)		\
	(sm_supported(&(_iommu)->iommu) ?		\
		IOMMU_MAX_VADDR : IOMMU_LM_MAX_VADDR)

#define DMAR_GSTS_EN_BITS	(DMA_GCMD_TE | DMA_GCMD_EAFL | \
				 DMA_GCMD_QIE | DMA_GCMD_IRE | \
				 DMA_GCMD_CFI)
#define DMAR_GCMD_PROTECTED	(DMA_GCMD_TE | DMA_GCMD_SRTP | \
				 DMA_GCMD_QIE)
#define DMAR_GCMD_DIRECT	(DMA_GCMD_SFL | DMA_GCMD_EAFL | \
				 DMA_GCMD_WBF | DMA_GCMD_IRE | \
				 DMA_GCMD_SIRTP | DMA_GCMD_CFI)

#define PKVM_IOMMU_WAIT_OP(offset, op, cond, sts)			\
do {									\
	while (1) {							\
		(sts) = op(offset);					\
		if (cond)						\
			break;						\
		cpu_relax();						\
	}								\
} while (0)

#define IQ_DESC_BASE_PHYS(reg)		((reg) & ~0xfff)
#define IQ_DESC_DW(reg)			(((reg) >> 11) & 1)
#define IQ_DESC_QS(reg)			((reg) & GENMASK_ULL(2, 0))
#define IQ_DESC_LEN(reg)		(1 << (7 + IQ_DESC_QS(reg) + !IQ_DESC_DW(reg)))
#define IQ_DESC_SHIFT(reg)		(4 + IQ_DESC_DW(reg))

#define QI_DESC_TYPE(qw)		((qw) & GENMASK_ULL(3, 0))
#define QI_DESC_CC_GRANU(qw)		(((qw) & GENMASK_ULL(5, 4)) >> 4)
#define QI_DESC_CC_DID(qw)		(((qw) & GENMASK_ULL(31, 16)) >> 16)
#define QI_DESC_CC_SID(qw)		(((qw) & GENMASK_ULL(47, 32)) >> 32)

#define QI_DESC_PC_GRANU(qw)		(((qw) & GENMASK_ULL(5, 4)) >> 4)
#define QI_DESC_PC_DID(qw)		(((qw) & GENMASK_ULL(31, 16)) >> 16)
#define QI_DESC_PC_PASID(qw)		(((qw) & GENMASK_ULL(51, 32)) >> 32)

#define QI_DESC_IOTLB_GRANU(qw)		(((qw) & GENMASK_ULL(5, 4)) >> 4)
#define QI_DESC_IOTLB_DID(qw)		(((qw) & GENMASK_ULL(31, 16)) >> 16)
#define QI_DESC_IOTLB_ADDR(qw)		((qw) & VTD_PAGE_MASK)
#define QI_DESC_IOTLB_AM(qw)		((qw) & GENMASK_ULL(5, 0))

/*
 * Domain ID reserved for pasid entries programmed for first-level
 * only and pass-through transfer modes.
 * (copied from drivers/iommu/intel/pasid.h)
 */
#define FLPT_DEFAULT_DID		1

#define pgt_to_pkvm_iommu(_pgt) container_of(_pgt, struct pkvm_iommu, pgt)

static inline void context_sm_clear_dte(struct context_entry *ce)
{
	entry_set_bits(&ce->lo, 1 << 2, 0);
}

static inline bool context_get_sm_dte(struct context_entry *ce)
{
	return READ_ONCE(ce->lo) & BIT_ULL(2);
}

static inline bool context_lm_is_present(struct context_entry *ce)
{
	return READ_ONCE(ce->lo) & 1;
}

static inline u8 context_lm_get_tt(struct context_entry *ce)
{
	return (READ_ONCE(ce->lo) >> 2) & 3;
}

static inline u64 context_lm_get_slptr(struct context_entry *ce)
{
	return READ_ONCE(ce->lo) & VTD_PAGE_MASK;
}

static inline u8 context_lm_get_aw(struct context_entry *ce)
{
	return READ_ONCE(ce->hi) & 0x7;
}

static inline u16 context_lm_get_did(struct context_entry *ce)
{
	return (READ_ONCE(ce->hi) >> 8) & 0xffff;
}

static inline void context_lm_set_tt(struct context_entry *ce, u8 value)
{
	entry_set_bits(&ce->lo, 3 << 2, value << 2);
}

static inline void context_lm_set_slptr(struct context_entry *ce, u64 value)
{
	entry_set_bits(&ce->lo, VTD_PAGE_MASK, value);
}

static inline void context_lm_set_aw(struct context_entry *ce, u8 value)
{
	entry_set_bits(&ce->hi, 0x7, value);
}

/*
 * Copied from drivers/iommu/intel/iommu.h:__iommu_flush_cache()
 */
static inline void __pkvm_iommu_flush_cache(
	struct intel_iommu *iommu, void *addr, int size)
{
	if (!ecap_coherent(iommu->ecap))
		pkvm_clflush_cache_range(addr, size);
}

static inline bool iommu_coherency(struct intel_iommu *iommu)
{
	return sm_supported(iommu) ?
		ecap_smpwc(iommu->ecap) : ecap_coherent(iommu->ecap);
}

/*
 * TODO: Add support for IH.
 */
static inline void setup_iotlb_qi_desc(struct pkvm_iommu *iommu,
				       struct qi_desc *desc, u16 did,
				       u64 addr, unsigned int size_order,
				       u64 type)
{
	u8 dw = 0, dr = 0;

	if (cap_write_drain(iommu->iommu.cap))
		dw = 1;

	if (cap_read_drain(iommu->iommu.cap))
		dr = 1;

	desc->qw0 = QI_IOTLB_DID(did) | QI_IOTLB_DR(dr) | QI_IOTLB_DW(dw) |
		    QI_IOTLB_GRAN(type) | QI_IOTLB_TYPE;
	desc->qw1 = QI_IOTLB_ADDR(addr) | QI_IOTLB_AM(size_order);
	desc->qw2 = 0;
	desc->qw3 = 0;
}

extern void root_tbl_walk(struct pkvm_iommu *iommu);

bool is_dev_in_satc(u16 bdf);

void flush_context_cache(struct pkvm_iommu *iommu, u16 did,
				u16 sid, u8 fm, u64 type);
void flush_iotlb(struct pkvm_iommu *iommu, u16 did, u64 addr,
			unsigned int size_order, u64 type);
void flush_dev_iotlb(struct pkvm_iommu *iommu, u16 sid, u16 pfsid,
			u16 qdep, u64 addr, unsigned int mask);
void flush_dev_iotlb_pasid(struct pkvm_iommu *iommu, u16 sid, u16 pfsid, u16 pasid,
			   u16 qdep, u64 addr, unsigned int size_order);
void flush_piotlb(struct pkvm_iommu *iommu, u16 did, u32 pasid, u64 addr,
		  unsigned long npages, bool ih);
void flush_pasid_cache(struct pkvm_iommu *iommu, u16 did,
		       u64 granu, u32 pasid);

void submit_qi(struct pkvm_iommu *iommu, struct qi_desc *base, int count);
void pkvm_cache_tag_flush_range(struct pkvm_iommu_domain *domain, unsigned long start,
				unsigned long end, int ih);
void pkvm_cache_tag_flush_range_np(struct pkvm_iommu_domain *domain, unsigned long start,
				   unsigned long end);

struct pkvm_iommu *find_iommu_by_reg_phys(unsigned long phys);

#ifdef CONFIG_PKVM_INTEL_PVIOMMU
int pkvm_iommu_iec_flush(u64 phys, bool global, u64 index, u64 mask);
int pkvm_iommu_clear_ce(u64 param_va);
int pkvm_iommu_set_lm_ce(u64 param_va);
int pkvm_iommu_set_sm_ce(u64 param_va);
struct context_entry *pkvm_iommu_context_addr(struct intel_iommu *iommu, u8 bus,
					      u8 devfn, u64 *context_phys);
int pkvm_iommu_domain_alloc(u64 param_va);
int pkvm_iommu_domain_free(u64 pgd_gpa);
int pkvm_iommu_cache_assign_domain(struct pkvm_iommu *iommu, struct pkvm_iommu_domain *domain,
				   u16 did, u16 bdf, u8 ats_qdep, ioasid_t pasid, bool dte);
void pkvm_iommu_cache_unassign_domain(struct pkvm_iommu *iommu, struct pkvm_iommu_domain *domain,
				      u16 did, u16 bdf, ioasid_t pasid, bool dte);
#else
int initialize_iommu_pgt(struct pkvm_iommu *iommu);
int handle_descriptor(struct pkvm_iommu *iommu, struct qi_desc *desc);
int handle_qi_invalidation(struct pkvm_iommu *iommu, unsigned long val);
int free_shadow_id(struct pkvm_iommu *iommu, unsigned long vaddr,
		       unsigned long vaddr_end);
int sync_shadow_id(struct pkvm_iommu *iommu, unsigned long vaddr,
		       unsigned long vaddr_end, u16 did);
#endif
#endif
