/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Google
 */
#ifndef __PKVM_PV_PASID_H
#define __PKVM_PV_PASID_H

#include <../drivers/iommu/intel/iommu.h>
#include <asm/pkvm.h>
#include <asm/pkvm_spinlock.h>
#include "ptdev.h"

#define PASID_PTE_PRESENT	1
#define PASID_PTE_MASK		0x3F
#define PASID_PTE_FPD		2
#define MAX_NR_PASID_BITS	PKVM_MAX_PASID_BITS

#define PDE_PFN_MASK		PAGE_MASK

#define PASIDTAB_BITS		6
#define PASIDTAB_SHIFT		0
#define PASIDTAB_ENTRIES	(1 << PASIDTAB_BITS)

#define PASIDDIR_BITS		(MAX_NR_PASID_BITS - PASIDTAB_BITS)
#define PASIDDIR_SHIFT		PASIDTAB_BITS

struct pasid_dir_entry {
	u64 val;
};

struct pasid_entry {
	u64 val[8];
};

#define is_pasid_enabled(entry)		(((entry)->lo >> 3) & 0x1)
#define get_pasid_dir_size(entry)	(1 << ((((entry)->lo >> 9) & 0x7) + 7))

static inline void entry_set_bits(u64 *ptr, u64 mask, u64 bits)
{
	u64 old;

	old = READ_ONCE(*ptr);
	WRITE_ONCE(*ptr, (old & ~mask) | bits);
}

/* Get PRESENT bit of a PASID directory entry. */
static inline bool pasid_pde_is_present(struct pasid_dir_entry *pde)
{
	return READ_ONCE(pde->val) & PASID_PTE_PRESENT;
}

/* Get PRESENT bit of a PASID table entry. */
static inline bool pasid_pte_is_present(struct pasid_entry *pte)
{
	return READ_ONCE(pte->val[0]) & PASID_PTE_PRESENT;
}

/* Get PASID table from a PASID directory entry. */
static inline struct pasid_entry *
get_pasid_table_from_pde(struct pasid_dir_entry *pde)
{
	if (!pasid_pde_is_present(pde))
		return NULL;

	return pkvm_phys_to_virt(READ_ONCE(pde->val) & VTD_PAGE_MASK);
}

/*
 * Interfaces for PASID table entry manipulation:
 */
static inline void pasid_clear_entry(struct pasid_entry *pe)
{
	WRITE_ONCE(pe->val[0], 0);
	WRITE_ONCE(pe->val[1], 0);
	WRITE_ONCE(pe->val[2], 0);
	WRITE_ONCE(pe->val[3], 0);
	WRITE_ONCE(pe->val[4], 0);
	WRITE_ONCE(pe->val[5], 0);
	WRITE_ONCE(pe->val[6], 0);
	WRITE_ONCE(pe->val[7], 0);
}

/*
 * Setup the DID(Domain Identifier) field (Bit 64~79) of scalable mode
 * PASID entry.
 */
static inline void
pasid_set_domain_id(struct pasid_entry *pe, u64 value)
{
	entry_set_bits(&pe->val[1], GENMASK_ULL(15, 0), value);
}

/*
 * Get domain ID value of a scalable mode PASID entry.
 */
static inline u16
pasid_get_domain_id(struct pasid_entry *pe)
{
	return (u16)(READ_ONCE(pe->val[1]) & GENMASK_ULL(15, 0));
}

/*
 * Setup the First Level Page table Pointer field (Bit 140~191)
 * of a scalable mode PASID entry.
 */
static inline void
pasid_set_flptr(struct pasid_entry *pe, u64 value)
{
	entry_set_bits(&pe->val[2], VTD_PAGE_MASK, value);
}

/*
 * Get the FLPTPTR(First Level Page Table Pointer) field (Bit 140 ~ 191)
 * of a scalable mode PASID entry.
 */
static inline u64
pasid_get_flptr(struct pasid_entry *pe)
{
	return (u64)(READ_ONCE(pe->val[2]) & VTD_PAGE_MASK);
}

/*
 * Setup the SLPTPTR(Second Level Page Table Pointer) field (Bit 12~63)
 * of a scalable mode PASID entry.
 */
static inline void
pasid_set_slptr(struct pasid_entry *pe, u64 value)
{
	entry_set_bits(&pe->val[0], VTD_PAGE_MASK, value);
}

/*
 * Get the SLPTPTR(First Level Page Table Pointer) field (Bit 140 ~ 191)
 * of a scalable mode PASID entry.
 */
static inline u64
pasid_get_slptr(struct pasid_entry *pe)
{
	return (u64)(READ_ONCE(pe->val[0]) & VTD_PAGE_MASK);
}

/*
 * Setup the First Level Paging Mode field (Bit 130~131) of a
 * scalable mode PASID entry.
 */
static inline void
pasid_set_flpm(struct pasid_entry *pe, u64 value)
{
	entry_set_bits(&pe->val[2], GENMASK_ULL(3, 2), value << 2);
}

/*
 * Get the First Level Paging Mode field (Bit 130~131) of a
 * scalable mode PASID entry.
 */
static inline u8
pasid_get_flpm(struct pasid_entry *pe)
{
	return (u8)((READ_ONCE(pe->val[2]) & GENMASK_ULL(3, 2)) >> 2);
}

/*
 * Get the AW(Address Width) field (Bit 2~4) of a scalable mode PASID
 * entry.
 */
static inline u8 pasid_get_address_width(struct pasid_entry *pe)
{
	return (pe->val[0] >> 2) & 0x7;
}

/*
 * Setup the AW(Address Width) field (Bit 2~4) of a scalable mode PASID
 * entry.
 */
static inline void
pasid_set_address_width(struct pasid_entry *pe, u64 value)
{
	entry_set_bits(&pe->val[0], GENMASK_ULL(4, 2), value << 2);
}

/* Get PGTT field of a PASID table entry */
static inline u16 pasid_get_translation_type(struct pasid_entry *pte)
{
	return (u16)((READ_ONCE(pte->val[0]) >> 6) & 0x7);
}

/*
 * Setup the PGTT(PASID Granular Translation Type) field (Bit 6~8)
 * of a scalable mode PASID entry.
 */
static inline void
pasid_set_translation_type(struct pasid_entry *pe, u64 value)
{
	entry_set_bits(&pe->val[0], GENMASK_ULL(8, 6), value << 6);
}

/*
 * Enable fault processing by clearing the FPD(Fault Processing
 * Disable) field (Bit 1) of a scalable mode PASID entry.
 */
static inline void pasid_set_fault_enable(struct pasid_entry *pe)
{
	entry_set_bits(&pe->val[0], 1 << 1, 0);
}

/*
 * Setup Page Walk Snoop bit (Bit 87) of a scalable mode PASID
 * entry.
 */
static inline void pasid_set_page_snoop(struct pasid_entry *pe, bool value)
{
	entry_set_bits(&pe->val[1], 1 << 23, value << 23);
}

/*
 * Get the Page Snoop (PGSNP) field (Bit 88) of a scalable mode
 * PASID entry.
 */
static inline u8 pasid_get_pgsnp(struct pasid_entry *pe)
{
	return (pe->val[1] >> 24) & 1;
}

/*
 * Setup the Page Snoop (PGSNP) field (Bit 88) of a scalable mode
 * PASID entry.
 */
static inline void
pasid_set_pgsnp(struct pasid_entry *pe)
{
	entry_set_bits(&pe->val[1], 1ULL << 24, 1ULL << 24);
}

/*
 * Setup the P(Present) field (Bit 0) of a scalable mode PASID
 * entry.
 */
static inline void pasid_set_present(struct pasid_entry *pe)
{
	entry_set_bits(&pe->val[0], 1 << 0, 1);
}

#define PASID_ENTRY_PGTT_FL_ONLY        (1)
#define PASID_ENTRY_PGTT_SL_ONLY        (2)
#define PASID_ENTRY_PGTT_NESTED         (3)
#define PASID_ENTRY_PGTT_PT             (4)

/*
 * Set the Second Stage Execute Enable field (Bit 5) of a scalable mode
 * PASID entry.
 */
static inline void pasid_set_ssee(struct pasid_entry *pe, bool value)
{
	entry_set_bits(&pe->val[0], 1 << 5, value << 5);
}

/*
 * Set the Second Stage Access/Dirty bit Enable field (Bit 9) of a scalable mode
 * PASID entry.
 */
static inline void pasid_set_ssade(struct pasid_entry *pe, bool value)
{
	entry_set_bits(&pe->val[0], 1 << 9, value << 9);
}

static inline bool pasid_copy_entry(struct pasid_entry *to, struct pasid_entry *from)
{
	bool updated = false;
	int i;

	for (i = 0; i < 8; i++) {
		u64 new = READ_ONCE(from->val[i]);

		if (READ_ONCE(to->val[i]) != new) {
			WRITE_ONCE(to->val[i], new);
			updated = true;
		}
	}

	return updated;
}

int pkvm_iommu_clear_pasid_entry(u64 param_va);
int pkvm_iommu_set_pasid_fl(u64 param_va);
int pkvm_iommu_set_pasid_sl(u64 param_va);
int pkvm_pasid_free_table(struct pasid_dir_entry *dir, int max_pde);
#endif /* __PKVM_PV_PASID_H */
