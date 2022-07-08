/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef __PKVM_MEM_PROTECT_H__
#define __PKVM_MEM_PROTECT_H__

/*
 * enum pkvm_pgtable_prot - The ignored bits in page-table.
 * pkvm will use these ignored bits as software bits to
 * identify the page status.
 */
enum pkvm_pgtable_prot {
	PKVM_PGTABLE_PROT_SW0		= BIT(56),
	PKVM_PGTABLE_PROT_SW1		= BIT(57),
};

/*
 * Using the ignored bits in page-table as SW bits.
 * SW bits 0-1 are used to track the memory ownership state of each page:
 *   00: The page has no mapping in page table (also invalid pte). And under
 *   this page state, host ept is using the pte ignored bits to record owner_id.
 *   01: The page is owned exclusively by the page-table owner.
 *   10: The page is owned by the page-table owner, but is shared
 *   	with another entity.
 *   11: The page is shared with, but not owned by the page-table owner.
 */
enum pkvm_page_state {
	PKVM_NOPAGE			= 0ULL,
	PKVM_PAGE_OWNED			= PKVM_PGTABLE_PROT_SW0,
	PKVM_PAGE_SHARED_OWNED		= PKVM_PGTABLE_PROT_SW1,
	PKVM_PAGE_SHARED_BORROWED	= PKVM_PGTABLE_PROT_SW0 |
					  PKVM_PGTABLE_PROT_SW1,
};

#define PKVM_PAGE_STATE_PROT_MASK	(PKVM_PGTABLE_PROT_SW0 | PKVM_PGTABLE_PROT_SW1)
/* use 20 bits[12~31] - not conflict w/ low 12 bits pte prot */
#define PKVM_INVALID_PTE_OWNER_MASK	GENMASK(31, 12)

static inline u64 pkvm_mkstate(u64 prot, enum pkvm_page_state state)
{
	return (prot & ~PKVM_PAGE_STATE_PROT_MASK) | state;
}

static inline enum pkvm_page_state pkvm_getstate(u64 pte)
{
	return pte & PKVM_PAGE_STATE_PROT_MASK;
}

typedef u32 pkvm_id;
static const pkvm_id pkvm_hyp_id = 0;

int host_ept_set_owner(phys_addr_t addr, u64 size, pkvm_id owner_id);

/*
 * __pkvm_host_donate_hyp() - Donate pages from host to hyp, then host cannot
 * access these donated pages.
 *
 * @hpa:	Start hpa of being donated pages, must be continues.
 * @size:	The size of memory to being donated.
 *
 * A range of pages [hpa, hpa + size) will be donated from host to hyp. And
 * this will unmap these pages from host ept and set the page owner as hyp_id
 * in the pte in host ept. For hyp mmu, it will do nothing, due to hyp mmu can
 * access the all memory by default, but modify host ept is necessary because a
 * page used by pkvm is private and can't be accessed by host.
 */
int __pkvm_host_donate_hyp(u64 hpa, u64 size);

/*
 * __pkvm_hyp_donate_host() - Donate pages from hyp to host, then host can
 * access these pages.
 *
 * @hpa:	Start hpa of being donated pages, must be continues.
 * @size:	The size of memory to being donated.
 *
 * A range of pages [hpa, hpa + size) will be donated from hyp to host. This
 * will create mapping in host ept for these pages, and nothing to do with hyp
 * mmu. This is paired with __pkvm_host_donate_hyp(), and sames as host reclaim
 * these pages back.
 */
int __pkvm_hyp_donate_host(u64 hpa, u64 size);

/*
 * __pkvm_host_share_guest() - Share pages between host and guest, host still
 * ownes the page and guest will have temporary access for these pages.
 *
 * @hpa:	Start hpa of being shared pages, must be continues.
 * @guest_pgt:	The guest ept pagetable.
 * @gpa:	Start gpa that will be used for mapping into the guest ept.
 * @size:	The size of pages to being shared.
 * @prot:	The prot that will be used for creating mapping for guest ept.
 *
 * A range of pages [hpa, hpa + size) in host ept that it's page state
 * will be modified from PAGE_OWNED to PAGE_SHARED_OWNED. And there will have
 * mapping to be created in guest ept that maps the gfn to pfn, and the @prot
 * and PAGE_SHARED_BORROWED will be used to create the mapping.
 */
int __pkvm_host_share_guest(u64 hpa, struct pkvm_pgtable *guest_pgt,
			    u64 gpa, u64 size, u64 prot);

#endif
