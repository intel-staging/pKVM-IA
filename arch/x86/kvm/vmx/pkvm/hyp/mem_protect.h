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

static inline bool owned_this_page(void *ptep)
{
	enum pkvm_page_state page_state = pkvm_getstate(*(u64 *)ptep);

	return (page_state == PKVM_PAGE_OWNED) || (page_state == PKVM_PAGE_SHARED_OWNED);
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

/*
 * __pkvm_host_unshare_guest() - Host unshare pages that being shared to guest
 * previously. Guest will can't access these pages.
 *
 * @hpa:	Start hpa of being shared pages, must be continues.
 * @guest_pgt:	The guest ept pagetable.
 * @gpa:	Start gpa of shared pages that being mapped in guest ept.
 * @size:	The size of pages to being shared.
 *
 * Unmap the range [gfn, gfn + nr_pages) in guest ept pagetable. And tranverse
 * the page state from PAGE_SHARED_BORROWED to PAGE_OWNED in the host ept.
 */
int __pkvm_host_unshare_guest(u64 hpa, struct pkvm_pgtable *guest_pgt,
			      u64 gpa, u64 size);

/*
 * __pkvm_host_donate_guest() - Host donate pages to guest. Then host can't
 * access these pages and guest can access.
 *
 * @hpa:	Start hpa of being donated pages, must be continues.
 * @guest_pgt:	The guest ept pagetable.
 * @gpa:	Start gpa of donated pages that will be mapped in guest ept.
 * @size:	The size of pages to being donated.
 * @prot:	The prot that will be used for creating mapping in guest ept.
 *
 * A range of pages [hpa, hpa + size) will be donated from host to guest. And
 * this will unmap these pages from host ept and set the page owner as guest_id
 * in the pte in host ept. The guest_id is equal to the vm's shadow_handle+1. In
 * the same time, the mapping gpa -> hpa with @size will be created in guest ept
 * with @prot.
 */
int __pkvm_host_donate_guest(u64 hpa, struct pkvm_pgtable *guest_pgt,
			     u64 gpa, u64 size, u64 prot);

/*
 * __pkvm_host_undoate_guest() - Host reclaim these pages donated to guest.
 * Then guest can't access these pages and host can access.
 *
 * @hpa:	Start hpa of being donated pages, must be continues.
 * @guest_pgt:	The guest ept pagetable.
 * @gpa:	Start gpa of donated pages that will be unmapped in guest ept.
 * @size:	The size of pages to being donated.
 *
 * A range of pages [hpa, hpa + size) will be donated from guest to host. And
 * this will unmap these pages [gpa, gpa + size) from guest ept. In the same
 * time, the identity mapping for hpa will be created in host ept.
 */
int __pkvm_host_undonate_guest(u64 hpa, struct pkvm_pgtable *guest_pgt,
			       u64 gpa, u64 size);
/*
 * __pkvm_guest_share_host() - Guest share pages to host, guest still
 * ownes the pages and host will have temporary access for these pages.
 *
 * @guest_pgt:	The guest ept pagetable.
 * @gpa:	Start gpa of being shared pages, must be continues.
 * @size:	The size of pages to be shared, should be PAGE_ALIGNED.
 *
 * Here no hpa in the paramter, due to the caller don't know it. So the hpa
 * depends on lookup the guest ept to get it.
 *
 * Now the function will share one PAGE at a time, if the size larger than
 * PAGE_SIZE, it will split it into multiple PAGE_SIZE page and share them using
 * a loop.
 *
 * A range of pages [gpa, gpa + size) in guest ept that it's page state
 * will be modified from PAGE_OWNED to PAGE_SHARED_OWNED. And there will have
 * mapping to be created in host ept for addr hpa, and it's page state will be
 * PAGE_SHARED_BORROWED.
 */
int __pkvm_guest_share_host(struct pkvm_pgtable *guest_pgt,
			    u64 gpa, u64 size);

/*
 * __pkvm_guest_unshare_host() - Guest reclaim these pages donated to host.
 * Then host can't access these pages and guest still ownes it.
 *
 * @guest_pgt:	The guest ept pagetable.
 * @gpa:	Start gpa of being unshared pages, must be continues.
 * @size:	The size of pages to be unshared, should be PAGE_ALIGNED.
 *
 * Here no hpa in the paramter, due to the caller don't know it. So the hpa
 * depends on lookup the guest ept to get it.
 *
 * Now the function will unshare one PAGE at a time, if the size larger than
 * PAGE_SIZE, it will split it into multiple PAGE_SIZE page and unshare them
 * using a loop.
 *
 * A range of pages [gpa, gpa + size) in guest ept that it's page state will be
 * modified from PAGE_SHARED_OWNED to PAGE_OWNED. And the mapping for these
 * pages in host ept will be unmapped and the owner_id will be set to guest_id.
 */
int __pkvm_guest_unshare_host(struct pkvm_pgtable *guest_pgt,
			      u64 gpa, u64 size);
#endif
