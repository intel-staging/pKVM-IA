/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <pkvm.h>

#include "pgtable.h"
#include "memory.h"
#include "mem_protect.h"
#include "debug.h"
#include "bug.h"

struct pgt_walk_data {
	struct pkvm_pgtable *pgt;
	struct pgt_flush_data flush_data;
	unsigned long vaddr;
	unsigned long vaddr_end;
	struct pkvm_pgtable_walker *walker;
};

struct pkvm_pgtable_lookup_data {
	unsigned long vaddr;
	unsigned long phys;
	u64 prot;
	int level;
};

static bool pkvm_phys_is_valid(u64 phys)
{
	return phys != INVALID_ADDR;
}

static bool leaf_mapping_valid(struct pkvm_pgtable_ops *pgt_ops,
			       unsigned long vaddr,
			       unsigned long vaddr_end,
			       int pgsz_mask,
			       int level)
{
	unsigned long page_size = pgt_ops->pgt_level_to_size(level);

	if (!((1 << level) & pgsz_mask))
		return false;

	if (!IS_ALIGNED(vaddr, page_size))
		return false;

	if (page_size > (vaddr_end - vaddr))
		return false;

	return true;
}

static bool leaf_mapping_allowed(struct pkvm_pgtable_ops *pgt_ops,
				 unsigned long vaddr,
				 unsigned long vaddr_end,
				 unsigned long phys,
				 int pgsz_mask,
				 int level)
{
	unsigned long page_size = pgt_ops->pgt_level_to_size(level);

	if (pkvm_phys_is_valid(phys) && !IS_ALIGNED(phys, page_size))
		return false;

	return leaf_mapping_valid(pgt_ops, vaddr, vaddr_end, pgsz_mask, level);
}

static void pgtable_set_entry(struct pkvm_pgtable_ops *pgt_ops,
			struct pkvm_mm_ops *mm_ops,
			void *ptep, u64 pte)
{
	pgt_ops->pgt_set_entry(ptep, pte);

	if (mm_ops->flush_cache)
		mm_ops->flush_cache(ptep, sizeof(u64));
}

static void pgtable_split(struct pkvm_pgtable_ops *pgt_ops,
			  struct pkvm_mm_ops *mm_ops,
			  unsigned long vaddr, unsigned long phys,
			  unsigned long size, void *ptep,
			  int level, u64 prot)
{
	unsigned long phys_end = phys + size;
	int level_size = pgt_ops->pgt_level_to_size(level);
	int entry_size = PAGE_SIZE / pgt_ops->pgt_level_to_entries(level);
	int i = 0;

	if (level > PG_LEVEL_4K)
		pgt_ops->pgt_entry_mkhuge(&prot);

	for (i = 0; phys < phys_end; phys += level_size, i++) {
		pgtable_set_entry(pgt_ops, mm_ops,(ptep + i * entry_size), phys | prot);
		mm_ops->get_page(ptep);
	}
}

static int pgtable_map_leaf(struct pkvm_pgtable *pgt,
			    unsigned long vaddr,
			    int level, void *ptep,
			    struct pgt_flush_data *flush_data,
			    struct pkvm_pgtable_map_data *data)
{
	struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	struct pkvm_mm_ops *mm_ops = pgt->mm_ops;
	u64 old = *(u64 *)ptep, new;

	if (pkvm_phys_is_valid(data->phys)) {
		new = data->phys | data->prot;
		if (level != PG_LEVEL_4K)
			pgt_ops->pgt_entry_mkhuge(&new);
	} else {
		new = data->annotation;
	}

	if (pgt_ops->pgt_entry_mapped(ptep)) {
		/* if just modify the page state, do set_pte directly */
		if (!((old ^ new) & ~PKVM_PAGE_STATE_PROT_MASK))
			goto set_pte;

		if (pgt_ops->pgt_entry_present(ptep)) {
			pgtable_set_entry(pgt_ops, mm_ops, ptep, 0);
			flush_data->flushtlb |= true;
		}
		mm_ops->put_page(ptep);
	}

	if (pgt_ops->pgt_entry_mapped(&new))
		mm_ops->get_page(ptep);

set_pte:
	pgtable_set_entry(pgt_ops, mm_ops, ptep, new);
	if (pkvm_phys_is_valid(data->phys))
		data->phys += page_level_size(level);

	return 0;
}

static int pgtable_map_try_leaf(struct pkvm_pgtable *pgt, unsigned long vaddr,
				unsigned long vaddr_end, int level, void *ptep,
				struct pgt_flush_data *flush_data,
				struct pkvm_pgtable_map_data *data)
{
	if (!leaf_mapping_allowed(pgt->pgt_ops, vaddr, vaddr_end,
				 data->phys, data->pgsz_mask, level)) {
		/* The 4K page shall be able to map, otherwise return err */
		return (level == PG_LEVEL_4K ? -EINVAL: -E2BIG);
	}

	if (data->map_leaf_override)
		return data->map_leaf_override(pgt, vaddr, level, ptep, flush_data, data);
	else
		return pgtable_map_leaf(pgt, vaddr, level, ptep, flush_data, data);
}

static int pgtable_map_walk_leaf(struct pkvm_pgtable *pgt,
				 unsigned long vaddr, unsigned long vaddr_end,
				 int level, void *ptep, unsigned long flags,
				 struct pgt_flush_data *flush_data,
				 struct pkvm_pgtable_map_data *data)
{
	struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	struct pkvm_mm_ops *mm_ops = pgt->mm_ops;
	unsigned long size = page_level_size(level);
	void *page;
	int ret;

	/* First try to create leaf page mapping on current level */
	ret = pgtable_map_try_leaf(pgt, vaddr, vaddr_end, level, ptep, flush_data, data);
	if (ret != -E2BIG)
		return ret;

	/*
	 * Be here is because the mapping needs to be done on smaller(or level-1)
	 * page size. We need to allocate a table page for the smaller(level-1)
	 * page mapping. And for current level, if the huge page mapping is already
	 * present, we need further split it.
	 */
	page = mm_ops->zalloc_page();
	if (!page)
		return -ENOMEM;

	if (pgt_ops->pgt_entry_huge(ptep)) {
		u64 prot = pgt_ops->pgt_entry_to_prot(ptep);

		prot = pkvm_mkstate(prot, pkvm_getstate(*(u64 *)ptep));

		/*
		 * Split the large mapping and reuse the
		 * large mapping's prot. The translation
		 * doesn't have a change, so no need to
		 * flush tlb.
		 */
		mm_ops->put_page(ptep);
		pgtable_split(pgt_ops, mm_ops, ALIGN_DOWN(vaddr, size),
			      pgt_ops->pgt_entry_to_phys(ptep),
			      size, page, level - 1, prot);
	}

	mm_ops->get_page(ptep);
	pgtable_set_entry(pgt_ops, mm_ops, ptep, pgt->table_prot | mm_ops->virt_to_phys(page));

	return 0;
}

/*
 *TODO: support merging small entries to a large one.
 */
static int pgtable_map_cb(struct pkvm_pgtable *pgt, unsigned long vaddr,
			  unsigned long vaddr_end, int level, void *ptep,
			  unsigned long flags, struct pgt_flush_data *flush_data,
			  void *const arg)
{
	struct pkvm_pgtable_map_data *data = arg;

	switch(flags) {
	case PKVM_PGTABLE_WALK_LEAF:
		return pgtable_map_walk_leaf(pgt, vaddr, vaddr_end, level,
					     ptep, flags, flush_data, data);
	case PKVM_PGTABLE_WALK_TABLE_PRE:
	case PKVM_PGTABLE_WALK_TABLE_POST:
		break;
	}

	return -EINVAL;
}

/*
 * put_page_to_free_list(): the page added to the freelist should not be used
 * by any one as this page will be used as a node linked to the freelist.
 */
static inline void put_page_to_freelist(void *page, struct list_head *head)
{
	struct list_head *node = page;

	list_add_tail(node, head);
}

/*
 * get_page_to_free_list(): the page got from the freelist is valid to be used
 * again.
 */
static inline void *get_page_from_freelist(struct list_head *head)
{
	struct list_head *node = head->next;

	list_del(node);
	memset(node, 0, sizeof(struct list_head));

	return (void *)node;
}

static int pgtable_unmap_leaf(struct pkvm_pgtable *pgt, unsigned long vaddr,
			      int level, void *ptep, struct pgt_flush_data *flush_data,
			      void *const arg)
{
	struct pkvm_pgtable_unmap_data *data = arg;
	struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	struct pkvm_mm_ops *mm_ops = pgt->mm_ops;
	unsigned long size = page_level_size(level);

	if (data->phys != INVALID_ADDR) {
		unsigned long phys = pgt_ops->pgt_entry_to_phys(ptep);

		PKVM_ASSERT(phys == data->phys);
	}

	if (pgt_ops->pgt_entry_present(ptep))
		flush_data->flushtlb |= true;

	pgtable_set_entry(pgt_ops, mm_ops, ptep, pgt_ops->default_prot);
	mm_ops->put_page(ptep);

	if (data->phys != INVALID_ADDR) {
		data->phys = ALIGN_DOWN(data->phys, size);
		data->phys += size;
	}

	return 0;
}

static void pgtable_free_child(struct pkvm_pgtable *pgt, void *ptep,
			    struct pgt_flush_data *flush_data)
{
	struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	struct pkvm_mm_ops *mm_ops = pgt->mm_ops;
	void *child_ptep;

	/*
	 * Check the child pte page refcount. Put the child pte page if
	 * no one else is using it.
	 */
	child_ptep = mm_ops->phys_to_virt(pgt_ops->pgt_entry_to_phys(ptep));
	if (mm_ops->page_count(child_ptep) == 1) {
		pgtable_set_entry(pgt_ops, mm_ops, ptep, pgt_ops->default_prot);
		mm_ops->put_page(ptep);
		put_page_to_freelist(child_ptep, &flush_data->free_list);
	}
}

static int pgtable_unmap_cb(struct pkvm_pgtable *pgt, unsigned long vaddr,
			    unsigned long vaddr_end, int level, void *ptep,
			    unsigned long flags, struct pgt_flush_data *flush_data,
			    void *const arg)
{
	struct pkvm_pgtable_unmap_data *data = arg;
	struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	struct pkvm_mm_ops *mm_ops = pgt->mm_ops;
	unsigned long size = page_level_size(level);

	if (!pgt_ops->pgt_entry_mapped(ptep))
		/* Nothing to do if the entry is not mapped */
		return 0;

	/*
	 * Unmap the page if the target address range belongs a
	 * - 4K PTE entry
	 * - huge page and don't need to split it
	 * - a full huge page
	 */
	if (level == PG_LEVEL_4K || (pgt_ops->pgt_entry_huge(ptep) &&
		(!data->split_huge_page || leaf_mapping_valid(pgt_ops, vaddr,
			vaddr_end, 1 << level, level)))) {

		if (data->unmap_leaf_override) {
			vaddr = ALIGN_DOWN(vaddr, pgt_ops->pgt_level_to_size(level));
			return data->unmap_leaf_override(pgt, vaddr, level, ptep,
							 flush_data, data);
		} else
			return pgtable_unmap_leaf(pgt, vaddr, level, ptep,
						  flush_data, data);
	}

	if (pgt_ops->pgt_entry_huge(ptep)) {
		/*
		 * if it is huge pte, split and goto next level.
		 */
		u64 prot = pgt_ops->pgt_entry_to_prot(ptep);
		void *page = mm_ops->zalloc_page();

		if (!page)
			return -ENOMEM;

		prot = pkvm_mkstate(prot, pkvm_getstate(*(u64 *)ptep));
		/*
		 * Split the large mapping and reuse the
		 * large mapping's prot. The translation
		 * doesn't have a change, so no need to
		 * flush tlb.
		 */
		pgtable_split(pgt_ops, mm_ops, ALIGN_DOWN(vaddr, size),
			      pgt_ops->pgt_entry_to_phys(ptep),
			      size, page, level - 1, prot);
		pgtable_set_entry(pgt_ops, mm_ops, ptep,
				pgt->table_prot | mm_ops->virt_to_phys(page));
		return 0;
	}

	/* if not huge entry then means it is table entry */
	pgtable_free_child(pgt, ptep, flush_data);
	return 0;
}

static int pgtable_lookup_cb(struct pkvm_pgtable *pgt,
			    unsigned long aligned_vaddr,
			    unsigned long aligned_vaddr_end,
			    int level,
			    void *ptep,
			    unsigned long flags,
			    struct pgt_flush_data *flush_data,
			    void *const arg)
{
	struct pkvm_pgtable_lookup_data *data = arg;
	struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	u64 pte = atomic64_read((atomic64_t *)ptep);

	data->phys = INVALID_ADDR;
	data->prot = 0;
	data->level = level;

	/*
	 * This cb shall only be called for leaf. If now it is not a leaf
	 * that means the pte is changed by others, and we shall re-walk the pgtable
	 */
	if (unlikely(!pgt_ops->pgt_entry_is_leaf(&pte, level)))
		return -EAGAIN;

	if (pgt_ops->pgt_entry_present(&pte)) {
		unsigned long offset =
			data->vaddr & ~pgt_ops->pgt_level_page_mask(level);

		data->phys = pgt_ops->pgt_entry_to_phys(&pte) + offset;
		data->prot = pgt_ops->pgt_entry_to_prot(&pte);
	}

	return PGTABLE_WALK_DONE;
}

static int pgtable_free_leaf(struct pkvm_pgtable *pgt,
			     struct pgt_flush_data *flush_data,
			     void *ptep)
{
	if (pgt->pgt_ops->pgt_entry_mapped(ptep)) {
		if (pgt->pgt_ops->pgt_entry_present(ptep))
			flush_data->flushtlb |= true;
		pgt->mm_ops->put_page(ptep);
	}

	return 0;
}

static int pgtable_free_cb(struct pkvm_pgtable *pgt,
			    unsigned long vaddr,
			    unsigned long vaddr_end,
			    int level,
			    void *ptep,
			    unsigned long flags,
			    struct pgt_flush_data *flush_data,
			    void *const arg)
{
	struct pkvm_pgtable_free_data *data = arg;
	struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;

	if (pgt_ops->pgt_entry_is_leaf(ptep, level)) {
		if (data->free_leaf_override)
			return data->free_leaf_override(pgt, vaddr, level, ptep,
							flush_data, data);
		else
			return pgtable_free_leaf(pgt, flush_data, ptep);
	}

	/* Free the child page */
	pgtable_free_child(pgt, ptep, flush_data);
	return 0;
}

static int _pgtable_walk(struct pgt_walk_data *data, void *ptep, int level);
static int pgtable_visit(struct pgt_walk_data *data, void *ptep, int level)
{
	struct pkvm_pgtable_ops *pgt_ops = data->pgt->pgt_ops;
	struct pkvm_mm_ops *mm_ops = data->pgt->mm_ops;
	struct pkvm_pgtable_walker *walker = data->walker;
	unsigned long flags = walker->flags;
	bool leaf = pgt_ops->pgt_entry_is_leaf(ptep, level);
	void *child_ptep;
	int ret = 0;

	if (!leaf && (flags & PKVM_PGTABLE_WALK_TABLE_PRE))
		ret = walker->cb(data->pgt, data->vaddr, data->vaddr_end,
				 level, ptep, PKVM_PGTABLE_WALK_TABLE_PRE,
				 &data->flush_data, walker->arg);

	if (leaf && (flags & PKVM_PGTABLE_WALK_LEAF)) {
		ret = walker->cb(data->pgt, data->vaddr, data->vaddr_end,
				 level, ptep, PKVM_PGTABLE_WALK_LEAF,
				 &data->flush_data, walker->arg);
		leaf = pgt_ops->pgt_entry_is_leaf(ptep, level);
	}

	if (ret)
		return ret;

	if (leaf) {
		unsigned long size = pgt_ops->pgt_level_to_size(level);
		data->vaddr = ALIGN_DOWN(data->vaddr, size);
		data->vaddr += size;
		return ret;
	}

	child_ptep = mm_ops->phys_to_virt(pgt_ops->pgt_entry_to_phys(ptep));
	ret = _pgtable_walk(data, child_ptep, level - 1);
	if (ret)
		return ret;

	if (flags & PKVM_PGTABLE_WALK_TABLE_POST)
		ret = walker->cb(data->pgt, data->vaddr, data->vaddr_end,
				 level, ptep, PKVM_PGTABLE_WALK_TABLE_POST,
				 &data->flush_data, walker->arg);

	return ret;
}

static int _pgtable_walk(struct pgt_walk_data *data, void *ptep, int level)
{
	struct pkvm_pgtable_ops *pgt_ops = data->pgt->pgt_ops;
	int entries = pgt_ops->pgt_level_to_entries(level);
	int entry_size = pgt_ops->pgt_level_entry_size(level);
	int idx = pgt_ops->pgt_entry_to_index(data->vaddr, level);
	int ret;

	for (; idx < entries; idx++) {
		if (data->vaddr >= data->vaddr_end)
			break;

		ret = pgtable_visit(data, (ptep + idx * entry_size), level);
		if (ret)
			return ret;
	}

	return 0;
}

int pgtable_walk(struct pkvm_pgtable *pgt, unsigned long vaddr,
			unsigned long size, bool page_aligned,
			struct pkvm_pgtable_walker *walker)
{
	unsigned long aligned_vaddr =
		page_aligned ? ALIGN_DOWN(vaddr, PAGE_SIZE) : vaddr;
	unsigned long aligned_size =
		page_aligned ? ALIGN(size, PAGE_SIZE) : size;
	struct pgt_walk_data data = {
		.pgt = pgt,
		.flush_data = {
			.flushtlb = false,
			.free_list = LIST_HEAD_INIT(data.flush_data.free_list),
		},
		.vaddr = aligned_vaddr,
		.vaddr_end = aligned_vaddr + aligned_size,
		.walker = walker,
	};
	struct pkvm_mm_ops *mm_ops = pgt->mm_ops;
	int ret;

	if (!size || data.vaddr == data.vaddr_end)
		return 0;

	ret = _pgtable_walk(&data, mm_ops->phys_to_virt(pgt->root_pa), pgt->level);

	if (data.flush_data.flushtlb || !list_empty(&data.flush_data.free_list))
		pgt->mm_ops->flush_tlb(pgt);

	while (!list_empty(&data.flush_data.free_list)) {
		void *page = get_page_from_freelist(&data.flush_data.free_list);

		pgt->mm_ops->put_page(page);
	}

	return ret;
}

int pkvm_pgtable_init(struct pkvm_pgtable *pgt,
			     struct pkvm_mm_ops *mm_ops,
			     struct pkvm_pgtable_ops *pgt_ops,
			     struct pkvm_pgtable_cap *cap,
			     bool alloc_root)
{
	void *root;

	if (!mm_ops || !pgt_ops || !cap)
		return -EINVAL;

	if (alloc_root && mm_ops->zalloc_page) {
		root = mm_ops->zalloc_page();
		if (!root)
			return -ENOMEM;
		pgt->root_pa = __pkvm_pa(root);
	}

	pgt->mm_ops = mm_ops;
	pgt->pgt_ops = pgt_ops;
	pgt->level = cap->level;
	pgt->allowed_pgsz = cap->allowed_pgsz;
	pgt->table_prot = cap->table_prot;

	return 0;
}

static int __pkvm_pgtable_map(struct pkvm_pgtable *pgt, unsigned long vaddr_start,
			      unsigned long phys, unsigned long size,
			      int pgsz_mask, u64 prot, pgtable_leaf_ov_fn_t map_leaf,
			      u64 annotation)
{
	struct pkvm_pgtable_map_data data = {
		.phys = phys,
		.annotation = annotation,
		.prot = prot,
		.pgsz_mask = pgsz_mask ? pgt->allowed_pgsz & pgsz_mask :
					 pgt->allowed_pgsz,
		.map_leaf_override = map_leaf,
	};
	struct pkvm_pgtable_walker walker = {
		.cb = pgtable_map_cb,
		.arg = &data,
		.flags = PKVM_PGTABLE_WALK_LEAF,
	};

	return pgtable_walk(pgt, vaddr_start, size, true, &walker);
}

int pkvm_pgtable_map(struct pkvm_pgtable *pgt, unsigned long vaddr_start,
		     unsigned long phys_start, unsigned long size,
		     int pgsz_mask, u64 prot, pgtable_leaf_ov_fn_t map_leaf)
{
	return __pkvm_pgtable_map(pgt, vaddr_start, ALIGN_DOWN(phys_start, PAGE_SIZE),
				  size, pgsz_mask, prot, map_leaf, 0);
}

int pkvm_pgtable_unmap(struct pkvm_pgtable *pgt, unsigned long vaddr_start,
		       unsigned long size, pgtable_leaf_ov_fn_t unmap_leaf)
{
	struct pkvm_pgtable_unmap_data data = {
		.phys = INVALID_ADDR,
		.split_huge_page = true,
		.unmap_leaf_override = unmap_leaf,
	};
	struct pkvm_pgtable_walker walker = {
		.cb = pgtable_unmap_cb,
		.arg = &data,
		.flags = PKVM_PGTABLE_WALK_LEAF | PKVM_PGTABLE_WALK_TABLE_POST,
	};

	return pgtable_walk(pgt, vaddr_start, size, true, &walker);
}

int pkvm_pgtable_unmap_safe(struct pkvm_pgtable *pgt, unsigned long vaddr_start,
			    unsigned long phys_start, unsigned long size,
			    pgtable_leaf_ov_fn_t unmap_leaf)
{
	struct pkvm_pgtable_unmap_data data = {
		.phys = ALIGN_DOWN(phys_start, PAGE_SIZE),
		.split_huge_page = true,
		.unmap_leaf_override = unmap_leaf,
	};
	struct pkvm_pgtable_walker walker = {
		.cb = pgtable_unmap_cb,
		.arg = &data,
		.flags = PKVM_PGTABLE_WALK_LEAF | PKVM_PGTABLE_WALK_TABLE_POST,
	};

	return pgtable_walk(pgt, vaddr_start, size, true, &walker);
}

int pkvm_pgtable_unmap_nosplit(struct pkvm_pgtable *pgt, unsigned long vaddr_start,
		       unsigned long size, pgtable_leaf_ov_fn_t unmap_leaf)
{
	struct pkvm_pgtable_unmap_data data = {
		.phys = INVALID_ADDR,
		.split_huge_page = false,
		.unmap_leaf_override = unmap_leaf,
	};
	struct pkvm_pgtable_walker walker = {
		.cb = pgtable_unmap_cb,
		.arg = &data,
		.flags = PKVM_PGTABLE_WALK_LEAF | PKVM_PGTABLE_WALK_TABLE_POST,
	};

	return pgtable_walk(pgt, vaddr_start, size, true, &walker);
}

void pkvm_pgtable_lookup(struct pkvm_pgtable *pgt, unsigned long vaddr,
		     unsigned long *pphys, u64 *pprot, int *plevel)
{
	struct pkvm_pgtable_lookup_data data = {
		.vaddr = vaddr,
	};
	struct pkvm_pgtable_walker walker = {
		.cb = pgtable_lookup_cb,
		.arg = &data,
		.flags = PKVM_PGTABLE_WALK_LEAF,
	};
	int ret, retry_cnt = 0;

retry:
	ret = pgtable_walk(pgt, vaddr, PAGE_SIZE, true, &walker);
	if ((ret == -EAGAIN) && (retry_cnt++ < 5))
		goto retry;

	if (pphys)
		*pphys = data.phys;
	if (pprot)
		*pprot = data.prot;
	if (plevel)
		*plevel = data.level;
}

void pkvm_pgtable_destroy(struct pkvm_pgtable *pgt, pgtable_leaf_ov_fn_t free_leaf)
{
	unsigned long size;
	void *virt_root;
	struct pkvm_pgtable_ops *pgt_ops;
	struct pkvm_pgtable_free_data data = {
		.free_leaf_override = free_leaf,
	};
	struct pkvm_pgtable_walker walker = {
		.cb 	= pgtable_free_cb,
		.arg 	= &data,
		.flags 	= PKVM_PGTABLE_WALK_LEAF | PKVM_PGTABLE_WALK_TABLE_POST,
	};

	pgt_ops = pgt->pgt_ops;
	size = pgt_ops->pgt_level_to_size(pgt->level + 1);

	pgtable_walk(pgt, 0, size, true, &walker);
	virt_root = pgt->mm_ops->phys_to_virt(pgt->root_pa);
	pgt->mm_ops->put_page(virt_root);
}

/*
 * pkvm_pgtable_annotate() - Unmap and annotate pages to track ownership.
 * @annotation:		The value stored in the invalid pte.
 * 			@annotation[2:0] must be 0.
 */
int pkvm_pgtable_annotate(struct pkvm_pgtable *pgt, unsigned long addr,
			  unsigned long size, u64 annotation)
{
	if (pgt->pgt_ops->pgt_entry_present(&annotation))
		return -EINVAL;

	return __pkvm_pgtable_map(pgt, addr, INVALID_ADDR,
				  size, 1 << PG_LEVEL_4K, 0,
				  NULL, annotation);
}

static int pgtable_sync_map_cb(struct pkvm_pgtable *pgt, unsigned long vaddr,
			       unsigned long vaddr_end, int level, void *ptep,
			       unsigned long flags, struct pgt_flush_data *flush_data,
			       void *const arg)
{
	struct pkvm_pgtable_ops *pgt_ops = pgt->pgt_ops;
	struct pkvm_pgtable_sync_data *data = arg;
	unsigned long phys;
	unsigned long size;
	u64 prot;

	if (!pgt->pgt_ops->pgt_entry_present(ptep))
		return 0;

	phys = pgt_ops->pgt_entry_to_phys(ptep);
	size = pgt_ops->pgt_level_to_size(level);
	if (data->prot_override)
		prot = *data->prot_override;
	else
		prot = pgt_ops->pgt_entry_to_prot(ptep);

	return pkvm_pgtable_map(data->dest_pgt, vaddr, phys,
				size, 0, prot, data->map_leaf_override);
}

/*
 * pkvm_pgtable_sync_map() - map the destination pgtable_pgt according to the source
 * pgtable_pgt, with the same phys address and desired property bits.
 *
 * @src:	source pgtable_pgt.
 * @dest:	destination pgtable_pgt.
 * @prot:	desired property bits. Can be NULL if use the same property
 *		bits as the source pgtable_pgt
 * @map_leaf:	function to map the leaf entry for destination pgtable_pgt.
 */
int pkvm_pgtable_sync_map(struct pkvm_pgtable *src, struct pkvm_pgtable *dest,
			  u64 *prot, pgtable_leaf_ov_fn_t map_leaf)
{
	struct pkvm_pgtable_sync_data data = {
		.dest_pgt = dest,
		.prot_override = prot,
		.map_leaf_override = map_leaf,
	};
	struct pkvm_pgtable_walker walker = {
		.cb = pgtable_sync_map_cb,
		.flags = PKVM_PGTABLE_WALK_LEAF,
		.arg = &data,
	};
	unsigned long size = src->pgt_ops->pgt_level_to_size(src->level + 1);

	return pgtable_walk(src, 0, size, true, &walker);
}
