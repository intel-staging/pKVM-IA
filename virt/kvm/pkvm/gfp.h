/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PKVM_GFP_H
#define __PKVM_GFP_H

#include <linux/mmzone.h>
#include <linux/list.h>

#include <buddy_memory.h>
#include <pkvm_spinlock.h>

#define PKVM_NO_ORDER	USHRT_MAX

struct pkvm_pool {
	/*
	 * Spinlock protecting concurrent changes to the memory pool as well as
	 * the struct pkvm_page of the pool's pages until we have a proper atomic
	 * API at hypervisor.
	 */
	pkvm_spinlock_t lock;
	struct list_head free_area[MAX_ORDER];
	phys_addr_t range_start;
	phys_addr_t range_end;
	unsigned short max_order;
};

/* Allocation */
void *pkvm_alloc_pages(struct pkvm_pool *pool, unsigned short order);
void pkvm_split_page(struct pkvm_page *page);
void pkvm_get_page(struct pkvm_pool *pool, void *addr);
void pkvm_put_page(struct pkvm_pool *pool, void *addr);

/* Used pages cannot be freed */
int pkvm_pool_init(struct pkvm_pool *pool, u64 pfn, unsigned int nr_pages,
		  unsigned int reserved_pages);
#endif /* __PKVM_GFP_H */
