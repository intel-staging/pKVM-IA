/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PKVM_BUDDY_MEMORY_H
#define __PKVM_BUDDY_MEMORY_H

#include <asm/kvm_pkvm.h>
#include <asm/page.h>

#include <linux/types.h>

struct pkvm_page {
	unsigned short refcount;
	unsigned short order;
};

extern u64 __pkvm_vmemmap;
#define pkvm_vmemmap ((struct pkvm_page *)__pkvm_vmemmap)

#define pkvm_phys_to_pfn(phys)	((phys) >> PAGE_SHIFT)
#define pkvm_pfn_to_phys(pfn)	((phys_addr_t)((pfn) << PAGE_SHIFT))
#define pkvm_phys_to_page(phys)	(&pkvm_vmemmap[pkvm_phys_to_pfn(phys)])
#define pkvm_virt_to_page(virt)	pkvm_phys_to_page(__pkvm_pa(virt))
#define pkvm_virt_to_pfn(virt)	pkvm_phys_to_pfn(__pkvm_pa(virt))

#define pkvm_page_to_pfn(page)	((struct pkvm_page *)(page) - pkvm_vmemmap)
#define pkvm_page_to_phys(page)  pkvm_pfn_to_phys((pkvm_page_to_pfn(page)))
#define pkvm_page_to_virt(page)	__pkvm_va(pkvm_page_to_phys(page))
#define pkvm_page_to_pool(page)	(((struct pkvm_page *)page)->pool)

static inline int pkvm_page_count(void *addr)
{
	struct pkvm_page *p = pkvm_virt_to_page(addr);

	return p->refcount;
}

#endif /* __PKVM_BUDDY_MEMORY_H */
