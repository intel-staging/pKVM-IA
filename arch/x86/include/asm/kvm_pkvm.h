/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_PKVM_H
#define _ASM_X86_KVM_PKVM_H

#ifdef CONFIG_PKVM_X86
#include <linux/memblock.h>
#include <linux/mm.h>
#include <asm/desc.h>
#include <asm/kvm_para.h>
#include <asm/pkvm_image.h>

#define PKVM_MEMBLOCK_REGIONS		128
#define PKVM_STACK_SIZE			SZ_16K
/* Size of reserved space for private parameter in pKVM stack */
#define PKVM_STACK_TOP_RESV		16
#define PKVM_PGTABLE_MAX_LEVELS		5

struct idt_page {
	gate_desc idt[IDT_ENTRIES];
} __aligned(PAGE_SIZE);

struct pkvm_pcpu {
	u8 stack[PKVM_STACK_SIZE] __aligned(16);
	struct gdt_page gdt_page;
	struct idt_page idt_page;
	struct tss_struct tss;
};

struct pkvm_hyp {
	int num_cpus;
	struct pkvm_pcpu *pcpus[CONFIG_NR_CPUS];
	struct kvm *host_kvm;
	struct kvm_vcpu *host_vcpus[CONFIG_NR_CPUS];
};

#define PKVM_HYP_PAGES		(PAGE_ALIGN(sizeof(struct pkvm_hyp)) >> PAGE_SHIFT)
#define PKVM_PCPU_PAGES		(PAGE_ALIGN(sizeof(struct pkvm_pcpu)) >> PAGE_SHIFT)

enum pkvm_mem_type {
	PKVM_RESERVED_UNUSED_MEMORY,
	PKVM_TEXT_DATA,
};

struct pkvm_mem_info {
	enum pkvm_mem_type type;
	unsigned long va;
	unsigned long pa;
	unsigned long size;
	u64 prot;
};

enum pkvm_hc {
	__pkvm__init_finalize,
};

#define __pkvm_hypercall_0(f)		kvm_hypercall4(f, 0, 0, 0, 0)
#define __pkvm_hypercall_1(f, p1)							\
	({										\
		kvm_hypercall4(f, (unsigned long)(p1), 0, 0, 0);			\
	})
#define __pkvm_hypercall_2(f, p1, p2)							\
	({										\
		kvm_hypercall4(f, (unsigned long)(p1), (unsigned long)(p2), 0, 0);	\
	})
#define __pkvm_hypercall_3(f, p1, p2, p3)						\
	({										\
		kvm_hypercall4(f, (unsigned long)(p1), (unsigned long)(p2),		\
			       (unsigned long)(p3), 0);					\
	})
#define __pkvm_hypercall_4(f, p1, p2, p3, p4)						\
	({										\
		kvm_hypercall4(f, (unsigned long)(p1), (unsigned long)(p2),		\
			       (unsigned long)(p3), (unsigned long)(p4));		\
	})
#define PKVM_HC(f)		CONCATENATE(__pkvm__, f)
#define pkvm_hypercall(f, ...)								\
	({										\
		CONCATENATE(__pkvm_hypercall_,						\
			    COUNT_ARGS(__VA_ARGS__))(PKVM_HC(f), ##__VA_ARGS__);	\
	})

extern unsigned long pkvm_sym(page_offset_base);
extern unsigned long pkvm_sym(phys_base);
extern struct pkvm_hyp *pkvm_sym(pkvm_hyp);
extern struct memblock_region pkvm_sym(pkvm_memory)[];
extern unsigned int pkvm_sym(pkvm_memblock_nr);
extern struct cpuinfo_x86 pkvm_sym(boot_cpu_data);
#ifdef CONFIG_DYNAMIC_PHYSICAL_MASK
extern phys_addr_t pkvm_sym(physical_mask);
#endif
extern pteval_t pkvm_sym(__default_kernel_pte_mask);
#ifdef CONFIG_AMD_MEM_ENCRYPT
extern u64 pkvm_sym(sme_me_mask);
#endif

u64 pkvm_total_reserve_pages(void);
PKVM_DECLARE(void *, pkvm_early_alloc_page, (void));
PKVM_DECLARE(void *, pkvm_early_alloc_contig, (unsigned int nr_pages));
PKVM_DECLARE(void, pkvm_early_alloc_init, (void *virt, unsigned long size));
PKVM_DECLARE(int, pkvm_setup_per_cpu, (int cpu, unsigned long base));
PKVM_DECLARE(unsigned int, pkvm_per_cpu_nr_pages, (void));
PKVM_DECLARE(unsigned long, pkvm_per_cpu_offset, (int cpu));
#define GEN(x, ...) PKVM_DECLARE(void, handle_exception_##x, (void));
#include <asm/GEN-for-each-exc.h>
#undef GEN

static inline unsigned long pkvm_data_pages(unsigned long extra_global,
					    unsigned long extra_percpu)
{
	unsigned long global_pages = PKVM_HYP_PAGES + extra_global;
	unsigned long percpu_pages = PKVM_PCPU_PAGES + extra_percpu +
				     pkvm_sym(pkvm_per_cpu_nr_pages)();

	return global_pages + percpu_pages * num_possible_cpus();
}

static inline unsigned long get_host_stack_top(struct pkvm_pcpu *pcpu)
{
	return (unsigned long) &pcpu->stack[sizeof(pcpu->stack)];
}

static inline unsigned long __pkvm_pgtable_max_pages(unsigned long nr_pages)
{
	unsigned long total = 0, i;

	/* Provision the worst case */
	for (i = 0; i < PKVM_PGTABLE_MAX_LEVELS; i++) {
		nr_pages = DIV_ROUND_UP(nr_pages, PTRS_PER_PTE);
		total += nr_pages;
	}

	return total;
}

static inline unsigned long __pkvm_pgtable_total_pages(void)
{
	unsigned long total = 0, i;

	for (i = 0; i < pkvm_sym(pkvm_memblock_nr); i++) {
		struct memblock_region *reg = &pkvm_sym(pkvm_memory)[i];

		total += __pkvm_pgtable_max_pages(reg->size >> PAGE_SHIFT);
	}

	return total;
}

static inline unsigned long pkvm_hyp_pgtable_pages(void)
{
	return __pkvm_pgtable_total_pages();
}

#endif /* CONFIG_PKVM_X86 */

#endif /* _ASM_X86_KVM_PKVM_H */
