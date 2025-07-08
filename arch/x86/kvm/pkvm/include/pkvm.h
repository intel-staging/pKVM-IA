/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_H_
#define __PKVM_H_

#include <asm/pkvm_image.h>
#include <vmx/vmx.h>

#define PKVM_STACK_SIZE		SZ_16K
/* Size of reserved space for private parameter in pkvm stack */
#define PKVM_STACK_TOP_RESV	16

struct pkvm_pcpu {
	u8 stack[PKVM_STACK_SIZE] __aligned(16);
};

struct pkvm_host_vcpu {
	struct vcpu_vmx vmx;
	struct pkvm_pcpu *pcpu;
	struct vmcs *vmxarea;
};

struct pkvm_host_vm {
	struct pkvm_host_vcpu *host_vcpus[CONFIG_NR_CPUS];
	u8 *io_bitmap;
};

struct pkvm_hyp {
	int num_cpus;
	struct vmcs_config vmcs_config;
	struct pkvm_pcpu *pcpus[CONFIG_NR_CPUS];
	struct pkvm_host_vm host_vm;
};

static inline struct pkvm_host_vcpu *vmx_to_host_vcpu(struct vcpu_vmx *vmx)
{
	return container_of(vmx, struct pkvm_host_vcpu, vmx);
}

static inline unsigned long get_host_stack_top(struct pkvm_pcpu *pcpu)
{
	return (unsigned long) &pcpu->stack[sizeof(pcpu->stack)];
}

#define PKVM_PAGES (ALIGN(sizeof(struct pkvm_hyp), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_EXTRA_PAGES 2 /*io_bitmap(A + B) */
#define PKVM_GLOBAL_PAGES (PKVM_PAGES + PKVM_EXTRA_PAGES)
#define PKVM_PCPU_PAGES (ALIGN(sizeof(struct pkvm_pcpu), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_HOST_VCPU_PAGES (ALIGN(sizeof(struct pkvm_host_vcpu), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_HOST_VCPU_VMCS_PAGES 3 /*vmxarea+vmcs+msr_bitmap*/
#define PKVM_PERCPU_PAGES (PKVM_PCPU_PAGES + PKVM_HOST_VCPU_PAGES + \
			   PKVM_HOST_VCPU_VMCS_PAGES + pkvm_sym(pkvm_per_cpu_nr_pages)())

PKVM_DECLARE(void *, pkvm_early_alloc_contig, (unsigned int nr_pages));
PKVM_DECLARE(void *, pkvm_early_alloc_page, (void));
PKVM_DECLARE(void, pkvm_early_alloc_init, (void *virt, unsigned long size));
PKVM_DECLARE(void, pkvm_host_vmexit_entry, (void));
PKVM_DECLARE(unsigned int, pkvm_per_cpu_nr_pages, (void));
PKVM_DECLARE(int, setup_pkvm_per_cpu, (int cpu, unsigned long base));
PKVM_DECLARE(unsigned long, pkvm_per_cpu_offset, (int cpu));

extern struct vmx_capability pkvm_sym(vmx_capability);
#ifdef CONFIG_DYNAMIC_MEMORY_LAYOUT
extern unsigned long pkvm_sym(page_offset_base);
#endif
extern unsigned long pkvm_sym(phys_base);

#endif
