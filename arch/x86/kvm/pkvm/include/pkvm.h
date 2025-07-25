/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_H_
#define __PKVM_H_

#include <vmx/vmx.h>

#define PKVM_STACK_SIZE		SZ_16K

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

#define PKVM_PAGES (ALIGN(sizeof(struct pkvm_hyp), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_EXTRA_PAGES 2 /*io_bitmap(A + B) */
#define PKVM_GLOBAL_PAGES (PKVM_PAGES + PKVM_EXTRA_PAGES)
#define PKVM_PCPU_PAGES (ALIGN(sizeof(struct pkvm_pcpu), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_HOST_VCPU_PAGES (ALIGN(sizeof(struct pkvm_host_vcpu), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_HOST_VCPU_VMCS_PAGES 3 /*vmxarea+vmcs+msr_bitmap*/
#define PKVM_PERCPU_PAGES (PKVM_PCPU_PAGES + PKVM_HOST_VCPU_PAGES + \
			   PKVM_HOST_VCPU_VMCS_PAGES)

void *pkvm_early_alloc_contig(unsigned int nr_pages);
void *pkvm_early_alloc_page(void);
void pkvm_early_alloc_init(void *virt, unsigned long size);

#endif
