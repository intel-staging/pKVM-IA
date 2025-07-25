/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_H_
#define __PKVM_H_

#include <vmx/vmx.h>

#define PKVM_STACK_SIZE		SZ_16K

struct pkvm_pcpu {
	u8 stack[PKVM_STACK_SIZE] __aligned(16);
};

struct pkvm_hyp {
	int num_cpus;
	struct vmcs_config vmcs_config;
	struct pkvm_pcpu *pcpus[CONFIG_NR_CPUS];
};

#define PKVM_PAGES (ALIGN(sizeof(struct pkvm_hyp), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_GLOBAL_PAGES PKVM_PAGES
#define PKVM_PCPU_PAGES (ALIGN(sizeof(struct pkvm_pcpu), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_PERCPU_PAGES PKVM_PCPU_PAGES

void *pkvm_early_alloc_contig(unsigned int nr_pages);
void pkvm_early_alloc_init(void *virt, unsigned long size);

#endif
