/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_H_
#define __PKVM_H_

#include <vmx/vmx.h>

struct pkvm_hyp {
	int num_cpus;
	struct vmcs_config vmcs_config;
};

#define PKVM_PAGES (ALIGN(sizeof(struct pkvm_hyp), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_GLOBAL_PAGES PKVM_PAGES
#define PKVM_PERCPU_PAGES 0

void *pkvm_early_alloc_contig(unsigned int nr_pages);
void pkvm_early_alloc_init(void *virt, unsigned long size);

#endif
