/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_H_
#define __PKVM_H_

struct pkvm_hyp {
	int num_cpus;
};

#define PKVM_GLOBAL_PAGES (ALIGN(sizeof(struct pkvm_hyp), PAGE_SIZE) >> PAGE_SHIFT)
#define PKVM_PERCPU_PAGES 0

#endif
