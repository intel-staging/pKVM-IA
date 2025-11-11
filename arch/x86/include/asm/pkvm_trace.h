/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PKVM_TRACE_H
#define _ASM_X86_PKVM_TRACE_H

#include <asm/pkvm_spinlock.h>
#include <asm/vmx.h>

/*
 * TODO: the implementation of vmexit tracing is VMX-specific.
 * Make it generic.
 */
#define MAX_EXIT_REASONS	MAX_VMX_EXIT_REASONS

struct vmexit_stats {
	u64 count;
	u64 cycles;
};

struct perf_data {
	struct vmexit_stats vmexit_reasons[MAX_EXIT_REASONS];
	int vcpu_id;
};

struct vmexit_perf {
	pkvm_spinlock_t lock;
	struct perf_data data;
	unsigned long long tsc;
};

#endif /* _ASM_X86_PKVM_TRACE_H */
