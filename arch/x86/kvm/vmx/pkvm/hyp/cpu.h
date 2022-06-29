// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef _PKVM_CPU_H_
#define _PKVM_CPU_H_

static inline u64 pkvm_msr_read(u32 reg)
{
	u32 msrl, msrh;

	asm volatile (" rdmsr ":"=a"(msrl), "=d"(msrh) : "c" (reg));
	return (((u64)msrh << 32U) | msrl);
}

#ifdef CONFIG_PKVM_INTEL_DEBUG
#include <linux/smp.h>
static inline u64 get_pcpu_id(void)
{
	return raw_smp_processor_id();
}
#else
/* this function shall only be used during pkvm runtime */
static inline u64 get_pcpu_id(void)
{
	return pkvm_msr_read(MSR_GS_BASE);
}
#endif

#endif
