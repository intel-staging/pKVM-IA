// SPDX-License-Identifier: GPL-2.0
#include <linux/smp.h>
#include "kern_stub.h"

void warn_thunk_thunk(void) {}

#ifdef CONFIG_DEBUG_PREEMPT
unsigned int debug_smp_processor_id(void)
{
	return raw_smp_processor_id();
}

void __this_cpu_preempt_check(const char *op) {}
#endif
