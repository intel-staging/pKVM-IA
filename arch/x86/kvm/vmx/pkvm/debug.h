/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_DEBUG_H_
#define __PKVM_X86_DEBUG_H_

#ifdef CONFIG_PKVM_INTEL_DEBUG

void __pkvm___dynamic_pr_debug(struct _ddebug *descriptor, const char *fmt, ...);
int __pkvm__printk(const char *fmt, ...);
noinstr struct cpu_entry_area *__pkvm_get_cpu_entry_area(int cpu);
int __pkvm____ratelimit(struct ratelimit_state *rs, const char *func);
void __pkvm___warn_printk(const char *fmt, ...);

#endif

#endif /* __PKVM_X86_DEBUG_H */
