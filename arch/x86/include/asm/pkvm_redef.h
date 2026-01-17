/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_PKVM_REDEF_H
#define _ASM_X86_KVM_PKVM_REDEF_H

#ifdef __PKVM_HYP__

#ifndef CONFIG_PKVM_X86_DEBUG

#undef WARN_ON
#undef WARN
#undef WARN_ON_ONCE
#undef WARN_ONCE
#undef _BUG_FLAGS

#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})

#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	no_printk(format);						\
	unlikely(__ret_warn_on);					\
})

#define WARN_ON_ONCE(condition) WARN_ON(condition)
#define WARN_ONCE(condition, format...) WARN(condition, format)

#define _BUG_FLAGS(ins, flags, extra)  asm volatile(ins)

#endif /* CONFIG_PKVM_X86_DEBUG */

#endif /* __PKVM_HYP__ */

#endif /* _ASM_X86_KVM_PKVM_REDEF_H */
