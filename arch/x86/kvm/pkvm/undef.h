/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_UNDEF_H
#define __PKVM_X86_UNDEF_H

/*
 * Special hack: pKVM runs in the highest privilege level, which is higher than
 * the linux kernel. This means that pKVM cannot use any of the linux kernel
 * symbols. To make pKVM being able to use the linux kernel headers without
 * introducing additional symbols, some kernel configuration options are
 * disabled. (This list needs to be extended when new variants are added.)
 */
#undef CONFIG_CALL_THUNKS_DEBUG
#undef CONFIG_PRINTK
#undef CONFIG_PARAVIRT
#undef CONFIG_PARAVIRT_XXL
#undef CONFIG_PARAVIRT_SPINLOCKS

#if defined(CONFIG_ARCH_HAS_LAZY_MMU_MODE) && !defined(__ASSEMBLY__)
/*
 * CONFIG_PARAVIRT_XXL selects CONFIG_ARCH_HAS_LAZY_MMU_MODE and provides these
 * hooks. After CONFIG_PARAVIRT_XXL is undefined, the provided hooks are still
 * needed due to CONFIG_ARCH_HAS_LAZY_MMU_MODE is still selected. To preserve
 * task struct's layout, keep CONFIG_ARCH_HAS_LAZY_MMU_MODE defined but use
 * no-op hooks because pKVM has no paravirtualized lazy MMU backend.
 */
static inline void arch_enter_lazy_mmu_mode(void) {}
static inline void arch_leave_lazy_mmu_mode(void) {}
#endif

#define NOTRACE

/*
 * Avoid undefining the below options, as it would change the layout of some
 * of the kernel's data structures. Most importantly this applies to structs
 * that are shared between the host kernel and pKVM, e.g. struct kvm and
 * struct kvm_vcpu. They absolutely must have the same size and layout in the
 * host KVM and in pKVM.
 *
 * But even for structs that are not shared between host and pKVM, such as
 * task_struct or vm_area_struct, it is still better to avoid changing their
 * layout. For instance, with CONFIG_DEBUG_INFO_BTF enabled, if those structs
 * are different in the host and in pKVM, multiple BTF type IDs are generated
 * for them, and then the resolve_btfids tool warns about multiple IDs found
 * and uses just one of them when adding the needed debug info to the vmlinux,
 * and there is no guarantee that it will use the correct type ID, i.e. the
 * host's one, not the pKVM's one.
 *
 * The following can be used (with CONFIG_DEBUG_INFO_BTF=y) to inspect layouts
 * of structs in the kernel image, for checking if there are no multiple
 * layouts of the same struct caused by pKVM mangling the config options:
 *
 *     make -C tools/bpf/bpftool
 *     tools/bpf/bpftool/bpftool btf dump file vmlinux.unstripped
 */
/*
#undef CONFIG_BUG
#undef CONFIG_GENERIC_BUG
#undef CONFIG_TRACEPOINTS
*/

#endif /* __PKVM_X86_UNDEF_H */
