/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * A stand-alone ticket spinlock implementation for use by the non-VHE
 * KVM hypervisor code running at EL2.
 *
 * Copyright (C) 2020 Google LLC
 * Author: Will Deacon <will@kernel.org>
 *
 * Heavily based on the implementation removed by c11090474d70 which was:
 * Copyright (C) 2012 ARM Ltd.
 */

#ifndef __ASM_ARM64_PKVM_SPINLOCK_H__
#define __ASM_ARM64_PKVM_SPINLOCK_H__

#include <asm/alternative.h>
#include <asm/lse.h>
#include <asm/rwonce.h>

typedef union arch_pkvm_spinlock {
	u32	__val;
	struct {
#ifdef __AARCH64EB__
		u16 next, owner;
#else
		u16 owner, next;
#endif
	};
} arch_pkvm_spinlock_t;

#define __ARCH_PKVM_SPINLOCK_UNLOCKED	{ 0 }

static inline void arch_pkvm_spin_lock(arch_pkvm_spinlock_t *lock)
{
	u32 tmp;
	arch_pkvm_spinlock_t lockval, newval;

	asm volatile(
	/* Atomically increment the next ticket. */
	ARM64_LSE_ATOMIC_INSN(
	/* LL/SC */
"	prfm	pstl1strm, %3\n"
"1:	ldaxr	%w0, %3\n"
"	add	%w1, %w0, #(1 << 16)\n"
"	stxr	%w2, %w1, %3\n"
"	cbnz	%w2, 1b\n",
	/* LSE atomics */
"	mov	%w2, #(1 << 16)\n"
"	ldadda	%w2, %w0, %3\n"
	__nops(3))

	/* Did we get the lock? */
"	eor	%w1, %w0, %w0, ror #16\n"
"	cbz	%w1, 3f\n"
	/*
	 * No: spin on the owner. Send a local event to avoid missing an
	 * unlock before the exclusive load.
	 */
"	sevl\n"
"2:	wfe\n"
"	ldaxrh	%w2, %4\n"
"	eor	%w1, %w2, %w0, lsr #16\n"
"	cbnz	%w1, 2b\n"
	/* We got the lock. Critical section starts here. */
"3:"
	: "=&r" (lockval), "=&r" (newval), "=&r" (tmp), "+Q" (*lock)
	: "Q" (lock->owner)
	: "memory");
}

static inline void arch_pkvm_spin_unlock(arch_pkvm_spinlock_t *lock)
{
	u64 tmp;

	asm volatile(
	ARM64_LSE_ATOMIC_INSN(
	/* LL/SC */
	"	ldrh	%w1, %0\n"
	"	add	%w1, %w1, #1\n"
	"	stlrh	%w1, %0",
	/* LSE atomics */
	"	mov	%w1, #1\n"
	"	staddlh	%w1, %0\n"
	__nops(1))
	: "=Q" (lock->owner), "=&r" (tmp)
	:
	: "memory");
}

static inline bool arch_pkvm_spin_is_locked(arch_pkvm_spinlock_t *lock)
{
	arch_pkvm_spinlock_t lockval = READ_ONCE(*lock);

	return lockval.owner != lockval.next;
}

#ifdef CONFIG_NVHE_EL2_DEBUG
static inline void arch_pkvm_assert_lock_held(arch_pkvm_spinlock_t *lock)
{
	/*
	 * The __pkvm_init() path accesses protected data-structures without
	 * holding locks as the other CPUs are guaranteed to not enter EL2
	 * concurrently at this point in time. The point by which EL2 is
	 * initialized on all CPUs is reflected in the pkvm static key, so
	 * wait until it is set before checking the lock state.
	 */
	if (static_branch_likely(&kvm_protected_mode_initialized))
		BUG_ON(!arch_pkvm_spin_is_locked(lock));
}
#else
static inline void arch_pkvm_assert_lock_held(arch_pkvm_spinlock_t *lock) { }
#endif

#endif /* __ASM_ARM64_PKVM_SPINLOCK_H__ */
