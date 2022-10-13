/*
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 * Copyright (C) 2018-2022 Intel Corporation
 *
 * pkvm runs in a self-contained environment
 * and requires a self-contained spinlock implementation
 * which doesn't rely on any other external symbols.
 *
 * This is arch specific implementation
 * */
#ifndef _ASM_X86_PKVM_SPINLOCK_H
#define _ASM_X86_PKVM_SPINLOCK_H

#include <linux/types.h>

typedef struct arch_pkvm_spinlock {
	union {
		u64 head_tail;
		struct {
			u32 head;
			u32 tail;
		};
	};
} arch_pkvm_spinlock_t;

#define __ARCH_PKVM_SPINLOCK_UNLOCKED	{ { 0 } }

static inline void arch_pkvm_spin_lock(arch_pkvm_spinlock_t *lock)
{
	/* The lock function atomically increments and exchanges the head
	 * counter of the queue. If the old head of the queue is equal to the
	 * tail, we have locked the spinlock. Otherwise we have to wait.
	 */

	asm volatile ("   movl $0x1,%%eax\n"
		      "   lock xaddl %%eax,%[head]\n"
		      "   cmpl %%eax,%[tail]\n"
		      "   jz 1f\n"
		      "2: pause\n"
		      "   cmpl %%eax,%[tail]\n"
		      "   jnz 2b\n"
		      "1:\n"
		      :
		      :
		      [head] "m"(lock->head),
		      [tail] "m"(lock->tail)
		      : "cc", "memory", "eax");
}

static inline void arch_pkvm_spin_unlock(arch_pkvm_spinlock_t *lock)
{
	/* Increment tail of queue */
	asm volatile ("   lock incl %[tail]\n"
				:
				: [tail] "m" (lock->tail)
				: "cc", "memory");

}

static inline void arch_pkvm_assert_lock_held(arch_pkvm_spinlock_t *lock) { }

#endif
