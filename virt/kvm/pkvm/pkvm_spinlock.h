/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 *
 * pkvm runs in a self-contained environment
 * and requires a self-contained spinlock implementation
 * which doesn't rely on any other external symbols.
 *
 * This is a common interface with wrapping the arch
 * specific implementation.
 * */
#ifndef __PKVM_SPINLOCK_H
#define __PKVM_SPINLOCK_H

#include <asm/pkvm_spinlock.h>

typedef struct pkvm_spinlock {
	arch_pkvm_spinlock_t 	pkvm_lock;
} pkvm_spinlock_t;

#define __PKVM_SPINLOCK_INITIALIZER 			\
	{ .pkvm_lock = __ARCH_PKVM_SPINLOCK_UNLOCKED }

#define __PKVM_SPINLOCK_UNLOCKED 			\
	((pkvm_spinlock_t) __PKVM_SPINLOCK_INITIALIZER)

#define pkvm_spinlock_init(l) 				\
do {							\
	*(l) = __PKVM_SPINLOCK_UNLOCKED;		\
} while (0);

static __always_inline void pkvm_spin_lock(pkvm_spinlock_t *lock)
{
	arch_pkvm_spin_lock(&lock->pkvm_lock);
}

static __always_inline void pkvm_spin_unlock(pkvm_spinlock_t *lock)
{
	arch_pkvm_spin_unlock(&lock->pkvm_lock);
}

static __always_inline void pkvm_assert_lock_held(pkvm_spinlock_t *lock)
{
	arch_pkvm_assert_lock_held(&lock->pkvm_lock);
}

#endif
