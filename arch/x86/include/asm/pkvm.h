/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PKVM_H
#define _ASM_X86_PKVM_H

#include <linux/init.h>

#ifdef CONFIG_PKVM_INTEL

#ifndef __PKVM_HYP__
extern bool __read_mostly enable_pkvm;	/* kernel command-line flag */
#endif

#endif

#endif
