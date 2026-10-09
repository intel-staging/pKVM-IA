// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/kvm_pkvm.h>
#include <asm/msr.h>
#include "vmx.h"

static int __init early_pkvm_parse_cmdline(char *buf)
{
	return kstrtobool(buf, &enable_pkvm);
}
early_param("kvm-intel.pkvm", early_pkvm_parse_cmdline);

unsigned long __init pkvm_vmx_reserve_pages(void)
{
	/* TODO: return the actual number of pages required by VMX */
	return 0;
}

int __init vmx_pkvm_init(void)
{
	if (!enable_pkvm)
		return 0;

	return -EOPNOTSUPP;
}

MODULE_LICENSE("GPL");
