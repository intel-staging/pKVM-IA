// SPDX-License-Identifier: GPL-2.0
#include <asm/pkvm.h>

__init void pkvm_guest_early_init(void)
{
	u32 sig;

	/*
	 * The convension with pkvm hypervisor to detect if guest is running on
	 * pkvm as a protected vm is:
	 *
	 * Use cpuid leaf=0x21, subleaf=0x0, and the return result will in eax,
	 * it's a string "pkvm".
	 */
	sig = cpuid_eax(0x21);

	if (memcmp("pkvm", &sig, sizeof(u32)))
		return;

	pr_info("pkvm guest detected\n");
}
