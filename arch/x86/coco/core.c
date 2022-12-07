// SPDX-License-Identifier: GPL-2.0-only
/*
 * Confidential Computing Platform Capability checks
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/export.h>
#include <linux/cc_platform.h>

#include <asm/coco.h>
#include <asm/processor.h>

static enum cc_vendor vendor __ro_after_init;
static u64 cc_mask __ro_after_init;

static bool pkvm_cc_platform_has(enum cc_attr attr)
{
	/*
	 * Since primary VM can't access pkvm guest's memory, pkvm guest need
	 * explicitly share DMA buffer with primary VM to make virtio work. By
	 * using these attribute, pkvm guest will using bounce buffer for DMA
	 * operation, and share the bounce buffer with primary VM.
	 *
	 * CC_ATTR_GUEST_UNROLL_STRING_IO: Since string io cause KVM to do
	 * instruction decode, to avoid it, using this attribute will unroll the
	 * string io. For example, in <asm/io.h>, the definition of the outsb
	 * check to attribute to determine if using string io.
	 *
	 * CC_ATTR_GUEST_MEM_ENCRYPT: This attribute has been checked in the
	 * force_dma_unencrypted(). Which means all DMA buffer will be shared
	 * between pkvm guest and primary VM. And checked in
	 * pci_swiotlb_detect(), this makes pkvm guest using bounce buffer.
	 *
	 * CC_ATTR_MEM_ENCRYPT: This attribute has been checked in the
	 * mem_encrypt_init(). Which will make all bounce buffer being shared
	 * between pkvm guest and primary VM.
	 */
	switch (attr) {
	case CC_ATTR_GUEST_UNROLL_STRING_IO:
	case CC_ATTR_GUEST_MEM_ENCRYPT:
	case CC_ATTR_MEM_ENCRYPT:
		return true;
	default:
		return false;
	}
}

static bool intel_cc_platform_has(enum cc_attr attr)
{
	switch (attr) {
	case CC_ATTR_GUEST_UNROLL_STRING_IO:
	case CC_ATTR_HOTPLUG_DISABLED:
	case CC_ATTR_GUEST_MEM_ENCRYPT:
	case CC_ATTR_MEM_ENCRYPT:
		return true;
	default:
		return false;
	}
}

/*
 * SME and SEV are very similar but they are not the same, so there are
 * times that the kernel will need to distinguish between SME and SEV. The
 * cc_platform_has() function is used for this.  When a distinction isn't
 * needed, the CC_ATTR_MEM_ENCRYPT attribute can be used.
 *
 * The trampoline code is a good example for this requirement.  Before
 * paging is activated, SME will access all memory as decrypted, but SEV
 * will access all memory as encrypted.  So, when APs are being brought
 * up under SME the trampoline area cannot be encrypted, whereas under SEV
 * the trampoline area must be encrypted.
 */
static bool amd_cc_platform_has(enum cc_attr attr)
{
#ifdef CONFIG_AMD_MEM_ENCRYPT
	switch (attr) {
	case CC_ATTR_MEM_ENCRYPT:
		return sme_me_mask;

	case CC_ATTR_HOST_MEM_ENCRYPT:
		return sme_me_mask && !(sev_status & MSR_AMD64_SEV_ENABLED);

	case CC_ATTR_GUEST_MEM_ENCRYPT:
		return sev_status & MSR_AMD64_SEV_ENABLED;

	case CC_ATTR_GUEST_STATE_ENCRYPT:
		return sev_status & MSR_AMD64_SEV_ES_ENABLED;

	/*
	 * With SEV, the rep string I/O instructions need to be unrolled
	 * but SEV-ES supports them through the #VC handler.
	 */
	case CC_ATTR_GUEST_UNROLL_STRING_IO:
		return (sev_status & MSR_AMD64_SEV_ENABLED) &&
			!(sev_status & MSR_AMD64_SEV_ES_ENABLED);

	case CC_ATTR_GUEST_SEV_SNP:
		return sev_status & MSR_AMD64_SEV_SNP_ENABLED;

	default:
		return false;
	}
#else
	return false;
#endif
}

static bool hyperv_cc_platform_has(enum cc_attr attr)
{
	return attr == CC_ATTR_GUEST_MEM_ENCRYPT;
}

bool cc_platform_has(enum cc_attr attr)
{
	switch (vendor) {
	case CC_VENDOR_AMD:
		return amd_cc_platform_has(attr);
	case CC_VENDOR_INTEL:
		return intel_cc_platform_has(attr);
	case CC_VENDOR_HYPERV:
		return hyperv_cc_platform_has(attr);
	case CC_VENDOR_PKVM:
		return pkvm_cc_platform_has(attr);
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(cc_platform_has);

u64 cc_mkenc(u64 val)
{
	/*
	 * Both AMD and Intel use a bit in the page table to indicate
	 * encryption status of the page.
	 *
	 * - for AMD, bit *set* means the page is encrypted
	 * - for Intel *clear* means encrypted.
	 */
	switch (vendor) {
	case CC_VENDOR_AMD:
		return val | cc_mask;
	case CC_VENDOR_INTEL:
		return val & ~cc_mask;
	default:
		return val;
	}
}

u64 cc_mkdec(u64 val)
{
	/* See comment in cc_mkenc() */
	switch (vendor) {
	case CC_VENDOR_AMD:
		return val & ~cc_mask;
	case CC_VENDOR_INTEL:
		return val | cc_mask;
	default:
		return val;
	}
}
EXPORT_SYMBOL_GPL(cc_mkdec);

__init void cc_set_vendor(enum cc_vendor v)
{
	vendor = v;
}

__init void cc_set_mask(u64 mask)
{
	cc_mask = mask;
}
