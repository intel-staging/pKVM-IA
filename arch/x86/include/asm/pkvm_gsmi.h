/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_PKVM_GSMI_H
#define _ASM_X86_KVM_PKVM_GSMI_H

#include <linux/cpumask.h>
#include <linux/types.h>

/*
 * Copied from drivers/firmware/google/gsmi.c. See also
 * src/drivers/elog/gsmi.c in coreboot.
 */
#define GSMI_CALLBACK			0xef
#define GSMI_CMD_HANDSHAKE_TYPE		0xc1
#define GSMI_HANDSHAKE_NONE		0x7f

struct gsmi_set_eventlog_param {
	u32	data_ptr;
	u32	data_len;
	u32	type;
} __packed;

struct gsmi_log_entry_type_1 {
	u16	type;
	u32	instance;
} __packed;

struct gsmi_clear_eventlog_param {
	u32	percentage;
	u32	data_type;
} __packed;

union pkvm_gsmi_bounce_buf {
	struct {
		struct gsmi_set_eventlog_param set_eventlog;
		struct gsmi_log_entry_type_1 log_entry;
	};
	struct gsmi_clear_eventlog_param clear_eventlog;
};

static inline unsigned long pkvm_gsmi_pages(void)
{
	unsigned long size = sizeof(union pkvm_gsmi_bounce_buf) * num_possible_cpus();

	return PAGE_ALIGN(size) >> PAGE_SHIFT;
}

#endif /* _ASM_X86_KVM_PKVM_GSMI_H */
