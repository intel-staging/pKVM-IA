// SPDX-License-Identifier: GPL-2.0
#include <asm/kvm_pkvm.h>
#include "gsmi.h"
#include "init.h"
#include "memory.h"

bool gsmi_present;
u16 smi_command_port;
phys_addr_t pkvm_gsmi_mem_base;
phys_addr_t pkvm_gsmi_mem_size;

static DEFINE_PER_CPU(union pkvm_gsmi_bounce_buf *, bounce_ptr);

static u16 gsmi_write(u8 subcmd, u32 param)
{
	u16 cmd = (subcmd << 8) | GSMI_CALLBACK;
	u16 result;

	/*
	 * See gsmi_exec() in drivers/firmware/google/gsmi.c for reference.
	 *
	 * Only support the GSMI_HANDSHAKE_NONE protocol, as that is what
	 * coreboot implements.
	 */
	asm volatile(
		"outb %%al, %%dx\n"
		: "=a" (result)
		: "0" (cmd),
		  "d" (smi_command_port),
		  "b" (param)
		: "memory", "cc"
		);

	return result;
}

int pkvm_init_gsmi(void)
{
	struct pkvm_pcpu *pcpu;
	int i;

	if (!gsmi_present)
		return 0;

	for_each_pkvm_pcpu(i, pcpu) {
		unsigned long offset = i * sizeof(union pkvm_gsmi_bounce_buf);

		if (offset + sizeof(union pkvm_gsmi_bounce_buf) > pkvm_gsmi_mem_size)
			return -ENOMEM;

		per_cpu(bounce_ptr, pcpu->cpu) = __pkvm_va(pkvm_gsmi_mem_base + offset);
	}

	return 0;
}

void pkvm_handle_gsmi(struct kvm_vcpu *vcpu)
{
	u8 subcmd = (vcpu->arch.regs[VCPU_REGS_RAX] >> 8) & 0xff;
	u32 param = vcpu->arch.regs[VCPU_REGS_RBX];
	u16 ret = GSMI_INVALID_PARAMETER;

	switch (subcmd) {
	case GSMI_CMD_SET_EVENT_LOG: {
		struct gsmi_set_eventlog_param *sel, *bounce_sel;
		struct gsmi_log_entry_type_1 *type1, *bounce_type1;
		u32 data_ptr, data_len, type;

		sel = __pkvm_va(param);
		bounce_sel = &this_cpu_read(bounce_ptr)->set_eventlog;

		if (pkvm_host_share_hyp(param, sizeof(*sel)))
			break;
		data_ptr = READ_ONCE(sel->data_ptr);
		data_len = READ_ONCE(sel->data_len);
		type = READ_ONCE(sel->type);
		pkvm_host_unshare_hyp(param, sizeof(*sel));

		if (type != 1) {
			ret = GSMI_UNSUPPORTED;
			break;
		}

		if (!data_ptr || data_len != sizeof(*type1))
			break;

		type1 = __pkvm_va(data_ptr);
		bounce_type1 = &this_cpu_read(bounce_ptr)->log_entry;

		if (pkvm_host_share_hyp(data_ptr, sizeof(*type1)))
			break;
		memcpy(bounce_type1, type1, sizeof(*type1));
		pkvm_host_unshare_hyp(data_ptr, sizeof(*type1));

		bounce_sel->data_ptr = __pkvm_pa(bounce_type1);
		bounce_sel->data_len = data_len;
		bounce_sel->type = type;

		ret = gsmi_write(subcmd, __pkvm_pa(bounce_sel));
		break;
	}
	case GSMI_CMD_CLEAR_EVENT_LOG: {
		struct gsmi_clear_eventlog_param *cel, *bounce_cel;

		cel = __pkvm_va(param);
		bounce_cel = &this_cpu_read(bounce_ptr)->clear_eventlog;

		if (pkvm_host_share_hyp(param, sizeof(*cel)))
			break;
		memcpy(bounce_cel, cel, sizeof(*cel));
		pkvm_host_unshare_hyp(param, sizeof(*cel));

		ret = gsmi_write(subcmd, __pkvm_pa(bounce_cel));
		break;
	}
	case GSMI_CMD_LOG_S0IX_SUSPEND:
	case GSMI_CMD_LOG_S0IX_RESUME:
		ret = gsmi_write(subcmd, 0);
		break;
	case GSMI_CMD_HANDSHAKE_TYPE:
		ret = GSMI_HANDSHAKE_NONE;
		break;
	default:
		ret = GSMI_UNSUPPORTED;
		break;
	}

	vcpu->arch.regs[VCPU_REGS_RAX] = ret;
}
