// SPDX-License-Identifier: GPL-2.0
#include <pkvm.h>
#include "vmsr.h"

int handle_read_msr(struct kvm_vcpu *vcpu)
{
	vcpu->arch.regs[VCPU_REGS_RAX] = 0;
	vcpu->arch.regs[VCPU_REGS_RDX] = 0;

	return 0;
}

int handle_write_msr(struct kvm_vcpu *vcpu)
{
	return 0;
}
