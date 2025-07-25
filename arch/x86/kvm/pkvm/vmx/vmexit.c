// SPDX-License-Identifier: GPL-2.0
#include <linux/memblock.h>
#include <asm/kvm_pkvm.h>
#include <vmx/vmx.h>
#include <pkvm.h>
#include "vmexit.h"
#include "vmsr.h"

#define CR4			4
#define MOV_TO_CR		0

static void skip_emulated_instruction(void)
{
	unsigned long rip;

	rip = vmcs_readl(GUEST_RIP);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs_writel(GUEST_RIP, rip);
}

static void handle_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	eax = vcpu->arch.regs[VCPU_REGS_RAX];
	ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	native_cpuid(&eax, &ebx, &ecx, &edx);
	vcpu->arch.regs[VCPU_REGS_RAX] = eax;
	vcpu->arch.regs[VCPU_REGS_RBX] = ebx;
	vcpu->arch.regs[VCPU_REGS_RCX] = ecx;
	vcpu->arch.regs[VCPU_REGS_RDX] = edx;
}

static void handle_cr(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qual, val;
	int cr;
	int type;
	int reg;

	exit_qual = vmx->exit_qualification;
	cr = exit_qual & 15;
	type = (exit_qual >> 4)	& 3;
	reg = (exit_qual >> 8) & 15;

	switch (type) {
	case MOV_TO_CR:
		switch (cr) {
		case CR4:
			/*
			 * VMXE bit is owned by host, others are owned by guest
			 * So only when guest is trying to modify VMXE bit it
			 * can cause vmexit and get here.
			 */
			val = vcpu->arch.regs[reg];
			vmcs_writel(CR4_READ_SHADOW, val);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}

static void handle_xsetbv(struct kvm_vcpu *vcpu)
{
	u32 eax = (u32)(vcpu->arch.regs[VCPU_REGS_RAX] & -1u);
	u32 edx = (u32)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u);
	u32 ecx = (u32)(vcpu->arch.regs[VCPU_REGS_RCX] & -1u);

	asm volatile(".byte 0x0f,0x01,0xd1"
			: : "a" (eax), "d" (edx), "c" (ecx));
}

static void handle_irq_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 cpu_based_exec_ctrl = exec_controls_get(vmx);

	exec_controls_set(vmx, cpu_based_exec_ctrl & ~CPU_BASED_INTR_WINDOW_EXITING);
}

static void handle_pending_events(struct kvm_vcpu *vcpu)
{
	struct pkvm_host_vcpu *hvcpu = vmx_to_host_vcpu(to_vmx(vcpu));

	if (!is_guest_mode(vcpu) && hvcpu->pending_nmi) {
		/* Inject if NMI is not blocked */
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
		hvcpu->pending_nmi = false;
	}
}

static inline void set_vcpu_mode(struct kvm_vcpu *vcpu, int mode)
{
	vcpu->mode = mode;
	/*
	 * Make sure vcpu->mode is set before checking/handling the pending
	 * requests. Pairs with kvm_vcpu_exiting_guest_mode().
	 */
	smp_wmb();
}

void pkvm_vmexit_main(struct vcpu_vmx *vmx)
{
	struct kvm_vcpu *vcpu = &vmx->vcpu;
	bool skip_instruction = false;

	vcpu->arch.cr2 = native_read_cr2();

	set_vcpu_mode(vcpu, OUTSIDE_GUEST_MODE);

	vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);
	vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);

	vmx->exit_reason.full = vmcs_read32(VM_EXIT_REASON);
	vmx->exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	switch (vmx->exit_reason.full) {
	case EXIT_REASON_CPUID:
		handle_cpuid(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_CR_ACCESS:
		handle_cr(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_MSR_READ:
		handle_read_msr(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_MSR_WRITE:
		handle_write_msr(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_XSETBV:
		handle_xsetbv(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_INTERRUPT_WINDOW:
		handle_irq_window(vcpu);
		break;
	default:
		break;
	}

	if (skip_instruction)
		skip_emulated_instruction();
handle_events:
	handle_pending_events(vcpu);

	set_vcpu_mode(vcpu, IN_GUEST_MODE);

	if (vcpu->mode == EXITING_GUEST_MODE || kvm_request_pending(vcpu))
		goto handle_events;

	native_write_cr2(vcpu->arch.cr2);
}
