// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_types.h>
#include <linux/memblock.h>
#include <asm/cpuid/api.h>
#include <kvm_emulate.h>
#include <vmx/x86_ops.h>
#include "ept.h"
#include "host_vmx.h"
#include "pkvm/init.h"
#include "pkvm.h"

#define CR4			4
#define MOV_TO_CR		0

struct vmcs_config host_vmcs_config;

static int vmx_hyp_mmu_finalize(struct pkvm_pgtable *pgt)
{
	if (!pgt)
		return -EINVAL;

	vmcs_writel(HOST_CR3, pgt->root_pa);

	return 0;
}

static struct pkvm_init_ops vmx_init_ops = {
	.hyp_mmu_finalize = vmx_hyp_mmu_finalize,
	.host_mmu_init = pkvm_host_ept_init,
};

struct pkvm_init_ops *pkvm_vmx_init_ops = &vmx_init_ops;

static void skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip;

	rip = vmcs_readl(GUEST_RIP);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs_writel(GUEST_RIP, rip);

	vmx_set_interrupt_shadow(vcpu, 0);
}

static void handle_irq_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_exec_ctrl = exec_controls_get(to_vmx(vcpu));

	exec_controls_set(to_vmx(vcpu), cpu_based_exec_ctrl &
					~CPU_BASED_INTR_WINDOW_EXITING);

	kvm_make_request(KVM_REQ_EVENT, vcpu);
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

static u32 get_cpl(void)
{
	return VMX_AR_DPL(vmcs_read32(GUEST_SS_AR_BYTES));
}

static int handle_vmcall(struct kvm_vcpu *vcpu)
{
	/* Host hypercalls are a kernel-only ABI. */
	if (get_cpl() > 0) {
		kvm_inject_gp(vcpu, 0);
		return X86EMUL_UNHANDLEABLE;
	}

	pkvm_handle_host_hypercall(vcpu);
	return X86EMUL_CONTINUE;
}

static void handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qual = vmcs_readl(EXIT_QUALIFICATION);
	int cr, type, reg;

	cr = exit_qual & 15;
	type = (exit_qual >> 4)	& 3;
	reg = (exit_qual >> 8) & 15;

	BUG_ON(type != MOV_TO_CR || cr != CR4);

	/*
	 * pKVM owns CR4.VMXE and the host owns all the other bits, so
	 * this VM exit only happens when the host writes a VMXE value
	 * different from CR4_READ_SHADOW. The host isn't expected to
	 * do so, as it eventually runs VMs via the PV interfaces
	 * instead of VMX.
	 *
	 * Nevertheless, don't inject #GP if it happens: the host
	 * doesn't expect a CR4 write to fault, so it would crash.
	 * Instead, record the new CR4 value in CR4_READ_SHADOW so that
	 * the host reads back what it wrote. Don't skip the
	 * instruction, as it is possible for the host to flip
	 * host-owned bits together with VMXE in one write. As VMXE bit
	 * then matches with CR4_READ_SHADOW, the host re-executes the
	 * MOV-to-CR4 without a VM exit so that other host-owned bits
	 * are directly updated to the hardware CR4, while the hardware
	 * CR4.VMXE stays unchanged.
	 *
	 * The host's following VMXON or VMXOFF will cause a VM exit
	 * as well, which will get #GP injected. The host expects these
	 * instructions to fault and handles #GP, so it will learn
	 * gracefully that VMX can't be used.
	 */
	vmcs_writel(CR4_READ_SHADOW, vcpu->arch.regs[reg]);
}

static bool is_msr_in_bitmap_range(u32 msr)
{
	return msr <= 0x1FFF || (msr >= 0xC0000000 && msr <= 0xC0001FFF);
}

static int handle_read_msr(struct kvm_vcpu *vcpu)
{
	u32 msr = vcpu->arch.regs[VCPU_REGS_RCX];
	u32 low, high;

	/*
	 * The MSR reading bitmap doesn't intercept any MSR. If the vmexit is
	 * caused by such MSR in the range of the bitmap, it should be a code
	 * bug.
	 */
	BUG_ON(is_msr_in_bitmap_range(msr));

	if (rdmsr_safe(msr, &low, &high)) {
		kvm_inject_gp(vcpu, 0);
		return X86EMUL_UNHANDLEABLE;
	}

	vcpu->arch.regs[VCPU_REGS_RAX] = low;
	vcpu->arch.regs[VCPU_REGS_RDX] = high;

	return X86EMUL_CONTINUE;
}

static int handle_write_msr(struct kvm_vcpu *vcpu)
{
	u32 msr = vcpu->arch.regs[VCPU_REGS_RCX];
	u32 low, high;

	/*
	 * The MSR writing bitmap doesn't intercept any MSR. If the vmexit is
	 * caused by such MSR in the range of the bitmap, it should be a code
	 * bug.
	 */
	BUG_ON(is_msr_in_bitmap_range(msr));

	low = vcpu->arch.regs[VCPU_REGS_RAX];
	high = vcpu->arch.regs[VCPU_REGS_RDX];

	if (wrmsr_safe(msr, low, high)) {
		kvm_inject_gp(vcpu, 0);
		return X86EMUL_UNHANDLEABLE;
	}

	return X86EMUL_CONTINUE;
}

static void handle_preemption_timer(struct kvm_vcpu *vcpu)
{
	pin_controls_clearbit(to_vmx(vcpu), PIN_BASED_VMX_PREEMPTION_TIMER);
}

static int handle_xsetbv(struct kvm_vcpu *vcpu)
{
	u32 eax = (u32)(vcpu->arch.regs[VCPU_REGS_RAX] & -1u);
	u32 edx = (u32)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u);
	u32 ecx = (u32)(vcpu->arch.regs[VCPU_REGS_RCX] & -1u);

	asm goto("1: xsetbv\n\t"
		 _ASM_EXTABLE(1b, %l[fault])
		 : : "a" (eax), "d" (edx), "c" (ecx) : : fault);

	return X86EMUL_CONTINUE;

fault:
	/*
	 * Although the SDM doesn't describe the priority of #UD and
	 * interception for xsetbv, the experiment shows that #UD due to
	 * CR4.OSXSAVE[bit 18] == 0 and the LOCK prefix has priority
	 * over the interception.
	 *
	 * So the pKVM hypervisor itself won't generate #UD when
	 * executes the xsetbv instruction, only #GP can be generated
	 * due to invalid configurations. Always inject #GP if xsetbv
	 * is failed.
	 *
	 * TODO: CPUID.01H:ECX.XSAVE[bit 26] == 0 will also result in
	 * #UD but all modern Intel CPUs have XSAVE. If the pKVM runs
	 * on such CPU without XSAVE, verify if this #UD also has
	 * priority over the interception.
	 */
	kvm_inject_gp(vcpu, 0);
	return X86EMUL_UNHANDLEABLE;
}

static void inject_pending_nmi(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.nmi_pending)
		return;

	/*
	 * Check for the NMI blocking and inject the NMI only when it is not
	 * blocked.
	 * The vmx code vmx_nmi_blocked() and vmx_inject_nmi() are not used at
	 * here as their implementation is related with the global parameter
	 * enable_vnmi which can determine how the guest VMs handle the NMI. The
	 * host VM has physical NMI passthrough which is not exactly fitting to
	 * the usage of enable_vnmi.
	 */
	if (!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
	      (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI |
	       GUEST_INTR_STATE_NMI))) {
		--vcpu->arch.nmi_pending;
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
		vmx_clear_hlt(vcpu);
	}

	/*
	 * If there are more pending NMI, open the irq window to inject the
	 * pending ones when the NMI is unblocked. Using irq window rather than
	 * the NMI window since this is for the physical NMI, while NMI window
	 * is for virtual-NMI when virtual-NMI execution control is enabled,
	 * which is not used for the host VM.
	 */
	if (vcpu->arch.nmi_pending)
		vmx_enable_irq_window(vcpu);
}

static void handle_pending_events(struct kvm_vcpu *vcpu, bool *req_immediate_exit)
{
	if (kvm_check_request(KVM_REQ_NMI, vcpu)) {
		vcpu->arch.nmi_pending += atomic_xchg(&vcpu->arch.nmi_queued, 0);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}

	if (kvm_check_request(KVM_REQ_EVENT, vcpu)) {
		if (vcpu->arch.exception.pending) {
			vmx_inject_exception(vcpu);
			vcpu->arch.exception.pending = false;
			vcpu->arch.exception.injected = true;
		}

		if (vcpu->arch.nmi_pending) {
			/*
			 * Inject pending NMI if no exception is already injected.
			 * Otherwise request an immediate exit to inject NMI in the
			 * next vmexit.
			 */
			if (!vcpu->arch.exception.injected)
				inject_pending_nmi(vcpu);
			else
				*req_immediate_exit = true;
		}
	}
}

void pkvm_host_vmexit_main(struct vcpu_vmx *vmx)
{
	struct kvm_vcpu *vcpu = &vmx->vcpu;
	bool req_immediate_exit = false;
	struct vcpu_vt *vt = &vmx->vt;
	bool skip_instruction = false;

	vcpu->arch.cr2 = native_read_cr2();
	vcpu->arch.exception.injected = false;

	vt->exit_reason.full = vmcs_read32(VM_EXIT_REASON);

	/*
	 * A well behaved pKVM should not cause a failed_vmentry. pKVM has no
	 * recovery path for failing to enter the deprivileged host.
	 *
	 * The bus_lock_detected/smi_pending_mtf/smi_from_vmx_root should not
	 * happen with the current host's VMCS control.
	 */
	BUG_ON(vt->exit_reason.failed_vmentry ||
	       vt->exit_reason.bus_lock_detected ||
	       vt->exit_reason.smi_pending_mtf ||
	       vt->exit_reason.smi_from_vmx_root);

	switch (vt->exit_reason.basic) {
	case EXIT_REASON_INTERRUPT_WINDOW:
		handle_irq_window(vcpu);
		break;
	case EXIT_REASON_CPUID:
		handle_cpuid(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_VMCALL:
		if (handle_vmcall(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	case EXIT_REASON_CR_ACCESS:
		/* Re-execute the MOV to CR4, see handle_cr() */
		handle_cr(vcpu);
		break;
	case EXIT_REASON_MSR_READ:
		if (handle_read_msr(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	case EXIT_REASON_MSR_WRITE:
		if (handle_write_msr(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	case EXIT_REASON_PREEMPTION_TIMER:
		handle_preemption_timer(vcpu);
		break;
	case EXIT_REASON_XSETBV:
		if (handle_xsetbv(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	default:
		kvm_inject_gp(vcpu, 0);
		break;
	}

	/*
	 * An enclave-mode VM-Exit saves the AEP (not the enclave's RIP) in
	 * GUEST_RIP, and VM_EXIT_INSTRUCTION_LEN is cleared to 0. Most
	 * instructions that cause VM-Exit will #UD in an enclave, except
	 * RDRAND, RDSEED and PAUSE which are not intercepted by pKVM, so
	 * instruction-based VM-Exits are not expected to occur in an enclave.
	 */
	BUG_ON(vt->exit_reason.enclave_mode && skip_instruction);

	if (skip_instruction)
		skip_emulated_instruction(vcpu);

	handle_pending_events(vcpu, &req_immediate_exit);

	if (req_immediate_exit) {
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		request_host_immediate_exit(vmx);
	}

	if (vcpu->arch.cr2 != native_read_cr2())
		native_write_cr2(vcpu->arch.cr2);
}
