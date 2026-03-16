// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_types.h>
#include <linux/memblock.h>
#include <kvm_emulate.h>
#include <vmx/x86_ops.h>
#include "debug.h"
#include "ept.h"
#include "host_vmx.h"
#include "pkvm/init.h"
#include "pkvm/lapic.h"
#include "pkvm/trace.h"
#include "pkvm.h"
#include "pkvm_iommu.h"

#define CR0			0
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

static int vmx_reset_host_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long cr0;

	if (vcpu->arch.mp_state != KVM_MP_STATE_INIT_RECEIVED)
		return -EPERM;

	atomic_set(&vcpu->arch.nmi_queued, 0);
	vcpu->arch.nmi_pending = 0;
	vcpu->arch.nmi_injected = false;
	kvm_clear_exception_queue(vcpu);

	set_debugreg(0, 0);
	set_debugreg(0, 1);
	set_debugreg(0, 2);
	set_debugreg(0, 3);
	set_debugreg(DR6_ACTIVE_LOW, 6);
	vmcs_writel(GUEST_DR7, DR7_FIXED_1);

	vcpu->arch.cr2 = 0;

	/* All GPRs except RDX (handled below) are zeroed on RESET/INIT. */
	memset(vcpu->arch.regs, 0, sizeof(vcpu->arch.regs));
	vcpu->arch.regs[VCPU_REGS_RDX] = native_cpuid_eax(1);

	vmx_seg_setup(VCPU_SREG_CS);
	vmx_seg_setup(VCPU_SREG_DS);
	vmx_seg_setup(VCPU_SREG_ES);
	vmx_seg_setup(VCPU_SREG_FS);
	vmx_seg_setup(VCPU_SREG_GS);
	vmx_seg_setup(VCPU_SREG_SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);

	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);

	vmcs_writel(GUEST_RFLAGS, X86_EFLAGS_FIXED);
	vmcs_writel(GUEST_RIP, 0xfff0);
	vmcs_writel(GUEST_RSP, 0);

	cr0 = X86_CR0_NE | X86_CR0_ET;
	cr0 |= vmcs_readl(GUEST_CR0) & (X86_CR0_NW | X86_CR0_CD);
	vmcs_writel(GUEST_CR0, cr0);
	vmcs_writel(GUEST_CR3, 0);
	vmcs_writel(CR4_READ_SHADOW, 0);
	vmcs_writel(GUEST_CR4, X86_CR4_VMXE);
	vmcs_write64(GUEST_IA32_EFER, 0);

	/* Set unrestricted guest mode to simplify the real mode emulation. */
	secondary_exec_controls_setbit(vmx, SECONDARY_EXEC_UNRESTRICTED_GUEST);

	/*
	 * Clear the IA32E mode to make sure the EFER.LMA will be cleared as the
	 * host will vmenter to real mode. Intercept the X86_CR0_PG bit so that
	 * the pKVM hypervisor can set the EFER.LMA when the host is ready to
	 * vmenter to long mode.
	 */
	vm_entry_controls_clearbit(vmx, VM_ENTRY_IA32E_MODE);
	vmcs_writel(CR0_GUEST_HOST_MASK, X86_CR0_PG);

	if (boot_cpu_has(X86_FEATURE_MPX))
		vmcs_write64(GUEST_BNDCFGS, 0);

	if (boot_cpu_has(X86_FEATURE_IBT) || boot_cpu_has(X86_FEATURE_SHSTK)) {
		vmcs_writel(GUEST_S_CET, 0);
		if (boot_cpu_has(X86_FEATURE_SHSTK)) {
			vmcs_writel(GUEST_SSP, 0);
			vmcs_writel(GUEST_INTR_SSP_TABLE, 0);
		}
	}

	return 0;
}

static int vmx_startup_host_vcpu(struct kvm_vcpu *vcpu, unsigned long start_ip)
{
	u8 vector = start_ip >> 12;

	if (vcpu->arch.mp_state != KVM_MP_STATE_SIPI_RECEIVED)
		return -EPERM;

	vmcs_write16(GUEST_CS_SELECTOR, vector << 8);
	vmcs_writel(GUEST_CS_BASE, vector << 12);
	vmcs_writel(GUEST_RIP, 0);

	return 0;
}

static struct pkvm_init_ops vmx_init_ops = {
	.hyp_mmu_finalize = vmx_hyp_mmu_finalize,
	.host_mmu_init = pkvm_host_ept_init,
	.host_mmu_finalize = pkvm_host_ept_finalize,
	.hyp_global_init = pkvm_vmx_init,
	.reprivilege_cpu = pkvm_vmx_reprivilege_cpu,
	.hyp_iommu_init = pkvm_intel_iommu_init,
	.reset_vcpu = vmx_reset_host_vcpu,
	.startup_vcpu = vmx_startup_host_vcpu,
};

struct pkvm_init_ops *pkvm_vmx_init_ops = &vmx_init_ops;

static void skip_emulated_instruction(void)
{
	unsigned long rip;

	rip = vmcs_readl(GUEST_RIP);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs_writel(GUEST_RIP, rip);
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

static void handle_vmcall(struct kvm_vcpu *vcpu)
{
	pkvm_handle_host_hypercall(vcpu);
}

static void handle_cr(struct kvm_vcpu *vcpu)
{
	struct vcpu_vt *vt = to_vt(vcpu);
	unsigned long exit_qual, val;
	int cr, type, reg;

	exit_qual = vt->exit_qualification;
	cr = exit_qual & 15;
	type = (exit_qual >> 4)	& 3;
	reg = (exit_qual >> 8) & 15;
	val = vcpu->arch.regs[reg];

	switch (type) {
	case MOV_TO_CR:
		switch (cr) {
		case CR0:
			if (val & X86_CR0_PG) {
				u64 efer = vmcs_read64(GUEST_IA32_EFER);

				if (efer & EFER_LME) {
					u64 cr0_guest_host_mask = vmcs_readl(CR0_GUEST_HOST_MASK) &
								  ~X86_CR0_PG;
					/*
					 * Enable the IA32E mode and EFER.LMA to
					 * active long mode. After this is done,
					 * no need to intercept the X86_PG_CR0
					 * bit.
					 */
					vm_entry_controls_setbit(to_vmx(vcpu), VM_ENTRY_IA32E_MODE);
					vmcs_write64(GUEST_IA32_EFER, efer | EFER_LMA);
					vmcs_writel(CR0_GUEST_HOST_MASK, cr0_guest_host_mask);
				}
			}
			vmcs_writel(GUEST_CR0, val);
			break;
		case CR4:
			/*
			 * VMXE bit is owned by pkvm, others are owned by host
			 * So only when guest is trying to modify VMXE bit it
			 * can cause vmexit and get here.
			 */
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

static bool is_msr_in_bitmap_range(unsigned long msr)
{
	return msr <= 0x1FFF || (msr >= 0xC0000000 && msr <= 0xC0001FFF);
}

static int handle_read_msr(struct kvm_vcpu *vcpu)
{
	unsigned long msr = vcpu->arch.regs[VCPU_REGS_RCX];
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
	unsigned long msr = vcpu->arch.regs[VCPU_REGS_RCX];
	int ret = X86EMUL_CONTINUE;
	u32 low, high;
	u64 val;

	low = vcpu->arch.regs[VCPU_REGS_RAX];
	high = vcpu->arch.regs[VCPU_REGS_RDX];
	val = low | ((u64)high << 32);

	switch (msr) {
	case MSR_CORE_PERF_GLOBAL_CTRL: {
		struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
		struct vcpu_vmx *vmx = to_vmx(vcpu);

		if (!kvm_pmu_has_perf_global_ctrl(pmu)) {
			ret = X86EMUL_UNHANDLEABLE;
			break;
		}

		if (pmu->global_ctrl == val)
			break;

		/*
		 * PMU is owned by the host. But the host must be prevented
		 * from profiling pKVM or pVM so the global ctrl MSR is kept
		 * as ZERO (disabled) outside of the host context.
		 *
		 * Capture the value written by host. If it's non-zero then
		 * update the VMCS guest field and rely on VM entry/exit
		 * control to switch the MSR value. The VMCS host field is
		 * fixed to ZERO.
		 */
		pmu->global_ctrl = val;
		if (val) {
			vmcs_write64(GUEST_IA32_PERF_GLOBAL_CTRL, val);
			vm_entry_controls_setbit(vmx,
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL);
			vm_exit_controls_setbit(vmx,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);
		} else {
			vm_entry_controls_clearbit(vmx,
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL);
			vm_exit_controls_clearbit(vmx,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);
		}
		break;
	}
	case MSR_IA32_APICBASE:
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0xff:
		if (pkvm_lapic_msr_write(msr, val))
			ret = X86EMUL_UNHANDLEABLE;
		break;
	default:
		/*
		 * The MSRs intercepted by the writing bitmap should be
		 * emulated by the switch cases. Otherwise it should be a code
		 * bug.
		 */
		BUG_ON(is_msr_in_bitmap_range(msr));

		if (wrmsr_safe(msr, low, high))
			ret = X86EMUL_UNHANDLEABLE;

		break;
	}

	if (ret == X86EMUL_UNHANDLEABLE)
		kvm_inject_gp(vcpu, 0);

	return ret;
}

static void handle_preemption_timer(struct kvm_vcpu *vcpu)
{
	pin_controls_clearbit(to_vmx(vcpu), PIN_BASED_VMX_PREEMPTION_TIMER);
}

static void handle_xsetbv(struct kvm_vcpu *vcpu)
{
	u32 eax = (u32)(vcpu->arch.regs[VCPU_REGS_RAX] & -1u);
	u32 edx = (u32)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u);
	u32 ecx = (u32)(vcpu->arch.regs[VCPU_REGS_RCX] & -1u);

	asm volatile(".byte 0x0f,0x01,0xd1"
			: : "a" (eax), "d" (edx), "c" (ecx));
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

	if (kvm_check_request(KVM_REQ_TLB_FLUSH_CURRENT, vcpu))
		pkvm_flush_host_ept();
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

static void fixup_host_vmx(struct vcpu_vmx *vmx)
{
	if (boot_cpu_has(X86_FEATURE_INTEL_PT)) {
		/*
		 * The VM_ENTRY_LOAD_IA32_RTIT_CTL bit may be cleared due to the
		 * MSR_IA32_RTIT_CTL TRACEEN bit is set before deprivileging. See
		 * comments in init_vmentry_control in pkvm_init.c.
		 *
		 * Ensure this bit is set after the host exits to the root mode.
		 * This can be done safely as VM_EXIT_CLEAR_IA32_RTIT_CTL is
		 * guaranteed to be set which causes the MSR_IA32_RTIT_CTL is 0.
		 */
		if (!(vm_entry_controls_get(vmx) & VM_ENTRY_LOAD_IA32_RTIT_CTL))
			vm_entry_controls_setbit(vmx, VM_ENTRY_LOAD_IA32_RTIT_CTL);
	}

	this_cpu_write(host_vcpu_fixup, false);
}

void pkvm_host_vmexit_main(struct vcpu_vmx *vmx)
{
	struct kvm_vcpu *vcpu = &vmx->vcpu;
	bool req_immediate_exit = false;
	struct vcpu_vt *vt = &vmx->vt;
	bool skip_instruction = false;

	pkvm_trace_vmexit_start(vcpu);

	set_vcpu_mode(vcpu, OUTSIDE_GUEST_MODE);

	vcpu->arch.cr2 = native_read_cr2();
	vcpu->arch.exception.injected = false;

	vt->exit_reason.full = vmcs_read32(VM_EXIT_REASON);
	vt->exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	switch (vt->exit_reason.full) {
	case EXIT_REASON_INIT_SIGNAL:
		/*
		 * INIT is used as kick when making a request.
		 * So just break the vmexits and go to pending
		 * events handling.
		 */
		break;
	case EXIT_REASON_INTERRUPT_WINDOW:
		handle_irq_window(vcpu);
		break;
	case EXIT_REASON_CPUID:
		handle_cpuid(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_VMCALL:
		handle_vmcall(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_CR_ACCESS:
		handle_cr(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_MSR_READ:
		if (handle_read_msr(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	case EXIT_REASON_MSR_WRITE:
		if (handle_write_msr(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	case EXIT_REASON_EPT_VIOLATION:
		/*
		 * Inject #GP to the host VM if its EPT violation
		 * cannot be handled.
		 */
		if (pkvm_handle_host_ept_violation())
			kvm_inject_gp(vcpu, 0);
		break;
	case EXIT_REASON_PREEMPTION_TIMER:
		handle_preemption_timer(vcpu);
		break;
	case EXIT_REASON_XSETBV:
		handle_xsetbv(vcpu);
		skip_instruction = true;
		break;
	default:
		pkvm_err_ratelimited("Unsupported vmexit reason 0x%x.\n",
				      vt->exit_reason.full);
		break;
	}

	if (skip_instruction)
		skip_emulated_instruction();

handle_events:
	handle_pending_events(vcpu, &req_immediate_exit);

	/*
	 * Once the pending events have been handled, set IN_GUEST_MODE to
	 * indicate kick is required for the new pending events.
	 */
	set_vcpu_mode(vcpu, IN_GUEST_MODE);

	if (req_immediate_exit) {
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		request_host_immediate_exit(vmx);
	} else if (READ_ONCE(vcpu->mode) == EXITING_GUEST_MODE ||
		   kvm_request_pending(vcpu)) {
		/*
		 * Some vcpu requests may be set after handle_pending_events()
		 * but before set vcpu mode to IN_GUEST_MODE. In this case the
		 * init signal will not be send to kick the vcpu. To guarantee
		 * such vcpu requests can be handled timely, try to handle
		 * pending event again.
		 */
		goto handle_events;
	}

	if (vcpu->arch.cr2 != native_read_cr2())
		native_write_cr2(vcpu->arch.cr2);

	if (unlikely(this_cpu_read(host_vcpu_fixup)))
		fixup_host_vmx(vmx);

	pkvm_trace_vmexit_end(vcpu, vt->exit_reason.basic);
}
