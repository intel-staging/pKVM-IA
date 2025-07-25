// SPDX-License-Identifier: GPL-2.0
#include <asm/ptrace.h>
#include <asm/trapnr.h>
#include <vmx/x86_ops.h>
#include <pkvm.h>
#include "pkvm/irq.h"

static void handle_nmi(struct pt_regs *regs, int vector, bool has_error_code)
{
	int cpu = raw_smp_processor_id();
	struct pkvm_host_vcpu *hvcpu;

	hvcpu = pkvm_hyp->host_vm.host_vcpus[cpu];
	if (!hvcpu || hvcpu->pending_nmi)
		return;
	/*
	 * This NMI could happen either before executing
	 * the injection code or after.
	 * For the before case, should record a pending NMI.
	 * For the after case, if no NMI is injected in guest
	 * we also need to record a pending NMI. If NMI is
	 * injected already, it is not necessary to inject
	 * again but injecting it in the next round should also
	 * be fine. So simply record a pending NMI here.
	 */
	hvcpu->pending_nmi = true;

	/* For case that when NMI happens the injection code is
	 * already executed, open the irq window. For the case
	 * happens before, opening irq window doesn't cause trouble.
	 */
	vmx_enable_irq_window(&hvcpu->vmx.vcpu);
}

void pkvm_vmx_register_excp_handlers(void)
{
	pkvm_register_excp_handler(X86_TRAP_NMI, handle_nmi);
}
