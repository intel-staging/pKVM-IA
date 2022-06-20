/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */

#include <pkvm.h>
#include <vmx/vmx_lib.h>
#include "cpu.h"
#include "pkvm_hyp.h"
#include "debug.h"

void handle_noop(void)
{
	pkvm_err("%s: unexpected exception\n", __func__);
}

void handle_nmi(void)
{
	int cpu_id = get_pcpu_id();
	struct pkvm_host_vcpu *pkvm_host_vcpu =
		pkvm_hyp->host_vm.host_vcpus[cpu_id];
	struct vcpu_vmx *vmx = &pkvm_host_vcpu->vmx;

	if (!pkvm_host_vcpu || !vmx)
		return;

	if (pkvm_host_vcpu->pending_nmi) {
		pkvm_dbg("%s: CPU%d already has a pending NMI\n",
			__func__, cpu_id);
		return;
	}

	/* load host vcpu vmcs for sure */
	vmcs_load(vmx->loaded_vmcs->vmcs);

	/*
	 * This NMI could happen either before executing
	 * the injection code or after.
	 * For the before case, should record a pending NMI.
	 * For the after case, if no NMI is injected in guest
	 * we also need to record a pending NMI. If NMI is
	 * injected already, then it is not neccessary to inject
	 * again but inject it in the next round should also
	 * be fine. So simply record a pending NMI here.
	 */
	pkvm_host_vcpu->pending_nmi = true;

	pkvm_dbg("%s: CPU%d pending NMI\n", __func__, cpu_id);

	/* For case that NMI happens that the injection code is
	 * already exected, open the NMI window. For the case
	 * happens before, opening NMI window doesn't cause trouble.
	 */
	_vmx_enable_nmi_window(vmx, false);

	/* switch if the current one is not host vcpu vmcs */
	if (pkvm_host_vcpu->current_vmcs &&
			(pkvm_host_vcpu->current_vmcs != vmx->loaded_vmcs->vmcs))
		vmcs_load(pkvm_host_vcpu->current_vmcs);
}
