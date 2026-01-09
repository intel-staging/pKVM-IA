// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "init.h"
#include "lapic.h"
#include "pkvm.h"
#include "trace.h"

/*
 * Needed by kvm_spurious_fault() which is a generic fault function for the
 * vendor operations, e.g., vmx ops or svm ops. The pKVM hypervisor doesn't
 * have the knowledge about the platform reboot or shutdown, so kvm_rebooting
 * is always false in the pKVM hypervisor.
 */
__visible bool kvm_rebooting;

struct pkvm_hyp *pkvm_hyp;
DEFINE_PER_CPU(struct pkvm_pcpu *, phys_cpu);
DEFINE_PER_CPU(struct kvm_vcpu *, host_vcpu);

void pkvm_handle_host_hypercall(struct kvm_vcpu *vcpu)
{
	int ret = 0;

	switch (pkvm_hc(vcpu)) {
	case __pkvm__init:
		ret = pkvm_init((struct pkvm_mem_info *)pkvm_hc_input1(vcpu),
				pkvm_hc_input2(vcpu));
		break;
	case __pkvm__init_finalize:
		ret = pkvm_init_finalize();
		break;
	case __pkvm__reprivilege_cpu:
		ret = pkvm_reprivilege_vcpu(vcpu);
		break;
	case __pkvm__enable_vmexit_trace:
		pkvm_enable_vmexit_trace(pkvm_hc_input1(vcpu));
		break;
	default:
		ret = -EINVAL;
		break;
	}

	pkvm_hc_set_ret(vcpu, ret);
}

void pkvm_kick_vcpu(struct kvm_vcpu *vcpu)
{
	/* No need to kick if a vcpu is already out of guest mode */
	if (kvm_vcpu_exiting_guest_mode(vcpu) != IN_GUEST_MODE)
		return;

	pkvm_lapic_send_init(READ_ONCE(vcpu->cpu));
}

void pkvm_wait_vcpu_kicked_out(struct kvm_vcpu *vcpu)
{
	int relax_iters = 0;
	u64 start;

	if (READ_ONCE(vcpu->mode) != EXITING_GUEST_MODE)
		return;

	start = rdtsc();
	do {
		cpu_relax();
		if (++relax_iters == 1000) {
			/*
			 * Bug the system if waiting for the remote CPU to ack
			 * the kick is taking longer than 1s. It may take
			 * microseconds, sometimes up to milliseconds (if the
			 * CPU needs to wake from a deeper low-power state) but
			 * should not take as long as a second.
			 */
			BUG_ON(tsc_khz && (((rdtsc() - start) / tsc_khz) > 1000));
			relax_iters = 0;
		}
	} while (READ_ONCE(vcpu->mode) == EXITING_GUEST_MODE);
}
