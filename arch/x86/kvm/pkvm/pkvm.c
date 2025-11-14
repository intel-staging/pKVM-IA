// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "init_finalize.h"
#include "pkvm.h"

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

int pkvm_handle_host_hypercall(unsigned long nr, unsigned long a0,
			       unsigned long a1, unsigned long a2,
			       unsigned long a3)
{
	int ret;

	switch (nr) {
	case __pkvm__init_finalize:
		ret = pkvm_init_finalize(a0, a1);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}
