// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "pkvm.h"

struct pkvm_hyp *pkvm_hyp;
DEFINE_PER_CPU(struct pkvm_pcpu *, phys_cpu);
DEFINE_PER_CPU(struct kvm_vcpu *, host_vcpu);

/*
 * Needed by kvm_spurious_fault() which is a generic fault function for the
 * vendor operations, e.g., vmx ops or svm ops. The pKVM hypervisor doesn't
 * have the knowledge about the platform reboot or shutdown, so virt_rebooting
 * is always false in the pKVM hypervisor.
 */
__visible bool virt_rebooting;
