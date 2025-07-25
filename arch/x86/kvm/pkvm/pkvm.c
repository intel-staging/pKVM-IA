// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <pkvm.h>

/*
 * Needed by kvm_spurious_fault() which is a generic fault function for the
 * vendor operations, e.g., vmx ops or sev ops. The pkvm hypervisor doesn't
 * have the knowledge about the platform reboot or shutdown, so kvm_rebooting
 * is always false in the pkvm hypervisor.
 */
__visible bool kvm_rebooting;
struct pkvm_hyp *pkvm_hyp;
