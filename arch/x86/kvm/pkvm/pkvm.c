// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>

/*
 * Needed by kvm_spurious_fault() which is a generic fault function for the
 * vendor operations, e.g., vmx ops or svm ops. The pkvm hypervisor doesn't
 * have the knowledge about the platform reboot or shutdown, so kvm_rebooting
 * is always false in the pkvm hypervisor.
 */
__visible bool kvm_rebooting;
