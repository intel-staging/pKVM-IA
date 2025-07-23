/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_VMX_VMSR_H_
#define __PKVM_VMX_VMSR_H_

int handle_read_msr(struct kvm_vcpu *vcpu);
int handle_write_msr(struct kvm_vcpu *vcpu);

#endif
