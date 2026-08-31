/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_PKVM_H
#define __PKVM_X86_PKVM_H

#include <asm/kvm_pkvm.h>

DECLARE_PER_CPU(struct pkvm_pcpu *, phys_cpu);
DECLARE_PER_CPU(struct kvm_vcpu *, host_vcpu);

static inline void pkvm_set_vcpu_in_guest(struct kvm_vcpu *vcpu)
{
	/*
	 * Ensure that IN_GUEST_MODE is globally visible before any subsequent
	 * loads of vcpu->requests (like those inside the run loop or if bump
	 * back to handle_events). This pairs with the full barrier in
	 * kvm_vcpu_exiting_guest_mode().
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);
}

static inline void pkvm_set_vcpu_outside_guest(struct kvm_vcpu *vcpu)
{
	/*
	 * Make the OUTSIDE_GUEST_MODE visible as early as possible for
	 * the other CPUs to skip unnecessary kicks. It can also prevent
	 * the vcpu->mode writing and the following vcpu->requests
	 * reading from being reordered, so that the vcpu->requests made
	 * before changing to OUTSIDE_GUEST_MODE can be handled. In fact
	 * the vcpu->requests reading can be reordered before vcpu->mode
	 * writing, as the missed vcpu->requests can be handled again
	 * after setting to IN_GUEST_MODE with full memory barrier in
	 * the next iteration. And a full memory barrier also cannot
	 * prevent this CPU from missing the new requests made by the
	 * other CPUs, e.g., the requests made after this CPU has
	 * executed the event handlers. So a write barrier is fine from
	 * functional point of view. But using a full memory barrier to
	 * propagate the OUTSIDE_GUEST_MODE.
	 */
	smp_store_mb(vcpu->mode, OUTSIDE_GUEST_MODE);
}

void pkvm_handle_host_hypercall(struct kvm_vcpu *vcpu);
void pkvm_kick_vcpu(struct kvm_vcpu *vcpu);
void pkvm_wait_vcpu_kicked_out(struct kvm_vcpu *vcpu);

#endif /* __PKVM_X86_PKVM_H */
