/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_GSMI_H
#define __PKVM_X86_GSMI_H

#include <linux/kvm_host.h>

int pkvm_init_gsmi(void);
void pkvm_handle_gsmi(struct kvm_vcpu *vcpu);

#endif /* __PKVM_X86_GSMI_H */
