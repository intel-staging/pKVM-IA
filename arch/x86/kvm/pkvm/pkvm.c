// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "pkvm.h"

struct pkvm_hyp *pkvm_hyp;
DEFINE_PER_CPU(struct pkvm_pcpu *, phys_cpu);
DEFINE_PER_CPU(struct kvm_vcpu *, host_vcpu);
