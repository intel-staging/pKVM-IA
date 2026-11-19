// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>
#include <asm/kvm_pkvm.h>
#include "pmu.h"
#include "x86_ops.h"

static int pkvm_check_processor_compat(void)
{
	return pkvm_hypercall(check_processor_compatibility);
}

static int pkvm_enable_virtualization_cpu(void)
{
	/*
	 * There is nothing to do here as virtualization was already enabled
	 * during pKVM initialization and is never disabled or re-enabled later.
	 */

	return 0;
}

struct kvm_x86_ops pkvm_host_vt_x86_ops __initdata = {
	.name = KBUILD_MODNAME,

	.check_processor_compatibility = pkvm_check_processor_compat,

	.hardware_unsetup = vmx_hardware_unsetup,

	.enable_virtualization_cpu = pkvm_enable_virtualization_cpu,
};

static struct kvm_pmc *pkvm_intel_rdpmc_ecx_to_pmc(struct kvm_vcpu *vcpu,
						   unsigned int idx, u64 *mask)
{
	return NULL;
}
static struct kvm_pmc *pkvm_intel_msr_idx_to_pmc(struct kvm_vcpu *vcpu, u32 msr) { return NULL; }
static bool pkvm_intel_is_valid_msr(struct kvm_vcpu *vcpu, u32 msr) { return false; }
static int pkvm_intel_pmu_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info) { return 1; }
static int pkvm_intel_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info) { return 1; }
static void pkvm_intel_pmu_refresh(struct kvm_vcpu *vcpu) {}
static void pkvm_intel_pmu_init(struct kvm_vcpu *vcpu) {}
static void pkvm_intel_pmu_reset(struct kvm_vcpu *vcpu) {}
static void pkvm_intel_pmu_deliver_pmi(struct kvm_vcpu *vcpu) {}
static void pkvm_intel_pmu_cleanup(struct kvm_vcpu *vcpu) {}
static bool pkvm_intel_is_mediated_pmu_supported(struct x86_pmu_capability *host_pmu)
{
	return false;
}
static void pkvm_intel_mediated_load(struct kvm_vcpu *vcpu) {}
static void pkvm_intel_mediated_put(struct kvm_vcpu *vcpu) {}

static struct kvm_pmu_ops pkvm_host_vt_pmu_ops __initdata = {
	.rdpmc_ecx_to_pmc = pkvm_intel_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = pkvm_intel_msr_idx_to_pmc,
	.is_valid_msr = pkvm_intel_is_valid_msr,
	.get_msr = pkvm_intel_pmu_get_msr,
	.set_msr = pkvm_intel_pmu_set_msr,
	.refresh = pkvm_intel_pmu_refresh,
	.init = pkvm_intel_pmu_init,
	.reset = pkvm_intel_pmu_reset,
	.deliver_pmi = pkvm_intel_pmu_deliver_pmi,
	.cleanup = pkvm_intel_pmu_cleanup,
	.is_mediated_pmu_supported = pkvm_intel_is_mediated_pmu_supported,
	.mediated_load = pkvm_intel_mediated_load,
	.mediated_put = pkvm_intel_mediated_put,
	.EVENTSEL_EVENT = ARCH_PERFMON_EVENTSEL_EVENT,
	.MAX_NR_GP_COUNTERS = 0,
	.MIN_NR_GP_COUNTERS = 0,
};

static void pkvm_leave_nested(struct kvm_vcpu *vcpu) {}
static bool pkvm_nested_is_exception_vmexit(struct kvm_vcpu *vcpu, u8 vector,
					    u32 error_code)
{
	return false;
}
static int pkvm_check_nested_events(struct kvm_vcpu *vcpu) { return 0; }
static void pkvm_nested_triple_fault(struct kvm_vcpu *vcpu) {}
static bool pkvm_get_nested_state_pages(struct kvm_vcpu *vcpu) { return true; }
static int pkvm_nested_write_pml_buffer(struct kvm_vcpu *vcpu, gpa_t gpa) { return 0; }
static int pkvm_get_nested_state(struct kvm_vcpu *vcpu,
				 struct kvm_nested_state __user *user_kvm_nested_state,
				 u32 user_data_size)
{
	return -EINVAL;
}
static int pkvm_set_nested_state(struct kvm_vcpu *vcpu,
				 struct kvm_nested_state __user *user_kvm_nested_state,
				 struct kvm_nested_state *kvm_state)
{
	return -EINVAL;
}
static gpa_t pkvm_translate_nested_gpa(struct kvm_vcpu *vcpu, gpa_t gpa,
				       u64 access,
				       struct x86_exception *exception,
				       u64 pte_access)
{
	WARN_ON_ONCE(1);
	return INVALID_GPA;
}
#ifdef CONFIG_KVM_HYPERV
static void pkvm_hv_inject_synthetic_vmexit_post_tlb_flush(struct kvm_vcpu *vcpu) {}
#endif

static struct kvm_x86_nested_ops pkvm_nested_ops = {
	.leave_nested = pkvm_leave_nested,
	.is_exception_vmexit = pkvm_nested_is_exception_vmexit,
	.check_events = pkvm_check_nested_events,
	.triple_fault = pkvm_nested_triple_fault,
	.get_state = pkvm_get_nested_state,
	.set_state = pkvm_set_nested_state,
	.get_nested_state_pages = pkvm_get_nested_state_pages,
	.write_log_dirty = pkvm_nested_write_pml_buffer,
	.translate_nested_gpa = pkvm_translate_nested_gpa,
#ifdef CONFIG_KVM_HYPERV
	.hv_inject_synthetic_vmexit_post_tlb_flush =
		pkvm_hv_inject_synthetic_vmexit_post_tlb_flush,
#endif
};

struct kvm_x86_init_ops pkvm_host_vt_init_ops __initdata = {
	.hardware_setup = vmx_hardware_setup,
	.handle_intel_pt_intr = NULL,

	.runtime_ops = &pkvm_host_vt_x86_ops,
	.pmu_ops = &pkvm_host_vt_pmu_ops,
	.nested_ops = &pkvm_nested_ops,
};
