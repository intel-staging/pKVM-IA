// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/trapnr.h>
#include <asm/kvm_pkvm.h>

#include <mmu.h>
#include <mmu/spte.h>
#include <pkvm.h>
#include "pkvm_constants.h"

MODULE_LICENSE("GPL");

static struct pkvm_hyp *pkvm;

struct pkvm_deprivilege_param {
	struct pkvm_hyp *pkvm;
	int ret;
};

#define is_aligned(POINTER, BYTE_COUNT) \
		(((uintptr_t)(const void *)(POINTER)) % (BYTE_COUNT) == 0)

/* only need GDT entries for KERNEL_CS & KERNEL_DS as pKVM only use these two */
static struct gdt_page pkvm_gdt_page = {
	.gdt = {
		[GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(0xa09b, 0, 0xfffff),
		[GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(0xc093, 0, 0xfffff),
	},
};

u64 hyp_total_reserve_pages(void)
{
	u64 total;

	total = pkvm_data_struct_pages(PKVM_PAGES, PKVM_PERCPU_PAGES, num_possible_cpus());
	total += pkvm_vmemmap_pages(PKVM_VMEMMAP_ENTRY_SIZE);
	total += pkvm_mmu_pgtable_pages();
	total += host_ept_pgtable_pages();

	return total;
}

static struct vmcs *pkvm_alloc_vmcs(struct vmcs_config *vmcs_config_ptr)
{
	struct vmcs *vmcs;
	int pages = ALIGN(vmcs_config_ptr->size, PAGE_SIZE) >> PAGE_SHIFT;

	vmcs = pkvm_sym(pkvm_early_alloc_contig)(pages);
	if (!vmcs)
		return NULL;

	memset(vmcs, 0, vmcs_config_ptr->size);
	vmcs->hdr.revision_id = vmcs_config_ptr->revision_id; /* vmcs revision id */

	return vmcs;
}

static inline void vmxon_setup_revid(void *vmxon_region)
{
	u32 rev_id = 0;
	u32 msr_high_value = 0;

	rdmsr(MSR_IA32_VMX_BASIC, rev_id, msr_high_value);

	memcpy(vmxon_region, &rev_id, 4);
}

static inline void cr4_set_vmxe(void)
{
	unsigned long cr4_value;

	cr4_value = __read_cr4();
	__write_cr4(cr4_value | X86_CR4_VMXE);
}

static inline void cr4_clear_vmxe(void)
{
	unsigned long cr4_value;

	cr4_value = __read_cr4();
	__write_cr4(cr4_value & ~(X86_CR4_VMXE));
}

static __init int pkvm_cpu_vmxon(u64 vmxon_pointer)
{
	u64 msr;

	cr4_set_vmxe();
	asm goto("1: vmxon %[vmxon_pointer]\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  : : [vmxon_pointer] "m"(vmxon_pointer)
			  : : fault);
	return 0;

fault:
	WARN_ONCE(1, "VMXON faulted, MSR_IA32_FEAT_CTL (0x3a) = 0x%llx\n",
		  rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ? 0xdeadbeef : msr);
	cr4_clear_vmxe();
	return -EFAULT;
}

static __init int pkvm_cpu_vmxoff(void)
{
	asm goto("1: vmxoff\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  ::: "cc", "memory" : fault);
	cr4_clear_vmxe();
	return 0;

fault:
	cr4_clear_vmxe();
	return -EFAULT;
}

static __init int pkvm_enable_vmx(struct pkvm_host_vcpu *vcpu)
{
	u64 phys_addr;

	vcpu->vmxarea = pkvm_sym(pkvm_early_alloc_page)();
	if (!vcpu->vmxarea)
		return -ENOMEM;

	phys_addr = __pa(vcpu->vmxarea);
	if (!is_aligned(phys_addr, PAGE_SIZE))
		return -ENOMEM;

	/*setup revision id in vmxon region*/
	vmxon_setup_revid(vcpu->vmxarea);

	return pkvm_cpu_vmxon(phys_addr);
}

static inline u32 get_ar(u16 sel)
{
	u32 access_rights;

	if (sel == 0) {
		access_rights = 0x10000;
	} else {
		asm ("lar %%ax, %%rax\n"
				: "=a"(access_rights) : "a"(sel));
		access_rights = access_rights >> 8;
		access_rights = access_rights & 0xf0ff;
	}

	return access_rights;
}

#define init_guestsegment(seg, SEG, base, limit)		\
	do  {							\
		u16 sel;					\
		u32 ar;						\
								\
		savesegment(seg, sel);				\
		ar = get_ar(sel);				\
		vmcs_write16(GUEST_##SEG##_SELECTOR, sel);	\
		vmcs_write32(GUEST_##SEG##_AR_BYTES, ar);	\
		vmcs_writel(GUEST_##SEG##_BASE, base);		\
		vmcs_write32(GUEST_##SEG##_LIMIT, limit);	\
	} while (0)

static __init void init_guest_state_area_from_native(int cpu)
{
	u16 ldtr;
	struct desc_ptr dt;
	unsigned long msrl;
	u32 high, low;

	/* load CR regiesters */
	vmcs_writel(GUEST_CR0, read_cr0() & ~X86_CR0_TS);
	vmcs_writel(GUEST_CR3, __read_cr3());
	vmcs_writel(GUEST_CR4, native_read_cr4());

	/* load cs/ss/ds/es */
	init_guestsegment(cs, CS, 0x0, 0xffffffff);
	init_guestsegment(ss, SS, 0x0, 0xffffffff);
	init_guestsegment(ds, DS, 0x0, 0xffffffff);
	init_guestsegment(es, ES, 0x0, 0xffffffff);

	/* load fs/gs */
	rdmsrl(MSR_FS_BASE, msrl);
	init_guestsegment(fs, FS, msrl, 0xffffffff);
	rdmsrl(MSR_GS_BASE, msrl);
	init_guestsegment(gs, GS, msrl, 0xffffffff);

	/* load GDTR */
	native_store_gdt(&dt);
	vmcs_writel(GUEST_GDTR_BASE, dt.address);
	vmcs_write32(GUEST_GDTR_LIMIT, dt.size);

	/* load TR */
	vmcs_write16(GUEST_TR_SELECTOR, GDT_ENTRY_TSS*8);
	vmcs_write32(GUEST_TR_AR_BYTES, get_ar(GDT_ENTRY_TSS*8));
	vmcs_writel(GUEST_TR_BASE, (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
	vmcs_write32(GUEST_TR_LIMIT, __KERNEL_TSS_LIMIT);

	/* load LDTR */
	store_ldt(ldtr);
	vmcs_write16(GUEST_LDTR_SELECTOR, ldtr);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x10000);
	vmcs_writel(GUEST_LDTR_BASE, 0x0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffffffff);

	store_idt(&dt);
	vmcs_writel(GUEST_IDTR_BASE, dt.address);
	vmcs_write32(GUEST_IDTR_LIMIT, dt.size);

	/* set MSRs */
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	rdmsr(MSR_IA32_SYSENTER_CS, low, high);
	vmcs_write32(GUEST_SYSENTER_CS, low);

	rdmsrl(MSR_IA32_SYSENTER_ESP, msrl);
	vmcs_writel(GUEST_SYSENTER_ESP, msrl);

	rdmsrl(MSR_IA32_SYSENTER_EIP, msrl);
	vmcs_writel(GUEST_SYSENTER_EIP, msrl);

	rdmsrl(MSR_EFER, msrl);
	vmcs_write64(GUEST_IA32_EFER, msrl);

	rdmsrl(MSR_IA32_CR_PAT, msrl);
	vmcs_write64(GUEST_IA32_PAT, msrl);
}

static __init void init_guest_state_area(struct pkvm_host_vcpu *vcpu, int cpu)
{
	init_guest_state_area_from_native(cpu);

	/*Guest non register state*/
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmcs_write64(VMCS_LINK_POINTER, -1ull);
}

static __init void _init_host_state_area(struct pkvm_pcpu *pcpu, int cpu)
{
	unsigned long a;
#ifdef CONFIG_PKVM_INTEL_DEBUG
	u32 high, low;
	struct desc_ptr dt;
	u16 selector;
#endif

	vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);
	vmcs_writel(HOST_CR3, pcpu->cr3);
	vmcs_writel(HOST_CR4, native_read_cr4());

#ifdef CONFIG_PKVM_INTEL_DEBUG
	savesegment(cs, selector);
	vmcs_write16(HOST_CS_SELECTOR, selector);
	savesegment(ss, selector);
	vmcs_write16(HOST_SS_SELECTOR, selector);
	savesegment(ds, selector);
	vmcs_write16(HOST_DS_SELECTOR, selector);
	savesegment(es, selector);
	vmcs_write16(HOST_ES_SELECTOR, selector);
	savesegment(fs, selector);
	vmcs_write16(HOST_FS_SELECTOR, selector);
	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a);
	savesegment(gs, selector);
	vmcs_write16(HOST_GS_SELECTOR, selector);
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a);

	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);
	vmcs_writel(HOST_TR_BASE, (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);

	native_store_gdt(&dt);
	vmcs_writel(HOST_GDTR_BASE, dt.address);
	store_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.address);

	rdmsr(MSR_IA32_SYSENTER_CS, low, high);
	vmcs_write32(HOST_IA32_SYSENTER_CS, low);

	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);

	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);
#else
	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);
	vmcs_write16(HOST_ES_SELECTOR, 0);
	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);
	vmcs_write16(HOST_FS_SELECTOR, 0);
	vmcs_write16(HOST_GS_SELECTOR, 0);
	vmcs_writel(HOST_FS_BASE, 0);
	vmcs_writel(HOST_GS_BASE, 0);

	vmcs_writel(HOST_TR_BASE, (unsigned long)&pcpu->tss);
	vmcs_writel(HOST_GDTR_BASE, (unsigned long)(&pcpu->gdt_page));
	vmcs_writel(HOST_IDTR_BASE, (unsigned long)(&pcpu->idt_page));

	vmcs_write16(HOST_GS_SELECTOR, __KERNEL_DS);
	vmcs_writel(HOST_GS_BASE, cpu);
#endif

	/* MSR area */
	rdmsrl(MSR_EFER, a);
	vmcs_write64(HOST_IA32_EFER, a);

	rdmsrl(MSR_IA32_CR_PAT, a);
	vmcs_write64(HOST_IA32_PAT, a);
}

static __init void init_host_state_area(struct pkvm_host_vcpu *vcpu, int cpu)
{
	struct pkvm_pcpu *pcpu = vcpu->pcpu;

	_init_host_state_area(pcpu, cpu);

	/*host RIP*/
	vmcs_writel(HOST_RIP, (unsigned long)pkvm_sym(__pkvm_vmx_vmexit));
}

static __init void init_execution_control(struct vcpu_vmx *vmx,
			    struct vmcs_config *vmcs_config_ptr,
			    struct vmx_capability *vmx_cap)
{
	u32 cpu_based_exec_ctrl = vmcs_config_ptr->cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl = vmcs_config_ptr->cpu_based_2nd_exec_ctrl;

	pin_controls_set(vmx, vmcs_config_ptr->pin_based_exec_ctrl);

	/*
	 * CR3 LOAD/STORE EXITING are not used by pkvm
	 * INTR/NMI WINDOW EXITING are toggled dynamically
	 */
	cpu_based_exec_ctrl &= ~(CPU_BASED_CR3_LOAD_EXITING |
				CPU_BASED_CR3_STORE_EXITING |
				CPU_BASED_INTR_WINDOW_EXITING |
				CPU_BASED_NMI_WINDOW_EXITING);
	exec_controls_set(vmx, cpu_based_exec_ctrl);

	/* disable EPT/VPID first, enable after EPT pgtable created */
	cpu_based_2nd_exec_ctrl &= ~(SECONDARY_EXEC_ENABLE_EPT |
				SECONDARY_EXEC_ENABLE_VPID);
	secondary_exec_controls_set(vmx, cpu_based_2nd_exec_ctrl);

	/* guest owns cr3 */
	vmcs_write32(CR3_TARGET_COUNT, 0);

	/* guest handles exception directly */
	vmcs_write32(EXCEPTION_BITMAP, 0);

	vmcs_write64(MSR_BITMAP, __pa(vmx->vmcs01.msr_bitmap));

	/*
	 * guest owns cr0, and owns cr4 except VMXE bit.
	 * does not care about IA32_VMX_CRx_FIXED0/1 setting, so if guest modify
	 * cr0/cr4 conflicting with FIXED0/1, just let #GP happen.
	 * For example, as pKVM does not enable unrestricted guest, cr0.PE/PG
	 * must keep as 1 in guest.
	 */
	vmcs_writel(CR0_GUEST_HOST_MASK, 0);
	vmcs_writel(CR4_GUEST_HOST_MASK, X86_CR4_VMXE);
}

static __init void init_vmexit_control(struct vcpu_vmx *vmx, struct vmcs_config *vmcs_config_ptr)
{
	vm_exit_controls_set(vmx, vmcs_config_ptr->vmexit_ctrl);
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
}

static __init void init_vmentry_control(struct vcpu_vmx *vmx, struct vmcs_config *vmcs_config_ptr)
{
	vm_entry_controls_set(vmx, vmcs_config_ptr->vmentry_ctrl);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
}

static __init int pkvm_host_init_vmx(struct pkvm_host_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = &vcpu->vmx;
	int ret;

	ret = pkvm_enable_vmx(vcpu);
	if (ret)
		return ret;

	/* vmcs01: host vmcs in pKVM */
	vmx->vmcs01.vmcs = pkvm_alloc_vmcs(&pkvm->vmcs_config);
	if (!vmx->vmcs01.vmcs)
		return -ENOMEM;

	vmx->vmcs01.msr_bitmap = pkvm_sym(pkvm_early_alloc_page)();
	if (!vmx->vmcs01.msr_bitmap) {
		pr_err("%s: No page for msr_bitmap\n", __func__);
		return -ENOMEM;
	}

	vmx->loaded_vmcs = &vmx->vmcs01;
	vmcs_load(vmx->loaded_vmcs->vmcs);

	init_guest_state_area(vcpu, cpu);
	init_host_state_area(vcpu, cpu);
	init_execution_control(vmx, &pkvm->vmcs_config, &pkvm->vmx_cap);
	init_vmexit_control(vmx, &pkvm->vmcs_config);
	init_vmentry_control(vmx, &pkvm->vmcs_config);

	return ret;
}

static __init void pkvm_host_deinit_vmx(struct pkvm_host_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = &vcpu->vmx;

	pkvm_cpu_vmxoff();

	if (vmx->vmcs01.vmcs)
		vmx->vmcs01.vmcs = NULL;

	if (vmx->vmcs01.msr_bitmap)
		vmx->vmcs01.msr_bitmap = NULL;
}

static __init int pkvm_host_check_and_setup_vmx_cap(struct pkvm_hyp *pkvm)
{
	struct vmcs_config *vmcs_config = &pkvm->vmcs_config;
	struct vmx_capability *vmx_cap = &pkvm->vmx_cap;
	int ret = 0;
	struct vmcs_config_setting setting = {
		.cpu_based_vm_exec_ctrl_req =
			CPU_BASED_INTR_WINDOW_EXITING |
			CPU_BASED_USE_MSR_BITMAPS |
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
		.cpu_based_vm_exec_ctrl_opt = 0,
		.secondary_vm_exec_ctrl_req =
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_SHADOW_VMCS,
		.secondary_vm_exec_ctrl_opt =
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_INVPCID |
			SECONDARY_EXEC_ENABLE_XSAVES |
			SECONDARY_EXEC_ENABLE_RDTSCP |
			SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE,
		.tertiary_vm_exec_ctrl_opt = 0,
		.pin_based_vm_exec_ctrl_req = 0,
		.pin_based_vm_exec_ctrl_opt = 0,
		.vmexit_ctrl_req =
			VM_EXIT_HOST_ADDR_SPACE_SIZE |
			VM_EXIT_LOAD_IA32_PAT |
			VM_EXIT_LOAD_IA32_EFER |
			VM_EXIT_SAVE_IA32_PAT |
			VM_EXIT_SAVE_IA32_EFER |
			VM_EXIT_SAVE_DEBUG_CONTROLS,
		.vmexit_ctrl_opt = 0,
		.vmentry_ctrl_req =
			VM_ENTRY_LOAD_DEBUG_CONTROLS |
			VM_ENTRY_IA32E_MODE |
			VM_ENTRY_LOAD_IA32_EFER |
			VM_ENTRY_LOAD_IA32_PAT,
		.vmentry_ctrl_opt = 0,
	};

	ret = setup_vmcs_config_common(vmcs_config, vmx_cap, &setting);
	if (ret) {
		pr_err("%s: fail with ret %d\n", __func__, ret);
	} else {
		pr_info("pin_based_exec_ctrl 0x%x\n", vmcs_config->pin_based_exec_ctrl);
		pr_info("cpu_based_exec_ctrl 0x%x\n", vmcs_config->cpu_based_exec_ctrl);
		pr_info("cpu_based_2nd_exec_ctrl 0x%x\n", vmcs_config->cpu_based_2nd_exec_ctrl);
		pr_info("vmexit_ctrl 0x%x\n", vmcs_config->vmexit_ctrl);
		pr_info("vmentry_ctrl 0x%x\n", vmcs_config->vmentry_ctrl);
	}

	return ret;
}

static __init int pkvm_init_mmu(struct pkvm_hyp *pkvm)
{
	int pgsz_mask = (1 << PG_LEVEL_2M) | (1 << PG_LEVEL_4K);

	if (boot_cpu_has(X86_FEATURE_GBPAGES))
		pgsz_mask |= 1 << PG_LEVEL_1G;

	/* record mmu pgtable cap for later mmu pgtable build */
	pkvm->mmu_cap.level = pgtable_l5_enabled() ? 5 : 4;
	pkvm->mmu_cap.allowed_pgsz = pgsz_mask;
	pkvm->mmu_cap.table_prot = (u64)_KERNPG_TABLE_NOENC;

	/* record ept pgtable cap for later ept pgtable build */
	pkvm->ept_cap.level = pkvm->vmx_cap.ept & VMX_EPT_PAGE_WALK_4_BIT ? 4 : 5;
	pkvm->ept_cap.allowed_pgsz = pgsz_mask;
	pkvm->ept_cap.table_prot = VMX_EPT_RWX_MASK;

	/*
	 * __page_base_offset stores the offset for pkvm
	 * to translate VA to a PA.
	 *
	 * __symbol_base_offset stores the offset for pkvm
	 * to translate its symbole's VA to a PA.
	 */
	pkvm_sym(__page_base_offset) = (unsigned long)__va(0);
	pkvm_sym(__symbol_base_offset) = (unsigned long)__pkvm_text_start - __pa_symbol(__pkvm_text_start);

	return 0;
}

static __init void init_gdt(struct pkvm_pcpu *pcpu)
{
	pcpu->gdt_page = pkvm_gdt_page;
}

void noop_handler(void)
{
	/* To be added */
}

static __init void init_idt(struct pkvm_pcpu *pcpu)
{
	gate_desc *idt = pcpu->idt_page.idt;
	struct idt_data d = {
		.segment = __KERNEL_CS,
		.bits.ist = 0,
		.bits.zero = 0,
		.bits.type = GATE_INTERRUPT,
		.bits.dpl = 0,
		.bits.p = 1,
	};
	gate_desc desc;
	int i;

	for (i = 0; i <= X86_TRAP_IRET; i++) {
		d.vector = i;
		d.bits.ist = 0;
		d.addr = (const void *)noop_handler;
		idt_init_desc(&desc, &d);
		write_idt_entry(idt, i, &desc);
	}
}

static __init void init_tss(struct pkvm_pcpu *pcpu)
{
	struct desc_struct *d = pcpu->gdt_page.gdt;
	tss_desc tss;

	set_tssldt_descriptor(&tss, (unsigned long)&pcpu->tss, DESC_TSS,
			__KERNEL_TSS_LIMIT);

	write_gdt_entry(d, GDT_ENTRY_TSS, &tss, DESC_TSS);
}

static __init int pkvm_setup_pcpu(struct pkvm_hyp *pkvm, int cpu)
{
	struct pkvm_pcpu *pcpu;

	if (cpu >= CONFIG_NR_CPUS)
		return -ENOMEM;

	pcpu = pkvm_sym(pkvm_early_alloc_contig)(PKVM_PCPU_PAGES);
	if (!pcpu)
		return -ENOMEM;

	/* tmp use host cr3, switch to pkvm owned cr3 after de-privilege */
	pcpu->cr3 = __read_cr3();

	init_gdt(pcpu);
	init_idt(pcpu);
	init_tss(pcpu);

	pkvm->pcpus[cpu] = pcpu;

	return 0;
}

static __init int pkvm_host_setup_vcpu(struct pkvm_hyp *pkvm, int cpu)
{
	struct pkvm_host_vcpu *pkvm_host_vcpu;

	if (cpu >= CONFIG_NR_CPUS)
		return -ENOMEM;

	pkvm_host_vcpu = pkvm_sym(pkvm_early_alloc_contig)(PKVM_HOST_VCPU_PAGES);
	if (!pkvm_host_vcpu)
		return -ENOMEM;

	pkvm_host_vcpu->pcpu = pkvm->pcpus[cpu];
	pkvm_host_vcpu->vmx.vcpu.cpu = cpu;

	pkvm->host_vm.host_vcpus[cpu] = pkvm_host_vcpu;

	return 0;
}

static inline void enable_feature_control(void)
{
	u64 old, test_bits;

	rdmsrl(MSR_IA32_FEAT_CTL, old);
	test_bits = FEAT_CTL_LOCKED;
	test_bits |= FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX;

	if ((old & test_bits) != test_bits)
		wrmsrl(MSR_IA32_FEAT_CTL, old | test_bits);
}

#define savegpr(gpr, value) 		\
	asm("mov %%" #gpr ",%0":"=r" (value) : : "memory")

static noinline int pkvm_host_run_vcpu(struct pkvm_host_vcpu *vcpu)
{
	u64 host_rsp;
	unsigned long *regs = vcpu->vmx.vcpu.arch.regs;
	volatile int ret = 0;

	/*
	 * prepare to RUN vcpu:
	 *
	 * - record gprs in vcpu.arch.regs[]:
	 *
	 * - record below guest vmcs fields:
	 * 	GUSET_RFLAGS - read from native
	 *
	 * - record below guest vmcs fields:
	 * 	GUSET_RFLAGS - read from native
	 * 	GUEST_RIP - vmentry_point
	 * 	GUEST_RSP - read from native
	 *
	 * - switch RSP to host_rsp
	 * - push guest_rsp to host stack
	 */
	savegpr(rax, regs[__VCPU_REGS_RAX]);
	savegpr(rcx, regs[__VCPU_REGS_RCX]);
	savegpr(rdx, regs[__VCPU_REGS_RDX]);
	savegpr(rbx, regs[__VCPU_REGS_RBX]);
	savegpr(rbp, regs[__VCPU_REGS_RBP]);
	savegpr(rsi, regs[__VCPU_REGS_RSI]);
	savegpr(rdi, regs[__VCPU_REGS_RDI]);
	savegpr(r8, regs[__VCPU_REGS_R8]);
	savegpr(r9, regs[__VCPU_REGS_R9]);
	savegpr(r10, regs[__VCPU_REGS_R10]);
	savegpr(r11, regs[__VCPU_REGS_R11]);
	savegpr(r12, regs[__VCPU_REGS_R12]);
	savegpr(r13, regs[__VCPU_REGS_R13]);
	savegpr(r14, regs[__VCPU_REGS_R14]);
	savegpr(r15, regs[__VCPU_REGS_R15]);
	host_rsp = (u64)vcpu->pcpu->stack + STACK_SIZE;
	asm volatile(
		"pushfq\n"
		"popq %%rax\n"
		"movq %0, %%rdx\n"
		"vmwrite %%rax, %%rdx\n"
		"movq $vmentry_point, %%rax\n"
		"movq %1, %%rdx\n"
		"vmwrite %%rax, %%rdx\n"
		"movq %%rsp, %%rax\n"
		"movq %2, %%rdx\n"
		"vmwrite %%rax, %%rdx\n"
		"movq %3, %%rsp\n"
		"pushq %%rax\n"
		:
		: "i"(GUEST_RFLAGS), "i"(GUEST_RIP), "i"(GUEST_RSP), "m"(host_rsp)
		: "rax", "rdx", "memory");

	/*
	 * call pkvm_main to do vmlaunch.
	 *
	 * if pkvm_main return - vmlaunch fail:
	 *     pop back guest_rsp, ret = -EINVAL
	 * if pkvm_main not return - vmlaunch success:
	 *     guest ret to vmentry_point, ret = 0
	 */
	pkvm_sym(pkvm_main)(&vcpu->vmx.vcpu);
	asm volatile(
			"popq %%rdx\n"
			"movq %%rdx, %%rsp\n"
			"movq %1, %%rdx\n"
			"movq %%rdx, %0\n"
			"vmentry_point:\n"
			: "=m"(ret) : "i"(-EINVAL) : "rdx", "memory");

	return ret;
}

static __init void pkvm_host_deprivilege_cpu(void *data)
{
	struct pkvm_deprivilege_param *p = data;
	unsigned long flags;
	int cpu = get_cpu(), ret;
	struct pkvm_host_vcpu *vcpu =
		p->pkvm->host_vm.host_vcpus[cpu];

	local_irq_save(flags);

	enable_feature_control();

	ret = pkvm_host_init_vmx(vcpu, cpu);
	if (ret) {
		pr_err("%s: init vmx failed\n", __func__);
		goto out;
	}

	ret = pkvm_host_run_vcpu(vcpu);
	if (ret == 0) {
		pr_info("%s: CPU%d in guest mode\n", __func__, cpu);
		goto ok;
	}

out:
	p->ret = ret;
	pkvm_host_deinit_vmx(vcpu);
	pr_err("%s: failed to deprivilege CPU%d\n", __func__, cpu);

ok:
	local_irq_restore(flags);

	put_cpu();
}

/*
 * Used in root mode to deprivilege CPUs
 */
static __init int pkvm_host_deprivilege_cpus(struct pkvm_hyp *pkvm)
{
	struct pkvm_deprivilege_param p = {
		.pkvm = pkvm,
		.ret = 0,
	};

	on_each_cpu(pkvm_host_deprivilege_cpu, &p, 1);
	if (p.ret) {
		/*
		 * TODO:
		 * We are here because some CPUs failed to be deprivileged, so
		 * the failed CPU will stay in root mode. But the others already
		 * in the non-root mode. In this case, we should let non-root mode
		 * CPUs go back to root mode, then the system can still run natively
		 * without pKVM enabled.
		 */
		pr_err("%s: WARNING - failed to deprivilege all CPUs!\n", __func__);
	} else {
		pr_info("%s: all cpus are in guest mode!\n", __func__);
	}

	return p.ret;
}

static __init void do_pkvm_finalise(void *data)
{
	kvm_hypercall2(PKVM_HC_INIT_FINALISE, 0, 0);
}

static __init int pkvm_init_finalise(void)
{
	int ret, cpu;
	int self = get_cpu();
	struct pkvm_section sections[] = {
		/*
		 * NOTE: please ensure kernel section is put at the beginning,
		 * as we do section mapping by the order, while kernel data
		 * sections have overlap with pkvm ones, put the kernel section
		 * after pkvm one will make pkvm section readonly!
		 */
		{
			/*
			 * Kernel section: addr is virtual, needed
			 * for pkvm to access kernel alias symbol
			 */
			.type = KERNEL_DATA_SECTIONS,
			.addr = (unsigned long)_sdata,
			.size = (unsigned long)(_edata - _sdata),
			.prot = (u64)pgprot_val(PAGE_KERNEL_RO),
		},
		{
			/*
			 * Kernel section: addr is virtual, needed
			 * for pkvm to access kernel alias symbol
			 */
			.type = KERNEL_DATA_SECTIONS,
			.addr = (unsigned long)__start_rodata,
			.size = (unsigned long)(__end_rodata - __start_rodata),
			.prot = (u64)pgprot_val(PAGE_KERNEL_RO),
		},
		{
			/* PKVM reserved memory: addr is physical */
			.type = PKVM_RESERVED_MEMORY,
			.addr = (unsigned long)hyp_mem_base,
			.size = (unsigned long)hyp_mem_size,
			.prot = (u64)pgprot_val(PAGE_KERNEL),
		},
		{
			/* PKVM section: addr is virtual */
			.type = PKVM_CODE_DATA_SECTIONS,
			.addr = (unsigned long)__pkvm_text_start,
			.size = (unsigned long)(__pkvm_text_end - __pkvm_text_start),
			.prot = (u64)pgprot_val(PAGE_KERNEL_EXEC),
		},
		{
			/* PKVM section: addr is virtual */
			.type = PKVM_CODE_DATA_SECTIONS,
			.addr = (unsigned long)__pkvm_rodata_start,
			.size = (unsigned long)(__pkvm_rodata_end - __pkvm_rodata_start),
			.prot = (u64)pgprot_val(PAGE_KERNEL_RO),
		},
		{
			/* PKVM section: addr is virtual */
			.type = PKVM_CODE_DATA_SECTIONS,
			.addr = (unsigned long)__pkvm_data_start,
			.size = (unsigned long)(__pkvm_data_end - __pkvm_data_start),
			.prot = (u64)pgprot_val(PAGE_KERNEL),
		},
		{
			/* PKVM section: addr is virtual */
			.type = PKVM_CODE_DATA_SECTIONS,
			.addr = (unsigned long)__pkvm_bss_start,
			.size = (unsigned long)(__pkvm_bss_end - __pkvm_bss_start),
			.prot = (u64)pgprot_val(PAGE_KERNEL),
		},
	};

	/*
	 * First hypercall to recreate the pgtable for pkvm, and init
	 * memory pool for later use.
	 * Input parameters are only needed for first hypercall.
	 */
	ret = kvm_hypercall2(PKVM_HC_INIT_FINALISE,
			(unsigned long)sections, ARRAY_SIZE(sections));

	if (ret) {
		pr_err("%s: pkvm finalise failed!\n", __func__);
		goto out;
	}

	for_each_possible_cpu(cpu) {
		if (cpu == self)
			continue;

		/*
		 * Second hypercall to switch the mmu and ept pgtable.
		 */
		ret = smp_call_function_single(cpu, do_pkvm_finalise,
					       NULL, true);
	}
out:
	put_cpu();

	return ret;
}

__init int pkvm_init(void)
{
	int ret = 0, cpu;

	if (pkvm_sym(pkvm_hyp)) {
		pr_err("pkvm hypervisor is running!");
		return -EBUSY;
	}

	if (!hyp_mem_base) {
		pr_err("pkvm required memory not get reserved!");
		ret = -ENOMEM;
		goto out;
	}
	pkvm_sym(pkvm_early_alloc_init)(__va(hyp_mem_base),
			pkvm_data_struct_pages(PKVM_PAGES, PKVM_PERCPU_PAGES,
				num_possible_cpus()) << PAGE_SHIFT);

	/* pkvm hypervisor keeps same VA mapping as deprivileged host */
	pkvm = pkvm_sym(pkvm_hyp) = pkvm_sym(pkvm_early_alloc_contig)(PKVM_PAGES);
	if (!pkvm) {
		ret = -ENOMEM;
		goto out;
	}

	ret = pkvm_host_check_and_setup_vmx_cap(pkvm);
	if (ret)
		goto out;

	ret = pkvm_init_mmu(pkvm);
	if (ret)
		goto out;

	for_each_possible_cpu(cpu) {
		ret = pkvm_setup_pcpu(pkvm, cpu);
		if (ret)
			goto out;
		ret = pkvm_host_setup_vcpu(pkvm, cpu);
		if (ret)
			goto out;
	}

	ret = pkvm_host_deprivilege_cpus(pkvm);
	if (ret)
		goto out;

	pkvm->num_cpus = num_possible_cpus();

	return pkvm_init_finalise();

out:
	pkvm_sym(pkvm_hyp) = NULL;
	return ret;
}
