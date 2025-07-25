// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/kvm_pkvm.h>
#include <asm/pkvm_image.h>
#include <pkvm.h>
#include "vmx.h"

MODULE_LICENSE("GPL");

bool __read_mostly enable_pkvm;

static int __init early_pkvm_parse_cmdline(char *buf)
{
	return kstrtobool(buf, &enable_pkvm);
}
early_param("kvm-intel.pkvm", early_pkvm_parse_cmdline);

static bool pkvm_init;

struct pkvm_deprivilege_param {
	struct pkvm_hyp *pkvm;
	int ret;
};

/* only need GDT entries for KERNEL_CS & KERNEL_DS as pKVM only use these two */
static struct gdt_page pkvm_gdt_page = {
	.gdt = {
		[GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(0xa09b, 0, 0xfffff),
		[GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(0xc093, 0, 0xfffff),
	},
};

u64 hyp_total_reserve_pages(void)
{
	return pkvm_data_struct_pages(PKVM_GLOBAL_PAGES,
				      PKVM_PERCPU_PAGES,
				      num_possible_cpus());
}

static struct vmcs *pkvm_alloc_vmcs(struct vmcs_config *vmcs_config_ptr)
{
	struct vmcs *vmcs;
	int pages = ALIGN(vmx_basic_vmcs_size(vmcs_config_ptr->basic), PAGE_SIZE) >> PAGE_SHIFT;

	vmcs = pkvm_sym(pkvm_early_alloc_contig)(pages);
	if (!vmcs)
		return NULL;

	memset(vmcs, 0, vmx_basic_vmcs_size(vmcs_config_ptr->basic));
	vmcs->hdr.revision_id = vmx_basic_vmcs_revision_id(vmcs_config_ptr->basic);

	return vmcs;
}

static inline void vmxon_setup_revid(void *vmxon_region)
{
	u32 rev_id = 0;
	u32 msr_high_value = 0;

	rdmsr(MSR_IA32_VMX_BASIC, rev_id, msr_high_value);

	memcpy(vmxon_region, &rev_id, 4);
}

static __init int pkvm_host_setup_vmxarea(struct pkvm_host_vcpu *hvcpu)
{
	u64 phys_addr;

	hvcpu->vmxarea = pkvm_sym(pkvm_early_alloc_page)();
	if (!hvcpu->vmxarea)
		return -ENOMEM;

	phys_addr = __pa(hvcpu->vmxarea);
	if (!PAGE_ALIGNED(phys_addr))
		return -ENOMEM;

	/*setup revision id in vmxon region*/
	vmxon_setup_revid(hvcpu->vmxarea);

	return 0;
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

static __init void init_guest_state_area_from_native(void)
{
	int cpu = smp_processor_id();
	struct desc_ptr dt;
	unsigned long msrl;
	u32 high, low;
	u16 ldtr;

	/* load CR regiesters */
	vmcs_writel(GUEST_CR0, read_cr0() & ~X86_CR0_TS);
	vmcs_writel(GUEST_CR3, __read_cr3());
	vmcs_writel(GUEST_CR4, __read_cr4());

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

static __init void init_guest_state_area(void)
{
	init_guest_state_area_from_native();

	/*Guest non register state*/
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmcs_write64(VMCS_LINK_POINTER, -1ull);
}

/*
 * [pcpu->stack, pcpu->stack + PKVM_STACK_SIZE) is per cpu pvm stack.
 * It is used as stack when the pcpu enters pKVM, i.e. HOST stack from
 * VMX point of view.
 *
 * Within the top of stack, a small region starting from stack_resv
 * is reserved  to store private paremeters,
 *
 *
 * ------------ Stack layout ----------
 * stack_top:
 * stack_resv + 8:	struct vcpu_vmx *vmx
 * stack_resv + 0:	pointer to vcpu->arch.regs
 * stack_resv: (stack_top - PKVM_STACK_TOP_RESV)
 *              VMCS.HOST_RSP for host VCPU
 *              .........
 *              .........
 * hstack_bottom:
 *
 */
static __init void init_host_state_area(struct vcpu_vmx *vmx)
{
	struct pkvm_host_vcpu *hvcpu = vmx_to_host_vcpu(vmx);
	int cpu = smp_processor_id();
	unsigned long host_rsp, val;

	vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);
	/* Use host cr3 until the pkvm hypervisor created its own MMU */
	vmcs_writel(HOST_CR3, __read_cr3());
	/*
	 * Disable FRED for the pkvm hypervisor if it is enabled by the host.
	 * There is no too much benifit for the pkvm hypervisor to use the FRED
	 * event delivery as the NMI is the only event expected to be received
	 * by the pkvm hypervisor. The exceptions are not expected to be
	 * happened in the pkvm hypervisor and all hardware interrupts will
	 * directly go to the host. Meanwhile, enabling the FRED in the pkvm
	 * hypervisor will result in additional FRED MSRs switching overhead. So
	 * keep the FRED being disabled in the pkvm hypervisor.
	 */
	vmcs_writel(HOST_CR4, __read_cr4() & ~X86_CR4_FRED);

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);
	vmcs_write16(HOST_ES_SELECTOR, 0);
	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);
	vmcs_write16(HOST_FS_SELECTOR, 0);
	vmcs_write16(HOST_GS_SELECTOR, 0);
	vmcs_writel(HOST_FS_BASE, 0);
	vmcs_writel(HOST_GS_BASE, pkvm_sym(pkvm_per_cpu_offset)(cpu));

	vmcs_writel(HOST_TR_BASE, (unsigned long)&hvcpu->pcpu->tss);
	vmcs_writel(HOST_GDTR_BASE, (unsigned long)(&hvcpu->pcpu->gdt_page));
	vmcs_writel(HOST_IDTR_BASE, (unsigned long)(&hvcpu->pcpu->idt_page));

	rdmsrl(MSR_EFER, val);
	vmcs_write64(HOST_IA32_EFER, val);

	rdmsrl(MSR_IA32_CR_PAT, val);
	vmcs_write64(HOST_IA32_PAT, val);

	host_rsp = get_host_stack_top(hvcpu->pcpu) - PKVM_STACK_TOP_RESV;

	vmcs_writel(HOST_RSP, host_rsp);
	*((struct vcpu_vmx **) (host_rsp + 8)) = vmx;
	*((unsigned long **) host_rsp) = vmx->vcpu.arch.regs;

	vmcs_writel(HOST_RIP, (unsigned long)pkvm_sym(pkvm_host_vmexit_entry));
}

static __init void init_execution_control(struct vcpu_vmx *vmx, struct pkvm_hyp *pkvm)
{
	u64 io_bitmap_pa = __pa(pkvm->host_vm.io_bitmap);

	pin_controls_set(vmx, pkvm->vmcs_config.pin_based_exec_ctrl);

	/*
	 * CR3 LOAD/STORE EXITING are not used by pkvm
	 * INTR/NMI WINDOW EXITING are toggled dynamically
	 */
	exec_controls_set(vmx, pkvm->vmcs_config.cpu_based_exec_ctrl &
			       ~(CPU_BASED_CR3_LOAD_EXITING |
				 CPU_BASED_CR3_STORE_EXITING |
				 CPU_BASED_INTR_WINDOW_EXITING |
				 CPU_BASED_NMI_WINDOW_EXITING));
	/* disable EPT/VPID first, enable after EPT pgtable created */
	secondary_exec_controls_set(vmx, pkvm->vmcs_config.cpu_based_2nd_exec_ctrl &
					 ~(SECONDARY_EXEC_ENABLE_EPT |
					   SECONDARY_EXEC_ENABLE_VPID));
	/*
	 * Shadow VMCS will not be used as the VMCS will be exposed via PV-based
	 * method.
	 */
	vmcs_write64(VMCS_LINK_POINTER, INVALID_GPA);

	/* guest owns cr3 */
	vmcs_write32(CR3_TARGET_COUNT, 0);

	/* guest handles exception directly */
	vmcs_write32(EXCEPTION_BITMAP, 0);

	vmcs_write64(IO_BITMAP_A, io_bitmap_pa);
	vmcs_write64(IO_BITMAP_B, io_bitmap_pa + PAGE_SIZE);

	vmcs_write64(MSR_BITMAP, __pa(vmx->vmcs01.msr_bitmap));

	/*
	 * Guest owns cr0, and owns cr4 except VMXE bit.
	 * Does not care about IA32_VMX_CRx_FIXED0/1 setting, so if guest modify
	 * cr0/cr4 conflicting with FIXED0/1, just let #GP happen.
	 * For example, as pKVM does not enable unrestricted guest, cr0.PE/PG
	 * must keep as 1 in guest.
	 */
	vmcs_writel(CR0_GUEST_HOST_MASK, 0);
	vmcs_writel(CR4_GUEST_HOST_MASK, X86_CR4_VMXE);
	/*
	 * Set the VMXE bit in CR4_READ_SHADOW so that the host VM will see the
	 * consistent values between "native" cr4 and its cached cpu_tlbstate.cr4
	 * (which is set when turns on VMX via kvm_vcpu_vmxon).
	 */
	vmcs_writel(CR4_READ_SHADOW, X86_CR4_VMXE);
}

static __init void init_vmexit_control(struct vcpu_vmx *vmx, struct pkvm_hyp *pkvm)
{
	vm_exit_controls_set(vmx, pkvm->vmcs_config.vmexit_ctrl);
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
}

static __init void init_vmentry_control(struct vcpu_vmx *vmx, struct pkvm_hyp *pkvm)
{
	vm_entry_controls_set(vmx, pkvm->vmcs_config.vmentry_ctrl);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
}

static __init int pkvm_host_init_vmx(struct vcpu_vmx *vmx, struct pkvm_hyp *pkvm)
{
	/* vmcs01: host vmcs in pKVM */
	vmx->vmcs01.vmcs = pkvm_alloc_vmcs(&pkvm->vmcs_config);
	if (!vmx->vmcs01.vmcs)
		return -ENOMEM;

	vmx->vmcs01.msr_bitmap = pkvm_sym(pkvm_early_alloc_page)();
	if (!vmx->vmcs01.msr_bitmap) {
		pr_err("pkvm: no memory page for msr_bitmap\n");
		return -ENOMEM;
	}

	vmx->loaded_vmcs = &vmx->vmcs01;
	vmcs_load(vmx->loaded_vmcs->vmcs);

	init_guest_state_area();
	init_host_state_area(vmx);
	init_execution_control(vmx, pkvm);
	init_vmexit_control(vmx, pkvm);
	init_vmentry_control(vmx, pkvm);

	return 0;
}

static __init int setup_pkvm_host_vmcs_config(struct pkvm_hyp *pkvm)
{
	struct vmcs_config *vmcs_config = &pkvm->vmcs_config;
	struct vmx_capability *vmx_cap = &pkvm_sym(vmx_capability);
	int ret = 0;
	struct vmcs_config_setting setting = {
		.cpu_based_vm_exec_ctrl_req =
			CPU_BASED_INTR_WINDOW_EXITING |
			CPU_BASED_USE_IO_BITMAPS |
			CPU_BASED_USE_MSR_BITMAPS |
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
		.cpu_based_vm_exec_ctrl_opt = 0,
		.secondary_vm_exec_ctrl_req =
			SECONDARY_EXEC_ENABLE_EPT,
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
		pr_err("pkvm: setup host vmcs config failed with ret %d\n", ret);
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
	/*
	 * page_offset_base/phys_base stores the offset for pkvm to translate
	 * between VA and PA.
	 */
#ifdef CONFIG_DYNAMIC_MEMORY_LAYOUT
	pkvm_sym(page_offset_base) = page_offset_base;
#endif
	pkvm_sym(phys_base) = phys_base;

	return 0;
}

static __init void init_gdt(struct pkvm_pcpu *pcpu)
{
	pcpu->gdt_page = pkvm_gdt_page;
}

static __init void init_idt(struct pkvm_pcpu *pcpu)
{
	void (*pkvm_exception_handlers[X86_TRAP_IRET])(void) = {
#define GEN(x, ...)	\
		[x] = pkvm_sym(handle_exception_##x),
#include <GEN-for-each-exc.h>
#undef GEN
	};
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

	for (i = 0; i < X86_TRAP_IRET; i++) {
		d.vector = i;
		d.bits.ist = 0;
		d.addr = (const void *)pkvm_exception_handlers[i];
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
	int nr_pages;

	if (cpu >= CONFIG_NR_CPUS)
		return -ENOMEM;

	nr_pages = pkvm_sym(pkvm_per_cpu_nr_pages)();
	if (nr_pages) {
		void *per_cpu_base = pkvm_sym(pkvm_early_alloc_contig)(nr_pages);

		if (!per_cpu_base || pkvm_sym(setup_pkvm_per_cpu)(cpu, __pa(per_cpu_base))) {
			pr_err("%s: No page for pKVM per cpu data\n", __func__);
			return -ENOMEM;
		}
	}

	pcpu = pkvm_sym(pkvm_early_alloc_contig)(PKVM_PCPU_PAGES);
	if (!pcpu)
		return -ENOMEM;

	init_gdt(pcpu);
	init_idt(pcpu);
	init_tss(pcpu);

	pkvm->pcpus[cpu] = pcpu;

	return 0;
}

static __init int pkvm_host_setup_vcpu(struct pkvm_hyp *pkvm, int cpu)
{
	struct pkvm_host_vcpu *hvcpu;

	if (cpu >= CONFIG_NR_CPUS)
		return -ENOMEM;

	hvcpu = pkvm_sym(pkvm_early_alloc_contig)(PKVM_HOST_VCPU_PAGES);
	if (!hvcpu)
		return -ENOMEM;

	hvcpu->pcpu = pkvm->pcpus[cpu];
	hvcpu->vmx.vcpu.cpu = cpu;

	pkvm->host_vm.host_vcpus[cpu] = hvcpu;

	return 0;
}

static __init int pkvm_init_io_emulation(struct pkvm_hyp *pkvm)
{
	pkvm->host_vm.io_bitmap = pkvm_sym(pkvm_early_alloc_contig)(2);

	if (!pkvm->host_vm.io_bitmap) {
		pr_err("pkvm: no memory page for io_bitmap\n");
		return -ENOMEM;
	}

	memset(pkvm->host_vm.io_bitmap, 0, 2 * PAGE_SIZE);

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

static noinline int local_deprivilege_cpu(void)
{
	int ret;

	asm volatile(
		"pushfq\n"
		"popq %%rax\n"
		"movq %3, %%rdx\n"
		"vmwrite %%rax, %%rdx\n"
		"movq %%rsp, %%rax\n"
		"movq %4, %%rdx\n"
		"vmwrite %%rax, %%rdx\n"
		"movq $host_vm_entry_point, %%rax\n"
		"movq %1, %%rdx\n"
		"vmwrite %%rax, %%rdx\n"
		"movl $0, %0\n"
		"vmlaunch\n"
		/* successfully deprivileged (CF=0 & ZF=0) */
		"ja host_vm_entry_point\n"
		/* vmlaunch failed */
		"movl %2, %0\n"
		"host_vm_entry_point: nop\n"
		: "=m"(ret)
		: "i"(GUEST_RIP), "i"(-EINVAL), "i"(GUEST_RFLAGS), "i"(GUEST_RSP)
		: "rax", "rdx", "memory");

	return ret;
}

static __init void pkvm_host_deprivilege_cpu(void *data)
{
	struct pkvm_deprivilege_param *p = data;
	struct pkvm_host_vcpu *hvcpu;
	struct kvm_vcpu *vcpu;
	struct pkvm_hyp *pkvm;
	unsigned long flags;
	int cpu, ret;

	if (!p || !p->pkvm)
		return;

	cpu = get_cpu();

	pkvm = p->pkvm;
	hvcpu = pkvm->host_vm.host_vcpus[cpu];

	local_irq_save(flags);

	enable_feature_control();

	ret = pkvm_host_setup_vmxarea(hvcpu);
	if (ret) {
		pr_err("pkvm: CPU%d setup vmxarea failed, ret %d\n", cpu, ret);
		goto done;
	}

	ret = kvm_cpu_vmxon(__pa(hvcpu->vmxarea));
	if (ret) {
		pr_err("pkvm: CPU%d vmxon failed, ret %d\n", cpu, ret);
		goto done;
	}

	ret = pkvm_host_init_vmx(&hvcpu->vmx, pkvm);
	if (ret) {
		pr_err("pkvm: CPU%d init vmx failed, ret %d\n", cpu, ret);
		goto vmxoff;
	}

	ret = local_deprivilege_cpu();
	if (ret) {
		pr_err("pkvm: CPU%d deprivilege failed, ret %d\n", cpu, ret);
		goto vmxoff;
	}

	vcpu = &hvcpu->vmx.vcpu;
	vcpu->mode = IN_GUEST_MODE;
	pr_info("pkvm: CPU%d in guest mode\n", cpu);
	goto done;

vmxoff:
	kvm_cpu_vmxoff();
done:
	p->ret = ret;
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
	int cpu, ret = 0;

	for_each_possible_cpu(cpu) {
		ret = smp_call_function_single(cpu, pkvm_host_deprivilege_cpu, &p, 1);
		if (ret || p.ret) {
			pr_err("Failed to deprivilege CPU%d: smp_call %d, deprivilege: %d\n",
			       cpu, ret, p.ret);
			break;
		}
	}

	return ret ? ret : p.ret;
}

int __init vmx_pkvm_init(void)
{
	unsigned long nr_pages;
	struct pkvm_hyp *pkvm;
	int ret, cpu;

	if (!enable_pkvm)
		return 0;

	if (cmpxchg(&pkvm_init, 0, 1) != 0) {
		pr_err("pkvm: init is already started\n");
		return -EBUSY;
	}

	if (!hyp_mem_base) {
		pr_err("pkvm: required memory not reserved\n");
		ret = -ENOMEM;
		goto out;
	}

	nr_pages = pkvm_data_struct_pages(PKVM_GLOBAL_PAGES,
					  PKVM_PERCPU_PAGES,
					  num_possible_cpus());
	pkvm_sym(pkvm_early_alloc_init)(__va(hyp_mem_base), nr_pages << PAGE_SHIFT);

	pkvm = pkvm_sym(pkvm_early_alloc_contig)(PKVM_PAGES);
	if (!pkvm) {
		pr_err("pkvm: cannot alloc pkvm_hyp\n");
		ret = -ENOMEM;
		goto out;
	}

	pkvm->num_cpus = num_possible_cpus();

	ret = setup_pkvm_host_vmcs_config(pkvm);
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

	ret = pkvm_init_io_emulation(pkvm);
	if (ret)
		goto out;

	ret = pkvm_host_deprivilege_cpus(pkvm);
	if (ret)
		goto out;

	pr_info("pkvm: All cpus are in guest mode!\n");

	/* FIXME: Should return 0 once pvVMCS is supported */
	return 1;
out:
	/* TODO: Re-privilege the deprivileged CPUs */
	pkvm_init = false;
	return ret;
}
