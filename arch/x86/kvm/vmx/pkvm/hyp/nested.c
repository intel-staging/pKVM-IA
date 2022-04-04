// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */

#include <pkvm.h>

#include "pkvm_hyp.h"
#include "debug.h"

/**
 * According to SDM Appendix B Field Encoding in VMCS, some fields only
 * exist on processor that support the 1-setting of the corresponding
 * fields in the control regs.
 */
static bool has_vmcs_field(u16 encoding)
{
	struct nested_vmx_msrs *msrs = &pkvm_hyp->vmcs_config.nested;

	switch (encoding) {
	case MSR_BITMAP:
		return msrs->procbased_ctls_high & CPU_BASED_USE_MSR_BITMAPS;
	case VIRTUAL_APIC_PAGE_ADDR:
	case VIRTUAL_APIC_PAGE_ADDR_HIGH:
	case TPR_THRESHOLD:
		return msrs->procbased_ctls_high & CPU_BASED_TPR_SHADOW;
	case SECONDARY_VM_EXEC_CONTROL:
		return msrs->procbased_ctls_high &
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;

	case VIRTUAL_PROCESSOR_ID:
		return msrs->secondary_ctls_high & SECONDARY_EXEC_ENABLE_VPID;
	case XSS_EXIT_BITMAP:
		return msrs->secondary_ctls_high & SECONDARY_EXEC_ENABLE_XSAVES;
	case PML_ADDRESS:
		return msrs->secondary_ctls_high & SECONDARY_EXEC_ENABLE_PML;
	case VM_FUNCTION_CONTROL:
		return msrs->secondary_ctls_high & SECONDARY_EXEC_ENABLE_VMFUNC;
	case EPT_POINTER:
		return msrs->secondary_ctls_high & SECONDARY_EXEC_ENABLE_EPT;
	case EOI_EXIT_BITMAP0:
	case EOI_EXIT_BITMAP1:
	case EOI_EXIT_BITMAP2:
	case EOI_EXIT_BITMAP3:
		return msrs->secondary_ctls_high &
			SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY;
	case VMREAD_BITMAP:
	case VMWRITE_BITMAP:
		return msrs->secondary_ctls_high & SECONDARY_EXEC_SHADOW_VMCS;
	case ENCLS_EXITING_BITMAP:
		return msrs->secondary_ctls_high &
			SECONDARY_EXEC_ENCLS_EXITING;
	case GUEST_INTR_STATUS:
		return msrs->secondary_ctls_high &
			SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY;
	case GUEST_PML_INDEX:
		return msrs->secondary_ctls_high & SECONDARY_EXEC_ENABLE_PML;
	case APIC_ACCESS_ADDR:
	case APIC_ACCESS_ADDR_HIGH:
		return msrs->secondary_ctls_high &
			SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
	case TSC_MULTIPLIER:
	case TSC_MULTIPLIER_HIGH:
		return msrs->secondary_ctls_high &
			SECONDARY_EXEC_TSC_SCALING;
	case GUEST_PHYSICAL_ADDRESS:
	case GUEST_PHYSICAL_ADDRESS_HIGH:
		return msrs->secondary_ctls_high &
			SECONDARY_EXEC_ENABLE_EPT;
	case GUEST_PDPTR0:
	case GUEST_PDPTR0_HIGH:
	case GUEST_PDPTR1:
	case GUEST_PDPTR1_HIGH:
	case GUEST_PDPTR2:
	case GUEST_PDPTR2_HIGH:
	case GUEST_PDPTR3:
	case GUEST_PDPTR3_HIGH:
		return msrs->secondary_ctls_high & SECONDARY_EXEC_ENABLE_EPT;
	case PLE_GAP:
	case PLE_WINDOW:
		return msrs->secondary_ctls_high &
			SECONDARY_EXEC_PAUSE_LOOP_EXITING;

	case VMX_PREEMPTION_TIMER_VALUE:
		return msrs->pinbased_ctls_high &
			PIN_BASED_VMX_PREEMPTION_TIMER;
	case POSTED_INTR_DESC_ADDR:
		return msrs->pinbased_ctls_high & PIN_BASED_POSTED_INTR;
	case POSTED_INTR_NV:
		return msrs->pinbased_ctls_high & PIN_BASED_POSTED_INTR;
	case GUEST_IA32_PAT:
	case GUEST_IA32_PAT_HIGH:
		return (msrs->entry_ctls_high & VM_ENTRY_LOAD_IA32_PAT) ||
			(msrs->exit_ctls_high & VM_EXIT_SAVE_IA32_PAT);
	case GUEST_IA32_EFER:
	case GUEST_IA32_EFER_HIGH:
		return (msrs->entry_ctls_high & VM_ENTRY_LOAD_IA32_EFER) ||
			(msrs->exit_ctls_high & VM_EXIT_SAVE_IA32_EFER);
	case GUEST_IA32_PERF_GLOBAL_CTRL:
	case GUEST_IA32_PERF_GLOBAL_CTRL_HIGH:
		return msrs->entry_ctls_high & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL;
	case GUEST_BNDCFGS:
	case GUEST_BNDCFGS_HIGH:
		return (msrs->entry_ctls_high & VM_ENTRY_LOAD_BNDCFGS) ||
			(msrs->exit_ctls_high & VM_EXIT_CLEAR_BNDCFGS);
	case GUEST_IA32_RTIT_CTL:
	case GUEST_IA32_RTIT_CTL_HIGH:
		return (msrs->entry_ctls_high & VM_ENTRY_LOAD_IA32_RTIT_CTL) ||
			(msrs->exit_ctls_high & VM_EXIT_CLEAR_IA32_RTIT_CTL);
	case HOST_IA32_PAT:
	case HOST_IA32_PAT_HIGH:
		return msrs->exit_ctls_high & VM_EXIT_LOAD_IA32_PAT;
	case HOST_IA32_EFER:
	case HOST_IA32_EFER_HIGH:
		return msrs->exit_ctls_high & VM_EXIT_LOAD_IA32_EFER;
	case HOST_IA32_PERF_GLOBAL_CTRL:
	case HOST_IA32_PERF_GLOBAL_CTRL_HIGH:
		return msrs->exit_ctls_high & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL;
	case EPTP_LIST_ADDRESS:
		return msrs->vmfunc_controls & VMX_VMFUNC_EPTP_SWITCHING;
	default:
		return true;
	}
}

enum VMXResult {
	VMsucceed,
	VMfailValid,
	VMfailInvalid,
};

struct shadow_vmcs_field {
	u16	encoding;
	u16	offset;
};

static u8 vmx_vmread_bitmap[PAGE_SIZE] __aligned(PAGE_SIZE);
static u8 vmx_vmwrite_bitmap[PAGE_SIZE] __aligned(PAGE_SIZE);

static struct shadow_vmcs_field shadow_read_only_fields[] = {
#define SHADOW_FIELD_RO(x, y) { x, offsetof(struct vmcs12, y) },
#include "pkvm_nested_vmcs_fields.h"
};
static int max_shadow_read_only_fields =
	ARRAY_SIZE(shadow_read_only_fields);
static struct shadow_vmcs_field shadow_read_write_fields[] = {
#define SHADOW_FIELD_RW(x, y) { x, offsetof(struct vmcs12, y) },
#include "pkvm_nested_vmcs_fields.h"
};
static int max_shadow_read_write_fields =
	ARRAY_SIZE(shadow_read_write_fields);
static struct shadow_vmcs_field emulated_fields[] = {
#define EMULATED_FIELD_RW(x, y) { x, offsetof(struct vmcs12, y) },
#include "pkvm_nested_vmcs_fields.h"
};
static int max_emulated_fields =
	ARRAY_SIZE(emulated_fields);

static void init_vmcs_shadow_fields(void)
{
	int i, j;

	memset(vmx_vmread_bitmap, 0xff, PAGE_SIZE);
	memset(vmx_vmwrite_bitmap, 0xff, PAGE_SIZE);

	for (i = j = 0; i < max_shadow_read_only_fields; i++) {
		struct shadow_vmcs_field entry = shadow_read_only_fields[i];
		u16 field = entry.encoding;

		if (!has_vmcs_field(field))
			continue;

		if (vmcs_field_width(field) == VMCS_FIELD_WIDTH_U64 &&
		    (i + 1 == max_shadow_read_only_fields ||
		     shadow_read_only_fields[i + 1].encoding != field + 1)) {
			pkvm_err("Missing field from shadow_read_only_field %x\n",
			       field + 1);
		}

		clear_bit(field, (unsigned long *)vmx_vmread_bitmap);
		if (field & 1)
			continue;
		shadow_read_only_fields[j++] = entry;
	}
	max_shadow_read_only_fields = j;

	for (i = j = 0; i < max_shadow_read_write_fields; i++) {
		struct shadow_vmcs_field entry = shadow_read_write_fields[i];
		u16 field = entry.encoding;

		if (!has_vmcs_field(field))
			continue;

		if (vmcs_field_width(field) == VMCS_FIELD_WIDTH_U64 &&
		    (i + 1 == max_shadow_read_write_fields ||
		     shadow_read_write_fields[i + 1].encoding != field + 1)) {
			pkvm_err("Missing field from shadow_read_write_field %x\n",
			       field + 1);
		}

		clear_bit(field, (unsigned long *)vmx_vmwrite_bitmap);
		clear_bit(field, (unsigned long *)vmx_vmread_bitmap);
		if (field & 1)
			continue;
		shadow_read_write_fields[j++] = entry;
	}
	max_shadow_read_write_fields = j;
}

static void init_emulated_vmcs_fields(void)
{
	int i, j;

	for (i = j = 0; i < max_emulated_fields; i++) {
		struct shadow_vmcs_field entry = emulated_fields[i];
		u16 field = entry.encoding;

		if (!has_vmcs_field(field))
			continue;

		emulated_fields[j++] = entry;
	}
	max_emulated_fields = j;
}

static void nested_vmx_result(enum VMXResult result, int error_number)
{
	u64 rflags = vmcs_readl(GUEST_RFLAGS);

	rflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF);

	if (result == VMfailValid) {
		rflags |= X86_EFLAGS_ZF;
		vmcs_write32(VM_INSTRUCTION_ERROR, error_number);
	} else if (result == VMfailInvalid) {
		rflags |= X86_EFLAGS_CF;
	} else {
		/* VMsucceed, do nothing */
	}

	if (result != VMsucceed)
		pkvm_err("VMX failed: %d/%d", result, error_number);

	vmcs_writel(GUEST_RFLAGS, rflags);
}

static int get_vmx_mem_address(struct kvm_vcpu *vcpu, unsigned long exit_qualification,
			u32 vmx_instruction_info, gva_t *ret)
{
	gva_t off;
	struct kvm_segment s;

	/*
	 * According to Vol. 3B, "Information for VM Exits Due to Instruction
	 * Execution", on an exit, vmx_instruction_info holds most of the
	 * addressing components of the operand. Only the displacement part
	 * is put in exit_qualification (see 3B, "Basic VM-Exit Information").
	 * For how an actual address is calculated from all these components,
	 * refer to Vol. 1, "Operand Addressing".
	 */
	int  scaling = vmx_instruction_info & 3;
	int  addr_size = (vmx_instruction_info >> 7) & 7;
	bool is_reg = vmx_instruction_info & (1u << 10);
	int  seg_reg = (vmx_instruction_info >> 15) & 7;
	int  index_reg = (vmx_instruction_info >> 18) & 0xf;
	bool index_is_valid = !(vmx_instruction_info & (1u << 22));
	int  base_reg       = (vmx_instruction_info >> 23) & 0xf;
	bool base_is_valid  = !(vmx_instruction_info & (1u << 27));

	if (is_reg) {
		/* TODO: inject #UD */
		return 1;
	}

	/* Addr = segment_base + offset */
	/* offset = base + [index * scale] + displacement */
	off = exit_qualification; /* holds the displacement */
	if (addr_size == 1)
		off = (gva_t)sign_extend64(off, 31);
	else if (addr_size == 0)
		off = (gva_t)sign_extend64(off, 15);
	if (base_is_valid)
		off += vcpu->arch.regs[base_reg];
	if (index_is_valid)
		off += vcpu->arch.regs[index_reg] << scaling;

	if (seg_reg == VCPU_SREG_FS)
		s.base = vmcs_readl(GUEST_FS_BASE);
	if (seg_reg == VCPU_SREG_GS)
		s.base = vmcs_readl(GUEST_GS_BASE);

	/* TODO: support more cpu mode beside long mode */
	/*
	 * The effective address, i.e. @off, of a memory operand is truncated
	 * based on the address size of the instruction.  Note that this is
	 * the *effective address*, i.e. the address prior to accounting for
	 * the segment's base.
	 */
	if (addr_size == 1) /* 32 bit */
		off &= 0xffffffff;
	else if (addr_size == 0) /* 16 bit */
		off &= 0xffff;

	/*
	 * The virtual/linear address is never truncated in 64-bit
	 * mode, e.g. a 32-bit address size can yield a 64-bit virtual
	 * address when using FS/GS with a non-zero base.
	 */
	if (seg_reg == VCPU_SREG_FS || seg_reg == VCPU_SREG_GS)
		*ret = s.base + off;
	else
		*ret = off;

	/* TODO: check addr is canonical, otherwise inject #GP/#SS */

	return 0;
}

static int nested_vmx_get_vmptr(struct kvm_vcpu *vcpu, gpa_t *vmpointer,
				int *ret)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	gva_t gva;
	struct x86_exception e;
	int r;

	if (get_vmx_mem_address(vcpu, vmx->exit_qualification,
			vmcs_read32(VMX_INSTRUCTION_INFO), &gva)) {
		*ret = 1;
		return -EINVAL;
	}

	r = read_gva(vcpu, gva, vmpointer, sizeof(*vmpointer), &e);
	if (r < 0) {
		/*TODO: handle memory failure exception */
		*ret = 1;
		return -EINVAL;
	}

	return 0;
}

static int validate_vmcs_revision_id(struct kvm_vcpu *vcpu, gpa_t vmpointer)
{
	struct vmcs_config *vmcs_config = &pkvm_hyp->vmcs_config;
	u32 rev_id;

	read_gpa(vcpu, vmpointer, &rev_id, sizeof(rev_id));

	return (rev_id == vmcs_config->revision_id);
}

static bool check_vmx_permission(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	bool permit = true;

	/*TODO: check more env (cr, cpl) and inject #UD/#GP */
	if (!vmx->nested.vmxon)
		permit = false;

	return permit;
}

int handle_vmxon(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	gpa_t vmptr;
	int r;

	/*TODO: check env error(cr, efer, rflags, cpl) */
	if (vmx->nested.vmxon) {
		nested_vmx_result(VMfailValid, VMXERR_VMXON_IN_VMX_ROOT_OPERATION);
	} else {
		if (nested_vmx_get_vmptr(vcpu, &vmptr, &r)) {
			nested_vmx_result(VMfailInvalid, 0);
			return r;
		} else if (!validate_vmcs_revision_id(vcpu, vmptr)) {
			nested_vmx_result(VMfailInvalid, 0);
		} else {
			vmx->nested.vmxon_ptr = vmptr;
			vmx->nested.vmxon = true;

			nested_vmx_result(VMsucceed, 0);
		}
	}

	return 0;
}

int handle_vmxoff(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (check_vmx_permission(vcpu)) {
		vmx->nested.vmxon = false;
		vmx->nested.vmxon_ptr = INVALID_GPA;

		nested_vmx_result(VMsucceed, 0);
	}

	return 0;
}

void pkvm_init_nest(void)
{
	init_vmcs_shadow_fields();
	init_emulated_vmcs_fields();
}
