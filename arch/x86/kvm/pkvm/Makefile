# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/arch/x86/kvm

pkvm-hyp-y			:= early_alloc.o

pkvm-hyp-$(CONFIG_PKVM_INTEL)	+= vmx/host_vmentry.o vmx/host_vmx.o

pkvm-obj 			:= $(patsubst %.o,%.pkvm.o,$(pkvm-hyp-y))
obj-$(CONFIG_PKVM_X86)		+= pkvm.o

targets += $(pkvm-obj) pkvm.lds

$(obj)/%.pkvm.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/%.pkvm.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)

$(obj)/pkvm.lds: $(src)/pkvm.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

LDFLAGS_pkvm.o := -r -T
$(obj)/pkvm.o: $(obj)/pkvm.lds $(addprefix $(obj)/,$(pkvm-obj)) FORCE
	$(call if_changed,ld)
