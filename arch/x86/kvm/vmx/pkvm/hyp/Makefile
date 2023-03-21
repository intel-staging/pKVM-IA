# SPDX-License-Identifier: GPL-2.0

KVM_PKVM = virt/kvm/pkvm

ccflags-y += -I $(srctree)/$(KVM_PKVM)/
ccflags-y += -I $(srctree)/arch/x86/kvm
ccflags-y += -I $(srctree)/arch/x86/kvm/vmx/pkvm/include
ccflags-y += -fno-stack-protector
ccflags-y += -D__DISABLE_EXPORTS
ccflags-y += -D__PKVM_HYP__

pkvm-hyp-obj	:= $(obj)/vmx_asm.o $(obj)/vmexit.o \
		   $(obj)/memory.o $(obj)/early_alloc.o \
		   $(obj)/pgtable.o $(obj)/mmu.o \
		   $(obj)/ept.o $(obj)/pkvm.o \
		   $(obj)/idt.o $(obj)/irq.o \
		   $(obj)/init_finalise.o $(obj)/nested.o \
		   $(obj)/vmx.o $(obj)/vmsr.o \
		   $(obj)/iommu.o $(obj)/iommu_debug.o \
		   $(obj)/mem_protect.o $(obj)/lapic.o \
		   $(obj)/ptdev.o $(obj)/iommu_spgt.o \
		   $(obj)/io_emulate.o $(obj)/trace.o

virt-dir	:= $(objtree)/$(KVM_PKVM)
pkvm-hyp-obj	+= $(virt-dir)/page_alloc.o

ifndef CONFIG_PKVM_INTEL_DEBUG
lib-dir		:= $(obj)/lib
lib2-dir	:= $(objtree)/lib
pkvm-hyp-obj	+= $(lib-dir)/memset_64.o
pkvm-hyp-obj	+= $(lib-dir)/memcpy_64.o
pkvm-hyp-obj	+= $(lib2-dir)/find_bit.o
ifdef CONFIG_DEBUG_LIST
pkvm-hyp-obj	+= $(lib-dir)/list_debug.o
endif
ifdef CONFIG_RETPOLINE
pkvm-hyp-obj	+= $(lib-dir)/retpoline.o
endif
endif

dir-obj		:= $(lib-dir) $(lib2-dir) $(virt-dir)

pkvm-rename-obj 	:= $(patsubst %.o,%.pkvm.o,$(pkvm-hyp-obj))
pkvm-obj		:= pkvm.o

$(dir-obj): FORCE
ifndef CONFIG_PKVM_INTEL_DEBUG
	$(Q)mkdir -p $(lib-dir) $(lib2-dir)
endif
	$(Q)mkdir -p $(virt-dir)

%.pkvm.o: %.c $(dir-obj) FORCE
	$(call if_changed_rule,cc_o_c)
%.pkvm.o: %.S $(dir-obj) FORCE
	$(call if_changed_rule,as_o_S)

$(obj)/pkvm.lds: $(src)/pkvm.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

LDFLAGS_pkvm.tmp.o := -r -T
$(obj)/pkvm.tmp.o: $(obj)/pkvm.lds $(pkvm-rename-obj) FORCE
	$(call if_changed,ld)

$(obj)/pkvm.o: $(obj)/pkvm.tmp.o FORCE
	$(call if_changed,pkvmcopy)

quiet_cmd_pkvmcopy = PKVMPCOPY $@
ifdef CONFIG_PKVM_INTEL_DEBUG
      cmd_pkvmcopy = $(OBJCOPY) --prefix-symbols= $< $@
else
      cmd_pkvmcopy = $(OBJCOPY) --prefix-symbols=__pkvm_ --remove-section=.retpoline_sites --remove-section=.return_sites $< $@
endif

obj-$(CONFIG_PKVM_INTEL)	+= $(pkvm-obj)

# Remove ftrace, Shadow Call Stack, and CFI CFLAGS.
# This is equivalent to the 'notrace', '__noscs', and '__nocfi' annotations.
KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_FTRACE) $(CC_FLAGS_SCS) $(CC_FLAGS_CFI), $(KBUILD_CFLAGS))
