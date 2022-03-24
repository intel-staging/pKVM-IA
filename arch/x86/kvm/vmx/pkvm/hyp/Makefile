# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/arch/x86/kvm
ccflags-y += -I $(srctree)/arch/x86/kvm/vmx/pkvm/include
ccflags-y += -fno-stack-protector
ccflags-y += -D__DISABLE_EXPORTS
ccflags-y += -D__PKVM_HYP__

pkvm-hyp-obj	:= $(obj)/vmx_asm.o $(obj)/vmexit.o \
		   $(obj)/memory.o

lib-dir		:= $(obj)/lib
ifdef CONFIG_RETPOLINE
pkvm-hyp-obj	+= $(lib-dir)/retpoline.o
endif

dir-obj		:= $(lib-dir)

pkvm-rename-obj 	:= $(patsubst %.o,%.pkvm.o,$(pkvm-hyp-obj))
pkvm-obj		:= pkvm.o

$(dir-obj): FORCE
	$(Q)mkdir -p $(lib-dir)

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
      cmd_pkvmcopy = $(OBJCOPY) --prefix-symbols=__pkvm_ --remove-section=.retpoline_sites --remove-section=.return_sites $< $@

obj-$(CONFIG_PKVM_INTEL)	+= $(pkvm-obj)

# Remove ftrace, Shadow Call Stack, and CFI CFLAGS.
# This is equivalent to the 'notrace', '__noscs', and '__nocfi' annotations.
KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_FTRACE) $(CC_FLAGS_SCS) $(CC_FLAGS_CFI), $(KBUILD_CFLAGS))
