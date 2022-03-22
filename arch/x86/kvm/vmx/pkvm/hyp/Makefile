# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/arch/x86/kvm
ccflags-y += -I $(srctree)/arch/x86/kvm/vmx/pkvm/include

pkvm-hyp-obj	:= vmx_asm.o vmexit.o

obj-$(CONFIG_PKVM_INTEL)	+= $(pkvm-hyp-obj)
