# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/arch/x86/kvm
ccflags-y += -I $(srctree)/arch/x86/kvm/pkvm/include

pkvm-hyp-obj			:= early_alloc.o

pkvm-hyp-obj			+= vmx/vmx_asm.o vmx/vmexit.o vmx/vmsr.o

obj-$(CONFIG_PKVM_INTEL)	+= $(pkvm-hyp-obj)
