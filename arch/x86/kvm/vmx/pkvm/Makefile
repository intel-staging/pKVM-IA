# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/arch/x86/kvm
ccflags-y += -I $(srctree)/arch/x86/kvm/vmx/pkvm/include

pkvm-obj		:= pkvm_host.o

obj-$(CONFIG_PKVM_INTEL)	+= $(pkvm-obj)
