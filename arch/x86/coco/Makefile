# SPDX-License-Identifier: GPL-2.0
CFLAGS_REMOVE_core.o	= -pg
KASAN_SANITIZE_core.o	:= n
CFLAGS_core.o		+= -fno-stack-protector

obj-y += core.o

obj-$(CONFIG_INTEL_TDX_GUEST)	+= tdx/ virt_exception.o
obj-$(CONFIG_PKVM_GUEST)	+= pkvm/ virt_exception.o
