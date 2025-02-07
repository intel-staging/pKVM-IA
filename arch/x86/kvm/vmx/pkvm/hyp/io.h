/* SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2023 Intel Corporation
 */
#ifndef _PKVM_IO_H_
#define _PKVM_IO_H_

/* Size mask for I/O access */
#define IO_SIZE_1 1
#define IO_SIZE_2 2
#define IO_SIZE_4 4
#define IO_SIZE_FULL 7

static inline void pkvm_pio_read(unsigned int port, int size, unsigned long *value)
{
	switch (size) {
	case IO_SIZE_1:
		*(u8 *)value = inb(port);
		break;
	case IO_SIZE_2:
		*(u16 *)value = inw(port);
		break;
	case IO_SIZE_4:
		*(u32 *)value = inl(port);
		break;
	default:
		break;
	}
}

static inline void pkvm_pio_write(unsigned int port, int size, unsigned long value)
{
	switch (size) {
	case IO_SIZE_1:
		outb((u8)value, port);
		break;
	case IO_SIZE_2:
		outw((u16)value, port);
		break;
	case IO_SIZE_4:
		outl((u32)value, port);
		break;
	default:
		break;
	}
}

#endif
