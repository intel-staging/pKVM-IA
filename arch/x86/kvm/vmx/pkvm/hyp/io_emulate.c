// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Intel Corporation. */
#include <pkvm.h>
#include "ept.h"
#include "io.h"
#include "io_emulate.h"

struct pkvm_pio_emul_table host_pio_emul_table;
struct pkvm_mmio_emul_table host_mmio_emul_table;

static int pkvm_pio_default_in(struct kvm_vcpu *vcpu, struct pkvm_pio_req *req)
{
	pkvm_pio_read(req->port, req->size, req->value);
	return 0;
}

static int pkvm_pio_default_out(struct kvm_vcpu *vcpu, struct pkvm_pio_req *req)
{
	pkvm_pio_write(req->port, req->size, *req->value);
	return 0;
}

struct pkvm_pio_handler default_pio_handler = {
	.read = pkvm_pio_default_in,
	.write = pkvm_pio_default_out
};

/*
 * Not thread safe and should hold a lock if called concurrently.
 */
int register_host_pio_handler(struct pkvm_host_vm *host_vm, unsigned int port,
	unsigned int size_mask, pio_handler_t read, pio_handler_t write)
{
	struct pkvm_pio_emul_table *table;
	struct pkvm_pio_handler *handler;
	unsigned long index;
	u8 bit;

	table = &host_pio_emul_table;
	index = find_first_zero_bit(table->bitmap, PKVM_MAX_PIO_EMUL_NUM);
	if (index >= PKVM_MAX_PIO_EMUL_NUM)
		return -ENOSPC;

	__set_bit(index, table->bitmap);

	handler = &table->table[index];
	handler->port = port;
	handler->size_mask = size_mask;
	handler->read = read;
	handler->write = write;

	index = port >> 3U;
	bit = (u8)(1U << (port & 0x7U));
	host_vm->io_bitmap[index] |= bit;

	return 0;
}

static bool pio_access_valid(int size)
{
	return size == IO_SIZE_1 || size == IO_SIZE_2 || size == IO_SIZE_4;
}

static struct pkvm_pio_handler *get_pio_handler(struct pkvm_pio_emul_table *table,
	struct pkvm_pio_req *req)
{
	struct pkvm_pio_handler *handler;
	unsigned long index;
	/*
	 * Port I/O access is expected to only based on their address and have a
	 * fixed access width. Note that they might overlap, for example PCI config
	 * space addr port 0xcf8 and ACPI reset port 0xcf9. So match the handler
	 * strictly based on their base address and access width here.
	 *
	 * There are two special situations to consider. One case is that the base
	 * address matches but the access width differs, this is regarded as an
	 * invalid access and thus return a NULL handler. Another case is no base
	 * address matches. This is due to an overlapped I/O access that triggered
	 * the IO VM exit, but we are not intended to handle the base address. So
	 * in this case choose the default handler to do plain pio.
	 */
	for_each_set_bit(index, table->bitmap, PKVM_MAX_PIO_EMUL_NUM) {
		handler = &table->table[index];
		if (req->port == handler->port) {
			if (pio_access_valid(req->size) && (req->size & handler->size_mask))
				return handler;

			pkvm_err("pkvm: I/O port 0x%x mismatched access witdth %d",
				req->port, req->size);
			return NULL;
		}
	}

	return &default_pio_handler;
}

static int emulate_host_pio(struct kvm_vcpu *vcpu, struct pkvm_pio_req *req)
{
	struct pkvm_pio_emul_table *table;
	struct pkvm_pio_handler *handler;
	int ret = 0;

	table = &host_pio_emul_table;
	handler = get_pio_handler(table, req);
	if (!handler)
		return -EINVAL;

	if (req->direction == PKVM_IO_READ && handler->read)
		ret = handler->read(vcpu, req);
	else if (req->direction == PKVM_IO_WRITE && handler->write)
		ret = handler->write(vcpu, req);

	return ret;
}

int handle_host_pio(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qual;
	struct pkvm_pio_req req;
	int string;

	exit_qual = vmx->exit_qualification;

	string = (exit_qual & 16) != 0;
	if (string) {
		pkvm_err("pkvm: unsupported string instruction\n");
		return -EINVAL;
	}

	req.port = exit_qual >> 16;
	req.size = (exit_qual & 7) + 1;
	req.value = &vcpu->arch.regs[VCPU_REGS_RAX];
	req.direction = (exit_qual & 8) == 0;

	pkvm_dbg("pkvm: host %s I/O port 0x%x width %d value %lx", req.direction ?
		"write" : "read", req.port, req.size, *req.value);

	return emulate_host_pio(vcpu, &req);
}

static struct pkvm_mmio_handler *emul_mmio_lookup(struct pkvm_mmio_emul_table *table,
	unsigned long start, unsigned long end)
{
	struct pkvm_mmio_handler *handler;
	unsigned long index;

	for_each_set_bit(index, table->bitmap, PKVM_MAX_MMIO_EMUL_NUM) {
		handler = &table->table[index];
		if (start <= handler->end && handler->start <= end)
			return handler;
	}

	return NULL;
}

/*
 * Not thread safe and should hold a lock if called concurrently.
 */
int register_host_mmio_handler(unsigned long start, unsigned long end,
	mmio_handler_t read, mmio_handler_t write)
{
	struct pkvm_mmio_emul_table *table;
	struct pkvm_mmio_handler *handler;
	unsigned long index;
	int ret = 0;

	if (start > end)
		return -EINVAL;

	table = &host_mmio_emul_table;

	if (emul_mmio_lookup(table, start, end))
		return -EINVAL;

	index = find_first_zero_bit(table->bitmap, PKVM_MAX_MMIO_EMUL_NUM);
	if (index >= PKVM_MAX_MMIO_EMUL_NUM)
		return -ENOSPC;

	__set_bit(index, table->bitmap);

	handler = &table->table[index];
	handler->start = start;
	handler->end = end;
	handler->read = read;
	handler->write = write;

	host_ept_lock();
	ret = pkvm_host_ept_unmap(start, start, end - start + 1);
	host_ept_unlock();

	return ret;
}
