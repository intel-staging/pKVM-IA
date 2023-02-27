/* SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2023 Intel Corporation
 */
#ifndef _PKVM_PCI_H_
#define _PKVM_PCI_H_

#define PCI_CFG_ADDR 0xcf8
#define PCI_CFG_DATA 0xcfc

union pci_cfg_addr_reg {
	u32 value;
	struct {
		u32 reg : 8;
		u32 bdf : 16;
		u32 resv : 7;
		u32 enable : 1;
	};
};

unsigned long pkvm_pci_cfg_space_read(u32 bdf, u32 offset, int size);
void pkvm_pci_cfg_space_write(u32 bdf, u32 offset, int size, unsigned long value);

int init_finalize_pci(struct pkvm_pci_info *pci);
#endif
