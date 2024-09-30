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

#endif
