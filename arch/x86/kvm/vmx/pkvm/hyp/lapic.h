/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#ifndef _PKVM_LAPIC_H_
#define _PKVM_LAPIC_H_

int pkvm_setup_lapic(struct pkvm_pcpu *pcpu, int cpu);
#endif
