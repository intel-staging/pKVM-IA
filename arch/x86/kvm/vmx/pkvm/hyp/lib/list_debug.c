// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/list.h>

bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
		struct list_head *next)
{
	return true;
}

bool __list_del_entry_valid_or_report(struct list_head *entry)
{
	return true;
}
