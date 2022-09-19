/*
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/list.h>

bool __list_add_valid(struct list_head *new, struct list_head *prev,
		struct list_head *next)
{
	return true;
}

bool __list_del_entry_valid(struct list_head *entry)
{
	return true;
}
