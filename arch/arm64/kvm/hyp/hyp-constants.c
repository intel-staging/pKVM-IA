// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kbuild.h>
#include <buddy_memory.h>

int main(void)
{
	DEFINE(STRUCT_HYP_PAGE_SIZE,	sizeof(struct pkvm_page));
	return 0;
}
