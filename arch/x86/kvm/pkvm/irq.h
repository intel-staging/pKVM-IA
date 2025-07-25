/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_IRQ_H
#define __PKVM_X86_IRQ_H

typedef void (*exception_handler_t)(struct pt_regs *regs, int vector, bool has_error_code);
void handle_exception(struct pt_regs *regs, int vector, bool has_error_code);

#endif
