/*
 * mailbox: interprocessor communication module
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef MAILBOX_H
#define MAILBOX_H

typedef u32 mbox_msg_t;
struct mailbox;

typedef int __bitwise mailbox_irq_t;
#define IRQ_TX ((__force mailbox_irq_t) 1)
#define IRQ_RX ((__force mailbox_irq_t) 2)

int mailbox_msg_send(struct mailbox *, mbox_msg_t msg);

struct mailbox *mailbox_get(const char *, struct notifier_block *nb);
void mailbox_put(struct mailbox *mbox, struct notifier_block *nb);

void mailbox_save_ctx(struct mailbox *mbox);
void mailbox_restore_ctx(struct mailbox *mbox);
void mailbox_enable_irq(struct mailbox *mbox, mailbox_irq_t irq);
void mailbox_disable_irq(struct mailbox *mbox, mailbox_irq_t irq);

#endif /* MAILBOX_H */
