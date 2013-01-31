/*
 * mailbox: interprocessor communication module
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef MAILBOX_INTERNAL_H
#define MAILBOX_INTERNAL_H

#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/kfifo.h>
#include <linux/mailbox.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

typedef int __bitwise mailbox_type_t;
#define MBOX_HW_FIFO1_TYPE	((__force mailbox_type_t) 1)
#define MBOX_HW_FIFO2_TYPE	((__force mailbox_type_t) 2)
#define MBOX_SHARED_MEM_TYPE	((__force mailbox_type_t) 3)

struct mailbox_ops {
	mailbox_type_t	type;
	int		(*startup)(struct mailbox *mbox);
	void		(*shutdown)(struct mailbox *mbox);
	/* mailbox access */
	void		(*read)(struct mailbox *mbox, struct mailbox_msg *msg);
	int		(*write)(struct mailbox *mbox, struct mailbox_msg *msg);
	int		(*empty)(struct mailbox *mbox);
	int		(*poll_for_space)(struct mailbox *mbox);
	/* irq */
	void		(*enable_irq)(struct mailbox *mbox, mailbox_irq_t irq);
	void		(*disable_irq)(struct mailbox *mbox, mailbox_irq_t irq);
	void		(*ack_irq)(struct mailbox *mbox, mailbox_irq_t irq);
	int		(*is_irq)(struct mailbox *mbox, mailbox_irq_t irq);
	/* ctx */
	void		(*save_ctx)(struct mailbox *mbox);
	void		(*restore_ctx)(struct mailbox *mbox);
};

struct mailbox_queue {
	spinlock_t		lock;
	struct mutex		mlock;
	struct kfifo		fifo;
	struct work_struct	work;
	struct tasklet_struct	tasklet;
	struct mailbox		*mbox;
	bool full;
};

struct mailbox {
	const char		*name;
	unsigned int		id;
	unsigned int		irq;
	struct mailbox_queue	*txq, *rxq;
	struct mailbox_ops	*ops;
	struct device		*dev;
	void			*priv;
	int			use_count;
	struct blocking_notifier_head	notifier;
};

void mailbox_init_seq(struct mailbox *);

int mailbox_register(struct device *parent, struct mailbox **);
int mailbox_unregister(void);

#endif /* MAILBOX_INTERNAL_H */
