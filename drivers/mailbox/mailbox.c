/*
 * Mailbox framework
 *
 * Copyright (C) 2006-2009 Nokia Corporation. All rights reserved.
 *
 * Contact: Hiroshi DOYU <Hiroshi.DOYU@nokia.com>
 * Author: Loic Pallardy <loic.pallardy@st.com> for ST-Ericsson
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/err.h>
#include <linux/notifier.h>
#include <linux/module.h>

#include "mailbox_internal.h"

static struct mailbox **mboxes;

static int mbox_configured;
static DEFINE_MUTEX(mbox_configured_lock);

static unsigned int mbox_kfifo_size = CONFIG_MBOX_KFIFO_SIZE;
module_param(mbox_kfifo_size, uint, S_IRUGO);
MODULE_PARM_DESC(mbox_kfifo_size, "Size of mailbox kfifo (bytes)");

/* Mailbox FIFO handle functions */
static inline void mbox_read(struct mailbox *mbox, struct mailbox_msg *msg)
{
	mbox->ops->read(mbox, msg);
}
static inline int mbox_write(struct mailbox *mbox, struct mailbox_msg *msg)
{
	return mbox->ops->write(mbox, msg);
}
static inline int mbox_empty(struct mailbox *mbox)
{
	return mbox->ops->empty(mbox);
}

/* Mailbox IRQ handle functions */
static inline void ack_mbox_irq(struct mailbox *mbox, mailbox_irq_t irq)
{
	if (mbox->ops->ack_irq)
		mbox->ops->ack_irq(mbox, irq);
}
static inline int is_mbox_irq(struct mailbox *mbox, mailbox_irq_t irq)
{
	return mbox->ops->is_irq(mbox, irq);
}

/*
 * message sender
 */
static int __mbox_poll_for_space(struct mailbox *mbox)
{
	return mbox->ops->poll_for_space(mbox);
}

int mailbox_msg_send(struct mailbox *mbox, struct mailbox_msg *msg)
{
	struct mailbox_queue *mq = mbox->txq;
	int ret = 0, len;

	mutex_lock(&mq->mlock);

	if (kfifo_avail(&mq->fifo) < (sizeof(*msg) + msg->size)) {
		ret = -ENOMEM;
		goto out;
	}

	if (kfifo_is_empty(&mq->fifo) && !__mbox_poll_for_space(mbox)) {
		ret = mbox_write(mbox, msg);
		goto out;
	}

	len = kfifo_in(&mq->fifo, (unsigned char *)msg, sizeof(*msg));
	WARN_ON(len != sizeof(*msg));

	if (msg->size && msg->pdata) {
		len = kfifo_in(&mq->fifo, (unsigned char *)msg->pdata,
								msg->size);
		WARN_ON(len != msg->size);
	}

	tasklet_schedule(&mbox->txq->tasklet);

out:
	mutex_unlock(&mq->mlock);
	return ret;
}
EXPORT_SYMBOL(mailbox_msg_send);

#define TRANSFER_TIMEOUT 30000 /* Becomes ~3s timeout */

static struct mailbox_msg no_irq_msg_res;

struct mailbox_msg *mailbox_msg_send_receive_no_irq(struct mailbox *mbox,
		struct mailbox_msg *msg)
{
	int ret = 0;
	int count = 0;

	BUG_ON(!irqs_disabled());

	if (likely(mbox->ops->write && mbox->ops->read)) {
		if (__mbox_poll_for_space(mbox)) {
			ret = -EBUSY;
			goto out;
		}
		mbox->ops->write(mbox, msg);
		while (!is_mbox_irq(mbox, IRQ_RX)) {
			udelay(100);
			cpu_relax();
			count++;
			if (count > TRANSFER_TIMEOUT) {
				pr_err("%s: Error: transfer timed out\n",
						__func__);
				ret = -EINVAL;
				goto out;
			}
		}
		mbox->ops->read(mbox, &no_irq_msg_res);
		ack_mbox_irq(mbox, IRQ_RX);
	} else {
		ret = -EINVAL;
	}

out:
	BUG_ON(ret < 0);

	return &no_irq_msg_res;
}
EXPORT_SYMBOL(mailbox_msg_send_receive_no_irq);

int mailbox_msg_send_no_irq(struct mailbox *mbox,
		struct mailbox_msg *msg)
{
	int ret = 0;

	BUG_ON(!irqs_disabled());

	if (likely(mbox->ops->write)) {
		if (__mbox_poll_for_space(mbox)) {
			ret = -EBUSY;
			goto out;
		}
		mbox->ops->write(mbox, msg);
	} else {
		ret = -EINVAL;
	}

out:
	WARN_ON(ret < 0);

	return ret;
}
EXPORT_SYMBOL(mailbox_msg_send_no_irq);

void mailbox_save_ctx(struct mailbox *mbox)
{
	if (!mbox->ops->save_ctx) {
		dev_err(mbox->dev, "%s:\tno save\n", __func__);
		return;
	}

	mbox->ops->save_ctx(mbox);
}
EXPORT_SYMBOL(mailbox_save_ctx);

void mailbox_restore_ctx(struct mailbox *mbox)
{
	if (!mbox->ops->restore_ctx) {
		dev_err(mbox->dev, "%s:\tno restore\n", __func__);
		return;
	}

	mbox->ops->restore_ctx(mbox);
}
EXPORT_SYMBOL(mailbox_restore_ctx);

void mailbox_enable_irq(struct mailbox *mbox, mailbox_irq_t irq)
{
	mbox->ops->enable_irq(mbox, irq);
}
EXPORT_SYMBOL(mailbox_enable_irq);

void mailbox_disable_irq(struct mailbox *mbox, mailbox_irq_t irq)
{
	mbox->ops->disable_irq(mbox, irq);
}
EXPORT_SYMBOL(mailbox_disable_irq);

static void mbox_tx_tasklet(unsigned long tx_data)
{
	struct mailbox *mbox = (struct mailbox *)tx_data;
	struct mailbox_queue *mq = mbox->txq;
	struct mailbox_msg msg;
	int ret;
	unsigned char tx_data_buf[CONFIG_MBOX_DATA_SIZE];

	while (kfifo_len(&mq->fifo)) {
		if (__mbox_poll_for_space(mbox)) {
			mailbox_enable_irq(mbox, IRQ_TX);
			break;
		}

		ret = kfifo_out(&mq->fifo, (unsigned char *)&msg, sizeof(msg));
		WARN_ON(ret != sizeof(msg));

		if (msg.size) {
			ret = kfifo_out(&mq->fifo, tx_data_buf,
							sizeof(msg.size));
			WARN_ON(ret != msg.size);
			msg.pdata = tx_data_buf;
		}

		ret = mbox_write(mbox, &msg);
		WARN_ON(ret);
	}
}

/*
 * Message receiver(workqueue)
 */
static unsigned char rx_work_data[CONFIG_MBOX_DATA_SIZE];

static void mbox_rx_work(struct work_struct *work)
{
	struct mailbox_queue *mq =
		container_of(work, struct mailbox_queue, work);
	int len;
	struct mailbox *mbox = mq->mbox;
	struct mailbox_msg msg;

	while (kfifo_len(&mq->fifo) >= sizeof(msg)) {
		len = kfifo_out(&mq->fifo, (unsigned char *)&msg, sizeof(msg));
		WARN_ON(len != sizeof(msg));

		if (msg.size) {
			len = kfifo_out(&mq->fifo, rx_work_data, msg.size);
			WARN_ON(len != msg.size);
			msg.pdata = rx_work_data;
		}

		blocking_notifier_call_chain(&mbox->notifier, len,
								(void *)&msg);
		spin_lock_irq(&mq->lock);
		if (mq->full) {
			mq->full = false;
			mailbox_enable_irq(mbox, IRQ_RX);
		}
		spin_unlock_irq(&mq->lock);
	}
}

/*
 * Mailbox interrupt handler
 */
static void __mbox_tx_interrupt(struct mailbox *mbox)
{
	mailbox_disable_irq(mbox, IRQ_TX);
	ack_mbox_irq(mbox, IRQ_TX);
	tasklet_schedule(&mbox->txq->tasklet);
}

static void __mbox_rx_interrupt(struct mailbox *mbox)
{
	struct mailbox_queue *mq = mbox->rxq;
	struct mailbox_msg msg;
	int len;

	while (!mbox_empty(mbox)) {
		if (unlikely(kfifo_avail(&mq->fifo) <
				(sizeof(msg) + CONFIG_MBOX_DATA_SIZE))) {
			mailbox_disable_irq(mbox, IRQ_RX);
			mq->full = true;
			goto nomem;
		}

		mbox_read(mbox, &msg);

		len = kfifo_in(&mq->fifo, (unsigned char *)&msg, sizeof(msg));
		WARN_ON(len != sizeof(msg));

		if (msg.pdata && msg.size) {
			len = kfifo_in(&mq->fifo, (unsigned char *)msg.pdata,
					msg.size);
			WARN_ON(len != msg.size);
		}
	}

	/* no more messages in the fifo. clear IRQ source. */
	ack_mbox_irq(mbox, IRQ_RX);
nomem:
	schedule_work(&mbox->rxq->work);
}

static irqreturn_t mbox_interrupt(int irq, void *p)
{
	struct mailbox *mbox = p;

	if (is_mbox_irq(mbox, IRQ_TX))
		__mbox_tx_interrupt(mbox);

	if (is_mbox_irq(mbox, IRQ_RX))
		__mbox_rx_interrupt(mbox);

	return IRQ_HANDLED;
}

static struct mailbox_queue *mbox_queue_alloc(struct mailbox *mbox,
		void (*work) (struct work_struct *),
		void (*tasklet)(unsigned long))
{
	struct mailbox_queue *mq;

	mq = kzalloc(sizeof(struct mailbox_queue), GFP_KERNEL);
	if (!mq)
		return NULL;

	spin_lock_init(&mq->lock);
	mutex_init(&mq->mlock);

	if (kfifo_alloc(&mq->fifo, mbox_kfifo_size, GFP_KERNEL))
		goto error;

	if (work)
		INIT_WORK(&mq->work, work);

	if (tasklet)
		tasklet_init(&mq->tasklet, tasklet, (unsigned long)mbox);
	return mq;
error:
	kfree(mq);
	return NULL;
}

static void mbox_queue_free(struct mailbox_queue *q)
{
	kfifo_free(&q->fifo);
	kfree(q);
}

static int mailbox_startup(struct mailbox *mbox)
{
	int ret = 0;
	struct mailbox_queue *mq;

	mutex_lock(&mbox_configured_lock);
	if (!mbox_configured++) {
		if (likely(mbox->ops->startup)) {
			ret = mbox->ops->startup(mbox);
			if (unlikely(ret))
				goto fail_startup;
		} else
			goto fail_startup;
	}

	if (!mbox->use_count++) {
		mq = mbox_queue_alloc(mbox, NULL, mbox_tx_tasklet);
		if (!mq) {
			ret = -ENOMEM;
			goto fail_alloc_txq;
		}
		mbox->txq = mq;

		mq = mbox_queue_alloc(mbox, mbox_rx_work, NULL);
		if (!mq) {
			ret = -ENOMEM;
			goto fail_alloc_rxq;
		}
		mbox->rxq = mq;
		mq->mbox = mbox;
		ret = request_irq(mbox->irq, mbox_interrupt,
				IRQF_SHARED | IRQF_NO_SUSPEND,
				mbox->name, mbox);
		if (unlikely(ret)) {
			pr_err("failed to register mailbox interrupt:%d\n",
					ret);
			goto fail_request_irq;
		}

		mailbox_enable_irq(mbox, IRQ_RX);
	}
	mutex_unlock(&mbox_configured_lock);
	return 0;

fail_request_irq:
	mbox_queue_free(mbox->rxq);
fail_alloc_rxq:
	mbox_queue_free(mbox->txq);
fail_alloc_txq:
	if (mbox->ops->shutdown)
		mbox->ops->shutdown(mbox);
	mbox->use_count--;
fail_startup:
	mbox_configured--;
	mutex_unlock(&mbox_configured_lock);
	return ret;
}

static void mailbox_fini(struct mailbox *mbox)
{
	mutex_lock(&mbox_configured_lock);

	if (!--mbox->use_count) {
		mailbox_disable_irq(mbox, IRQ_RX);
		free_irq(mbox->irq, mbox);
		tasklet_kill(&mbox->txq->tasklet);
		flush_work(&mbox->rxq->work);
		mbox_queue_free(mbox->txq);
		mbox_queue_free(mbox->rxq);
	}

	if (likely(mbox->ops->shutdown)) {
		if (!--mbox_configured)
			mbox->ops->shutdown(mbox);
	}

	mutex_unlock(&mbox_configured_lock);
}

struct mailbox *mailbox_get(const char *name, struct notifier_block *nb)
{
	struct mailbox *_mbox, *mbox = NULL;
	int i, ret;

	if (!mboxes)
		return ERR_PTR(-EINVAL);

	for (i = 0; (_mbox = mboxes[i]); i++) {
		if (!strcmp(_mbox->name, name)) {
			mbox = _mbox;
			break;
		}
	}

	if (!mbox)
		return ERR_PTR(-ENOENT);

	if (nb)
		blocking_notifier_chain_register(&mbox->notifier, nb);

	ret = mailbox_startup(mbox);
	if (ret) {
		blocking_notifier_chain_unregister(&mbox->notifier, nb);
		return ERR_PTR(-ENODEV);
	}

	return mbox;
}
EXPORT_SYMBOL(mailbox_get);

void mailbox_put(struct mailbox *mbox, struct notifier_block *nb)
{
	if (nb)
		blocking_notifier_chain_unregister(&mbox->notifier, nb);
	mailbox_fini(mbox);
}
EXPORT_SYMBOL(mailbox_put);

static struct class mailbox_class = { .name = "mbox", };

int mailbox_register(struct device *parent, struct mailbox **list)
{
	int ret;
	int i;

	mboxes = list;
	if (!mboxes)
		return -EINVAL;

	for (i = 0; mboxes[i]; i++) {
		struct mailbox *mbox = mboxes[i];
		mbox->dev = device_create(&mailbox_class,
				parent, 0, mbox, "%s", mbox->name);
		if (IS_ERR(mbox->dev)) {
			ret = PTR_ERR(mbox->dev);
			goto err_out;
		}

		BLOCKING_INIT_NOTIFIER_HEAD(&mbox->notifier);
	}
	return 0;

err_out:
	while (i--)
		device_unregister(mboxes[i]->dev);
	return ret;
}
EXPORT_SYMBOL(mailbox_register);

int mailbox_unregister(void)
{
	int i;

	if (!mboxes)
		return -EINVAL;

	for (i = 0; mboxes[i]; i++)
		device_unregister(mboxes[i]->dev);
	mboxes = NULL;
	return 0;
}
EXPORT_SYMBOL(mailbox_unregister);

static int __init mailbox_init(void)
{
	int err;

	err = class_register(&mailbox_class);
	if (err)
		return err;

	/* kfifo size sanity check: alignment and minimal size */
	mbox_kfifo_size = ALIGN(mbox_kfifo_size, sizeof(struct mailbox_msg));
	mbox_kfifo_size = max_t(unsigned int, mbox_kfifo_size,
			sizeof(struct mailbox_msg) + CONFIG_MBOX_DATA_SIZE);
	return 0;
}
subsys_initcall(mailbox_init);

static void __exit mailbox_exit(void)
{
	class_unregister(&mailbox_class);
}
module_exit(mailbox_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("mailbox framework: interrupt driven messaging");
MODULE_AUTHOR("Toshihiro Kobayashi");
MODULE_AUTHOR("Hiroshi DOYU");
