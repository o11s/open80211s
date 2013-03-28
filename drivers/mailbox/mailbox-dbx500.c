/*
 * Copyright (C) ST-Ericsson SA 2012
 *
 * License Terms: GNU General Public License v2
 * Author: Loic Pallardy <loic.pallardy@st.com> for ST-Ericsson
 * DBX500 PRCM Mailbox driver
 *
 */

#include <linux/module.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/platform_data/mailbox-dbx500.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/irqdomain.h>

#include "mailbox_internal.h"

#define MAILBOX_LEGACY		0
#define MAILBOX_UPAP		1

enum {
	MAILBOX_BLOCKING,
	MAILBOX_ATOMIC,
};

/* CPU mailbox registers */
#define PRCM_MBOX_CPU_VAL	0x0fc
#define PRCM_MBOX_CPU_SET	0x100
#define PRCM_MBOX_CPU_CLR	0x104

#define PRCM_ARM_IT1_CLR	0x48C
#define PRCM_ARM_IT1_VAL	0x494

#define NUM_MB 8
#define MBOX_BIT BIT
#define ALL_MBOX_BITS (MBOX_BIT(NUM_MB) - 1)

/* CPU mailbox shared memory */
#define PRCM_MBOX_LEGACY_SIZE		0x220
#define _PRCM_MBOX_HEADER		0x214 /* 16 bytes */
#define PRCM_MBOX_HEADER_REQ_MB0	(_PRCM_MBOX_HEADER + 0x0)
#define PRCM_MBOX_HEADER_REQ_MB1	(_PRCM_MBOX_HEADER + 0x1)
#define PRCM_MBOX_HEADER_REQ_MB2	(_PRCM_MBOX_HEADER + 0x2)
#define PRCM_MBOX_HEADER_REQ_MB3	(_PRCM_MBOX_HEADER + 0x3)
#define PRCM_MBOX_HEADER_REQ_MB4	(_PRCM_MBOX_HEADER + 0x4)
#define PRCM_MBOX_HEADER_REQ_MB5	(_PRCM_MBOX_HEADER + 0x5)
#define PRCM_MBOX_HEADER_ACK_MB0	(_PRCM_MBOX_HEADER + 0x8)

/* Req Mailboxes */
#define PRCM_REQ_MB0			0x208 /* 12 bytes  */
#define PRCM_REQ_MB1			0x1FC /* 12 bytes  */
#define PRCM_REQ_MB2			0x1EC /* 16 bytes  */
#define PRCM_REQ_MB3			0x78  /* 372 bytes  */
#define PRCM_REQ_MB4			0x74  /* 4 bytes  */
#define PRCM_REQ_MB5			0x70  /* 4 bytes  */
#define PRCM_REQ_PASR			0x30 /* 4 bytes */

/* Ack Mailboxes */
#define PRCM_ACK_MB0			0x34 /* 52 bytes  */
#define PRCM_ACK_MB1			0x30 /* 4 bytes */
#define PRCM_ACK_MB2			0x2C /* 4 bytes */
#define PRCM_ACK_MB3			0x28 /* 4 bytes */
#define PRCM_ACK_MB4			0x24 /* 4 bytes */
#define PRCM_ACK_MB5			0x20 /* 4 bytes */

/* Ack Mailboxe sizes */
#define PRCM_ACK_MB0_SIZE		0x24 /* 52 bytes  */
#define PRCM_ACK_MB1_SIZE		0x4 /* 4 bytes */
#define PRCM_ACK_MB2_SIZE		0x1 /* 1 bytes */
#define PRCM_ACK_MB3_SIZE		0x2 /* 2 bytes */
#define PRCM_ACK_MB4_SIZE		0x0 /* 0 bytes */
#define PRCM_ACK_MB5_SIZE		0x4 /* 4 bytes */

static void __iomem *mbox_base;
static void __iomem *tcdm_mem_base;

static u8 prcm_mbox_irq_mask; /* masked by default */
static DEFINE_SPINLOCK(prcm_mbox_irqs_lock);

struct dbx500_mbox_priv {
	int			access_mode;
	int			type;
	int			header_size;
	unsigned int		tx_header_offset;
	unsigned int		rx_header_offset;
	unsigned int		tx_offset;
	unsigned int		rx_offset;
	unsigned int		rx_size;
	unsigned int		sw_irq;
	bool			empty_flag;
};

static inline unsigned int mbox_read_reg(size_t ofs)
{
	return __raw_readl(mbox_base + ofs);
}

static inline void mbox_write_reg(u32 val, size_t ofs)
{
	__raw_writel(val, mbox_base + ofs);
}

/* Mailbox H/W preparations */
static struct irq_chip dbx500_mbox_irq_chip;
static struct irq_domain *dbx500_mbox_irq_domain;

static int dbx500_mbox_startup(struct mailbox *mbox)
{
	/* Nothing to do */
	return 0;
}

/* Mailbox IRQ handle functions */

static void dbx500_mbox_enable_irq(struct mailbox *mbox, mailbox_irq_t irq)
{
	unsigned long flags;

	spin_lock_irqsave(&prcm_mbox_irqs_lock, flags);

	prcm_mbox_irq_mask |= MBOX_BIT(mbox->id);

	spin_unlock_irqrestore(&prcm_mbox_irqs_lock, flags);

}

static void dbx500_mbox_disable_irq(struct mailbox *mbox, mailbox_irq_t irq)
{
	unsigned long flags;

	spin_lock_irqsave(&prcm_mbox_irqs_lock, flags);

	prcm_mbox_irq_mask &= ~MBOX_BIT(mbox->id);

	spin_unlock_irqrestore(&prcm_mbox_irqs_lock, flags);

}

static void dbx500_mbox_ack_irq(struct mailbox *mbox, mailbox_irq_t irq)
{
	if (irq == IRQ_RX)
		mbox_write_reg(MBOX_BIT(mbox->id), PRCM_ARM_IT1_CLR);
}

static int dbx500_mbox_is_irq(struct mailbox *mbox, mailbox_irq_t irq)
{
	struct dbx500_mbox_priv *priv = (struct dbx500_mbox_priv *)mbox->priv;

	if (irq == IRQ_RX) {
		if (mbox_read_reg(PRCM_ARM_IT1_VAL) & MBOX_BIT(mbox->id)) {
			priv->empty_flag = true;
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

/* message management */

static int dbx500_mbox_is_ready(struct mailbox *mbox)
{
	return mbox_read_reg(PRCM_MBOX_CPU_VAL) & MBOX_BIT(mbox->id);
}

static int dbx500_mbox_write(struct mailbox *mbox,
		struct mailbox_msg *msg)
{
	int j;
	struct dbx500_mbox_priv *priv = (struct dbx500_mbox_priv *)mbox->priv;

	if (msg->size && !msg->pdata)
		return -EINVAL;

	while (dbx500_mbox_is_ready(mbox))
		cpu_relax();

	/* write header */
	if (priv->header_size)
		writeb(msg->header, tcdm_mem_base + priv->tx_header_offset);

	/* write data */
	for (j = 0; j < msg->size; j++)
		writeb(((unsigned char *)msg->pdata)[j],
				tcdm_mem_base + priv->tx_offset + j);

	/* send event */
	mbox_write_reg(MBOX_BIT(mbox->id), PRCM_MBOX_CPU_SET);

	return 0;
}

static void dbx500_mbox_read(struct mailbox *mbox, struct mailbox_msg *msg)
{
	struct dbx500_mbox_priv *priv = (struct dbx500_mbox_priv *)mbox->priv;

	msg->header = readb(tcdm_mem_base + priv->rx_header_offset);
	msg->pdata = (unsigned char *)(tcdm_mem_base + priv->rx_offset);

	msg->size = priv->rx_size;
	priv->empty_flag = false;
}

static int dbx500_mbox_empty(struct mailbox *mbox)
{
	struct dbx500_mbox_priv *priv = (struct dbx500_mbox_priv *)mbox->priv;
	if (priv->empty_flag)
		return 0;
	else
		return 1;
}

static int dbx500_mbox_poll_for_space(struct mailbox *mbox)
{
	return 0;
}
/*  interrupt management */

/*  mask/unmask must be managed by SW */

static void mbox_irq_mask(struct irq_data *d)
{
	unsigned long flags;

	spin_lock_irqsave(&prcm_mbox_irqs_lock, flags);

	prcm_mbox_irq_mask &= ~MBOX_BIT(d->hwirq);

	spin_unlock_irqrestore(&prcm_mbox_irqs_lock, flags);
}

static void mbox_irq_unmask(struct irq_data *d)
{
	unsigned long flags;

	spin_lock_irqsave(&prcm_mbox_irqs_lock, flags);

	prcm_mbox_irq_mask |= MBOX_BIT(d->hwirq);

	spin_unlock_irqrestore(&prcm_mbox_irqs_lock, flags);
}

static void mbox_irq_ack(struct irq_data *d)
{
	mbox_write_reg(MBOX_BIT(d->hwirq), PRCM_ARM_IT1_CLR);
}

static struct irq_chip dbx500_mbox_irq_chip = {
	.name		= "dbx500_mbox",
	.irq_disable	= mbox_irq_unmask,
	.irq_ack	= mbox_irq_ack,
	.irq_mask	= mbox_irq_mask,
	.irq_unmask	= mbox_irq_unmask,
};

static int dbx500_mbox_irq_map(struct irq_domain *d, unsigned int irq,
			       irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &dbx500_mbox_irq_chip,
				handle_simple_irq);
	set_irq_flags(irq, IRQF_VALID);

	return 0;
}

static struct irq_domain_ops dbx500_mbox_irq_ops = {
	.map    = dbx500_mbox_irq_map,
	.xlate  = irq_domain_xlate_twocell,
};

static irqreturn_t dbx500_mbox_irq_handler(int irq, void *data)
{
	u32 bits;
	u8 n;

	bits = (mbox_read_reg(PRCM_ARM_IT1_VAL) & ALL_MBOX_BITS);
	if (unlikely(!bits))
		return IRQ_NONE;

	bits &= prcm_mbox_irq_mask;

	for (n = 0; bits; n++) {
		if (bits & MBOX_BIT(n)) {
			bits -= MBOX_BIT(n);
			generic_handle_irq(
				irq_find_mapping(dbx500_mbox_irq_domain, n));
		}
	}
	return IRQ_HANDLED;
}

/* 5 mailboxes AP <--> PRCMU */
static struct mailbox_ops dbx500_mbox_ops = {
	.type		= MBOX_SHARED_MEM_TYPE,
	.startup	= dbx500_mbox_startup,
	.enable_irq	= dbx500_mbox_enable_irq,
	.disable_irq	= dbx500_mbox_disable_irq,
	.ack_irq	= dbx500_mbox_ack_irq,
	.is_irq		= dbx500_mbox_is_irq,
	.read		= dbx500_mbox_read,
	.write		= dbx500_mbox_write,
	.empty		= dbx500_mbox_empty,
	.poll_for_space = dbx500_mbox_poll_for_space,
};

struct dbx500_mbox_priv mbox0_priv = {
	.access_mode		= MAILBOX_ATOMIC,
	.type			= MAILBOX_LEGACY,
	.tx_header_offset	= PRCM_MBOX_HEADER_REQ_MB0,
	.header_size		= 1,
	.tx_offset		= PRCM_REQ_MB0,
	.rx_header_offset	= PRCM_MBOX_HEADER_ACK_MB0,
	.rx_offset		= PRCM_ACK_MB0,
	.rx_size		= PRCM_ACK_MB0_SIZE,
};

struct mailbox mbox0_info = {
	.name	= "mbox0",
	.id	= 0,
	.ops	= &dbx500_mbox_ops,
	.priv	= &mbox0_priv,
};

struct dbx500_mbox_priv mbox1_priv = {
	.access_mode		= MAILBOX_BLOCKING,
	.type			= MAILBOX_LEGACY,
	.tx_header_offset	= PRCM_MBOX_HEADER_REQ_MB1,
	.header_size		= 1,
	.tx_offset		= PRCM_REQ_MB1,
	.rx_header_offset	= PRCM_MBOX_HEADER_REQ_MB1,
	.rx_offset		= PRCM_ACK_MB1,
	.rx_size		= PRCM_ACK_MB1_SIZE,
};

struct mailbox mbox1_info = {
	.name	= "mbox1",
	.id	= 1,
	.ops	= &dbx500_mbox_ops,
	.priv	= &mbox1_priv,
};

struct dbx500_mbox_priv mbox2_priv = {
	.access_mode		= MAILBOX_BLOCKING,
	.type			= MAILBOX_LEGACY,
	.tx_header_offset	= PRCM_MBOX_HEADER_REQ_MB2,
	.header_size		= 1,
	.tx_offset		= PRCM_REQ_MB2,
	.rx_header_offset	= PRCM_MBOX_HEADER_REQ_MB2,
	.rx_offset		= PRCM_ACK_MB2,
	.rx_size		= PRCM_ACK_MB2_SIZE,
};

struct mailbox mbox2_info = {
	.name	= "mbox2",
	.id	= 2,
	.ops	= &dbx500_mbox_ops,
	.priv	= &mbox2_priv,
};

struct dbx500_mbox_priv mbox3_priv = {
	.access_mode		= MAILBOX_BLOCKING,
	.type			= MAILBOX_LEGACY,
	.tx_header_offset	= PRCM_MBOX_HEADER_REQ_MB3,
	.header_size		= 1,
	.tx_offset		= PRCM_REQ_MB3,
	.rx_header_offset	= PRCM_MBOX_HEADER_REQ_MB3,
	.rx_offset		= PRCM_ACK_MB3,
	.rx_size		= PRCM_ACK_MB3_SIZE,
};

struct mailbox mbox3_info = {
	.name	= "mbox3",
	.id	= 3,
	.ops	= &dbx500_mbox_ops,
	.priv	= &mbox3_priv,
};

struct dbx500_mbox_priv mbox4_priv = {
	.access_mode		= MAILBOX_BLOCKING,
	.type			= MAILBOX_LEGACY,
	.tx_header_offset	= PRCM_MBOX_HEADER_REQ_MB4,
	.header_size		= 1,
	.tx_offset		= PRCM_REQ_MB4,
	.rx_header_offset	= PRCM_MBOX_HEADER_REQ_MB4,
	.rx_offset		= PRCM_ACK_MB4,
	.rx_size		= PRCM_ACK_MB4_SIZE,
};

struct mailbox mbox4_info = {
	.name	= "mbox4",
	.id	= 4,
	.ops	= &dbx500_mbox_ops,
	.priv	= &mbox4_priv,
};

struct dbx500_mbox_priv mbox5_priv = {
	.access_mode		= MAILBOX_BLOCKING,
	.type			= MAILBOX_LEGACY,
	.tx_header_offset	= PRCM_MBOX_HEADER_REQ_MB5,
	.header_size		= 1,
	.tx_offset		= PRCM_REQ_MB5,
	.rx_header_offset	= PRCM_MBOX_HEADER_REQ_MB5,
	.rx_offset		= PRCM_ACK_MB5,
	.rx_size		= PRCM_ACK_MB5_SIZE,
};

struct mailbox mbox5_info = {
	.name	= "mbox5",
	.id	= 5,
	.ops	= &dbx500_mbox_ops,
	.priv	= &mbox5_priv,
};

struct mailbox mbox6_info = {
	.name	= "mbox6",
	.id	= 6,
	.ops	= &dbx500_mbox_ops,
};

struct mailbox mbox7_info = {
	.name	= "mbox7",
	.id	= 7,
	.ops	= &dbx500_mbox_ops,
};

/* x540 mailbox definition */
struct dbx500_mbox_priv mbox1_upap_priv = {
	.access_mode	= MAILBOX_BLOCKING,
	.type			= MAILBOX_UPAP,
	.tx_header_offset	= 0,
	.header_size	= 0,
	.tx_offset	= 0,
	.rx_offset	= 0, /* TODO to be replaced by dynamic detection */
	.rx_size	= 0x40,
};

struct mailbox mbox1_upap_info = {
	.name	= "mbox1_upap",
	.id	= 1,
	.ops	= &dbx500_mbox_ops,
	.priv	= &mbox1_upap_priv,
};

struct mailbox *db8500_mboxes[] = { &mbox0_info, &mbox1_info, &mbox2_info,
	&mbox3_info, &mbox4_info, &mbox5_info, &mbox6_info, &mbox7_info,
	NULL };

struct mailbox *dbx540_mboxes[] = { &mbox0_info, &mbox2_info,
	&mbox3_info, &mbox4_info, &mbox5_info, &mbox6_info, &mbox7_info,
	&mbox1_upap_info, NULL };

static const struct of_device_id dbx500_mailbox_match[] = {
	{ .compatible = "stericsson,db8500-mailbox",
		.data = (void *)db8500_mboxes,
	},
	{ .compatible = "stericsson,db9540-mailbox",
		.data = (void *)dbx540_mboxes,
	},
	{ /* sentinel */}
};

static int dbx500_mbox_probe(struct platform_device *pdev)
{
	const struct platform_device_id *platid = platform_get_device_id(pdev);
	struct resource *mem;
	int ret, i, irq;
	u32 legacy_offset = 0;
	u32 upap_offset = 0, upap_size = PRCM_MBOX_LEGACY_SIZE;
	struct mailbox **list;
	struct dbx500_plat_data *pdata = dev_get_platdata(&pdev->dev);
	struct device_node *np = pdev->dev.of_node;
	bool upap_used = false;

	if (!pdata) {
		if (np) {
			if (of_property_read_u32(np, "legacy-offset",
							&legacy_offset)) {
				/* missing legacy-offset */
				dev_err(&pdev->dev, "No legacy offset found\n");
				return -ENODEV;
			}
			if (of_property_read_u32(np, "upap-offset",
							&upap_offset)) {
				dev_dbg(&pdev->dev, "No upap offset found\n");
				upap_offset = -1;
			}
			list = (struct mailbox **)of_match_device(
					dbx500_mailbox_match, &pdev->dev)->data;
			if (!list) {
				/* No mailbox configuration */
				dev_err(&pdev->dev, "No configuration found\n");
				return -ENODEV;
			}
		} else {
			/* No mailbox configuration */
			dev_err(&pdev->dev, "No configuration found\n");
			return -ENODEV;
		}
	} else {
		list = (struct mailbox **)platid->driver_data;
		legacy_offset = pdata->legacy_offset;
		upap_offset = pdata->upap_offset;
	}

	mem = platform_get_resource_byname(pdev, IORESOURCE_MEM, "prcm-reg");
	mbox_base = devm_ioremap(&pdev->dev, mem->start, resource_size(mem));
	if (!mbox_base) {
		ret = -ENOMEM;
		goto out;
	}

	mem = platform_get_resource_byname(pdev, IORESOURCE_MEM, "prcmu-tcdm");
	tcdm_mem_base = devm_ioremap(&pdev->dev, mem->start,
							resource_size(mem));
	if (!tcdm_mem_base) {
		ret = -ENOMEM;
		goto out;
	}

	/* check mailbox offset values */
	if (legacy_offset >= (resource_size(mem) - PRCM_MBOX_LEGACY_SIZE)) {
		dev_err(&pdev->dev, "Incorrect legacy offset value\n");
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; list[i]; i++) {
		struct mailbox *mbox = list[i];
		struct dbx500_mbox_priv *priv =
			(struct dbx500_mbox_priv *)mbox->priv;
		if (!priv)
			continue;
		if (priv->type == MAILBOX_UPAP) {
			upap_used = true;
			upap_size += priv->rx_size;
			break;
		}
	}

	if (upap_used && (upap_offset >= (resource_size(mem) - upap_size))) {
		dev_err(&pdev->dev, "Incorrect upap offset value\n");
		ret = -EINVAL;
		goto out;
	}

	irq = platform_get_irq(pdev, 0);
	/* clean all mailboxes */
	mbox_write_reg(ALL_MBOX_BITS, PRCM_ARM_IT1_CLR);
	ret = request_irq(irq, dbx500_mbox_irq_handler,
			IRQF_NO_SUSPEND, "db8500_mbox", NULL);
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	dbx500_mbox_irq_domain = irq_domain_add_linear(
		np, NUM_MB, &dbx500_mbox_irq_ops, NULL);

	if (!dbx500_mbox_irq_domain) {
		dev_err(&pdev->dev, "Failed to create irqdomain\n");
		ret = -ENOSYS;
		goto irq_free;
	}

	/*
	 * Update mailbox shared memory buffer offset according to mailbox
	 * type
	 */
	for (i = 0; list[i]; i++) {
		struct mailbox *mbox = list[i];
		struct dbx500_mbox_priv *priv =
			(struct dbx500_mbox_priv *)mbox->priv;
		if (!priv)
			continue;
		mbox->irq = irq_create_mapping(dbx500_mbox_irq_domain,
								mbox->id);
		if (priv->type == MAILBOX_LEGACY) {
			priv->rx_offset += legacy_offset;
			priv->rx_header_offset += legacy_offset;
			priv->tx_offset += legacy_offset;
			priv->tx_header_offset += legacy_offset;
		} else if (priv->type == MAILBOX_UPAP) {
			priv->tx_offset += upap_offset;
			priv->rx_offset += upap_offset;
		}
	}

	ret = mailbox_register(&pdev->dev, list);
irq_free:
	if (ret)
		free_irq(irq, NULL);

out:
	return ret;
}

static int dbx500_mbox_remove(struct platform_device *pdev)
{
	mailbox_unregister();
	iounmap(mbox_base);
	return 0;
}

static const struct platform_device_id dbx500_mbox_id[] = {
	{
		.name = "db8500-mailbox",
		.driver_data = (unsigned long) db8500_mboxes,
	}, {
		.name = "db9540-mailbox",
		.driver_data = (unsigned long) dbx540_mboxes,
	}, {
		/* sentinel */
	}
};

static struct platform_driver dbx500_mbox_driver = {
	.probe = dbx500_mbox_probe,
	.remove = dbx500_mbox_remove,
	.driver = {
		.name = "dbx500-mailbox",
		.of_match_table = dbx500_mailbox_match,
	},
	.id_table = dbx500_mbox_id,
};

static int __init dbx500_mbox_init(void)
{
	return platform_driver_register(&dbx500_mbox_driver);
}

static void __exit dbx500_mbox_exit(void)
{
	platform_driver_unregister(&dbx500_mbox_driver);
}

postcore_initcall(dbx500_mbox_init);
module_exit(dbx500_mbox_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("ST-Ericsson mailbox: dbx500 architecture specific functions");
MODULE_AUTHOR("Loic Pallardy <loic.pallardy@st.com>");
MODULE_ALIAS("platform:dbx500-mailbox");
