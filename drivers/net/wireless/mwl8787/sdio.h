/*
 * Copyright cozybit, inc. 2013
 *
 * All rights reserved.
 */
#ifndef _MWL8787_SDIO_H
#define _MWL8787_SDIO_H

#include <linux/module.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/card.h>

#define BLOCK_MODE	1
#define BYTE_MODE	0

#define REG_PORT			0

#define MWL8787_SDIO_IO_PORT_MASK	0xfffff

#define MWL8787_SDIO_BYTE_MODE_MASK	0x80000000

#define SDIO_MPA_ADDR_BASE		0x1000
#define CTRL_PORT			0
#define CTRL_PORT_MASK			0x0001

#define CMD_PORT_UPLD_INT_MASK		(0x1U<<6)
#define CMD_PORT_DNLD_INT_MASK		(0x1U<<7)
#define HOST_TERM_CMD53			(0x1U << 2)
#define REG_PORT			0
#define MEM_PORT			0x10000
#define CMD_RD_LEN_0			0xB4
#define CMD_RD_LEN_1			0xB5
#define CARD_CONFIG_2_1_REG             0xCD
#define CMD53_NEW_MODE			(0x1U << 0)
#define CMD_CONFIG_0			0xB8
#define CMD_PORT_RD_LEN_EN		(0x1U << 2)
#define CMD_CONFIG_1			0xB9
#define CMD_PORT_AUTO_EN		(0x1U << 0)
#define CMD_PORT_SLCT			0x8000
#define UP_LD_CMD_PORT_HOST_INT_STATUS	(0x40U)
#define DN_LD_CMD_PORT_HOST_INT_STATUS	(0x80U)

#define SDIO_MP_TX_AGGR_DEF_BUF_SIZE        (8192)	/* 8K */

/* Multi port RX aggregation buffer size */
#define SDIO_MP_RX_AGGR_DEF_BUF_SIZE        (16384)	/* 16K */

/* Misc. Config Register : Auto Re-enable interrupts */
#define AUTO_RE_ENABLE_INT              BIT(4)

/* Host Control Registers */
/* Host Control Registers : I/O port 0 */
#define IO_PORT_0_REG			0x78
/* Host Control Registers : I/O port 1 */
#define IO_PORT_1_REG			0x79
/* Host Control Registers : I/O port 2 */
#define IO_PORT_2_REG			0x7A

/* Host Control Registers : Configuration */
#define CONFIGURATION_REG		0x00
/* Host Control Registers : Host power up */
#define HOST_POWER_UP			(0x1U << 1)

/* Host Control Registers : Host interrupt mask */
#define HOST_INT_MASK_REG		0x02
/* Host Control Registers : Upload host interrupt mask */
#define UP_LD_HOST_INT_MASK		(0x1U)
/* Host Control Registers : Download host interrupt mask */
#define DN_LD_HOST_INT_MASK		(0x2U)

/* Disable Host interrupt mask */
#define	HOST_INT_DISABLE		0xff

/* Host Control Registers : Host interrupt status */
#define HOST_INTSTATUS_REG		0x03
/* Host Control Registers : Upload host interrupt status */
#define UP_LD_HOST_INT_STATUS		(0x1U)
/* Host Control Registers : Download host interrupt status */
#define DN_LD_HOST_INT_STATUS		(0x2U)

/* Host Control Registers : Host interrupt RSR */
#define HOST_INT_RSR_REG		0x01

/* Host Control Registers : Host interrupt status */
#define HOST_INT_STATUS_REG		0x28

/* Card Control Registers : Card I/O ready */
#define CARD_IO_READY                   (0x1U << 3)
/* Card Control Registers : Download card ready */
#define DN_LD_CARD_RDY                  (0x1U << 0)

/* Max retry number of CMD53 write */
#define MAX_WRITE_IOMEM_RETRY		2

#define MWL8787_MAX_PORTS		16

/* misc. */
#define MWL8787_HOST_INT_ENABLE	(UP_LD_HOST_INT_MASK | DN_LD_HOST_INT_MASK)
#define MWL8787_SDIO_INT_MASK		0x3f
#define MWL8787_DATA_PORT_MASK		0x0000fffe
#define MWL8787_MAX_MP_REGS		64
#define MWL8787_RD_BITMAP_L		0x04
#define MWL8787_RD_BITMAP_U		0x05
#define MWL8787_WR_BITMAP_L		0x06
#define MWL8787_WR_BITMAP_U		0x07
#define MWL8787_RD_LEN_P0_L		0x08
#define MWL8787_RD_LEN_P0_U		0x09

/* register definitions */
#define MWL8787_REG_START_RD_PORT	1
#define MWL8787_REG_START_WR_PORT	1
#define MWL8787_REG_BASE_0		0x0040
#define MWL8787_REG_BASE_1		0x0041
#define MWL8787_REG_POLL		0x30
#define MWL8787_REG_STATUS_0		0x60
#define MWL8787_REG_STATUS_1		0x61
#define MWL8787_REG_SCRATCH_START	0x62
#define MWL8787_REG_SCRATCH_LEN		0x8
#define MWL8787_REG_CARD_MISC_CFG	0x6c

#define MWL8787_SDIO_BLOCK_SIZE            256

#define MWL8787_SDIO_MP_TX_AGGR_DEF_BUF_SIZE        (8192)	/* 8K */
#define MWL8787_SDIO_MP_RX_AGGR_DEF_BUF_SIZE        (16384)	/* 16K */

int mwl8787_read_scratch_area(struct mwl8787_priv *priv, u64 *dat);
void mwl8787_dev_debugfs_init(struct mwl8787_priv *priv);
void mwl8787_dev_debugfs_remove(struct mwl8787_priv *priv);

enum mwl8787_sdio_type {
	MWL8787_TYPE_DATA = 0,
	MWL8787_TYPE_CMD = 1,
	MWL8787_TYPE_EVENT = 3,
};

/* SDIO Tx aggregation in progress ? */
#define MP_TX_AGGR_IN_PROGRESS(a) (a->mpa_tx.pkt_cnt > 0)

/* SDIO Tx aggregation buffer room for next packet ? */
#define MP_TX_AGGR_BUF_HAS_ROOM(a, len) ((a->mpa_tx.buf_len+len)	\
						<= a->mpa_tx.buf_size)

/* Copy current packet (SDIO Tx aggregation buffer) to SDIO buffer */
#define MP_TX_AGGR_BUF_PUT(a, payload, pkt_len, port) do {		\
	memmove(&a->mpa_tx.buf[a->mpa_tx.buf_len],			\
			payload, pkt_len);				\
	a->mpa_tx.buf_len += pkt_len;					\
	if (!a->mpa_tx.pkt_cnt)						\
		a->mpa_tx.start_port = port;				\
	if (a->mpa_tx.start_port <= port)				\
		a->mpa_tx.ports |= (1<<(a->mpa_tx.pkt_cnt));		\
	else								\
		a->mpa_tx.ports |= (1<<(a->mpa_tx.pkt_cnt+1+(MWL8787_MAX_PORTS -	\
						a->mp_end_port)));	\
	a->mpa_tx.pkt_cnt++;						\
} while (0)

/* SDIO Tx aggregation limit ? */
#define MP_TX_AGGR_PKT_LIMIT_REACHED(a)					\
			(a->mpa_tx.pkt_cnt == a->mpa_tx.pkt_aggr_limit)

/* SDIO Tx aggregation port limit ? */
#define MP_TX_AGGR_PORT_LIMIT_REACHED(a) ((a->curr_wr_port <		\
			a->mpa_tx.start_port) && (((MWL8787_MAX_PORTS -		\
			a->mpa_tx.start_port) + a->curr_wr_port) >=	\
			MWL8787_SDIO_MP_AGGR_DEF_PKT_LIMIT))

/* Reset SDIO Tx aggregation buffer parameters */
#define MP_TX_AGGR_BUF_RESET(a) do {					\
	a->mpa_tx.pkt_cnt = 0;						\
	a->mpa_tx.buf_len = 0;						\
	a->mpa_tx.ports = 0;						\
	a->mpa_tx.start_port = 0;					\
} while (0)

#define MP_RX_AGGR_SETUP(a, skb, port) do {				\
	a->mpa_rx.buf_len += skb->len;					\
	if (!a->mpa_rx.pkt_cnt)						\
		a->mpa_rx.start_port = port;				\
	if (a->mpa_rx.start_port <= port)				\
		a->mpa_rx.ports |= (1<<(a->mpa_rx.pkt_cnt));		\
	else								\
		a->mpa_rx.ports |= (1<<(a->mpa_rx.pkt_cnt+1));		\
	a->mpa_rx.skb_arr[a->mpa_rx.pkt_cnt] = skb;			\
	a->mpa_rx.len_arr[a->mpa_rx.pkt_cnt] = skb->len;		\
	a->mpa_rx.pkt_cnt++;						\
} while (0)

/* SDIO Rx aggregation limit ? */
#define MP_RX_AGGR_PKT_LIMIT_REACHED(a)					\
			(a->mpa_rx.pkt_cnt == a->mpa_rx.pkt_aggr_limit)

/* SDIO Rx aggregation port limit ? */
#define MP_RX_AGGR_PORT_LIMIT_REACHED(a) ((a->curr_rd_port <		\
			a->mpa_rx.start_port) && (((MWL8787_MAX_PORTS -		\
			a->mpa_rx.start_port) + a->curr_rd_port) >=	\
			MWL8787_SDIO_MP_AGGR_DEF_PKT_LIMIT))

/* Reset SDIO Rx aggregation buffer parameters */
#define MP_RX_AGGR_BUF_RESET(a) do {					\
	a->mpa_rx.pkt_cnt = 0;						\
	a->mpa_rx.buf_len = 0;						\
	a->mpa_rx.ports = 0;						\
	a->mpa_rx.start_port = 0;					\
} while (0)
#endif /* _MWL8787_SDIO_H_ */
