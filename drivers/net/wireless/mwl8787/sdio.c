#include <linux/mmc/host.h>
#include <linux/regulator/consumer.h>

#include "mwl8787.h"
#include "sdio.h"
#include "fw.h"

#include "trace.h"

MODULE_DESCRIPTION("Marvell 8787 SDIO wireless");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cozybit Inc.");

static struct sdio_device_id mwl8787_sdio_ids[] = {

	{ SDIO_DEVICE(0x02df, 0x9119) },
	{}
};
MODULE_DEVICE_TABLE(sdio, mwl8787_sdio_ids);

/*
 * This function reads data from SDIO card register.
 */
static int
mwl8787_read_reg(struct mwl8787_priv *priv, u32 reg, u8 *data)
{
	struct sdio_func *func = priv->bus_priv;
	int ret = -1;
	u8 val;

	sdio_claim_host(func);
	val = sdio_readb(func, reg, &ret);
	sdio_release_host(func);

	trace_mwl8787_sdio_reg(priv, false, reg, val, ret);

	*data = val;

	return ret;
}

/*
 * This function writes data into SDIO card register.
 */
static int
mwl8787_write_reg(struct mwl8787_priv *priv, u32 reg, u8 data)
{
	struct sdio_func *func = priv->bus_priv;
	int ret = -1;

	sdio_claim_host(func);
	sdio_writeb(func, data, reg, &ret);
	sdio_release_host(func);

	trace_mwl8787_sdio_reg(priv, true, reg, data, ret);

	return ret;
}

/*
 * This function writes multiple data into SDIO card memory.
 *
 * This does not work in suspended mode.
 */
static int
mwl8787_write_data_sync(struct mwl8787_priv *priv,
			u8 *buffer, u32 pkt_len, u32 port)
{
	struct sdio_func *func = priv->bus_priv;
	int ret;
	u8 blk_mode =
		(port & MWL8787_SDIO_BYTE_MODE_MASK) ? BYTE_MODE : BLOCK_MODE;
	u32 blk_size = (blk_mode == BLOCK_MODE) ? MWL8787_SDIO_BLOCK_SIZE : 1;
	u32 blk_cnt =
		(blk_mode ==
		 BLOCK_MODE) ? (pkt_len /
				MWL8787_SDIO_BLOCK_SIZE) : pkt_len;
	u32 ioport = (port & MWL8787_SDIO_IO_PORT_MASK);

	trace_mwl8787_sdio(priv, true, ioport, buffer, blk_cnt * blk_size);

	sdio_claim_host(func);

	ret = sdio_writesb(func, ioport, buffer, blk_cnt * blk_size);

	sdio_release_host(func);

	return ret;
}

static bool mwl8787_is_tx_busy(struct mwl8787_priv *priv)
{
	return !(priv->mp_wr_bitmap & BIT(priv->curr_wr_port));
}

static int mwl8787_get_write_port(struct mwl8787_priv *priv, u8 *port)
{
	u32 wr_bitmap = priv->mp_wr_bitmap;

	dev_dbg(priv->dev, "data: mp_wr_bitmap=0x%08x\n", wr_bitmap);

	if (priv->mp_wr_bitmap & BIT(priv->curr_wr_port)) {
		priv->mp_wr_bitmap &= ~BIT(priv->curr_wr_port);
		*port = priv->curr_wr_port;

		if (++priv->curr_wr_port == priv->mp_end_port)
			priv->curr_wr_port = MWL8787_REG_START_WR_PORT;

	} else {
		return -EBUSY;
	}

	dev_dbg(priv->dev, "data: port=%d mp_wr_bitmap=0x%08x -> 0x%08x\n",
		*port, wr_bitmap, priv->mp_wr_bitmap);

	return 0;
}

/*
 * This function polls the card status.
 */
static int
mwl8787_sdio_poll_card_status(struct mwl8787_priv *priv, u8 bits)
{
	u32 tries;
	u8 cs;

	for (tries = 0; tries < MAX_POLL_TRIES; tries++) {
		if (mwl8787_read_reg(priv, MWL8787_REG_POLL, &cs))
			break;
		else if ((cs & bits) == bits)
			return 0;

		usleep_range(10, 20);
	}

	dev_err(priv->dev, "poll card status failed, tries = %d\n", tries);

	return -1;
}

/*
 * This function reads the scratch area used by firmware to report error codes.
 */
int mwl8787_read_scratch_area(struct mwl8787_priv *priv, u64 *dat)
{
	u32 i;
	u8 scrch;

	for (i = 0; i < MWL8787_REG_SCRATCH_LEN; i++) {
		if (mwl8787_read_reg(priv, MWL8787_REG_SCRATCH_START + i, &scrch))
			return -1;
		*dat = ((*dat << 8) | scrch);
	}

	return 0;
}

/*
 * This function reads the firmware status.
 */
static int
mwl8787_sdio_read_fw_status(struct mwl8787_priv *priv, u16 *dat)
{
	u8 fws0, fws1;

	if (mwl8787_read_reg(priv, MWL8787_REG_STATUS_0, &fws0))
		return -1;

	if (mwl8787_read_reg(priv, MWL8787_REG_STATUS_1, &fws1))
		return -1;

	*dat = (u16) ((fws1 << 8) | fws0);

	return 0;
}

/*
 * This function checks the firmware status in card.
 */
static int mwl8787_sdio_check_fw_ready(struct mwl8787_priv *priv,
				       u32 poll_num)
{
	int ret = 0;
	u16 firmware_stat;
	u32 tries;

	/* Wait for firmware initialization event */
	for (tries = 0; tries < poll_num; tries++) {
		ret = mwl8787_sdio_read_fw_status(priv, &firmware_stat);
		if (ret)
			continue;
		if (firmware_stat == FIRMWARE_READY_SDIO) {
			ret = 0;
			break;
		} else {
			mdelay(100);
			ret = -1;
		}
	}

	dev_dbg(priv->dev, "read firmware status: %4X \n", firmware_stat);

	return ret;
}

/* This function initializes the IO ports.
 *
 * The following operations are performed -
 *      - Read the IO ports (0, 1 and 2)
 *      - Set host interrupt Reset-To-Read to clear
 *      - Set auto re-enable interrupt
 */
static int mwl8787_init_sdio_ioport(struct mwl8787_priv *priv)
{
	u8 reg;

	priv->ioport = 0;

	/* Read the IO port */
	if (!mwl8787_read_reg(priv, IO_PORT_0_REG, &reg))
		priv->ioport |= (reg & 0xff);
	else
		return -1;

	if (!mwl8787_read_reg(priv, IO_PORT_1_REG, &reg))
		priv->ioport |= ((reg & 0xff) << 8);
	else
		return -1;

	if (!mwl8787_read_reg(priv, IO_PORT_2_REG, &reg))
		priv->ioport |= ((reg & 0xff) << 16);
	else
		return -1;

	pr_debug("info: SDIO FUNC1 IO port: %#x\n", priv->ioport);

	/* Set Host interrupt reset to read to clear */
	if (!mwl8787_read_reg(priv, HOST_INT_RSR_REG, &reg))
		mwl8787_write_reg(priv, HOST_INT_RSR_REG,
				  reg | MWL8787_SDIO_INT_MASK);
	else
		return -1;

	/* Dnld/Upld ready set to auto reset */
	if (!mwl8787_read_reg(priv, MWL8787_REG_CARD_MISC_CFG, &reg))
		mwl8787_write_reg(priv, MWL8787_REG_CARD_MISC_CFG,
				  reg | AUTO_RE_ENABLE_INT);
	else
		return -1;

	return 0;
}

/*
 * This function downloads the firmware to the card.
 *
 * Firmware is downloaded to the card in blocks. Every block download
 * is tested for CRC errors, and retried a number of times before
 * returning failure.
 */
static int mwl8787_sdio_prog_fw(struct mwl8787_priv *priv,
				const struct firmware *fw)
{
	int ret, firmware_len = fw->size;
	u32 offset = 0;
	u8 base0, base1;
	u8 *fwbuf;
	u16 len = 0;
	u32 txlen, tx_blocks = 0, tries;
	u32 i = 0;

	if (!firmware_len) {
		dev_err(priv->dev,
			"firmware image not found! Terminating download\n");
		return -1;
	}

	dev_dbg(priv->dev, "info: downloading FW image (%d bytes)\n",
		firmware_len);

	/* Assume that the allocated buffer is 8-byte aligned */
	fwbuf = kzalloc(MWL8787_UPLD_SIZE, GFP_KERNEL);
	if (!fwbuf)
		return -ENOMEM;

	/* FIXME - found this necessary if fw loader is called from within
	 * probe; many times we timeout while polling card status.  So we
	 * may need more tries or bigger sleep between polls for the dev
	 * devices.  Waiting a bit after power up skirts the issue.
	 */
	msleep(1000);
	/* Perform firmware data transfer */
	do {
		/* The host polls for the DN_LD_CARD_RDY and CARD_IO_READY
		   bits */
		ret = mwl8787_sdio_poll_card_status(priv, CARD_IO_READY |
						    DN_LD_CARD_RDY);
		if (ret) {
			dev_err(priv->dev, "FW download with helper:"
				" poll status timeout @ %d\n", offset);
			goto done;
		}

		/* More data? */
		if (offset >= firmware_len)
			break;

		for (tries = 0; tries < MAX_POLL_TRIES; tries++) {
			ret = mwl8787_read_reg(priv, MWL8787_REG_BASE_0,
					       &base0);
			if (ret) {
				dev_err(priv->dev,
					"dev BASE0 register read failed: "
					"base0=%#04X(%d). Terminating dnld\n",
					base0, base0);
				goto done;
			}
			ret = mwl8787_read_reg(priv, MWL8787_REG_BASE_1,
					       &base1);
			if (ret) {
				dev_err(priv->dev,
					"dev BASE1 register read failed: "
					"base1=%#04X(%d). Terminating dnld\n",
					base1, base1);
				goto done;
			}
			len = (u16) (((base1 & 0xff) << 8) | (base0 & 0xff));

			if (len)
				break;

			usleep_range(10, 20);
		}

		if (!len) {
			break;
		} else if (len > MWL8787_UPLD_SIZE) {
			dev_err(priv->dev,
				"FW dnld failed @ %d, invalid length %d\n",
				offset, len);
			ret = -1;
			goto done;
		}

		txlen = len;

		if (len & BIT(0)) {
			i++;
			if (i > MAX_WRITE_IOMEM_RETRY) {
				dev_err(priv->dev,
					"FW dnld failed @ %d, over max retry\n",
					offset);
				ret = -1;
				goto done;
			}
			dev_err(priv->dev, "CRC indicated by the helper:"
				" len = 0x%04X, txlen = %d\n", len, txlen);
			len &= ~BIT(0);
			/* Setting this to 0 to resend from same offset */
			txlen = 0;
		} else {
			i = 0;

			/* Set blocksize to transfer - checking for last
			   block */
			if (firmware_len - offset < txlen)
				txlen = firmware_len - offset;

			tx_blocks = DIV_ROUND_UP(txlen, MWL8787_SDIO_BLOCK_SIZE);

			/* Copy payload to buffer */
			memcpy(fwbuf, &fw->data[offset], txlen);
			dev_dbg(priv->dev, "txlen: %d\n", txlen);
		}

		ret = mwl8787_write_data_sync(priv, fwbuf, tx_blocks *
					      MWL8787_SDIO_BLOCK_SIZE,
					      priv->ioport);
		if (ret) {
			dev_err(priv->dev,
				"FW download, write iomem (%d) failed @ %d\n",
				i, offset);
			if (mwl8787_write_reg(priv, CONFIGURATION_REG, 0x04))
				dev_err(priv->dev, "write CFG reg failed\n");

			ret = -1;
			goto done;
		}

		offset += txlen;
	} while (true);

	dev_dbg(priv->dev, "info: FW download over, size %d bytes\n",
		offset);

	ret = 0;
done:
	kfree(fwbuf);
	return ret;
}

/*
 * This function reads multiple data from SDIO card memory.
 */
static int mwl8787_read_data_sync(struct mwl8787_priv *priv, u8 *buffer,
				  u32 len, u32 port, u8 claim)
{
	struct sdio_func *func = priv->bus_priv;
	int ret;
	u8 blk_mode = (port & MWL8787_SDIO_BYTE_MODE_MASK) ? BYTE_MODE
		       : BLOCK_MODE;
	u32 blk_size = (blk_mode == BLOCK_MODE) ? MWL8787_SDIO_BLOCK_SIZE : 1;
	u32 blk_cnt = (blk_mode == BLOCK_MODE) ? (len / MWL8787_SDIO_BLOCK_SIZE)
			: len;
	u32 ioport = (port & MWL8787_SDIO_IO_PORT_MASK);

	if (claim)
		sdio_claim_host(func);

	ret = sdio_readsb(func, buffer, ioport, blk_cnt * blk_size);

	if (claim)
		sdio_release_host(func);

	trace_mwl8787_sdio(priv, false, ioport, buffer, blk_cnt * blk_size);

	return ret;
}


static int mwl8787_write(struct mwl8787_priv *priv,
			 u8 *buf, size_t len, u32 port)
{
	u32 i = 0;
	int ret;

	for (i=0; i < MAX_WRITE_IOMEM_RETRY; i++) {
		ret = mwl8787_write_data_sync(priv, buf, len, port);
		if (!ret)
			break;

		mwl8787_write_reg(priv, CONFIGURATION_REG, 0x04);
	}
	if (ret)
		dev_err(priv->dev, "write iomem (%d) failed (%d)\n", port, ret);

	return ret;
}

/*
 * For multi-port transfers, the hardware wants a bitmask of subsequent
 * ports to read after start_port.  This would be the same as one bit per
 * number of frames, but we need to insert an additional zero to skip the
 * ctrl port, in case we wrapped around MWL8787_MAX_PORTS.
 */
static int mwl8787_mp_bitmask(struct mwl8787_priv *priv,
			      int start_port, int nframes)
{
	int wrapped_bits = nframes + start_port - MWL8787_MAX_PORTS;
	int unwrapped_bits;

	if (wrapped_bits < 0)
		wrapped_bits = 0;

	unwrapped_bits = nframes - wrapped_bits;
	return ((1 << unwrapped_bits) - 1) |
		((1 << wrapped_bits) - 1) << (unwrapped_bits + 1);
}

static int mwl8787_send_data_aggr(struct mwl8787_priv *priv)
{
	int ret;
	int port_mask;
	u32 port_desc;

	if (!priv->mpa_tx.pkt_cnt)
		return 0;

	port_mask = mwl8787_mp_bitmask(priv, priv->mpa_tx.start_port,
				       priv->mpa_tx.pkt_cnt);

	port_desc = priv->ioport | 0x1000 | (port_mask << 4) |
		priv->mpa_tx.start_port;

	ret = mwl8787_write(priv, priv->mpa_tx.buf, priv->mpa_tx.buf_len,
			    port_desc);

	priv->mpa_tx.pkt_cnt = 0;
	priv->mpa_tx.buf_len = 0;
	priv->mpa_tx.start_port = 0;

	return ret;
}

static int mwl8787_host_to_card_mp_aggr(struct mwl8787_priv *priv,
					u8 *payload, u32 pkt_len, u8 port,
					bool more_data)
{
	int ret;

	/* if the frame happens to be larger than the aggr buffer, punt */
	if (pkt_len > priv->mpa_tx.buf_size)
		return mwl8787_write(priv, payload, pkt_len,
				     priv->ioport + port);

	/* if aggr buffer is full, go ahead and send it. */
	if (priv->mpa_tx.pkt_cnt == MWL8787_SDIO_MP_AGGR_DEF_PKT_LIMIT ||
	    priv->mpa_tx.buf_len + pkt_len > priv->mpa_tx.buf_size) {
		ret = mwl8787_send_data_aggr(priv);
		if (ret)
			return ret;
	}

	/* copy this frame into the buffer */
	memcpy(&priv->mpa_tx.buf[priv->mpa_tx.buf_len], payload, pkt_len);
	if (!priv->mpa_tx.pkt_cnt)
		priv->mpa_tx.start_port = port;

	priv->mpa_tx.buf_len += pkt_len;
	priv->mpa_tx.pkt_cnt++;

	ret = 0;
	/* if out of data ports, or no more data is coming, send the buffer */
	if (!more_data ||
	    !(priv->mp_wr_bitmap & BIT(priv->curr_wr_port)) ||
	    priv->mpa_tx.pkt_cnt == MWL8787_SDIO_MP_AGGR_DEF_PKT_LIMIT) {
		ret = mwl8787_send_data_aggr(priv);
	}
	return ret;
}

static int mwl8787_sdio_send_tx(struct mwl8787_priv *priv,
				struct sk_buff *skb, bool more_frames)
{
	struct mwl8787_sdio_header *hdr;
	size_t buf_block_len;
	int ret;
	u8 port;

	skb_push(skb, sizeof(*hdr));
	hdr = (struct mwl8787_sdio_header *) skb->data;

	hdr->type = cpu_to_le16(MWL8787_TYPE_DATA);
	hdr->len = cpu_to_le16(skb->len);

	buf_block_len = roundup(skb->len, MWL8787_SDIO_BLOCK_SIZE);

	ret = mwl8787_get_write_port(priv, &port);
	if (ret) {
		dev_err(priv->dev, "no wr_port available\n");
		return ret;
	}

#if 0
	ret = mwl8787_write(priv, skb->data, buf_block_len, priv->ioport + port);
	return ret;
#else
	ret = mwl8787_host_to_card_mp_aggr(priv, skb->data, buf_block_len,
					   priv->ioport + port, more_frames);

	return ret;
#endif
}

static int mwl8787_sdio_send_cmd(struct mwl8787_priv *priv,
				 u8 *buf, size_t len)
{
	u8 *payload;
	size_t buf_block_len;
	struct mwl8787_sdio_header *hdr;
	int ret;

	hdr = (struct mwl8787_sdio_header *) (buf - priv->bus_headroom);
	len += sizeof(*hdr);

	hdr->type = cpu_to_le16(MWL8787_TYPE_CMD);
	hdr->len = cpu_to_le16(len);

	/*
	 * Allocate buffer and copy payload
	 * TODO avoid this alloc/copy...
	 */
	buf_block_len = roundup(len, MWL8787_SDIO_BLOCK_SIZE);

	payload = kzalloc(buf_block_len, GFP_KERNEL);
	if (!payload)
		return -ENOMEM;

	memcpy(payload, hdr, len);
	ret = mwl8787_write(priv, payload, buf_block_len, priv->ioport + CTRL_PORT);
	kfree(payload);

	return ret;
}

/*
 * This function decodes a received packet.
 *
 * Based on the type, the packet is treated as either a data, or
 * a command response, or an event, and the correct handler
 * function is invoked.
 */
static
int mwl8787_decode_rx_packet(struct mwl8787_priv *priv,
			     struct sk_buff *skb, u32 upld_typ)
{
	struct mwl8787_sdio_header *hdr = (void *) skb->data;
	skb_trim(skb, le16_to_cpu(hdr->len));
	skb_pull(skb, sizeof(*hdr));

	switch (upld_typ) {
	case MWL8787_TYPE_DATA:
		dev_dbg(priv->dev, "info: --- Rx: Data packet ---\n");
		mwl8787_rx(priv, skb);
		break;

	case MWL8787_TYPE_CMD:
		dev_dbg(priv->dev, "info: --- Rx: Cmd Response ---\n");
		mwl8787_cmd_rx(priv, skb);
		break;

	case MWL8787_TYPE_EVENT:
		dev_dbg(priv->dev, "info: --- Rx: Event ---\n");
		mwl8787_event_rx(priv, skb);
		break;

	default:
		dev_err(priv->dev, "unknown upload type %#x\n", upld_typ);
		dev_kfree_skb_any(skb);
		break;
	}

	return 0;
}

static int __mwl8787_sdio_card_to_host(struct mwl8787_priv *priv,
				       u32 *type, u8 *buffer,
				       u32 npayload, u32 ioport)
{
	struct mwl8787_sdio_header *hdr;
	int ret;
	u32 nb;

	if (!buffer) {
		dev_err(priv->dev, "%s: buffer is NULL\n", __func__);
		return -1;
	}

	ret = mwl8787_read_data_sync(priv, buffer, npayload, ioport, 1);

	if (ret) {
		dev_err(priv->dev, "%s: read iomem failed: %d\n", __func__,
			ret);
		return -1;
	}

	hdr = (struct mwl8787_sdio_header *) buffer;
	nb = le16_to_cpu(hdr->len);
	if (nb > npayload) {
		dev_err(priv->dev, "%s: invalid packet, nb=%d npayload=%d\n",
			__func__, nb, npayload);
		return -1;
	}
	*type = le16_to_cpu(hdr->type);

	return ret;
}

/*
 * This function gets the read port.
 *
 * If control port bit is set in MP read bitmap, the control port
 * is returned, otherwise the current read port is returned and
 * the value is increased (provided it does not reach the maximum
 * limit, in which case it is reset to 1)
 */
static int mwl8787_get_rd_port(struct mwl8787_priv *priv, u8 *port)
{
	u32 rd_bitmap = priv->mp_rd_bitmap;

	dev_dbg(priv->dev, "data: mp_rd_bitmap=0x%08x\n", rd_bitmap);

	if (!(rd_bitmap & (CTRL_PORT_MASK | MWL8787_DATA_PORT_MASK)))
		return -1;

	if ((rd_bitmap & CTRL_PORT_MASK)) {
		priv->mp_rd_bitmap &= (u32) (~CTRL_PORT_MASK);
		*port = CTRL_PORT;
		dev_dbg(priv->dev, "data: port=%d mp_rd_bitmap=0x%08x\n",
			*port, priv->mp_rd_bitmap);
		return 0;
	}

	if (!(priv->mp_rd_bitmap & (1 << priv->curr_rd_port)))
		return -1;

	/* We are now handling the SDIO data ports */
	priv->mp_rd_bitmap &= (u32)(~(1 << priv->curr_rd_port));
	*port = priv->curr_rd_port;

	if (++priv->curr_rd_port == MWL8787_MAX_PORTS)
		priv->curr_rd_port = MWL8787_REG_START_RD_PORT;

	dev_dbg(priv->dev,
		"data: port=%d mp_rd_bitmap=0x%08x -> 0x%08x\n",
		*port, rd_bitmap, priv->mp_rd_bitmap);

	return 0;
}

static int mwl8787_sdio_card_to_host(struct mwl8787_priv *priv,
				     struct sk_buff *skb, u8 port)
{
	u32 rx_len = skb->len;
	u32 pkt_type;

	dev_dbg(priv->dev, "info: RX: port: %d, rx_len: %d\n",
		port, rx_len);

	if (__mwl8787_sdio_card_to_host(priv, &pkt_type,
				      skb->data, skb->len,
				      priv->ioport + port)) {
		dev_kfree_skb_any(skb);
		return -1;
	}

	mwl8787_decode_rx_packet(priv, skb, pkt_type);
	return 0;
}

static int mwl8787_rx_data_aggr(struct mwl8787_priv *priv)
{
	int ret;
	int port_mask;
	u32 port_desc;
	u8 *ptr;
	int i;
	struct mwl8787_sdio_header *hdr;
	struct sk_buff *skb;
	u16 pkt_len, pkt_type;

	if (!priv->mpa_rx.pkt_cnt)
		return 0;

	port_mask = mwl8787_mp_bitmask(priv, priv->mpa_rx.start_port,
				       priv->mpa_rx.pkt_cnt);

	port_desc = priv->ioport | 0x1000 | (port_mask << 4) |
		priv->mpa_rx.start_port;

	ret = mwl8787_read_data_sync(priv, priv->mpa_rx.buf,
				     priv->mpa_rx.buf_len, port_desc, 1);

	if (ret) {
		/* free skb array on error */
		for (i = 0; i < priv->mpa_rx.pkt_cnt; i++) {
			skb = priv->mpa_rx.skb_arr[i];
			dev_kfree_skb_any(skb);
		}
		goto out;
	}

	/* split out buffer into individual skbs */
	ptr = priv->mpa_rx.buf;
	for (i = 0; i < priv->mpa_rx.pkt_cnt; i++) {
		hdr = (struct mwl8787_sdio_header *) ptr;
		skb = priv->mpa_rx.skb_arr[i];

		pkt_len = le16_to_cpu(hdr->len);
		pkt_type = le16_to_cpu(hdr->type);

		if (pkt_type == MWL8787_TYPE_DATA &&
		    pkt_len <= priv->mpa_rx.len_arr[i]) {
			memcpy(skb->data, ptr, pkt_len);
			skb_trim(skb, pkt_len);
			mwl8787_decode_rx_packet(priv, skb, pkt_type);
		} else {
			dev_err(priv->dev, "invalid frame: type=%d "
				"len=%d max_len=%d\n",
				pkt_type, pkt_len,
				priv->mpa_rx.len_arr[i]);
			dev_kfree_skb_any(skb);
		}
		ptr += priv->mpa_rx.len_arr[i];
	}
out:
	priv->mpa_rx.pkt_cnt = 0;
	priv->mpa_rx.buf_len = 0;
	priv->mpa_rx.start_port = 0;
	return ret;
}

static int mwl8787_sdio_card_to_host_aggr(struct mwl8787_priv *priv,
					  struct sk_buff *skb, u8 port)
{
	int ret;
	bool more_pending;

	/* if control port, rx just the one cmd response */
	if (port == CTRL_PORT || !priv->mpa_rx.enabled)
		return mwl8787_sdio_card_to_host(priv, skb, port);

	more_pending = priv->mp_rd_bitmap & MWL8787_DATA_PORT_MASK;

	/* if this frame won't fit, go ahead and rx the frames. */
	if (((priv->mpa_rx.buf_len + skb->len) > priv->mpa_rx.buf_size)) {
		ret = mwl8787_rx_data_aggr(priv);
		if (ret)
			return ret;
	}

	/* current frame will go to aggr buf */
	if (!priv->mpa_rx.pkt_cnt) {
		/* skip copy if this is the first and only one... */
		if (!more_pending)
			return mwl8787_sdio_card_to_host(priv, skb, port);

		priv->mpa_rx.start_port = port;
	}

	priv->mpa_rx.buf_len += skb->len;
	priv->mpa_rx.skb_arr[priv->mpa_rx.pkt_cnt] = skb;
	priv->mpa_rx.len_arr[priv->mpa_rx.pkt_cnt] = skb->len;
	priv->mpa_rx.pkt_cnt++;

	ret = 0;
	/* if now full, or nothing else pending, go ahead and rx */
	if (priv->mpa_rx.pkt_cnt == MWL8787_SDIO_MP_AGGR_DEF_PKT_LIMIT ||
	    !more_pending) {
		ret = mwl8787_rx_data_aggr(priv);
	}
	return ret;
}

/*
 * Allocate aggregation buffers.
 */
static int mwl8787_alloc_sdio_mpa_buffers(struct mwl8787_priv *priv,
					  u32 mpa_tx_buf_size,
					  u32 mpa_rx_buf_size)
{
	int ret;

	ret = -ENOMEM;
	priv->mpa_tx.buf = kzalloc(mpa_tx_buf_size, GFP_KERNEL);
	if (!priv->mpa_tx.buf)
		goto error;

	priv->mpa_tx.buf_size = mpa_tx_buf_size;

	priv->mpa_rx.buf = kzalloc(mpa_rx_buf_size, GFP_KERNEL);
	if (!priv->mpa_rx.buf)
		goto error;

	ret = 0;
	priv->mpa_rx.buf_size = mpa_rx_buf_size;

error:
	if (ret) {
		kfree(priv->mpa_tx.buf);
		kfree(priv->mpa_rx.buf);
	}

	return ret;
}

/*
 * This function checks the current interrupt status.
 *
 * The following interrupts are checked and handled by this function -
 *      - Data sent
 *      - Command sent
 *      - Packets received
 *
 * Since the firmware does not generate download ready interrupt if the
 * port updated is command port only, command sent interrupt checking
 * should be done manually, and for every SDIO interrupt.
 *
 * In case of Rx packets received, the packets are uploaded from card to
 * host and processed accordingly.
 */
static int mwl8787_process_int_status(struct mwl8787_priv *priv)
{
	int ret = 0;
	u8 sdio_ireg;
	struct sk_buff *skb;
	u8 port = CTRL_PORT;
	u32 len_reg_l, len_reg_u;
	u32 rx_blocks;
	u16 rx_len;
	unsigned long flags;
	u32 bitmap;
	u8 cr;

	spin_lock_irqsave(&priv->int_lock, flags);
	sdio_ireg = priv->int_status;
	priv->int_status = 0;
	spin_unlock_irqrestore(&priv->int_lock, flags);

	if (!sdio_ireg)
		return ret;

	if (sdio_ireg & DN_LD_HOST_INT_STATUS) {
		bitmap = (u32) priv->mp_regs[MWL8787_WR_BITMAP_L];
		bitmap |= ((u32) priv->mp_regs[MWL8787_WR_BITMAP_U]) << 8;

		/* card bitmap holds writes which have completed? */
		priv->mp_wr_bitmap |= bitmap;

		dev_dbg(priv->dev, "int: DNLD: wr_bitmap=0x%x\n",
			priv->mp_wr_bitmap);
		if (bitmap & priv->mp_data_port_mask) {
			dev_dbg(priv->dev,
				"info:  <--- Tx DONE Interrupt --->\n");
		}
	}

	/* set mp_wr_bitmap for cmd responses */
	priv->mp_wr_bitmap |=
		(u32) priv->mp_regs[MWL8787_WR_BITMAP_L] & CTRL_PORT_MASK;

	if (sdio_ireg & UP_LD_HOST_INT_STATUS) {
		bitmap = (u32) priv->mp_regs[MWL8787_RD_BITMAP_L];
		bitmap |= ((u32) priv->mp_regs[MWL8787_RD_BITMAP_U]) << 8;
		priv->mp_rd_bitmap = bitmap;
		dev_dbg(priv->dev, "int: UPLD: rd_bitmap=0x%x\n",
			priv->mp_rd_bitmap);

		while (true) {
			ret = mwl8787_get_rd_port(priv, &port);
			if (ret) {
				dev_dbg(priv->dev,
					"info: no more rd_port available\n");
				break;
			}
			len_reg_l = MWL8787_RD_LEN_P0_L + (port << 1);
			len_reg_u = MWL8787_RD_LEN_P0_U + (port << 1);
			rx_len = ((u16) priv->mp_regs[len_reg_u]) << 8;
			rx_len |= (u16) priv->mp_regs[len_reg_l];
			dev_dbg(priv->dev, "info: RX: port=%d rx_len=%u\n",
				port, rx_len);
			rx_blocks = DIV_ROUND_UP(rx_len,
						 MWL8787_SDIO_BLOCK_SIZE);
			if (rx_len <= sizeof(struct mwl8787_sdio_header) ||
			    (rx_blocks * MWL8787_SDIO_BLOCK_SIZE) >
			     MWL8787_RX_DATA_BUF_SIZE) {
				dev_err(priv->dev, "invalid rx_len=%d\n",
					rx_len);
				return -1;
			}
			rx_len = (u16) (rx_blocks * MWL8787_SDIO_BLOCK_SIZE);

			skb = dev_alloc_skb(rx_len);

			if (!skb) {
				dev_err(priv->dev, "%s: failed to alloc skb",
					__func__);
				return -1;
			}

			skb_put(skb, rx_len);

			dev_dbg(priv->dev, "info: rx_len = %d skb->len = %d\n",
				rx_len, skb->len);

			if (mwl8787_sdio_card_to_host_aggr(priv, skb, port)) {
				dev_err(priv->dev, "card_to_host failed:"
					" int status=%#x\n", sdio_ireg);
				goto term_cmd;
			}
		}
	}

	return 0;

term_cmd:
	/* terminate cmd */
	if (mwl8787_read_reg(priv, CONFIGURATION_REG, &cr))
		dev_err(priv->dev, "read CFG reg failed\n");
	else
		dev_dbg(priv->dev, "info: CFG reg val = %d\n", cr);

	if (mwl8787_write_reg(priv, CONFIGURATION_REG, (cr | 0x04)))
		dev_err(priv->dev, "write CFG reg failed\n");
	else
		dev_dbg(priv->dev, "info: write success\n");

	if (mwl8787_read_reg(priv, CONFIGURATION_REG, &cr))
		dev_err(priv->dev, "read CFG reg failed\n");
	else
		dev_dbg(priv->dev, "info: CFG reg val =%x\n", cr);

	return -1;
}

static int mwl8787_enable_int(struct mwl8787_priv *priv)
{
	int ret;
	ret = mwl8787_write_reg(priv, HOST_INT_MASK_REG,
				MWL8787_HOST_INT_ENABLE);

	if (ret)
		dev_err(priv->dev, "enable host interrupt failed\n");
	return ret;
}

static int mwl8787_sdio_disable_int(struct mwl8787_priv *priv)
{
	int ret = mwl8787_write_reg(priv, HOST_INT_MASK_REG, 0);

	if (ret)
		dev_err(priv->dev, "disable host interrupt failed\n");

	return ret;
}

static int mwl8787_sdio_reset(void)
{
	int ret;
        struct regulator *wifi_en, *wifi_rst;

        wifi_en = regulator_get(NULL, "wifi-en");
	if (IS_ERR(wifi_en))
		return PTR_ERR(wifi_en);

        wifi_rst = regulator_get(NULL, "wifi-rst-l");
	if (IS_ERR(wifi_rst)) {
		regulator_put(wifi_en);
		return PTR_ERR(wifi_rst);
	}

	regulator_disable(wifi_rst);
	regulator_disable(wifi_en);

	ret = regulator_enable(wifi_rst);
	if (ret)
		goto out;

	/* as per 8797 datasheet section 1.5.2 */
	mdelay(1);
	ret = regulator_enable(wifi_en);
out:
	regulator_put(wifi_rst);
	regulator_put(wifi_en);
	return ret;
}

static void sdio_card_reset_worker(struct work_struct *work)
{
	struct mwl8787_priv *priv = container_of(work, struct mwl8787_priv, card_reset_work);
	struct sdio_func *func = priv->bus_priv;
	struct mmc_host *target = func->card->host;

	/* The actual reset operation must be run outside of driver thread.
	 * This is because mmc_remove_host() will cause the device to be
	 * instantly destroyed, and the driver then needs to end its thread,
	 * leading to a deadlock.
	 *
	 * We run it in a totally independent workqueue.
	 */

	pr_err("Resetting card...\n");
	mmc_remove_host(target);
        device_del(priv->dev);
	if (mwl8787_sdio_reset())
		pr_err("External card reset failed! Trying to reattach...\n");
	/* 20ms delay is based on experiment with sdhci controller */
	mdelay(20);
	mmc_add_host(target);
}

static void mwl8787_sdio_card_reset(struct mwl8787_priv *priv)
{
	schedule_work(&priv->card_reset_work);
}

static struct mwl8787_bus_ops sdio_ops = {
	.prog_fw = mwl8787_sdio_prog_fw,
	.check_fw_ready = mwl8787_sdio_check_fw_ready,
	.send_cmd = mwl8787_sdio_send_cmd,
	.send_tx = mwl8787_sdio_send_tx,
	.process_int_status = mwl8787_process_int_status,
	.enable_int = mwl8787_enable_int,
	.card_reset = mwl8787_sdio_card_reset,
	.is_tx_busy = mwl8787_is_tx_busy,
};

static int mwl8787_init_sdio(struct mwl8787_priv *priv)
{
	u8 sdio_ireg;
	int ret;

	/*
	 * Read the HOST_INT_STATUS_REG for ACK the first interrupt got
	 * from the bootloader. If we don't do this we get a interrupt
	 * as soon as we register the irq.
	 */
	mwl8787_read_reg(priv, HOST_INTSTATUS_REG, &sdio_ireg);

	/* Disable host interrupt mask register for SDIO */
	mwl8787_sdio_disable_int(priv);

	/* Get SDIO ioport */
	mwl8787_init_sdio_ioport(priv);

	priv->mp_rd_bitmap = 0;
	priv->mp_wr_bitmap = ~0;

	priv->curr_rd_port = MWL8787_REG_START_RD_PORT;
	priv->curr_wr_port = MWL8787_REG_START_WR_PORT;

	priv->mp_data_port_mask = MWL8787_DATA_PORT_MASK;

	INIT_WORK(&priv->card_reset_work, sdio_card_reset_worker);

	priv->mpa_tx.buf_len = 0;
	priv->mpa_tx.pkt_cnt = 0;
	priv->mpa_tx.start_port = 0;

	priv->mpa_tx.enabled = 1;

	priv->mpa_rx.buf_len = 0;
	priv->mpa_rx.pkt_cnt = 0;
	priv->mpa_rx.start_port = 0;

	priv->mpa_rx.enabled = 1;

	/* Allocate buffers for SDIO MP-A */
	priv->mp_regs = kzalloc(MWL8787_MAX_MP_REGS, GFP_KERNEL);
	if (!priv->mp_regs)
		return -ENOMEM;

	ret = mwl8787_alloc_sdio_mpa_buffers(priv,
					     MWL8787_SDIO_MP_TX_AGGR_DEF_BUF_SIZE,
					     MWL8787_SDIO_MP_RX_AGGR_DEF_BUF_SIZE);
	if (ret) {
		kfree(priv->mp_regs);
		return -ENOMEM;
	}

	return 0;
}

/*
 * This function reads the interrupt status from card.
 */
static void mwl8787_interrupt_status(struct mwl8787_priv *priv)
{
	u8 sdio_ireg;
	unsigned long flags;

	if (mwl8787_read_data_sync(priv, priv->mp_regs, MWL8787_MAX_MP_REGS,
				   REG_PORT | MWL8787_SDIO_BYTE_MODE_MASK, 0)) {
		dev_err(priv->dev, "read mp_regs failed\n");
		return;
	}

	sdio_ireg = priv->mp_regs[HOST_INTSTATUS_REG];
	if (sdio_ireg) {
		/*
		 * DN_LD_HOST_INT_STATUS and/or UP_LD_HOST_INT_STATUS
		 * For SDIO new mode CMD port interrupts
		 *	DN_LD_CMD_PORT_HOST_INT_STATUS and/or
		 *	UP_LD_CMD_PORT_HOST_INT_STATUS
		 * Clear the interrupt status register
		 */
		dev_dbg(priv->dev, "int: sdio_ireg = %#x\n", sdio_ireg);
		spin_lock_irqsave(&priv->int_lock, flags);
		priv->int_status |= sdio_ireg;
		spin_unlock_irqrestore(&priv->int_lock, flags);
	}
}

/*
 * SDIO interrupt handler.
 *
 * This function reads the interrupt status from firmware and handles
 * the interrupt in current thread (ksdioirqd) right away.
 */
static void
mwl8787_sdio_interrupt(struct sdio_func *func)
{
	struct mwl8787_priv *priv;

	priv = sdio_get_drvdata(func);
	if (!priv) {
		pr_debug("mwl8787: no priv? func=%p\n", func);
		return;
	}

	mwl8787_interrupt_status(priv);
	mwl8787_main_process(priv);
}

static void mwl8787_fw_cb(const struct firmware *fw, void *context)
{
	struct mwl8787_priv *priv = context;
	int ret;

	if (!fw) {
		dev_err(priv->dev, "request for firmware file '%s' failed",
			MWL8787_FW_NAME);
		ret = -ENOENT;
		goto disable;
	}

	/* try to load the firmware, then register with mac80211 on success */
	priv->fw = fw;
	ret = mwl8787_dnld_fw(priv);
	if (ret)
		goto disable;

	ret = mwl8787_init_fw(priv);
	if (ret)
		goto disable;

	/* now we know the mac addr, so program it */
	SET_IEEE80211_PERM_ADDR(priv->hw, priv->addr);

	/* FW loaded, so register with mac80211 */
	ret = mwl8787_register(priv);

disable:
	/* FIXME unbind device */
	release_firmware(fw);
	return;
}

static int mwl8787_sdio_probe(struct sdio_func *func,
			      const struct sdio_device_id *id)
{
	struct mwl8787_priv *priv;
	int ret;

	priv = mwl8787_init();

	if (IS_ERR(priv))
		return PTR_ERR(priv);

	priv->bus_priv = func;
	sdio_set_drvdata(func, priv);

	func->card->quirks |= MMC_QUIRK_BLKSZ_FOR_BYTE_MODE;

	sdio_claim_host(func);
	ret = sdio_enable_func(func);
	if (ret)
		goto release;

	ret = sdio_set_block_size(func, MWL8787_SDIO_BLOCK_SIZE);
	if (ret) {
		pr_err("cannot set SDIO block size\n");
		goto disable;
	}

	ret = sdio_claim_irq(func, mwl8787_sdio_interrupt);
	if (ret) {
		pr_err("claim irq failed: ret=%d\n", ret);
		goto disable;
	}

	SET_IEEE80211_DEV(priv->hw, &func->dev);

	priv->bus_headroom = sizeof(struct mwl8787_sdio_header);
	priv->bus_ops = &sdio_ops;
	priv->dev = &func->dev;

	ret = mwl8787_init_sdio(priv);
	if (ret)
		goto disable;

	ret = request_firmware_nowait(THIS_MODULE, 1, MWL8787_FW_NAME,
				      priv->dev, GFP_KERNEL, priv,
				      mwl8787_fw_cb);
	if (ret) {
		pr_err("request_firmware_nowait failed (%d)\n", ret);
		goto disable;
	}
	sdio_release_host(func);
	return 0;

disable:
	sdio_disable_func(func);
release:
	sdio_release_host(func);
	mwl8787_free(priv);
	return ret;
}

static void mwl8787_sdio_remove(struct sdio_func *func)
{
	struct mwl8787_priv *priv = sdio_get_drvdata(func);

	if (priv->registered)
		mwl8787_unregister(priv);

	sdio_claim_host(func);
	sdio_release_irq(func);
	sdio_release_host(func);

	kfree(priv->mp_regs);
	mwl8787_free(priv);
}

static struct sdio_driver mwl8787_sdio_driver = {
	.name =	 "mwl8787_sdio",
	.probe = mwl8787_sdio_probe,
	.remove = mwl8787_sdio_remove,
	.id_table = mwl8787_sdio_ids,
};

static int __init mwl8787_sdio_init(void)
{
	return sdio_register_driver(&mwl8787_sdio_driver);
}

static void __exit mwl8787_sdio_exit(void)
{
	sdio_unregister_driver(&mwl8787_sdio_driver);
}

module_init(mwl8787_sdio_init);
module_exit(mwl8787_sdio_exit);
