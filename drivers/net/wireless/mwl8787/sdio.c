#include "mwl8787.h"
#include "sdio.h"
#include "fw.h"

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

	sdio_claim_host(func);

	ret = sdio_writesb(func, ioport, buffer, blk_cnt * blk_size);

	sdio_release_host(func);

	return ret;
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
			print_hex_dump_bytes("fwbuf: ", DUMP_PREFIX_NONE, fwbuf, txlen);
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

static int mwl8787_sdio_send_cmd(struct mwl8787_priv *priv,
				 u8 *buf, size_t len)
{
	u8 *payload;
	size_t buf_block_len;
	struct mwl8787_sdio_header *hdr;
	int ret;

	hdr = (struct mwl8787_sdio_header *) buf - priv->bus_headroom;

	hdr->type = cpu_to_le16(MWL8787_TYPE_CMD);
	hdr->len = cpu_to_le16(len);

	/*
	 * Allocate buffer and copy payload
	 * TODO avoid this alloc/copy...
	 */
	buf_block_len = DIV_ROUND_UP(len, MWL8787_SDIO_BLOCK_SIZE);

	payload = kzalloc(buf_block_len, GFP_KERNEL);
	if (!payload)
		return -ENOMEM;

	memcpy(payload, hdr, len + sizeof(*hdr));
	ret = mwl8787_write(priv, payload, buf_block_len, CTRL_PORT);
	kfree(payload);

	return ret;
}

static struct mwl8787_bus_ops sdio_ops = {
	.prog_fw = mwl8787_sdio_prog_fw,
	.check_fw_ready = mwl8787_sdio_check_fw_ready,
	.send_cmd = mwl8787_sdio_send_cmd,
};

/*
 * This function disables the host interrupt.
 *
 * The host interrupt mask is read, the disable bit is reset and
 * written back to the card host interrupt mask register.
 */
static int mwl8787_sdio_disable_host_int(struct mwl8787_priv *priv)
{
	u8 host_int_mask, host_int_disable = HOST_INT_DISABLE;

	/* Read back the host_int_mask register */
	if (mwl8787_read_reg(priv, HOST_INT_MASK_REG, &host_int_mask))
		return -1;

	/* Update with the mask and write back to the register */
	host_int_mask &= ~host_int_disable;

	if (mwl8787_write_reg(priv, HOST_INT_MASK_REG, host_int_mask)) {
		dev_err(priv->dev, "disable host interrupt failed\n");
		return -1;
	}

	return 0;
}

static int mwl8787_init_sdio(struct mwl8787_priv *priv)
{
	u8 sdio_ireg;

	/*
	 * Read the HOST_INT_STATUS_REG for ACK the first interrupt got
	 * from the bootloader. If we don't do this we get a interrupt
	 * as soon as we register the irq.
	 */
	mwl8787_read_reg(priv, HOST_INTSTATUS_REG, &sdio_ireg);

	/* Disable host interrupt mask register for SDIO */
	mwl8787_sdio_disable_host_int(priv);

	/* Get SDIO ioport */
	mwl8787_init_sdio_ioport(priv);
	/* XXX: maybe need this stuff for RX/TX
	card->mp_rd_bitmap = 0;
	card->mp_wr_bitmap = 0;
	card->curr_rd_port = reg->start_rd_port;
	card->curr_wr_port = reg->start_wr_port;

	card->mp_data_port_mask = reg->data_port_mask;

	card->mpa_tx.buf_len = 0;
	card->mpa_tx.pkt_cnt = 0;
	card->mpa_tx.start_port = 0;

	card->mpa_tx.enabled = 1;
	card->mpa_tx.pkt_aggr_limit = card->mp_agg_pkt_limit;

	card->mpa_rx.buf_len = 0;
	card->mpa_rx.pkt_cnt = 0;
	card->mpa_rx.start_port = 0;

	card->mpa_rx.enabled = 1;
	card->mpa_rx.pkt_aggr_limit = card->mp_agg_pkt_limit;
	*/

	/* Allocate buffers for SDIO MP-A */
	priv->mp_regs = kzalloc(MWL8787_MAX_MP_REGS, GFP_KERNEL);
	if (!priv->mp_regs)
		return -ENOMEM;

	return 0;
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

	return ret;
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

static int mwl8787_sdio_probe(struct sdio_func *func,
			      const struct sdio_device_id *id)
{
	struct mwl8787_priv *priv;
	int ret;

	priv = mwl8787_init();

	if (IS_ERR(priv))
		return PTR_ERR(priv);

	func->card->quirks |= MMC_QUIRK_BLKSZ_FOR_BYTE_MODE;

	sdio_claim_host(func);

	ret = sdio_enable_func(func);

	/* Request the SDIO IRQ */
	ret = sdio_claim_irq(func, mwl8787_sdio_interrupt);
	if (ret) {
		pr_err("claim irq failed: ret=%d\n", ret);
		goto disable;
	}

	/* Set block size */
	ret = sdio_set_block_size(func, MWL8787_SDIO_BLOCK_SIZE);
	if (ret) {
		pr_err("cannot set SDIO block size\n");
		ret = -1;
		goto release;
	}

	sdio_release_host(func);
	if (ret)
		goto release;

	priv->bus_priv = func;
	sdio_set_drvdata(func, priv);
	SET_IEEE80211_DEV(priv->hw, &func->dev);

	priv->bus_headroom = sizeof(struct mwl8787_sdio_header);
	priv->bus_ops = &sdio_ops;
	priv->dev = &func->dev;

	ret = mwl8787_init_sdio(priv);
	if (ret)
		goto release;

	ret = mwl8787_register(priv);
	if (ret)
		goto release;

	return 0;
disable:
	sdio_disable_func(func);
	sdio_release_host(func);
release:
	mwl8787_free(priv);
	return ret;
}

static void mwl8787_sdio_remove(struct sdio_func *func)
{
	struct mwl8787_priv *priv = sdio_get_drvdata(func);

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
