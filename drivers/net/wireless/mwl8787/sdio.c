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

	return ret;
}

static int mwl8787_sdio_prog_fw(struct mwl8787_priv *priv,
				const struct firmware *fw)
{
	return 0; /* that was easy */
}

static struct mwl8787_bus_ops sdio_ops = {
	.prog_fw = mwl8787_sdio_prog_fw,
	.check_fw_ready = mwl8787_sdio_check_fw_ready,
};


static int mwl8787_sdio_probe(struct sdio_func *func,
			      const struct sdio_device_id *id)
{
	struct mwl8787_priv *priv;
	int ret;

	priv = mwl8787_init();

	if (IS_ERR(priv))
		return PTR_ERR(priv);

	sdio_claim_host(func);
	ret = sdio_enable_func(func);
	sdio_release_host(func);
	if (ret)
		goto release;

	priv->bus_priv = func;
	sdio_set_drvdata(func, priv);
	SET_IEEE80211_DEV(priv->hw, &func->dev);

	priv->bus_ops = &sdio_ops;
	priv->dev = &func->dev;

	ret = mwl8787_register(priv);
	if (ret)
		goto release;

	return 0;
release:
	mwl8787_free(priv);
	return ret;
}

static void mwl8787_sdio_remove(struct sdio_func *func)
{
	struct mwl8787_priv *priv = sdio_get_drvdata(func);

	mwl8787_unregister(priv);
	mwl8787_free(priv);
}

static struct sdio_driver mwl8787_sdio_driver = {
	.name =	 "mwl8787_sdio",
	.probe = mwl8787_sdio_probe,
	.remove = mwl8787_sdio_remove,
	.id_table = mwl8787_sdio_ids,
};

/* for testing basic setup without hw, skips all sdio stuff */
#define MWLFAKEDEV
#ifdef MWLFAKEDEV
#include <linux/platform_device.h>

static struct mwl8787_priv *fake_device = NULL;
static struct class *mwl8787_class;

static struct platform_driver mwl8787_fake_driver = {
	.driver = {
		.name = "mwl8787_sdio",
		.owner = THIS_MODULE,
	},
};


static int register_fake_driver(void)
{
	struct mwl8787_priv *priv;
	struct device *dev;
	int err;

	err = platform_driver_register(&mwl8787_fake_driver);
	if (err)
		return err;

	mwl8787_class = class_create(THIS_MODULE, "mwl8787_sdio");
	if (IS_ERR(mwl8787_class))
		return PTR_ERR(mwl8787_class);

	priv = mwl8787_init();

	if (IS_ERR(priv))
		return PTR_ERR(priv);

	dev = device_create(mwl8787_class, NULL, 0, priv, "mwlfake0");
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto release;
	}
	priv->bus_priv = dev;

	dev->driver = &mwl8787_fake_driver.driver;
	err = device_bind_driver(dev);
	if (err)
		return err;

	SET_IEEE80211_DEV(priv->hw, dev);
	fake_device = priv;
	err = mwl8787_register(priv);
	if (err)
		goto release;

	return 0;

release:
	mwl8787_free(priv);
	return err;
}

static void unregister_fake_driver(void)
{
	struct mwl8787_priv *priv = fake_device;
	if (!priv)
		return;

	mwl8787_unregister(priv);
	device_release_driver(priv->bus_priv);
	device_unregister(priv->bus_priv);
	mwl8787_free(priv);
	platform_driver_unregister(&mwl8787_fake_driver);
	class_destroy(mwl8787_class);
}

static int __init mwl8787_sdio_init(void)
{
	return register_fake_driver();
}

static void __exit mwl8787_sdio_exit(void)
{
	unregister_fake_driver();
}

#else
static int __init mwl8787_sdio_init(void)
{
	return sdio_register_driver(&mwl8787_sdio_driver);
}

static void __exit mwl8787_sdio_exit(void)
{
	sdio_unregister_driver(&mwl8787_sdio_driver);
}
#endif
module_init(mwl8787_sdio_init);
module_exit(mwl8787_sdio_exit);
