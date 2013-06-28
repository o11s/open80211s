#include "mwl8787.h"
#include <linux/module.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/sdio_ids.h>

MODULE_DESCRIPTION("Marvell 8787 SDIO wireless");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cozybit Inc.");

static struct sdio_device_id mwl8787_sdio_ids[] = {

	{ SDIO_DEVICE(0x02df, 0x9119) },
	{}
};
MODULE_DEVICE_TABLE(sdio, mwl8787_sdio_ids);

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
