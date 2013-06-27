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
