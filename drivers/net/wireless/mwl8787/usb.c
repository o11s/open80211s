#include "mwl8787.h"
#include <linux/module.h>
#include <linux/usb.h>

MODULE_DESCRIPTION("Marvell 8787 USB wireless");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cozybit Inc.");

static struct usb_device_id mwl8787_usb_ids[] = {

	{ USB_DEVICE(0x1286, 0x2043) },
	{ USB_DEVICE(0x1286, 0x2044) },
	{}
};
MODULE_DEVICE_TABLE(usb, mwl8787_usb_ids);

static int mwl8787_usb_probe(struct usb_interface *intf,
			     const struct usb_device_id *id)
{
	struct mwl8787_priv *priv;

	priv = mwl8787_init();

	if (IS_ERR(priv))
		return PTR_ERR(priv);

	usb_set_intfdata(intf, priv);
	SET_IEEE80211_DEV(priv->hw, &intf->dev);

	return 0;
}

static void mwl8787_usb_disconnect(struct usb_interface *intf)
{
	struct mwl8787_priv *priv = usb_get_intfdata(intf);

	mwl8787_unregister(priv);
	mwl8787_free(priv);
}

static struct usb_driver mwl8787_usb_driver = {
	.name =	 "mwl8787_usb",
	.probe = mwl8787_usb_probe,
	.disconnect = mwl8787_usb_disconnect,
	.id_table = mwl8787_usb_ids,
};

module_usb_driver(mwl8787_usb_driver);
