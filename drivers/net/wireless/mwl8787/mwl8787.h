#ifndef MWL8787_H
#define MWL8787_H

#include <net/mac80211.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/spinlock.h>

#define MWL8787_UPLD_SIZE               (2312)

struct mwl8787_priv;

struct mwl8787_bus_ops
{
	int (*prog_fw)(struct mwl8787_priv *, const struct firmware *);
	int (*check_fw_ready)(struct mwl8787_priv *, u32);
	int (*enable_int) (struct mwl8787_priv *);
	int (*send_cmd)(struct mwl8787_priv *priv, int id, u8 *buf, size_t len);
};

struct mwl8787_priv
{
	struct ieee80211_hw *hw;
	const struct firmware *fw;
	void *bus_priv;
	struct mwl8787_bus_ops *bus_ops;
	struct device *dev;
	spinlock_t int_lock;
	u32 int_status;

	/* sdio */
	u32 ioport;
	u8 *mp_regs;
};

/* main */
struct mwl8787_priv *mwl8787_init(void);
int mwl8787_register(struct mwl8787_priv *priv);
void mwl8787_unregister(struct mwl8787_priv *priv);
void mwl8787_free(struct mwl8787_priv *priv);
int mwl8787_main_process(struct mwl8787_priv *priv);

/* fw.c? */
int mwl8787_send_cmd(struct mwl8787_priv *priv, int id,
		     u8 *buf, size_t len);

/* tx */
void mwl8787_tx(struct ieee80211_hw *hw,
		struct ieee80211_tx_control *control,
		struct sk_buff *skb);

/* testmode */
int mwl8787_testmode_cmd(struct ieee80211_hw *hw, void *data, int len);
int mwl8787_testmode_dump(struct ieee80211_hw *hw, struct sk_buff *skb,
			  struct netlink_callback *cb,
			  void *data, int len);
#endif
