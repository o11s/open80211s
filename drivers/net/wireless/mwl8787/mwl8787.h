#ifndef MWL8787_H
#define MWL8787_H

#include <net/mac80211.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/spinlock.h>

#include "fw.h"

#define MWL8787_UPLD_SIZE               (2312)
#define MWL8787_RX_DATA_BUF_SIZE     (4 * 1024)

enum mwl8787_hw_status {
	MWL8787_HW_STATUS_READY,
	MWL8787_HW_STATUS_INITIALIZING,
	MWL8787_HW_STATUS_FW_READY,
	MWL8787_HW_STATUS_INIT_DONE,
	MWL8787_HW_STATUS_RESET,
	MWL8787_HW_STATUS_CLOSING,
	MWL8787_HW_STATUS_NOT_READY
};

struct mwl8787_priv;

struct mwl8787_bus_ops
{
	int (*prog_fw)(struct mwl8787_priv *, const struct firmware *);
	int (*check_fw_ready)(struct mwl8787_priv *, u32);
	int (*enable_int) (struct mwl8787_priv *);
	int (*send_cmd)(struct mwl8787_priv *priv, u8 *buf, size_t len);
	int (*process_int_status) (struct mwl8787_priv *);
};

struct mwl8787_priv
{
	struct ieee80211_hw *hw;
	const struct firmware *fw;

	struct mwl8787_bus_ops *bus_ops;
	void *bus_priv;
	int bus_headroom;

	u16 init_wait_q_woken;
	wait_queue_head_t init_wait_q;
	u16 cmd_completed;
	wait_queue_head_t cmd_wait_q;

	enum mwl8787_hw_status hw_status;

	struct device *dev;
	spinlock_t int_lock;
	u32 int_status;

	int cmd_seq;
	struct sk_buff *cmd_resp_skb;
	u8 cmd_sent;
	u8 data_sent;

	/* sdio */
	u32 ioport;
	u8 *mp_regs;
	u32 mp_rd_bitmap;
	u32 mp_wr_bitmap;
	u8 curr_rd_port;
	u8 curr_wr_port;
};

/* main */
struct mwl8787_priv *mwl8787_init(void);
int mwl8787_register(struct mwl8787_priv *priv);
void mwl8787_unregister(struct mwl8787_priv *priv);
void mwl8787_free(struct mwl8787_priv *priv);
int mwl8787_main_process(struct mwl8787_priv *priv);

/* cmd.c */
int mwl8787_send_cmd(struct mwl8787_priv *priv, u8 *buf, size_t len);
int mwl8787_reset(struct mwl8787_priv *priv);
int mwl8787_cmd_init(struct mwl8787_priv *priv);
struct mwl8787_cmd *mwl8787_cmd_alloc(struct mwl8787_priv *priv,
				      int id, size_t len, gfp_t gfp_flags);
void mwl8787_cmd_free(struct mwl8787_priv *priv, void *ptr);
int mwl8787_process_cmdresp(struct mwl8787_priv *priv, struct sk_buff *skb);

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
