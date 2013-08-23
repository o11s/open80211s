#ifndef MWL8787_H
#define MWL8787_H

#include <net/mac80211.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/spinlock.h>

#include "fw.h"

#define MWL8787_FW_NAME "mrvl/sd8787_uapsta.bin"

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
	int (*send_tx)(struct mwl8787_priv *priv, struct sk_buff *skb);
	int (*process_int_status) (struct mwl8787_priv *);
	void (*card_reset) (struct mwl8787_priv *);
};

struct mwl8787_priv
{
	struct ieee80211_hw *hw;
	const struct firmware *fw;
	bool registered;

	u8 addr[ETH_ALEN];

	struct mwl8787_bus_ops *bus_ops;
	void *bus_priv;
	int bus_headroom;

	struct completion init_wait;
	struct completion cmd_wait;

	enum mwl8787_hw_status hw_status;

	struct device *dev;
	spinlock_t int_lock;
	u32 int_status;

	int cmd_seq;
	struct sk_buff *cmd_resp_skb;
	bool keep_resp;
	u8 cmd_sent;
	u8 data_sent;

	u16 mac_ctrl;			/* cache of filter flags & cts prot */

	struct work_struct tx_work;
	struct sk_buff_head tx_queue;
	struct sk_buff_head tx_status_queue;
	u16 tx_seq;			/* sequence number for ASSIGN_SEQ */

	struct ieee80211_channel *channel;
	struct dentry *dfs_dev_dir;

	/* sdio */
	u32 ioport;
	u8 *mp_regs;
	u32 mp_rd_bitmap;
	u32 mp_wr_bitmap;
	u32 mp_data_port_mask;
	u8 curr_rd_port;
	u8 curr_wr_port;
	u8 mp_end_port;
};

/* main */
struct mwl8787_priv *mwl8787_init(void);
int mwl8787_register(struct mwl8787_priv *priv);
void mwl8787_unregister(struct mwl8787_priv *priv);
void mwl8787_free(struct mwl8787_priv *priv);
int mwl8787_main_process(struct mwl8787_priv *priv);
int mwl8787_init_fw(struct mwl8787_priv *priv);
int mwl8787_dnld_fw(struct mwl8787_priv *priv);

/* cmd.c */
int mwl8787_send_cmd(struct mwl8787_priv *priv, struct mwl8787_cmd *cmd);
int mwl8787_send_cmd_sync(struct mwl8787_priv *priv, struct mwl8787_cmd *cmd);
int mwl8787_send_cmd_tm(struct mwl8787_priv *priv,
			struct mwl8787_cmd *cmd,
			struct sk_buff **reply);
int mwl8787_reset(struct mwl8787_priv *priv);
int mwl8787_cmd_mac_ctrl(struct mwl8787_priv *priv, u16 control);
int mwl8787_cmd_hw_spec(struct mwl8787_priv *priv);
int mwl8787_cmd_init(struct mwl8787_priv *priv);
int mwl8787_cmd_rf_channel(struct mwl8787_priv *priv, u16 channel);
int mwl8787_cmd_scan(struct mwl8787_priv *priv,
		     struct cfg80211_scan_request *request);
struct mwl8787_cmd *mwl8787_cmd_alloc(struct mwl8787_priv *priv,
				      int id, size_t len, gfp_t gfp_flags);
void mwl8787_cmd_free(struct mwl8787_priv *priv, void *ptr);
int mwl8787_process_cmdresp(struct mwl8787_priv *priv, struct sk_buff *skb);
int mwl8787_cmd_radio_ctrl(struct mwl8787_priv *priv, bool on);
int mwl8787_cmd_monitor(struct mwl8787_priv *priv, bool on);
int mwl8787_cmd_beacon_set(struct mwl8787_priv *priv, struct sk_buff *skb);
int mwl8787_cmd_beacon_ctrl(struct mwl8787_priv *priv, u16 beacon_int,
			    bool enable_beacon);
int mwl8787_cmd_subscribe_events(struct mwl8787_priv *priv, u16 events);
int mwl8787_cmd_snmp_mib(struct mwl8787_priv *priv, enum mwl8787_oid oid,
			 u16 value);

/* tx */
void mwl8787_tx(struct ieee80211_hw *hw,
		struct ieee80211_tx_control *control,
		struct sk_buff *skb);
void mwl8787_tx_work(struct work_struct *work);
void mwl8787_tx_status(struct mwl8787_priv *priv,
		       struct mwl8787_event *tx_status_event);
void mwl8787_tx_cleanup(struct mwl8787_priv *priv);

/* rx.c */
void mwl8787_rx(struct mwl8787_priv *priv, struct sk_buff *skb);

/* event.c */
void mwl8787_event_rx(struct mwl8787_priv *priv, struct sk_buff *skb);

/* testmode */
#ifdef CONFIG_NL80211_TESTMODE
int mwl8787_testmode_cmd(struct ieee80211_hw *hw, void *data, int len);
int mwl8787_testmode_dump(struct ieee80211_hw *hw, struct sk_buff *skb,
			  struct netlink_callback *cb,
			  void *data, int len);
int mwl8787_testmode_event(struct mwl8787_priv *priv,
			   struct mwl8787_event *event, size_t len);
#else
static inline
int mwl8787_testmode_event(struct mwl8787_priv *priv,
			   struct mwl8787_event *event, size_t len) {
	return 0;
}
#endif

#endif
