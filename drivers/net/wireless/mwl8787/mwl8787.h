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

#define MWL8787_TX_CT_HI		100
#define MWL8787_TX_CT_LO		80

/*
 * We can only track 7 frames in the sdio aggregation buffer: because
 * the bitmap to represent pending frames has 8 bits, 8 neighboring ports
 * can be occupied.  However, one of these may be the control port, in
 * which case 8 data frames would overflow the bitmap.
 */
#define MWL8787_SDIO_MP_AGGR_DEF_PKT_LIMIT 7
#define MWL8787_MAX_AMPDU_SESSIONS 2

enum mwl8787_hw_status {
	MWL8787_HW_STATUS_READY,
	MWL8787_HW_STATUS_INITIALIZING,
	MWL8787_HW_STATUS_FW_READY,
	MWL8787_HW_STATUS_INIT_DONE,
	MWL8787_HW_STATUS_RESET,
	MWL8787_HW_STATUS_CLOSING,
	MWL8787_HW_STATUS_NOT_READY
};

enum mwl8787_ampdu_state {
	MWL8787_AMPDU_NONE,
	MWL8787_AMPDU_INIT,
	MWL8787_AMPDU_START,
	MWL8787_AMPDU_OPERATIONAL,
};

struct mwl8787_sta
{
	struct mwl8787_priv *priv;
	struct ieee80211_sta *sta;
	struct work_struct ampdu_work;
	enum mwl8787_ampdu_state ampdu_state[IEEE80211_NUM_TIDS];
	int ssn[IEEE80211_NUM_TIDS];
};

struct mwl8787_priv;

struct mwl8787_bus_ops
{
	int (*prog_fw)(struct mwl8787_priv *, const struct firmware *);
	int (*check_fw_ready)(struct mwl8787_priv *, u32);
	int (*enable_int) (struct mwl8787_priv *);
	int (*send_cmd)(struct mwl8787_priv *priv, u8 *buf, size_t len);
	int (*send_tx)(struct mwl8787_priv *priv, struct sk_buff *skb,
		       bool more_frames);
	int (*process_int_status) (struct mwl8787_priv *);
	void (*card_reset) (struct mwl8787_priv *);
	bool (*is_tx_busy) (struct mwl8787_priv *);
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

	struct completion fw_done;	/* completed when firmware loaded */
	struct completion init_wait;

	enum mwl8787_hw_status hw_status;

	struct device *dev;
	spinlock_t int_lock;
	u32 int_status;

	/* device capabilities */
	u16 region_code;		/* regulatory region */
	u16 num_ant;			/* number of antennas */
	u32 fw_cap_info;		/* firmware capability flags */
	u32 dot_11n_dev_cap;		/* 802.11n capabilities */
	u8 num_streams;			/* # of spatial streams */

	/* information about pending command */
	struct mutex cmd_mutex;
	spinlock_t cmd_resp_lock;	/* protects next 3 fields */
	u16 cmd_id;			/* fw id of submitted command */
	struct sk_buff *cmd_resp_skb;	/* stores return result */
	bool keep_resp;			/* true if caller wants response */
	struct completion cmd_wait;	/* completed on command response */
	int cmd_seq;			/* next cmd sequence number */

	u32 mac_ctrl;			/* cache of filter flags & cts prot */

	int num_ampdu_sessions;		/* how many ampdu sessions active */
	u8 addba_dialog_token;		/* cookie for ampdu requests */

	struct work_struct tx_work;
	struct work_struct card_reset_work;
	struct sk_buff_head tx_queue;
	struct sk_buff_head tx_status_queue[IEEE80211_NUM_ACS];

	atomic_t tx_pending[IEEE80211_NUM_ACS];

	struct dentry *dfs_dev_dir;

	bool stopped[IEEE80211_NUM_ACS];

	/* sdio */
	u32 ioport;
	u8 *mp_regs;
	u32 mp_rd_bitmap;
	u32 mp_wr_bitmap;
	u32 mp_data_port_mask;
	u8 curr_rd_port;
	u8 curr_wr_port;
	u8 mp_end_port;

	/* tx failure event threshold */
	int tx_fail;

	struct {
		u8 *buf;
		u32 buf_len;
		u32 pkt_cnt;
		u16 start_port;
		u8 enabled;
		u32 buf_size;
	} mpa_tx;

	struct {
		u8 *buf;
		u32 buf_len;
		u32 pkt_cnt;
		u16 start_port;
		struct sk_buff *skb_arr[MWL8787_SDIO_MP_AGGR_DEF_PKT_LIMIT];
		u32 len_arr[MWL8787_SDIO_MP_AGGR_DEF_PKT_LIMIT];
		u8 enabled;
		u32 buf_size;
	} mpa_rx;
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
int mwl8787_send_cmd_reply(struct mwl8787_priv *priv,
			   struct mwl8787_cmd *cmd,
			   struct sk_buff **reply);
int mwl8787_cmd_mac_ctrl(struct mwl8787_priv *priv, u32 control);
int mwl8787_cmd_hw_spec(struct mwl8787_priv *priv);
int mwl8787_cmd_init(struct mwl8787_priv *priv);
int mwl8787_cmd_rf_channel(struct mwl8787_priv *priv,
			   struct cfg80211_chan_def *chandef);
int mwl8787_cmd_11n_cfg(struct mwl8787_priv *priv,
			struct cfg80211_chan_def *chandef);
struct mwl8787_cmd *mwl8787_cmd_alloc(struct mwl8787_priv *priv,
				      int id, size_t len, gfp_t gfp_flags);
void mwl8787_cmd_free(struct mwl8787_priv *priv, void *ptr);
int mwl8787_cmd_rx(struct mwl8787_priv *priv, struct sk_buff *skb);
int mwl8787_cmd_radio_ctrl(struct mwl8787_priv *priv, bool on);
int mwl8787_cmd_monitor(struct mwl8787_priv *priv, bool on);
int mwl8787_cmd_beacon_set(struct mwl8787_priv *priv, struct sk_buff *skb);
int mwl8787_cmd_beacon_ctrl(struct mwl8787_priv *priv, u16 beacon_int,
			    bool enable_beacon);
int mwl8787_cmd_subscribe_events(struct mwl8787_priv *priv, u16 action,
				 u16 events);
int mwl8787_cmd_snmp_mib(struct mwl8787_priv *priv, enum mwl8787_oid oid,
			 u16 value);
int mwl8787_cmd_get_tsf(struct mwl8787_priv *priv, u64 *tsf);
int mwl8787_cmd_set_tsf(struct mwl8787_priv *priv, const u64 tsf);
int mwl8787_cmd_log(struct mwl8787_priv *priv,
		    struct ieee80211_low_level_stats *stats);
int mwl8787_cmd_link_stats(struct mwl8787_priv *priv, u8 *addr,
			   struct ieee80211_link_stats *stats);
int mwl8787_cmd_set_wmm_conf(struct mwl8787_priv *priv, u16 ac,
			     struct ieee80211_tx_queue_params *params);
int mwl8787_cmd_set_mac_addr(struct mwl8787_priv *priv, u8 *addr);
int mwl8787_cmd_set_peer(struct mwl8787_priv *priv, struct ieee80211_sta *sta);
int mwl8787_cmd_del_peer(struct mwl8787_priv *priv, struct ieee80211_sta *sta);
int mwl8787_cmd_addba_req(struct mwl8787_priv *priv,
			  struct ieee80211_sta *sta,
			  u16 tid, u16 ssn, u8 buf_size);
int mwl8787_cmd_delba(struct mwl8787_priv *priv,
		      struct ieee80211_sta *sta,
		      u16 tid);
int mwl8787_cmd_tx_power(struct mwl8787_priv *priv, int max_tx_power);

/* tx */
void mwl8787_tx(struct ieee80211_hw *hw,
		struct ieee80211_tx_control *control,
		struct sk_buff *skb);
void mwl8787_tx_work(struct work_struct *work);
void mwl8787_tx_status(struct mwl8787_priv *priv,
		       struct mwl8787_event *tx_status_event);
void mwl8787_tx_fail(struct mwl8787_priv *priv,
		     struct mwl8787_event *tx_fail_event);
void mwl8787_tx_cleanup(struct mwl8787_priv *priv);

/* ampdu.c */
void mwl8787_ampdu_work(struct work_struct *work);
void mwl8787_ampdu_check(struct mwl8787_priv *priv,
			 struct ieee80211_sta *sta,
			 struct sk_buff *skb);
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
