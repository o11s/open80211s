/*
 * Copyright (c) 2013 Cozybit, Inc.
 */

#include "mwl8787.h"
#include "fw.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

#define CHAN(_freq, _idx) { \
	.center_freq = (_freq), \
	.hw_value = (_idx), \
	.max_power = 20, \
}

static struct ieee80211_channel mwl8787_2ghz_chantable[] = {
	CHAN(2412, 1),
	CHAN(2417, 2),
	CHAN(2422, 3),
	CHAN(2427, 4),
	CHAN(2432, 5),
	CHAN(2437, 6),
	CHAN(2442, 7),
	CHAN(2447, 8),
	CHAN(2452, 9),
	CHAN(2457, 10),
	CHAN(2462, 11),
	CHAN(2467, 12),
	CHAN(2472, 13),
	CHAN(2484, 14),
};

static struct ieee80211_channel mwl8787_5ghz_chantable[] = {
	CHAN(5180, 36),
	CHAN(5200, 40),
	CHAN(5220, 44),
	CHAN(5240, 48),
	CHAN(5260, 52),
	CHAN(5280, 56),
	CHAN(5300, 60),
	CHAN(5320, 64),
	CHAN(5500, 100),
	CHAN(5520, 104),
	CHAN(5540, 108),
	CHAN(5560, 112),
	CHAN(5580, 116),
	CHAN(5600, 120),
	CHAN(5620, 124),
	CHAN(5640, 128),
	CHAN(5660, 132),
	CHAN(5680, 136),
	CHAN(5700, 140),
	CHAN(5745, 149),
	CHAN(5765, 153),
	CHAN(5785, 157),
	CHAN(5805, 161),
	CHAN(5825, 165),
};

#define RATE(_bitrate, _idx, _flags) {              \
	.bitrate        = (_bitrate),               \
	.flags          = (_flags),                 \
	.hw_value       = (_idx),                   \
}
static struct ieee80211_rate mwl8787_rates[] = {
	RATE(10, 0, 0),
	RATE(20, 1, IEEE80211_RATE_SHORT_PREAMBLE),
	RATE(55, 2, IEEE80211_RATE_SHORT_PREAMBLE),
	RATE(110, 3, IEEE80211_RATE_SHORT_PREAMBLE),
	RATE(60, 4, 0),
	RATE(90, 5, 0),
	RATE(120, 6, 0),
	RATE(180, 7, 0),
	RATE(240, 8, 0),
	RATE(360, 9, 0),
	RATE(480, 10, 0),
	RATE(540, 11, 0),
};

#define mwl8787_2ghz_rates mwl8787_rates
#define mwl8787_2ghz_rates_len ARRAY_SIZE(mwl8787_rates)
#define mwl8787_5ghz_rates (mwl8787_rates + 4)
#define mwl8787_5ghz_rates_len ARRAY_SIZE(mwl8787_rates) - 4

static struct ieee80211_supported_band mwl8787_2ghz_band = {
	.channels = mwl8787_2ghz_chantable,
	.n_channels = ARRAY_SIZE(mwl8787_2ghz_chantable),
	.bitrates = mwl8787_2ghz_rates,
	.n_bitrates = mwl8787_2ghz_rates_len
};

static struct ieee80211_supported_band mwl8787_5ghz_band = {
	.channels = mwl8787_5ghz_chantable,
	.n_channels = ARRAY_SIZE(mwl8787_5ghz_chantable),
	.bitrates = mwl8787_5ghz_rates,
	.n_bitrates = mwl8787_5ghz_rates_len
};

/*
 * This function issues commands to initialize firmware.
 *
 * This is called after firmware download to bring the card to
 * working state.
 *
 * The following commands are issued sequentially -
 *      - Set PCI-Express host buffer configuration (PCIE only)
 *      - Function init (for first interface only)
 *      - Read MAC address (for first interface only)
 *      - Reconfigure Tx buffer size (for first interface only)
 *      - Enable auto deep sleep (for first interface only)
 *      - Get Tx rate
 *      - Get Tx power
 *      - Set MAC control (this must be the last command to initialize firmware)
 */
int mwl8787_fw_init_cmd(struct mwl8787_priv *priv)
{
	int ret;

	ret = mwl8787_cmd_init(priv);
	if (ret)
		return ret;

	/* get hw description & mac address */
	ret = mwl8787_cmd_hw_spec(priv);
	if (ret)
		return ret;

	/* turn on the radio */
	ret = mwl8787_cmd_radio_ctrl(priv, true);
	if (ret)
		return ret;

#if 0
	/* Reconfigure tx buf size */
	ret = mwifiex_send_cmd_sync(priv,
				    HostCmd_CMD_RECONFIGURE_TX_BUFF,
				    HostCmd_ACT_GEN_SET, 0,
				    &priv->adapter->tx_buf_size);
	if (ret)
		return ret;

	/* get tx rate */
	ret = mwifiex_send_cmd_sync(priv, HostCmd_CMD_TX_RATE_CFG,
				    HostCmd_ACT_GEN_GET, 0, NULL);
	if (ret)
		return ret;
	priv->data_rate = 0;

	/* get tx power */
	ret = mwifiex_send_cmd_sync(priv, HostCmd_CMD_RF_TX_PWR,
				    HostCmd_ACT_GEN_GET, 0, NULL);
	if (ret)
		return ret;

	if (priv->bss_type == MWL8787_BSS_TYPE_STA) {
		/* set ibss coalescing_status */
		ret = mwifiex_send_cmd_sync(
				priv, HostCmd_CMD_802_11_IBSS_COALESCING_STATUS,
				HostCmd_ACT_GEN_SET, 0, &enable);
		if (ret)
			return ret;
	}
#endif
	return ret;
}
/*
 * This function initializes the firmware.
 *
 * The following operations are performed sequentially -
 *      - Allocate adapter structure
 *      - Initialize the adapter structure
 *      - Initialize the private structure
 *      - Add BSS priority tables to the adapter structure
 *      - For each interface, send the init commands to firmware
 *      - Send the first command in command pending queue, if available
 */
int mwl8787_init_fw(struct mwl8787_priv *priv)
{
	int ret;

	priv->hw_status = MWL8787_HW_STATUS_INITIALIZING;

	ret = mwl8787_fw_init_cmd(priv);
	if (ret)
		return ret;

	priv->hw_status = MWL8787_HW_STATUS_READY;

	return ret;
}

int mwl8787_dnld_fw(struct mwl8787_priv *priv)
{
	int ret;

	if (WARN_ON(!priv->fw))
		return -EINVAL;

	/* check if firmware is already running */
	ret = priv->bus_ops->check_fw_ready(priv, 1);
	if (!ret) {
		dev_notice(priv->dev,
			   "WLAN FW already running! Skip FW dnld\n");
		goto done;
	}

	/* Download firmware with helper */
	ret = priv->bus_ops->prog_fw(priv, priv->fw);
	if (ret) {
		dev_err(priv->dev, "prog_fw failed ret=%#x\n", ret);
		return ret;
	}

	/* Check if the firmware is downloaded successfully or not */
	ret = priv->bus_ops->check_fw_ready(priv, MAX_FIRMWARE_POLL_TRIES);
	if (ret) {
		dev_err(priv->dev, "FW failed to be active in time\n");
		return ret;
	}

done:
	/* re-enable host interrupt for mwifiex after fw dnld is successful */
	if (priv->bus_ops->enable_int)
		priv->bus_ops->enable_int(priv);

	return ret;
}

/*
 * The main process.
 *
 * This function is the main procedure of the driver and handles various driver
 * operations. It runs in a loop and provides the core functionalities.
 *
 * The main responsibilities of this function are -
 *      - Ensure concurrency control
 *      - Handle pending interrupts and call interrupt handlers
 *      - Wake up the card if required
 *      - Handle command responses and call response handlers
 *      - Handle events and call event handlers
 *      - Execute pending commands
 *      - Transmit pending data packets
 */
int mwl8787_main_process(struct mwl8787_priv *priv)
{
	int ret = 0;

	dev_dbg(priv->dev, "got IRQs: %4X!\n", priv->int_status);

	if (priv->int_status)
		priv->bus_ops->process_int_status(priv);

	/* Check for Cmd Resp */
	if (priv->cmd_resp_skb)
		mwl8787_process_cmdresp(priv, priv->cmd_resp_skb);

	return ret;
}

static int mwl8787_start(struct ieee80211_hw *hw)
{
	return 0;
}

static void mwl8787_stop(struct ieee80211_hw *hw)
{
}

static int mwl8787_add_interface(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif)
{
	return 0;
}

static void mwl8787_remove_interface(struct ieee80211_hw *hw,
				     struct ieee80211_vif *vif)
{
}

static int mwl8787_config(struct ieee80211_hw *hw, u32 changed)
{
	struct mwl8787_priv *priv = hw->priv;
	u16 channel;

	if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
		channel = hw->conf.chandef.chan->hw_value;
		mwl8787_cmd_rf_channel(priv, channel);
	}

	return 0;
}

static void mwl8787_configure_filter(struct ieee80211_hw *hw,
				     unsigned int changed_flags,
				     unsigned int *total_flags,
				     u64 multicast)
{
	struct mwl8787_priv *priv = hw->priv;
	int supported_flags = FIF_PROMISC_IN_BSS | FIF_ALLMULTI;

	u16 filter = MWL8787_FIF_ENABLE_RX |
		     MWL8787_FIF_ENABLE_TX |
		     MWL8787_FIF_ENABLE_80211 |
		     MWL8787_FIF_ENABLE_MGMT;

	/* TODO: some of these should likely set PROMISC
	  FIF_FCSFAIL | FIF_PLCPFAIL | FIF_BCN_PRBRESP_PROMISC |
	  FIF_CONTROL | FIF_OTHER_BSS | FIF_PSPOLL | FIF_PROBE_REQ
	*/
	changed_flags &= supported_flags;
	*total_flags &= supported_flags;

	if (*total_flags & FIF_PROMISC_IN_BSS) {
		*total_flags &= ~FIF_PROMISC_IN_BSS;
		filter |= MWL8787_FIF_ENABLE_PROMISC;
	}

	if (*total_flags & FIF_ALLMULTI) {
		*total_flags &= ~FIF_ALLMULTI;
		filter |= MWL8787_FIF_ENABLE_ALLMULTI;
	}

	mwl8787_cmd_mac_ctrl(priv, filter);
}

static int mwl8787_hw_scan(struct ieee80211_hw *hw,
			   struct ieee80211_vif *vif,
			   struct cfg80211_scan_request *req)
{
	return mwl8787_cmd_scan(hw->priv, req);
}

const struct ieee80211_ops mwl8787_ops = {
	.tx = mwl8787_tx,
	.start = mwl8787_start,
	.stop = mwl8787_stop,
	.add_interface = mwl8787_add_interface,
	.remove_interface = mwl8787_remove_interface,
	.config = mwl8787_config,
	.configure_filter = mwl8787_configure_filter,
	.hw_scan = mwl8787_hw_scan,
	CFG80211_TESTMODE_CMD(mwl8787_testmode_cmd)
	CFG80211_TESTMODE_DUMP(mwl8787_testmode_dump)
};

struct mwl8787_priv *mwl8787_init(void)
{
	struct mwl8787_priv *priv;
	struct ieee80211_hw *hw;

	hw = ieee80211_alloc_hw(sizeof(*priv), &mwl8787_ops);
	if (!hw)
		return ERR_PTR(-ENOMEM);

	priv = hw->priv;
	priv->hw = hw;

	spin_lock_init(&priv->int_lock);
	init_completion(&priv->init_wait);
	init_completion(&priv->cmd_wait);

	/* TODO revisit all this */
	hw->wiphy->interface_modes =
		BIT(NL80211_IFTYPE_STATION) |
		BIT(NL80211_IFTYPE_MESH_POINT);
	hw->flags = IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING;
	hw->queues = 4;
	hw->max_rates = 4;
	hw->max_rate_tries = 11;
	hw->channel_change_time = 100;
	hw->wiphy->bands[IEEE80211_BAND_2GHZ] = &mwl8787_2ghz_band;
	hw->wiphy->bands[IEEE80211_BAND_5GHZ] = &mwl8787_5ghz_band;

	hw->wiphy->max_scan_ssids = 4;
	hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;

	return priv;
}

int mwl8787_register(struct mwl8787_priv *priv)
{
	int ret = ieee80211_register_hw(priv->hw);
	priv->registered = (ret == 0);
	return ret;
}

void mwl8787_unregister(struct mwl8787_priv *priv)
{
	ieee80211_unregister_hw(priv->hw);
	priv->registered = false;
}

void mwl8787_free(struct mwl8787_priv *priv)
{
	ieee80211_free_hw(priv->hw);
}
