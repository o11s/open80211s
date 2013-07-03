/*
 * Copyright (c) 2013 Cozybit, Inc.
 */

#include "mwl8787.h"
#include "fw.h"

#define MWL8787_FW_NAME "mrvl/sd8787_uapsta.bin"

#define CHAN(_freq, _idx) { \
	.center_freq = (_freq), \
	.hw_value = (_idx), \
	.max_power = 20, \
}

static struct ieee80211_channel mwl8787_2ghz_chantable[] = {
	CHAN(2412, 0),
	CHAN(2417, 1),
	CHAN(2422, 2),
	CHAN(2427, 3),
	CHAN(2432, 4),
	CHAN(2437, 5),
	CHAN(2442, 6),
	CHAN(2447, 7),
	CHAN(2452, 8),
	CHAN(2457, 9),
	CHAN(2462, 10),
	CHAN(2467, 11),
	CHAN(2472, 12),
	CHAN(2484, 13),
};

static struct ieee80211_channel mwl8787_5ghz_chantable[] = {
	CHAN(5180, 14),
	CHAN(5200, 15),
	CHAN(5220, 16),
	CHAN(5240, 17),
	CHAN(5260, 18),
	CHAN(5280, 19),
	CHAN(5300, 20),
	CHAN(5320, 21),
	CHAN(5500, 22),
	CHAN(5520, 23),
	CHAN(5540, 24),
	CHAN(5560, 25),
	CHAN(5580, 26),
	CHAN(5600, 27),
	CHAN(5620, 28),
	CHAN(5640, 29),
	CHAN(5660, 30),
	CHAN(5680, 31),
	CHAN(5700, 32),
	CHAN(5745, 33),
	CHAN(5765, 34),
	CHAN(5785, 35),
	CHAN(5805, 36),
	CHAN(5825, 37),
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

static int mwl8787_dnld_fw(struct mwl8787_priv *priv)
{
	int ret;

	if (!priv->fw) {
		dev_dbg(priv->dev, "no firmware? \n");
		return -1;
	}

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
		return -1;
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

	return ret;
}

static int mwl8787_start(struct ieee80211_hw *hw)
{
	struct mwl8787_priv *priv = hw->priv;
	int ret;

	ret = request_firmware(&priv->fw, MWL8787_FW_NAME,
			       wiphy_dev(hw->wiphy));
	if (ret) {
		dev_err(priv->dev,
		       "mwl8787: unable to find firmware %s\n",
		       MWL8787_FW_NAME);
		return ret;
	}

	ret = mwl8787_dnld_fw(priv);

	if (ret) {
		dev_err(priv->dev,
		       "mwl8787: unable to download firmware!\n");
		return ret;
	}

	return 0;
}

static void mwl8787_stop(struct ieee80211_hw *hw)
{
	struct mwl8787_priv *priv = hw->priv;

	release_firmware(priv->fw);
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
	return 0;
}

static void mwl8787_configure_filter(struct ieee80211_hw *hw,
				     unsigned int changed_flags,
				     unsigned int *total_flags,
				     u64 multicast)
{
	*total_flags = 0;
}


int mwl8787_send_cmd(struct mwl8787_priv *priv, int id,
		     u8 *buf, size_t len)
{
	return priv->bus_ops->send_cmd(priv, id, buf, len);
}

const struct ieee80211_ops mwl8787_ops = {
	.tx = mwl8787_tx,
	.start = mwl8787_start,
	.stop = mwl8787_stop,
	.add_interface = mwl8787_add_interface,
	.remove_interface = mwl8787_remove_interface,
	.config = mwl8787_config,
	.configure_filter = mwl8787_configure_filter,
	CFG80211_TESTMODE_CMD(mwl8787_testmode_cmd)
	CFG80211_TESTMODE_DUMP(mwl8787_testmode_dump)
};

struct mwl8787_priv *mwl8787_init(void)
{
	struct mwl8787_priv *priv;
	struct ieee80211_hw *hw;
	u8 mac[ETH_ALEN] = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x20
	};

	hw = ieee80211_alloc_hw(sizeof(*priv), &mwl8787_ops);
	if (!hw)
		return ERR_PTR(-ENOMEM);

	priv = hw->priv;
	priv->hw = hw;

	spin_lock_init(&priv->int_lock);

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

	SET_IEEE80211_PERM_ADDR(hw, mac);

	return priv;
}

int mwl8787_register(struct mwl8787_priv *priv)
{
	return ieee80211_register_hw(priv->hw);
}

void mwl8787_unregister(struct mwl8787_priv *priv)
{
	ieee80211_unregister_hw(priv->hw);
}

void mwl8787_free(struct mwl8787_priv *priv)
{
	ieee80211_free_hw(priv->hw);
}
