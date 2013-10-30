/*
 * Copyright (c) 2013 Cozybit, Inc.
 */

#include "mwl8787.h"
#include "fw.h"
#include "sdio.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

#define CHAN(_freq, _idx) { \
	.center_freq = (_freq), \
	.hw_value = (_idx), \
	.max_power = MWL8787_DEFAULT_TX_POWER, \
}

static char *mwl8787_modparam_mac_addr;
module_param_named(mac_addr, mwl8787_modparam_mac_addr, charp, S_IRUGO);

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
	RATE(10, MRVL_RATEID_DBPSK1Mbps, 0),
	RATE(20, MRVL_RATEID_DQPSK2Mbps, IEEE80211_RATE_SHORT_PREAMBLE),
	RATE(55, MRVL_RATEID_CCK5_5Mbps, IEEE80211_RATE_SHORT_PREAMBLE),
	RATE(110, MRVL_RATEID_CCK11Mbps, IEEE80211_RATE_SHORT_PREAMBLE),
	RATE(220, MRVL_RATEID_CCK22Mbps, 0),
	RATE(60, MRVL_RATEID_OFDM6Mbps, 0),
	RATE(90, MRVL_RATEID_OFDM9Mbps, 0),
	RATE(120, MRVL_RATEID_OFDM12Mbps, 0),
	RATE(180, MRVL_RATEID_OFDM18Mbps, 0),
	RATE(240, MRVL_RATEID_OFDM24Mbps, 0),
	RATE(360, MRVL_RATEID_OFDM36Mbps, 0),
	RATE(480, MRVL_RATEID_OFDM48Mbps, 0),
	RATE(540, MRVL_RATEID_OFDM54Mbps, 0),
};

#define mwl8787_2ghz_rates mwl8787_rates
#define mwl8787_2ghz_rates_len ARRAY_SIZE(mwl8787_rates)
#define mwl8787_5ghz_rates (mwl8787_rates + 5)
#define mwl8787_5ghz_rates_len ARRAY_SIZE(mwl8787_rates) - 5

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
 * Setup the ht capabilities based on firmware response.
 */
static void mwl8787_setup_ht_cap(struct mwl8787_priv *priv,
				 struct ieee80211_sta_ht_cap *ht_cap)
{
	ht_cap->ht_supported = true;
	ht_cap->ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
	ht_cap->ampdu_density = IEEE80211_HT_MPDU_DENSITY_NONE;

	if (priv->dot_11n_dev_cap & MWL8787_DEV_HT_CAP_SUP_WIDTH_20_40)
		ht_cap->cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	if (priv->dot_11n_dev_cap & MWL8787_DEV_HT_CAP_SGI_20)
		ht_cap->cap |= IEEE80211_HT_CAP_SGI_20;
	if (priv->dot_11n_dev_cap & MWL8787_DEV_HT_CAP_SGI_40)
		ht_cap->cap |= IEEE80211_HT_CAP_SGI_40;
	if (priv->dot_11n_dev_cap & MWL8787_DEV_HT_CAP_TX_STBC)
		ht_cap->cap |= IEEE80211_HT_CAP_TX_STBC;
	if (priv->dot_11n_dev_cap & MWL8787_DEV_HT_CAP_RX_STBC)
		ht_cap->cap |= IEEE80211_HT_CAP_RX_STBC;
	if (priv->dot_11n_dev_cap & MWL8787_DEV_HT_CAP_GRN_FLD)
		ht_cap->cap |= IEEE80211_HT_CAP_GRN_FLD;
	if (priv->dot_11n_dev_cap & MWL8787_DEV_HT_CAP_LDPC_CODING)
		ht_cap->cap |= IEEE80211_HT_CAP_LDPC_CODING;
	if (priv->dot_11n_dev_cap & MWL8787_DEV_HT_CAP_40MHZ_INTOLERANT)
		ht_cap->cap |= IEEE80211_HT_CAP_40MHZ_INTOLERANT;

	memset(ht_cap->mcs.rx_mask, 0xff,
	       min_t(u8, priv->num_streams, IEEE80211_HT_MCS_MASK_LEN));
	/* enable MCS 32 */
	ht_cap->mcs.rx_mask[4] |= 1;

	ht_cap->mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;
}

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
static int mwl8787_fw_init_cmd(struct mwl8787_priv *priv)
{
	int ret;

	ret = mwl8787_cmd_init(priv);
	if (ret)
		return ret;

	/* get hw description & mac address */
	ret = mwl8787_cmd_hw_spec(priv);
	if (ret)
		return ret;

	/* override mac addr if requested */
	if (mwl8787_modparam_mac_addr)
		mac_pton(mwl8787_modparam_mac_addr, priv->addr);

	/* setup caps for each band */
	mwl8787_setup_ht_cap(priv,
		&priv->hw->wiphy->bands[IEEE80211_BAND_2GHZ]->ht_cap);
	mwl8787_setup_ht_cap(priv,
		&priv->hw->wiphy->bands[IEEE80211_BAND_5GHZ]->ht_cap);

	/* set default txpower */
	mwl8787_cmd_tx_power(priv, MWL8787_DEFAULT_TX_POWER);

	/* turn on the radio */
	ret = mwl8787_cmd_radio_ctrl(priv, true);
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

	if (priv->int_status)
		priv->bus_ops->process_int_status(priv);

	/* I/O ports may now be available if tx stalled, so resume */
	if (!skb_queue_empty(&priv->tx_queue))
		ieee80211_queue_work(priv->hw, &priv->tx_work);

	return ret;
}

static int mwl8787_start(struct ieee80211_hw *hw)
{
	struct mwl8787_priv *priv = hw->priv;

	/* register for tx feedback events */
	mwl8787_cmd_subscribe_events(priv, MWL8787_ACT_BITWISE_SET,
				     MWL8787_EVT_SUB_TX_STATUS);

	return 0;
}

static void mwl8787_stop(struct ieee80211_hw *hw)
{
	struct mwl8787_priv *priv = hw->priv;

	/* disable RX and events while stopped */
	mwl8787_cmd_mac_ctrl(priv, 0);
	mwl8787_cmd_subscribe_events(priv, MWL8787_ACT_SET, 0);

	cancel_work_sync(&priv->tx_work);
	mwl8787_tx_cleanup(priv);
}

static bool is_beaconing_iftype(enum nl80211_iftype type)
{
	return type == NL80211_IFTYPE_AP ||
	       type == NL80211_IFTYPE_MESH_POINT ||
	       type == NL80211_IFTYPE_ADHOC;
}

static int mwl8787_add_interface(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif)
{
	struct mwl8787_priv *priv = hw->priv;

	/* only allow one beaconing vif */
	if (is_beaconing_iftype(vif->type)) {
		if (priv->vif)
			return -ELNRNG;

		priv->vif = vif;
	}

	mwl8787_cmd_set_mac_addr(hw->priv, vif->addr);
	return 0;
}

static void mwl8787_remove_interface(struct ieee80211_hw *hw,
				     struct ieee80211_vif *vif)
{
	struct mwl8787_priv *priv = hw->priv;

	u8 zero_addr[ETH_ALEN] = {};

	if (is_beaconing_iftype(vif->type))
		priv->vif = NULL;

	mwl8787_cmd_set_mac_addr(priv, zero_addr);
}

static int mwl8787_config(struct ieee80211_hw *hw, u32 changed)
{
	struct mwl8787_priv *priv = hw->priv;

	if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
		mwl8787_cmd_rf_channel(priv, &hw->conf.chandef);
		mwl8787_cmd_11n_cfg(priv, &hw->conf.chandef);
	}

#if 0
	/* FIXME this means different things in STA and mesh mode */
	if (changed & IEEE80211_CONF_CHANGE_PS)
		mwl8787_cmd_ps_mode(priv, hw->conf.flags & IEEE80211_CONF_PS);
#endif

	return 0;
}

static u64 mwl8787_prepare_multicast(struct ieee80211_hw *hw,
				     struct netdev_hw_addr_list *mc_list)
{
	struct mwl8787_priv *priv = hw->priv;
	struct netdev_hw_addr *ha;
	struct mwl8787_cmd *cmd;
	int num = 0;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_MULTICAST_ADDR,
		sizeof(struct mwl8787_cmd_multicast_addr),
		GFP_ATOMIC);

	if (!cmd)
		return 0;

	netdev_hw_addr_list_for_each(ha, mc_list) {
		memcpy(cmd->u.multicast_addr.mac_list[num],
		       ha->addr, ETH_ALEN);
		if (num++ == MWL8787_MAX_MULTICAST_LIST_SIZE)
			break;
	}

	/*
	 * Store requested count instead of num, so that we can set
	 * FIF_ALLMULTI if more than max mcast addresses requested.
	 */
	cmd->u.multicast_addr.num = cpu_to_le16(mc_list->count);
	cmd->u.multicast_addr.action = cpu_to_le16(MWL8787_ACT_SET);
	return (unsigned long) cmd;
}

static void mwl8787_configure_filter(struct ieee80211_hw *hw,
				     unsigned int changed_flags,
				     unsigned int *total_flags,
				     u64 multicast)
{
	struct mwl8787_priv *priv = hw->priv;
	struct mwl8787_cmd *mcast_cmd = (void *) (unsigned long) multicast;
	int supported_flags = FIF_PROMISC_IN_BSS | FIF_ALLMULTI |
			      FIF_BCN_PRBRESP_PROMISC | FIF_OTHER_BSS;
	int mcast_num = 0;

	u32 filter = MWL8787_MAC_ENABLE_RX |
		     MWL8787_MAC_ENABLE_80211 |
		     MWL8787_MAC_ENABLE_MGMT |
		     MWL8787_MAC_ENABLE_BCAST |
		     (priv->mac_ctrl & MWL8787_MAC_ENABLE_CTS);

	/* TODO: some of these should likely set PROMISC
	  FIF_FCSFAIL | FIF_PLCPFAIL | FIF_CONTROL |
	  FIF_PSPOLL | FIF_PROBE_REQ
	*/
	changed_flags &= supported_flags;
	*total_flags &= supported_flags;

	if (*total_flags & FIF_BCN_PRBRESP_PROMISC) {
		*total_flags &= ~FIF_BCN_PRBRESP_PROMISC;
		filter |= (MWL8787_MAC_ENABLE_OTHER_PRESP |
			   MWL8787_MAC_ENABLE_OTHER_BCN);
	}

	if (*total_flags & FIF_PROMISC_IN_BSS) {
		*total_flags &= ~FIF_PROMISC_IN_BSS;
		filter |= (MWL8787_MAC_ENABLE_ALLMULTI |
			   MWL8787_MAC_ENABLE_ALL_UNICAST);
	}

	if (*total_flags & FIF_OTHER_BSS) {
		*total_flags &= ~FIF_OTHER_BSS;
		filter |= (MWL8787_MAC_ENABLE_OTHER_BSS |
			   MWL8787_MAC_ENABLE_OTHER_BCN);
	}

	if (mcast_cmd)
		mcast_num = le16_to_cpu(mcast_cmd->u.multicast_addr.num);

	if (*total_flags & FIF_ALLMULTI ||
	    mcast_num > MWL8787_MAX_MULTICAST_LIST_SIZE) {
		*total_flags &= ~FIF_ALLMULTI;
		filter |= MWL8787_MAC_ENABLE_ALLMULTI;
	} else {
		/* set mcast list previously prepared */
		if (mcast_cmd)
			mwl8787_send_cmd(priv, mcast_cmd);
	}
	mwl8787_cmd_free(priv, mcast_cmd);

	priv->mac_ctrl = filter;
	mwl8787_cmd_mac_ctrl(priv, priv->mac_ctrl);
}

static int mwl8787_set_mcast_rate(struct mwl8787_priv *priv,
				  struct ieee80211_bss_conf *info)
{
	enum ieee80211_band band = priv->hw->conf.chandef.chan->band;
	struct ieee80211_supported_band *sband = priv->hw->wiphy->bands[band];
	int rateidx = sband->bitrates[info->mcast_rate[band] - 1].hw_value;

	return mwl8787_cmd_snmp_mib(priv, MWL8787_OID_MCAST_RATE, rateidx);
}

static void mwl8787_bss_info_changed(struct ieee80211_hw *hw,
				     struct ieee80211_vif *vif,
				     struct ieee80211_bss_conf *info,
				     u32 changed)
{
	struct mwl8787_priv *priv = hw->priv;

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		mwl8787_cmd_subscribe_events(priv,
			(info->enable_beacon) ?
			MWL8787_ACT_BITWISE_SET : MWL8787_ACT_BITWISE_CLR,
			MWL8787_EVT_SUB_PRE_TBTT);
		mwl8787_cmd_beacon_ctrl(priv, info->beacon_int,
					info->enable_beacon);
	}

	if (changed & BSS_CHANGED_ERP_CTS_PROT) {
		priv->mac_ctrl &= ~MWL8787_MAC_ENABLE_CTS;
		if (info->use_cts_prot)
			priv->mac_ctrl |= MWL8787_MAC_ENABLE_CTS;
		mwl8787_cmd_mac_ctrl(priv, priv->mac_ctrl);
	}

	if (changed & BSS_CHANGED_LOW_ACK_COUNT) {
		priv->tx_fail = info->low_ack_count;

		mwl8787_cmd_subscribe_events(priv,
					     priv->tx_fail ?
					     MWL8787_ACT_BITWISE_SET :
					     MWL8787_ACT_BITWISE_CLR,
					     MWL8787_EVT_SUB_TX_FAIL);
	}

	if (changed & BSS_CHANGED_TXPOWER)
		mwl8787_cmd_tx_power(priv, info->txpower);

	if (changed & BSS_CHANGED_MCAST_RATE)
		mwl8787_set_mcast_rate(priv, info);
}

static int mwl8787_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	struct mwl8787_priv *priv = hw->priv;
	return mwl8787_cmd_snmp_mib(priv, MWL8787_OID_RTS_THRESHOLD, value);
}

static int mwl8787_set_frag_threshold(struct ieee80211_hw *hw, u32 value)
{
	struct mwl8787_priv *priv = hw->priv;
	return mwl8787_cmd_snmp_mib(priv, MWL8787_OID_FRAG_THRESHOLD, value);
}

static int mwl8787_sta_add(struct ieee80211_hw *hw,
			    struct ieee80211_vif *vif,
			    struct ieee80211_sta *sta)
{
	struct mwl8787_sta *mwl8787_sta = (struct mwl8787_sta *) sta->drv_priv;

	mwl8787_sta->priv = hw->priv;
	mwl8787_sta->sta = sta;

	INIT_WORK(&mwl8787_sta->ampdu_work, mwl8787_ampdu_work);
	mwl8787_cmd_set_peer(hw->priv, sta);
	return 0;
}

static int mwl8787_sta_remove(struct ieee80211_hw *hw,
			       struct ieee80211_vif *vif,
			       struct ieee80211_sta *sta)
{
	struct mwl8787_sta *mwl8787_sta = (struct mwl8787_sta *) sta->drv_priv;
	cancel_work_sync(&mwl8787_sta->ampdu_work);
	mwl8787_cmd_del_peer(hw->priv, sta);
	return 0;
}

static u64 mwl8787_get_tsf(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct mwl8787_priv *priv = hw->priv;
	u64 tsf = -1;

	mwl8787_cmd_get_tsf(priv, &tsf);
	return tsf;
}

static void mwl8787_set_tsf(struct ieee80211_hw *hw,
			   struct ieee80211_vif *vif, u64 tsf)
{
	struct mwl8787_priv *priv = hw->priv;

	mwl8787_cmd_set_tsf(priv, tsf);
}

static int mwl8787_get_stats(struct ieee80211_hw *hw,
			     struct ieee80211_low_level_stats *stats)
{
	struct mwl8787_priv *priv = hw->priv;
	return mwl8787_cmd_log(priv, stats);
}

static int mwl8787_ampdu_action(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				enum ieee80211_ampdu_mlme_action action,
				struct ieee80211_sta *sta,
				u16 tid, u16 *ssn, u8 buf_size)
{
	struct mwl8787_priv *priv = hw->priv;
	struct mwl8787_sta *priv_sta;
	int ret;

	switch (action) {
	case IEEE80211_AMPDU_RX_START:
		return 0;
	case IEEE80211_AMPDU_RX_STOP:
		return 0;
	case IEEE80211_AMPDU_TX_START:
		priv_sta = (struct mwl8787_sta *) sta->drv_priv;
		priv_sta->ampdu_state[tid] = MWL8787_AMPDU_START;
		priv_sta->ssn[tid] = *ssn;

		ieee80211_start_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		break;
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		priv_sta = (struct mwl8787_sta *) sta->drv_priv;

		ret = mwl8787_cmd_addba_req(priv, sta, tid,
					    priv_sta->ssn[tid], buf_size);
		if (ret)
			return ret;

		priv_sta->ampdu_state[tid] = MWL8787_AMPDU_OPERATIONAL;
		break;
	case IEEE80211_AMPDU_TX_STOP_CONT:
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
		priv_sta = (struct mwl8787_sta *) sta->drv_priv;
		mwl8787_cmd_delba(priv, sta, tid);
		ieee80211_stop_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		priv->num_ampdu_sessions--;
		priv_sta->ampdu_state[tid] = MWL8787_AMPDU_NONE;
		break;
	}
	return 0;
}

static int mwl8787_link_stats(struct ieee80211_hw *hw,
			      struct ieee80211_vif *vif,
			      u8 *peer,
			      struct ieee80211_link_stats *stats)
{
	struct mwl8787_priv *priv = hw->priv;
	return mwl8787_cmd_link_stats(priv, peer, stats);
}

static int mwl8787_conf_tx(struct ieee80211_hw *hw,
			   struct ieee80211_vif *vif, u16 ac,
			   const struct ieee80211_tx_queue_params *params)
{
	struct mwl8787_priv *priv = hw->priv;
	return mwl8787_cmd_set_wmm_conf(priv, ac, params);
}

static void mwl8787_flush(struct ieee80211_hw *hw, u32 queues, bool drop)
{
	mwl8787_tx_flush(hw->priv, queues, drop);
}

static void mwl8787_mesh_ps_doze(struct ieee80211_hw *hw, u64 next_tbtt)
{
	mwl8787_cmd_doze(hw->priv, next_tbtt);
}

/*
 * Implement own suspend/resume ops so stack doesn't deconfigure
 * the device completely -- we'll remain attached to the mesh and
 * wake up the host with WoW settings.
 */
static int mwl8787_suspend(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan)
{
	/*
	 * we should tell the device how to wake up the host based on
	 * wowlan... and only suspend if succeeded.
	 */
	mwl8787_stop(hw);
	return 0;
}

static int mwl8787_resume(struct ieee80211_hw *hw)
{
	mwl8787_start(hw);
	/* go through regular reconfig */
	return 1;
}

static void mwl8787_set_wakeup(struct ieee80211_hw *hw, bool enabled)
{
	struct mwl8787_priv *priv = hw->priv;
	device_set_wakeup_enable(priv->dev, enabled);
}

static const struct ieee80211_ops mwl8787_ops = {
	.tx = mwl8787_tx,
	.start = mwl8787_start,
	.stop = mwl8787_stop,
	.add_interface = mwl8787_add_interface,
	.remove_interface = mwl8787_remove_interface,
	.config = mwl8787_config,
	.conf_tx = mwl8787_conf_tx,
	.bss_info_changed = mwl8787_bss_info_changed,
	.prepare_multicast = mwl8787_prepare_multicast,
	.configure_filter = mwl8787_configure_filter,
	.set_rts_threshold = mwl8787_set_rts_threshold,
	.set_frag_threshold = mwl8787_set_frag_threshold,
	.get_tsf = mwl8787_get_tsf,
	.set_tsf = mwl8787_set_tsf,
	.get_stats = mwl8787_get_stats,
	.sta_add = mwl8787_sta_add,
	.sta_remove = mwl8787_sta_remove,
	.ampdu_action = mwl8787_ampdu_action,
	.get_link_stats = mwl8787_link_stats,
	.flush = mwl8787_flush,
#ifdef CONFIG_PM
	.suspend = mwl8787_suspend,
	.resume = mwl8787_resume,
	.set_wakeup = mwl8787_set_wakeup,
#endif
#ifdef CONFIG_MAC80211_MESH
	.mesh_ps_doze = mwl8787_mesh_ps_doze,
#endif
	CFG80211_TESTMODE_CMD(mwl8787_testmode_cmd)
	CFG80211_TESTMODE_DUMP(mwl8787_testmode_dump)
};

struct mwl8787_priv *mwl8787_init(void)
{
	struct mwl8787_priv *priv;
	struct ieee80211_hw *hw;
	int i;

	hw = ieee80211_alloc_hw(sizeof(*priv), &mwl8787_ops);
	if (!hw)
		return ERR_PTR(-ENOMEM);

	priv = hw->priv;
	priv->hw = hw;

	spin_lock_init(&priv->int_lock);
	init_completion(&priv->init_wait);
	init_completion(&priv->cmd_wait);
	mutex_init(&priv->cmd_mutex);
	spin_lock_init(&priv->cmd_resp_lock);

	INIT_WORK(&priv->tx_work, mwl8787_tx_work);
	skb_queue_head_init(&priv->tx_queue);

	for (i=0; i < IEEE80211_NUM_ACS; i++)
		skb_queue_head_init(&priv->tx_status_queue[i]);

	/* TODO revisit all this */
	hw->wiphy->interface_modes =
		BIT(NL80211_IFTYPE_STATION) |
		BIT(NL80211_IFTYPE_MESH_POINT);
	hw->flags =
		IEEE80211_HW_HAS_RATE_CONTROL |
		IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING |
		IEEE80211_HW_SUPPORTS_PS |
		IEEE80211_HW_PS_NULLFUNC_STACK |
		IEEE80211_HW_REPORTS_TX_ACK_STATUS |
		IEEE80211_HW_CONNECTION_MONITOR |
		IEEE80211_HW_AMPDU_AGGREGATION |
		IEEE80211_HW_MFP_CAPABLE |
		IEEE80211_HW_SIGNAL_DBM;

	/* wowlan settings */
	hw->wiphy->wowlan.flags = WIPHY_WOWLAN_ANY;

	hw->queues = IEEE80211_NUM_ACS;
	hw->max_rates = 4;
	hw->max_rate_tries = 11;
	hw->max_tx_aggregation_subframes = 16;
	hw->channel_change_time = 100;
	hw->sta_data_size = sizeof(struct mwl8787_sta);
	hw->wiphy->bands[IEEE80211_BAND_2GHZ] = &mwl8787_2ghz_band;
	hw->wiphy->bands[IEEE80211_BAND_5GHZ] = &mwl8787_5ghz_band;

	hw->extra_tx_headroom = sizeof(struct mwl8787_tx_desc) +
				sizeof(struct mwl8787_sdio_header) +
				4;	/* alignment */

	hw->wiphy->max_scan_ssids = 4;
	hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;

	return priv;
}

int mwl8787_register(struct mwl8787_priv *priv)
{
	int ret = ieee80211_register_hw(priv->hw);
	priv->registered = (ret == 0);

	if (priv->registered)
		mwl8787_dev_debugfs_init(priv);

	return ret;
}

void mwl8787_unregister(struct mwl8787_priv *priv)
{
	if (!priv->registered)
		return;

	mwl8787_dev_debugfs_remove(priv);
	ieee80211_unregister_hw(priv->hw);
	priv->registered = false;
}

void mwl8787_free(struct mwl8787_priv *priv)
{
	ieee80211_free_hw(priv->hw);
}
