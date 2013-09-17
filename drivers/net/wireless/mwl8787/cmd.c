#include "mwl8787.h"
#include "fw.h"

static int __mwl8787_send_cmd(struct mwl8787_priv *priv,
			      struct mwl8787_cmd *cmd)
{
	return priv->bus_ops->send_cmd(priv, (u8 *) cmd,
				       le16_to_cpu(cmd->hdr.len));
}

/**
 * mwl8787_send_cmd_reply() - send a cmd to the fw and wait for reply
 * @priv: mwl8787 driver context
 * @cmd: command structure to send
 * @reply: response returned here
 *
 * Synchronously sends a firmware command.  If @reply is not null
 * and the command is successful, the response skb is saved in the
 * passed pointer, and the caller must free it.
 */
int mwl8787_send_cmd_reply(struct mwl8787_priv *priv,
			   struct mwl8787_cmd *cmd,
			   struct sk_buff **reply)
{
	int ret;

	/* only one command may be in flight at a time */
	mutex_lock(&priv->cmd_mutex);

	spin_lock(&priv->cmd_resp_lock);
	priv->cmd_id = le16_to_cpu(cmd->hdr.id);
	priv->cmd_resp_skb = NULL;
	priv->keep_resp = reply != NULL;
	INIT_COMPLETION(priv->cmd_wait);
	spin_unlock(&priv->cmd_resp_lock);

	ret = __mwl8787_send_cmd(priv, cmd);
	if (ret)
		goto out;

	ret = wait_for_completion_timeout(&priv->cmd_wait, HZ);
	if (ret == 0) {
		dev_err(priv->dev, "cmd_wait timed out (cmdid %x)\n",
			priv->cmd_id);
		ret = -ETIMEDOUT;
		goto out;
	}

	ret = 0;
	spin_lock(&priv->cmd_resp_lock);
	if (reply)
		*reply = priv->cmd_resp_skb;
	spin_unlock(&priv->cmd_resp_lock);

out:
	mutex_unlock(&priv->cmd_mutex);
	return ret;
}

/**
 * mwl8787_send_cmd() - send a cmd to the fw, no reply requested
 * @priv: mwl8787 driver context
 * @cmd: command structure to send
 *
 * Convenience function for the normal case where caller is not
 * interested in the contents of the firmware response to a command.
 * This function still waits for the response.
 */
int mwl8787_send_cmd(struct mwl8787_priv *priv, struct mwl8787_cmd *cmd)
{
	return mwl8787_send_cmd_reply(priv, cmd, NULL);
}

struct mwl8787_cmd *mwl8787_cmd_alloc(struct mwl8787_priv *priv,
				      int id, size_t len, gfp_t gfp_flags)
{
	struct mwl8787_cmd *cmd;
	int pktlen = len + sizeof(struct mwl8787_cmd_header);
	void *buf;

	buf = kzalloc(pktlen + priv->bus_headroom, gfp_flags);
	if (!buf)
		return NULL;

	cmd = buf + priv->bus_headroom;

	cmd->hdr.id = cpu_to_le16(id);
	cmd->hdr.len = cpu_to_le16(pktlen);
	cmd->hdr.seq = cpu_to_le16(SEQ_NO_BSS_INFO(priv->cmd_seq++,
						   0, MWL8787_BSS_TYPE_TM));
	return cmd;
}

void mwl8787_cmd_free(struct mwl8787_priv *priv, void *ptr)
{
	if (!ptr)
		return;

	return kfree(ptr - priv->bus_headroom);
}

static
int mwl8787_cmd_hw_spec_resp(struct mwl8787_priv *priv,
			     struct mwl8787_cmd *resp)
{
	u32 fw_version;
	struct mwl8787_cmd_hw_spec *hw_spec = &resp->u.hw_spec;

	fw_version = le32_to_cpu(resp->u.hw_spec.fw_version);
	dev_info(priv->dev, "loaded fw revision %u.%u.%u.p%u\n",
		 (fw_version >> 16) & 0xff,
		 (fw_version >> 8) & 0xff,
		 fw_version & 0xff,
		 fw_version >> 24);

	memcpy(priv->addr, hw_spec->perm_addr, ETH_ALEN);
	priv->region_code = le16_to_cpu(hw_spec->region_code);
	priv->num_ant = le16_to_cpu(hw_spec->num_ant);
	priv->fw_cap_info = le32_to_cpu(hw_spec->fw_cap_info);
	priv->dot_11n_dev_cap = le32_to_cpu(hw_spec->dot_11n_dev_cap);
	priv->num_streams = hw_spec->tx_rx_chains & 0x0f;
	priv->mp_end_port = le16_to_cpu(hw_spec->mp_end_port);

	dev_info(priv->dev, "caps reported: addr=%pM, region=%X, ant=%X, "
			    "fw_cap=%X, 11n=%X, streams=%X, mp_end=%X\n",
			    priv->addr, priv->region_code, priv->num_ant,
			    priv->fw_cap_info, priv->dot_11n_dev_cap,
			    priv->num_streams, priv->mp_end_port);
	return 0;
}

static
int mwl8787_cmd_mac_addr_resp(struct mwl8787_priv *priv,
			      struct mwl8787_cmd *resp)
{
	memcpy(priv->addr, &resp->u.mac_addr, ETH_ALEN);
	return 0;
}

int mwl8787_cmd_rx(struct mwl8787_priv *priv, struct sk_buff *skb)
{
	struct mwl8787_cmd *resp;
	int ret;
	u16 cmdid;
	u16 result;
	struct timeval tstamp;
	bool free_skb = true;

	if (!skb) {
		dev_err(priv->dev, "CMD_RESP: no response?,\n");
		return -1;
	}

	resp = (struct mwl8787_cmd *) skb->data;

	/* ignore BSS and BSS number for now */

	cmdid = le16_to_cpu(resp->hdr.id);
	result = le16_to_cpu(resp->hdr.result);

	do_gettimeofday(&tstamp);
	dev_dbg(priv->dev, "cmd: CMD_RESP: (%lu.%lu): 0x%x, result %d,"
		" len %d, seqno 0x%x\n",
	       tstamp.tv_sec, tstamp.tv_usec, cmdid, result,
	       le16_to_cpu(resp->hdr.len), le16_to_cpu(resp->hdr.seq));

	if (!(cmdid & MWL8787_CMD_RET_BIT)) {
		dev_err(priv->dev, "CMD_RESP: invalid cmd resp\n");
		ret = -EIO;
		goto out;
	}

	if (result != MWL8787_CMD_SUCCESS) {
		ret = -EIO;
		goto out;
	}

	cmdid &= ~MWL8787_CMD_RET_BIT;
	/* FIXME check that skb is large enough for response struct */

	switch (cmdid) {
	case MWL8787_CMD_HW_SPEC:
		ret = mwl8787_cmd_hw_spec_resp(priv, resp);
		break;

	case MWL8787_CMD_MAC_ADDR:
		ret = mwl8787_cmd_mac_addr_resp(priv, resp);
		break;

	case MWL8787_CMD_FUNC_INIT:
		if (priv->hw_status == MWL8787_HW_STATUS_INITIALIZING) {
			priv->hw_status = MWL8787_HW_STATUS_INIT_DONE;
			complete(&priv->init_wait);
		}
		break;
	default:
		break;
	}

	/*
	 * Complete the pending command only on successful response,
	 * and if this cmd id matches that of the waiting thread.
	 * If a different response is received (or none) then the
	 * pending command will timeout.
	 */
	ret = 0;
	spin_lock(&priv->cmd_resp_lock);
	if (cmdid != priv->cmd_id)
		goto out_unlock;

	if (priv->keep_resp) {
		priv->cmd_resp_skb = skb;
		free_skb = false;
	}
	complete(&priv->cmd_wait);

out_unlock:
	spin_unlock(&priv->cmd_resp_lock);
out:
	if (free_skb)
		dev_kfree_skb_any(skb);
	return ret;
}

int mwl8787_cmd_init(struct mwl8787_priv *priv)
{
	int ret;
	struct mwl8787_cmd *cmd;

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_FUNC_INIT,
				0,
				GFP_KERNEL);

	if (!cmd)
		return -ENOMEM;

	ret = mwl8787_send_cmd(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_hw_spec(struct mwl8787_priv *priv)
{
	int ret;
	struct mwl8787_cmd *cmd;

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_HW_SPEC,
				sizeof(struct mwl8787_cmd_hw_spec),
				GFP_KERNEL);

	if (!cmd)
		return -ENOMEM;

	ret = mwl8787_send_cmd(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_mac_ctrl(struct mwl8787_priv *priv, u32 control)
{
	int ret;
	struct mwl8787_cmd *cmd;

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_MAC_CTRL,
				sizeof(struct mwl8787_cmd_mac_ctrl),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->u.mac_ctrl.control = cpu_to_le32(control);
	ret = mwl8787_send_cmd(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_rf_channel(struct mwl8787_priv *priv,
			   struct cfg80211_chan_def *chandef)
{
	int ret;
	struct mwl8787_cmd *cmd;
	u16 channel;
	u16 rftype = 0;

	/* set up band/channel flags in rftype field based on chandef */
	channel = chandef->chan->hw_value;
	switch (chandef->chan->band) {
	case IEEE80211_BAND_2GHZ:
		rftype |= MWL8787_BAND_2GHZ;
		break;
	case IEEE80211_BAND_5GHZ:
		rftype |= MWL8787_BAND_5GHZ;
		break;
	default:
		return -EINVAL;
	}

	switch (chandef->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
	case NL80211_CHAN_WIDTH_20:
		rftype |= MWL8787_CHAN_WIDTH_20;
		break;
	case NL80211_CHAN_WIDTH_40:
		rftype |= MWL8787_CHAN_WIDTH_40;
		if (chandef->center_freq1 > chandef->chan->center_freq)
			rftype |= MWL8787_SEC_OFF_ABOVE;
		else
			rftype |= MWL8787_SEC_OFF_BELOW;
		break;
	default:
		return -EINVAL;
	}

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_RF_CHANNEL,
				sizeof(struct mwl8787_cmd_rf_channel),
				GFP_KERNEL);

	if (!cmd)
		return -ENOMEM;

	cmd->u.rf_channel.action = cpu_to_le16(MWL8787_ACT_SET);
	cmd->u.rf_channel.current_channel = cpu_to_le16(channel);
	cmd->u.rf_channel.rftype = cpu_to_le16(rftype);

	ret = mwl8787_send_cmd(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_radio_ctrl(struct mwl8787_priv *priv, bool on)
{
	int ret;
	struct mwl8787_cmd *cmd;

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_RADIO_CTRL,
				sizeof(struct mwl8787_cmd_radio_ctrl),
				GFP_KERNEL);

	if (!cmd)
		return -ENOMEM;

	cmd->u.radio_ctrl.action = cpu_to_le16(MWL8787_ACT_SET);
	cmd->u.radio_ctrl.control = cpu_to_le16(on);
	ret = mwl8787_send_cmd(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_beacon_set(struct mwl8787_priv *priv, struct sk_buff *skb)
{
	struct mwl8787_cmd *cmd;
	size_t len;
	int ret;

	if (skb->len > MWL8787_MAX_BEACON_SIZE)
		return -ENOSPC;

	len = sizeof(struct mwl8787_cmd_beacon_set) + skb->len;
	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_BEACON_SET, len,
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->u.beacon_set.len = cpu_to_le16(len);
	memcpy(cmd->u.beacon_set.beacon, skb->data, skb->len);

	ret = mwl8787_send_cmd(priv, cmd);
	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_beacon_ctrl(struct mwl8787_priv *priv, u16 beacon_int,
			    bool enable_beacon)
{
	struct mwl8787_cmd *cmd;
	int ret;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_BEACON_CTRL,
				sizeof(struct mwl8787_cmd_beacon_ctrl),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->u.beacon_ctrl.action = cpu_to_le16(MWL8787_ACT_SET);
	cmd->u.beacon_ctrl.beacon_enable = cpu_to_le16(enable_beacon);
	cmd->u.beacon_ctrl.beacon_period = cpu_to_le16(beacon_int);

	ret = mwl8787_send_cmd(priv, cmd);
	mwl8787_cmd_free(priv, cmd);
	return ret;
}


int mwl8787_cmd_subscribe_events(struct mwl8787_priv *priv, u16 events)
{
	struct mwl8787_cmd *cmd;
	struct mwl8787_tlv *tx_fail_params;
	int ret;
	size_t cmd_len;

	cmd_len = sizeof(struct mwl8787_cmd_subscribe_events);
	if (events & MWL8787_EVT_SUB_TX_FAIL)
		cmd_len += sizeof(struct mwl8787_tlv_tx_fail);

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_SUBSCRIBE_EVENTS,
				cmd_len, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->u.subscribe_events.action = cpu_to_le16(MWL8787_ACT_SET);
	cmd->u.subscribe_events.events = cpu_to_le16(events);

	if (events & MWL8787_EVT_SUB_TX_FAIL) {
		tx_fail_params = (struct mwl8787_tlv *)
			cmd->u.subscribe_events.tlvs;
		tx_fail_params->hdr.type = cpu_to_le16(MWL8787_TYPE_TX_FAIL);
		tx_fail_params->hdr.len = cpu_to_le16(2);
		tx_fail_params->u.tx_fail.fail_threshold = priv->tx_fail;
		tx_fail_params->u.tx_fail.reporting_freq = 1;
	}

	ret = mwl8787_send_cmd(priv, cmd);
	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_snmp_mib(struct mwl8787_priv *priv, enum mwl8787_oid oid,
			 u16 value)
{
	struct mwl8787_cmd *cmd;
	size_t payload_size;
	int ret;

	switch (oid) {
	case MWL8787_OID_RTS_THRESHOLD:
	case MWL8787_OID_FRAG_THRESHOLD:
			payload_size = 2;
			break;
	default:
			payload_size = 1;
			break;
	}

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_SNMP_MIB,
				sizeof(struct mwl8787_cmd_snmp_mib) +
				payload_size, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->u.snmp_mib.action = cpu_to_le16(MWL8787_ACT_SET);
	cmd->u.snmp_mib.oid = cpu_to_le16(oid);
	cmd->u.snmp_mib.payload_size = cpu_to_le16(payload_size);
	if (payload_size == 2)
		put_unaligned_le16(value, cmd->u.snmp_mib.payload);
	else
		cmd->u.snmp_mib.payload[0] = (u8) value;

	ret = mwl8787_send_cmd(priv, cmd);
	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_get_tsf(struct mwl8787_priv *priv, u64 *tsf)
{
	struct mwl8787_cmd *cmd, *resp;
	struct sk_buff *reply_skb;
	int ret;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_GET_TSF,
				sizeof(struct mwl8787_cmd_get_tsf),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	ret = mwl8787_send_cmd_reply(priv, cmd, &reply_skb);
	mwl8787_cmd_free(priv, cmd);

	if (ret)
		return ret;

	resp = (struct mwl8787_cmd *) reply_skb->data;
	*tsf = le64_to_cpu(resp->u.get_tsf.tsf);
	dev_kfree_skb_any(reply_skb);
	return 0;
}

int mwl8787_cmd_set_tsf(struct mwl8787_priv *priv, const u64 tsf)
{
	struct mwl8787_cmd *cmd;
	int ret;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_SET_TSF,
				sizeof(struct mwl8787_cmd_get_tsf),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->u.set_tsf.tsf = cpu_to_le64(tsf);
	ret = mwl8787_send_cmd(priv, cmd);
	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_log(struct mwl8787_priv *priv,
		    struct ieee80211_low_level_stats *stats)
{
	struct mwl8787_cmd *cmd, *resp;
	struct mwl8787_cmd_log *log;
	struct sk_buff *reply_skb;
	int ret;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_LOG,
				sizeof(struct mwl8787_cmd_log),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	ret = mwl8787_send_cmd_reply(priv, cmd, &reply_skb);
	mwl8787_cmd_free(priv, cmd);
	if (ret)
		return ret;

	resp = (struct mwl8787_cmd *) reply_skb->data;

	log = &resp->u.log;
	stats->dot11ACKFailureCount = le32_to_cpu(log->dot11ACKFailureCount);
	stats->dot11RTSFailureCount = le32_to_cpu(log->dot11RTSFailureCount);
	stats->dot11FCSErrorCount = le32_to_cpu(log->dot11FCSErrorCount);
	stats->dot11RTSSuccessCount = le32_to_cpu(log->dot11RTSSuccessCount);

	dev_kfree_skb_any(reply_skb);
	return 0;
}

int mwl8787_cmd_link_stats(struct mwl8787_priv *priv, u8 *addr,
			   struct ieee80211_link_stats *stats)
{
	struct mwl8787_cmd *cmd, *resp;
	struct sk_buff *reply_skb;
	enum ieee80211_band band = priv->hw->conf.chandef.chan->band;
	struct ieee80211_supported_band *sband = priv->hw->wiphy->bands[band];
	int idx, ret, fwrate;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_TX_RATE_QUERY,
				sizeof(struct mwl8787_cmd_rate_query),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	memcpy(&cmd->u.rate_query.addr, addr, ETH_ALEN);
	ret = mwl8787_send_cmd_reply(priv, cmd, &reply_skb);
	mwl8787_cmd_free(priv, cmd);
	if (ret)
		return ret;

	resp = (struct mwl8787_cmd *) reply_skb->data;

	fwrate = resp->u.rate_query.tx_rate;
	stats->fail_avg = le32_to_cpu(resp->u.rate_query.tx_err);

	stats->last_tx_rate.count = 1;
	if (resp->u.rate_query.ht_info & BIT(0)) {
		stats->last_tx_rate.idx = fwrate;
		stats->last_tx_rate.flags |= IEEE80211_TX_RC_MCS;
		if (resp->u.rate_query.ht_info & BIT(1))
			stats->last_tx_rate.flags |=
						  IEEE80211_TX_RC_40_MHZ_WIDTH;
		if (resp->u.rate_query.ht_info & BIT(2))
			stats->last_tx_rate.flags |= IEEE80211_TX_RC_SHORT_GI;
	} else {
		for (idx = 0; idx < sband->n_bitrates; idx++) {
			/* fw rate is in 500kb/s */
			if (fwrate * 5 == sband->bitrates[idx].bitrate)
				break;
		}

		if (idx == sband->n_bitrates) {
			dev_err(priv->dev, "got bogus tx rate?\n");
			ret = -ENOENT;
			goto out;
		}
		stats->last_tx_rate.idx = idx;
	}

out:
	dev_kfree_skb_any(reply_skb);
	return ret;
}

int mwl8787_cmd_set_mac_addr(struct mwl8787_priv *priv, u8 *addr)
{
	struct mwl8787_cmd *cmd;
	int ret;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_MAC_ADDR,
				sizeof(struct mwl8787_cmd_mac_addr),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->u.mac_addr.action = cpu_to_le16(MWL8787_ACT_SET);
	memcpy(&cmd->u.mac_addr.addr, addr, ETH_ALEN);
	ret = mwl8787_send_cmd(priv, cmd);
	mwl8787_cmd_free(priv, cmd);

	return ret;
}

static u32 mwl8787_rates_to_hw_values(struct mwl8787_priv *priv,
				      unsigned long supp_rates, u8 *mcs_mask)
{
	enum ieee80211_band band = priv->hw->conf.chandef.chan->band;
	struct ieee80211_supported_band *sband = priv->hw->wiphy->bands[band];
	int i;
	u32 hw_values = 0;

	/* XXX: luckily 8787 (1x1!) rates all fit in a u32... */
	for_each_set_bit(i, &supp_rates, MRVL_MCS_SHIFT)
		hw_values |= BIT(sband->bitrates[i].hw_value);

	/* ...with this hack! */
	for (i = 0; i < 2; i++)
		hw_values |= mcs_mask[i] << (MRVL_MCS_SHIFT + (i * 8));

	return hw_values;
}

int mwl8787_cmd_set_peer(struct mwl8787_priv *priv, struct ieee80211_sta *sta)
{
	struct mwl8787_cmd *cmd;
	int ret;
	u32 supp_rates;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_SET_PEER,
				sizeof(struct mwl8787_cmd_set_peer),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	memcpy(cmd->u.set_peer.addr, sta->addr, ETH_ALEN);

	supp_rates = sta->supp_rates[priv->hw->conf.chandef.chan->band];
	supp_rates = mwl8787_rates_to_hw_values(priv, supp_rates,
						sta->ht_cap.mcs.rx_mask);

	cmd->u.set_peer.supp_rate_map = cpu_to_le32(supp_rates);

	ret = mwl8787_send_cmd(priv, cmd);
	mwl8787_cmd_free(priv, cmd);

	return ret;
}

int mwl8787_cmd_del_peer(struct mwl8787_priv *priv, struct ieee80211_sta *sta)
{
	struct mwl8787_cmd *cmd;
	int ret;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_DEL_PEER,
				sizeof(struct mwl8787_cmd_del_peer),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	memcpy(cmd->u.del_peer.addr, sta->addr, ETH_ALEN);
	ret = mwl8787_send_cmd(priv, cmd);
	mwl8787_cmd_free(priv, cmd);

	return ret;
}

int mwl8787_cmd_addba_req(struct mwl8787_priv *priv,
			  struct ieee80211_sta *sta, u16 tid)
{
	struct mwl8787_cmd *cmd, *resp;
	struct sk_buff *reply_skb;
	int ret;
	u16 block_params;

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_ADDBA_REQ,
				sizeof(struct mwl8787_cmd_addba_req),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	block_params = 16 << 6 |	/* tx window size */
		       tid << 2 |
		       1 << 1 |		/* immediate block ack */
		       1;		/* no amsdu */

	if (!++priv->addba_dialog_token)
		priv->addba_dialog_token = 1;

	memcpy(cmd->u.addba_req.addr, sta->addr, ETH_ALEN);
	cmd->u.addba_req.token = priv->addba_dialog_token;
	cmd->u.addba_req.ba_param_set = cpu_to_le16(block_params);
	cmd->u.addba_req.ba_timeout = cpu_to_le16(5000);

	ret = mwl8787_send_cmd_reply(priv, cmd, &reply_skb);
	mwl8787_cmd_free(priv, cmd);
	if (ret)
		return ret;

	resp = (struct mwl8787_cmd *) reply_skb->data;
	switch (resp->u.addba_req.add_req_result) {
		case MWL8787_BA_SUCCESS:
			break;
		case MWL8787_BA_TIMEOUT:
			return -ETIMEDOUT;
		case MWL8787_BA_DATA_INVALID:
			return -EINVAL;
		case MWL8787_BA_EXEC_FAILURE:
		default:
			return -ECANCELED;
	}
	/* successful addba, record ssn and all that */
	dev_kfree_skb_any(reply_skb);
	return 0;
}
