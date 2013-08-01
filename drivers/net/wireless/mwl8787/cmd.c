#include "mwl8787.h"
#include "fw.h"

int mwl8787_send_cmd(struct mwl8787_priv *priv, struct mwl8787_cmd *cmd)
{
	return priv->bus_ops->send_cmd(priv, (u8 *) cmd,
				       le16_to_cpu(cmd->hdr.len));
}

int mwl8787_send_cmd_sync(struct mwl8787_priv *priv, struct mwl8787_cmd *cmd)
{
	int ret = 0;

	INIT_COMPLETION(priv->cmd_wait);
	ret = mwl8787_send_cmd(priv, cmd);
	if (ret)
		return ret;

	ret = wait_for_completion_timeout(&priv->cmd_wait, HZ);
	if (ret == 0) {
		dev_err(priv->dev, "cmd_wait timed out\n");
		return -ETIMEDOUT;
	}
	return 0;
}

int mwl8787_send_cmd_tm(struct mwl8787_priv *priv,
			struct mwl8787_cmd *cmd,
			struct sk_buff **reply)
{
	int ret;

	priv->keep_resp = true;
	ret = mwl8787_send_cmd_sync(priv, cmd);
	*reply = priv->cmd_resp_skb;
	priv->keep_resp = false;
	priv->cmd_resp_skb = NULL;
	return ret;
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

int mwl8787_cmd_hw_spec_resp(struct mwl8787_priv *priv,
			     struct mwl8787_cmd *resp)
{
	u32 fw_version;

	memcpy(priv->addr, &resp->u.hw_spec.perm_addr, ETH_ALEN);
	priv->mp_end_port = resp->u.hw_spec.mp_end_port;

	fw_version = le32_to_cpu(resp->u.hw_spec.fw_version);
	dev_info(priv->dev, "loaded fw revision %u.%u.%u.p%u\n",
		 (fw_version >> 16) & 0xff,
		 (fw_version >> 8) & 0xff,
		 fw_version & 0xff,
		 fw_version >> 24);

	return 0;
}

int mwl8787_cmd_mac_addr_resp(struct mwl8787_priv *priv,
			      struct mwl8787_cmd *resp)
{
	memcpy(priv->addr, &resp->u.mac_addr, ETH_ALEN);
	return 0;
}

int mwl8787_cmd_scan_resp(struct mwl8787_priv *priv,
			  struct mwl8787_cmd *resp)
{
	dev_dbg(priv->dev, "scan found %d APs of size %d\n",
		resp->u.scan_resp.num,
		resp->u.scan_resp.bss_size);
	return 0;
}

int mwl8787_process_cmdresp(struct mwl8787_priv *priv, struct sk_buff *skb)
{
	struct mwl8787_cmd *resp;
	int ret;
	u16 cmdid;
	u16 result;
	struct timeval tstamp;

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

	ret = 0;
	cmdid &= ~MWL8787_CMD_RET_BIT;
	switch (cmdid) {
		case MWL8787_CMD_HW_SPEC:
			ret = mwl8787_cmd_hw_spec_resp(priv, resp);
			break;

		case MWL8787_CMD_MAC_ADDR:
			ret = mwl8787_cmd_mac_addr_resp(priv, resp);
			break;

		case MWL8787_CMD_SCAN:
			ret = mwl8787_cmd_scan_resp(priv, resp);
			ieee80211_scan_completed(priv->hw, false);
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

out:
	complete(&priv->cmd_wait);
	if (!priv->keep_resp) {
		priv->cmd_resp_skb = NULL;
		dev_kfree_skb_any(skb);
	}
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

	ret = mwl8787_send_cmd_sync(priv, cmd);

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

	ret = mwl8787_send_cmd_sync(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_mac_ctrl(struct mwl8787_priv *priv, u16 control)
{
	int ret;
	struct mwl8787_cmd *cmd;

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_MAC_CTRL,
				sizeof(struct mwl8787_cmd_mac_ctrl),
				GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->u.mac_ctrl.control = cpu_to_le16(control);
	ret = mwl8787_send_cmd_sync(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_rf_channel(struct mwl8787_priv *priv, u16 channel)
{
	int ret;
	struct mwl8787_cmd *cmd;

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_RF_CHANNEL,
				sizeof(struct mwl8787_cmd_rf_channel),
				GFP_KERNEL);

	if (!cmd)
		return -ENOMEM;

	cmd->u.rf_channel.action = cpu_to_le16(MWL8787_ACT_SET);
	cmd->u.rf_channel.current_channel = cpu_to_le16(channel);

	ret = mwl8787_send_cmd_sync(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_reset(struct mwl8787_priv *priv)
{
	int ret;
	struct mwl8787_cmd *cmd;

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_RESET,
				sizeof(struct mwl8787_cmd_reset),
				GFP_KERNEL);

	if (!cmd)
		return -ENOMEM;

	cmd->u.reset.action = cpu_to_le16(MWL8787_ACT_SET);
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
	ret = mwl8787_send_cmd_sync(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

int mwl8787_cmd_monitor(struct mwl8787_priv *priv, bool on)
{
	int ret;
	struct mwl8787_cmd *cmd;
	struct mwl8787_cmd_monitor *mon;
	size_t len;

	len = sizeof(struct mwl8787_cmd_monitor) +
	      sizeof(struct mwl8787_band_channel);

	cmd = mwl8787_cmd_alloc(priv, MWL8787_CMD_MONITOR, len,
				GFP_KERNEL);

	if (!cmd)
		return -ENOMEM;

	mon = &cmd->u.monitor;
	mon->action = cpu_to_le16(MWL8787_ACT_SET);
	mon->enable = cpu_to_le16(on);
	mon->flags = MWL8787_MONITOR_MODE_ALL;
	mon->channel.hdr.type = cpu_to_le16(MWL8787_TYPE_BAND_CHAN);
	mon->channel.hdr.len = sizeof(struct mwl8787_band_channel);
	/* FIXME */
	mon->channel.bc[0].band = 0;
	mon->channel.bc[0].channel = 1;

	ret = mwl8787_send_cmd_sync(priv, cmd);

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

	ret = mwl8787_send_cmd_sync(priv, cmd);
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

	ret = mwl8787_send_cmd_sync(priv, cmd);
	mwl8787_cmd_free(priv, cmd);
	return ret;
}
