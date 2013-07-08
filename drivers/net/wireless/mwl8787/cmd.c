#include "mwl8787.h"
#include "fw.h"

int mwl8787_send_cmd(struct mwl8787_priv *priv, u8 *buf, size_t len)
{
	return priv->bus_ops->send_cmd(priv, buf, len);
}

int mwl8787_send_cmd_sync(struct mwl8787_priv *priv, u8 *buf, size_t len)
{
	int ret = 0;

	INIT_COMPLETION(priv->cmd_wait);
	ret = priv->bus_ops->send_cmd(priv, buf, len);
	if (ret)
		return ret;

	ret = wait_for_completion_timeout(&priv->cmd_wait, HZ);
	if (ret == 0) {
		dev_err(priv->dev, "cmd_wait timed out\n");
		return -ETIMEDOUT;
	}
	return 0;
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
	cmd->hdr.seq = cpu_to_le16(priv->cmd_seq++);
	return cmd;
}

void mwl8787_cmd_free(struct mwl8787_priv *priv, void *ptr)
{
	if (!ptr)
		return;

	return kfree(ptr - priv->bus_headroom);
}

int mwl8787_process_cmdresp(struct mwl8787_priv *priv, struct sk_buff *skb)
{
	struct mwl8787_cmd *resp;
	int ret = 0;
	uint16_t orig_cmdresp_no;
	uint16_t cmdid;
	uint16_t result;
	struct timeval tstamp;
	unsigned long flags;

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

		dev_kfree_skb_any(skb);
		return -1;
	}

	/* handle response */
	/*
	ret = mwifiex_process_sta_cmdresp(priv, cmdresp_no, resp);
	*/

	if (priv->hw_status == MWL8787_HW_STATUS_INITIALIZING &&
	    cmdid == MWL8787_CMD_FUNC_INIT &&
	    result == MWL8787_CMD_SUCCESS) {
		priv->hw_status = MWL8787_HW_STATUS_INIT_DONE;
		complete(&priv->init_wait);
	}

	dev_kfree_skb_any(skb);
	complete(&priv->cmd_wait);
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

	ret = mwl8787_send_cmd_sync(priv, (u8 *) cmd, le16_to_cpu(cmd->hdr.len));

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
	ret = mwl8787_send_cmd(priv, (u8 *) cmd, le16_to_cpu(cmd->hdr.len));

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

