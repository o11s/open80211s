#include "mwl8787.h"
#include "fw.h"

int mwl8787_send_cmd(struct mwl8787_priv *priv, u8 *buf, size_t len)
{
	return priv->bus_ops->send_cmd(priv, buf, len);
}

int mwl8787_send_cmd_sync(struct mwl8787_priv *priv, u8 *buf, size_t len)
{
	int ret = 0;

	priv->cmd_completed = false;
	ret = priv->bus_ops->send_cmd(priv, buf, len);
	if (ret)
		return ret;

	ret = wait_event_interruptible(priv->cmd_wait_q,
				       priv->cmd_completed);
	if (ret)
		dev_err(priv->dev, "cmd_wait_q terminated: %d\n", ret);

	return ret;
}

struct mwl8787_cmd *mwl8787_cmd_alloc(struct mwl8787_priv *priv,
				      int id, size_t len, gfp_t gfp_flags)
{
	struct mwl8787_cmd *cmd;
	int pktlen = len + sizeof(struct mwl8787_cmd_header);

	cmd = kzalloc(pktlen + priv->bus_headroom, gfp_flags);
	if (!cmd)
		return NULL;

	cmd->hdr.id = id;
	cmd->hdr.len = pktlen;
	cmd->hdr.seq = priv->cmd_seq++;
	return (void *)cmd + priv->bus_headroom;
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
		priv->init_wait_q_woken = true;
		wake_up_interruptible(&priv->init_wait_q);
	}

	dev_kfree_skb_any(skb);
	priv->cmd_completed = true;
	wake_up_interruptible(&priv->cmd_wait_q);
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

	ret = mwl8787_send_cmd_sync(priv, (u8 *) cmd, cmd->hdr.len);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}
