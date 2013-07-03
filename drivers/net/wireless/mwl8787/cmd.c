#include "mwl8787.h"
#include "fw.h"

int mwl8787_send_cmd(struct mwl8787_priv *priv, u8 *buf, size_t len)
{
	return priv->bus_ops->send_cmd(priv, buf, len);
}

struct mwl8787_cmd *mwl8787_cmd_alloc(struct mwl8787_priv *priv,
				      int id, size_t len, gfp_t gfp_flags)
{
	struct mwl8787_cmd *cmd;

	cmd = kzalloc(len + sizeof(struct mwl8787_cmd_header) +
		      priv->bus_headroom, gfp_flags);
	if (!cmd)
		return NULL;

	cmd->hdr.id = id;
	cmd->hdr.len = len;
	cmd->hdr.seq = priv->cmd_seq++;
	return (void *)cmd + priv->bus_headroom;
}

void mwl8787_cmd_free(struct mwl8787_priv *priv, void *ptr)
{
	if (!ptr)
		return;

	return kfree(ptr - priv->bus_headroom);
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

	cmd->u.reset.action = MWL8787_ACT_SET;
	ret = mwl8787_send_cmd(priv, (u8 *) cmd, cmd->hdr.len);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}
