#ifdef NL80211_TESTMODE
#include <net/genetlink.h>

#include "mwl8787.h"

enum mwl8787_tm_commands {
	MWL8787_TM_CMD_UNSPEC,
	MWL8787_TM_CMD_FW,
	MWL8787_TM_CMD_DATA,

	__MWL8787_TM_CMD_AFTER_LAST
};
#define MWL8787_TM_CMD_MAX (__MWL8787_TM_CMD_AFTER_LAST + 1)

enum mwl8787_tm_attrs {
	MWL8787_TM_ATTR_UNSPEC,
	MWL8787_TM_ATTR_CMD_ID,
	MWL8787_TM_ATTR_FW_CMD_ID,
	MWL8787_TM_ATTR_DATA,

	__MWL8787_TM_ATTR_AFTER_LAST
};
#define MWL8787_TM_ATTR_MAX (__MWL8787_TM_ATTR_AFTER_LAST + 1)
#define MWL8787_TM_MAX_DATA_LEN 1024

static
struct nla_policy mwl8787_tm_policy[MWL8787_TM_ATTR_MAX + 1] = {
	[MWL8787_TM_ATTR_CMD_ID] =	{ .type = NLA_U32 },

	[MWL8787_TM_ATTR_FW_CMD_ID] =	{ .type = NLA_U32 },
	[MWL8787_TM_ATTR_DATA] =	{ .type = NLA_BINARY,
					  .len = MWL8787_TM_MAX_DATA_LEN },
};

static int mwl8787_tm_cmd_tx(struct mwl8787_priv *priv,
			     struct nlattr *tb[])
{
	u8 *buf;
	size_t buf_len;
	struct sk_buff *skb;
	int ret = 0;

	if (!tb[MWL8787_TM_ATTR_DATA])
		return -EINVAL;

	buf = nla_data(tb[MWL8787_TM_ATTR_DATA]);
	buf_len = nla_len(tb[MWL8787_TM_ATTR_DATA]);

	skb = dev_alloc_skb(buf_len + priv->bus_headroom);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, priv->bus_headroom);
	memcpy(skb_put(skb, buf_len), buf, buf_len);

	ret = priv->bus_ops->send_tx(priv, skb);

	dev_kfree_skb(skb);
	return ret;
}
static int mwl8787_tm_cmd_fw(struct mwl8787_priv *priv,
			     struct nlattr *tb[])
{
	u32 id;
	u8 *buf;
	size_t buf_len;
	struct mwl8787_cmd *cmd, *rcmd;
	int ret;
	struct sk_buff *reply, *resp;

	if (!tb[MWL8787_TM_ATTR_CMD_ID] ||
	    !tb[MWL8787_TM_ATTR_DATA])
		return -EINVAL;

	id = nla_get_u32(tb[MWL8787_TM_ATTR_FW_CMD_ID]);
	buf = nla_data(tb[MWL8787_TM_ATTR_DATA]);
	buf_len = nla_len(tb[MWL8787_TM_ATTR_DATA]);

	/* create cmd payload from nlmsg & send to hw */
	cmd = mwl8787_cmd_alloc(priv, id, buf_len, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	memcpy(cmd->u.data, buf, buf_len);
	ret = mwl8787_send_cmd_tm(priv, cmd, &resp);
	mwl8787_cmd_free(priv, cmd);

	if (ret)
		return ret;

	reply = cfg80211_testmode_alloc_reply_skb(priv->hw->wiphy,
		MWL8787_TM_MAX_DATA_LEN);
	if (!reply)
		goto out;

	/* copy command response back to userspace */
	rcmd = (struct mwl8787_cmd *) resp->data;

	if (nla_put_u32(reply, MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW) ||
	    nla_put_u32(reply, MWL8787_TM_ATTR_FW_CMD_ID,
		        le16_to_cpu(rcmd->hdr.id)) ||
	    nla_put(reply, MWL8787_TM_ATTR_DATA,
		    le16_to_cpu(rcmd->hdr.len) - sizeof(rcmd->hdr),
		    rcmd->u.data))
		goto out;

	dev_kfree_skb_any(resp);
	cfg80211_testmode_reply(reply);
	return ret;

out:
	dev_kfree_skb_any(resp);
	kfree_skb(reply);
	return -ENOMEM;
}

int mwl8787_testmode_cmd(struct ieee80211_hw *hw, void *data, int len)
{
	struct mwl8787_priv *priv = hw->priv;

	struct nlattr *tb[MWL8787_TM_ATTR_MAX + 1];
	int err;

	err = nla_parse(tb, MWL8787_TM_ATTR_MAX, data, len,
			mwl8787_tm_policy);
	if (err)
		return err;

	if (!tb[MWL8787_TM_ATTR_CMD_ID])
		return -EINVAL;

	switch (nla_get_u32(tb[MWL8787_TM_ATTR_CMD_ID])) {

	case MWL8787_TM_CMD_FW:
		return mwl8787_tm_cmd_fw(priv, tb);
	case MWL8787_TM_CMD_DATA:
		return mwl8787_tm_cmd_tx(priv, tb);
	default:
		return -ENOSYS;
	}
}

int mwl8787_testmode_dump(struct ieee80211_hw *hw,
			  struct sk_buff *skb,
			  struct netlink_callback *cb,
			  void *data, int len)
{
	return 0;
}

#endif
