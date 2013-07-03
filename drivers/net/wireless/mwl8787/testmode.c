#include <net/genetlink.h>

#include "mwl8787.h"

enum mwl8787_tm_commands {
	MWL8787_TM_CMD_UNSPEC,
	MWL8787_TM_CMD_FW,

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

static int mwl8787_tm_cmd_fw(struct mwl8787_priv *priv,
			     struct nlattr *tb[])
{
	u32 id;
	u8 *buf;
	size_t buf_len;

	if (!tb[MWL8787_TM_ATTR_CMD_ID] ||
	    !tb[MWL8787_TM_ATTR_DATA])
		return -EINVAL;

	id = nla_get_u32(tb[MWL8787_TM_ATTR_FW_CMD_ID]);
	buf = nla_data(tb[MWL8787_TM_ATTR_DATA]);
	buf_len = nla_len(tb[MWL8787_TM_ATTR_DATA]);

	return mwl8787_send_cmd(priv, buf, buf_len);
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
