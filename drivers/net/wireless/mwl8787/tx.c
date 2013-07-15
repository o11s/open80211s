#include "mwl8787.h"

void mwl8787_tx(struct ieee80211_hw *hw,
		struct ieee80211_tx_control *control,
		struct sk_buff *skb)
{
	struct mwl8787_priv *priv = hw->priv;
	struct mwl8787_tx_desc *desc;
	size_t frame_len = skb->len;
	int pad;

	/* frame data needs to be 4-byte aligned */
	pad = PTR_ALIGN(skb->data, 4) - skb->data;

	skb_push(skb, sizeof(*desc) + pad);

	desc = (struct mwl8787_tx_desc *) skb->data;
	memset(desc, 0, sizeof(*desc));

	desc->frame_len = cpu_to_le16(frame_len);
	desc->frame_offset = sizeof(*desc) + pad;
	desc->frame_type = cpu_to_le16(MWL8787_TX_TYPE_802_11);
	desc->priority = (u8) skb->priority;

	priv->bus_ops->send_tx(priv, skb);

	/* TODO queue skb and do tx status reporting */
	ieee80211_free_txskb(hw, skb);
}

