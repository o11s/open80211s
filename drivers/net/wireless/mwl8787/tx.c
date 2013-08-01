#include "mwl8787.h"

static void mwl8787_tx_setup(struct mwl8787_priv *priv,
			     struct sk_buff *skb)
{
	struct mwl8787_tx_desc *desc;
	size_t frame_len = skb->len;
	int pad;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;

	/* frame data needs to be 4-byte aligned */
	pad = PTR_ALIGN(skb->data, 4) - skb->data;

	skb_push(skb, sizeof(*desc) + pad);

	desc = (struct mwl8787_tx_desc *) skb->data;
	memset(desc, 0, sizeof(*desc));

	desc->bss_type = MWL8787_BSS_TYPE_TM;
	desc->frame_len = cpu_to_le16(frame_len);
	desc->frame_offset = cpu_to_le16(sizeof(*desc) + pad);

	if (ieee80211_is_mgmt(hdr->frame_control))
		desc->frame_type = cpu_to_le16(MWL8787_TX_TYPE_MGMT);
	else
		desc->frame_type = cpu_to_le16(MWL8787_TX_TYPE_802_11);

	desc->priority = (u8) skb->priority;
}


static int mwl8787_tx_frame(struct mwl8787_priv *priv,
			     struct sk_buff *skb)
{
	mwl8787_tx_setup(priv, skb);
	return priv->bus_ops->send_tx(priv, skb);
}

void mwl8787_tx_work(struct work_struct *work)
{
	struct mwl8787_priv *priv;
	struct sk_buff *skb;
	u8 *data_ptr;
	int ret;

	priv = container_of(work, struct mwl8787_priv, tx_work);

	while ((skb = skb_dequeue(&priv->tx_queue))) {

		data_ptr = skb->data;
		ret = mwl8787_tx_frame(priv, skb);

		/* move skb->data back to 802.11 header */
		skb_pull(skb, data_ptr - skb->data);
		if (ret) {
			ieee80211_free_txskb(priv->hw, skb);
			return;
		}
		/* TODO tx status reporting */
		ieee80211_free_txskb(priv->hw, skb);
	}
}

void mwl8787_tx(struct ieee80211_hw *hw,
		struct ieee80211_tx_control *control,
		struct sk_buff *skb)
{
	struct mwl8787_priv *priv = hw->priv;

	skb_queue_tail(&priv->tx_queue, skb);
	ieee80211_queue_work(priv->hw, &priv->tx_work);
}

