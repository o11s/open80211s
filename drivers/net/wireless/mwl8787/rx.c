#include "mwl8787.h"

void mwl8787_rx(struct mwl8787_priv *priv, struct sk_buff *skb)
{
	struct ieee80211_rx_status *rx_status;
	struct mwl8787_rx_desc *desc;
	u16 frame_offset = 0, frame_len = 0;

	desc = (struct mwl8787_rx_desc *) skb->data;
	if (skb->len < sizeof(*desc))
		goto drop;

	frame_offset = le16_to_cpu(desc->frame_offset);
	frame_len = le16_to_cpu(desc->frame_len);

	if (skb->len < frame_offset + frame_len)
		goto drop;

	skb_pull(skb, frame_offset);
	skb_trim(skb, frame_len);

	rx_status = IEEE80211_SKB_RXCB(skb);
	memset(rx_status, 0, sizeof(*rx_status));

	rx_status->signal = desc->snr - desc->nf;
	rx_status->rate_idx = desc->rx_rate;
	rx_status->mactime = le64_to_cpu(desc->mactime);
	rx_status->flag |= RX_FLAG_MACTIME_END;

	if (desc->ht_info & MWL8787_RX_HT_RATE)
		rx_status->flag |= RX_FLAG_HT;
	else if (priv->hw->conf.chandef.chan->band == IEEE80211_BAND_5GHZ)
		/* skip CCK for 5 GHz legacy rates */
		rx_status->rate_idx -= 5;

	if (desc->ht_info & MWL8787_RX_HT_40)
		rx_status->flag |= RX_FLAG_40MHZ;

	if (desc->ht_info & MWL8787_RX_HT_SHORT_GI)
		rx_status->flag |= RX_FLAG_SHORT_GI;

	rx_status->freq = priv->hw->conf.chandef.chan->center_freq;
	rx_status->band = priv->hw->conf.chandef.chan->band;

	ieee80211_rx_irqsafe(priv->hw, skb);
	return;

drop:
	dev_dbg(priv->dev,
		"short packet: len=%d, off=%d, skblen=%d\n",
		frame_len, frame_offset, skb->len);

	dev_kfree_skb_any(skb);
}
