#include "mwl8787.h"

void mwl8787_event_rx(struct mwl8787_priv *priv, struct sk_buff *skb)
{
	struct mwl8787_event *event;

	event = (struct mwl8787_event *) skb->data;
	mwl8787_testmode_event(priv, event, skb->len);

	switch (le16_to_cpu(event->hdr.id))
	{
	case MWL8787_EVT_TX_STATUS:
		mwl8787_tx_status(priv, event);
		break;
	case MWL8787_EVT_TX_FAIL:
		mwl8787_tx_fail(priv, event);
		break;
	case MWL8787_EVT_PRE_TBTT:
		mwl8787_beacon_prepare(priv, priv->vif);
		break;
	default:
		dev_err(priv->dev, "Unknown event: %d\n", le16_to_cpu(event->hdr.id));
		break;
	}

	dev_kfree_skb_any(skb);
}
