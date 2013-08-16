#include "mwl8787.h"

void mwl8787_event_rx(struct mwl8787_priv *priv, struct sk_buff *skb)
{
	mwl8787_testmode_event(priv, (struct mwl8787_event *) skb->data,
			       skb->len);
	dev_kfree_skb_any(skb);
}
