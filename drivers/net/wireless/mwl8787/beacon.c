#include "mwl8787.h"

/**
 * mwl8787_beacon_prepare() - load new beacon and CAB queue
 *
 * @priv: mwl8787 driver context
 * @vif: virtual beaconing interface
 *
 * This function is called before this device's target beacon
 * transmit time to load the content after beacon queue with
 * buffered frames, and to update the TIM.
 */
void mwl8787_beacon_prepare(struct mwl8787_priv *priv,
			    struct ieee80211_vif *vif)
{
	struct sk_buff *skb;
	u16 tim_offset, tim_len;

	skb = ieee80211_beacon_get_tim(priv->hw, priv->vif,
				       &tim_offset, &tim_len);

	mwl8787_cmd_beacon_set(priv, skb);
	dev_kfree_skb_any(skb);

	skb = ieee80211_get_buffered_bc(priv->hw, priv->vif);
	while (skb) {
		mwl8787_tx(priv->hw, NULL, skb);
		skb = ieee80211_get_buffered_bc(priv->hw, priv->vif);
	}
}
