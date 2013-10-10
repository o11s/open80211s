#include "mwl8787.h"

static inline void mwl8787_stop_queue(struct mwl8787_priv *priv, u8 q)
{
	if (priv->stopped[q])
		return;

	priv->stopped[q] = true;
	ieee80211_stop_queue(priv->hw, q);
}

static inline void mwl8787_start_queue(struct mwl8787_priv *priv, u8 q)
{
	if (!priv->stopped[q])
		return;

	priv->stopped[q] = false;
	ieee80211_wake_queue(priv->hw, q);
}

static void mwl8787_tx_setup(struct mwl8787_priv *priv,
			     struct sk_buff *skb)
{
	struct mwl8787_tx_desc *desc;
	size_t frame_len = skb->len;
	u32 tx_ctl = 0;
	int pad;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	/* frame data needs to be 4-byte aligned */
	pad = PTR_ALIGN(skb->data, 4) - skb->data;

	skb_push(skb, sizeof(*desc) + pad);

	desc = (struct mwl8787_tx_desc *) skb->data;
	memset(desc, 0, sizeof(*desc));

	desc->bss_type = MWL8787_BSS_TYPE_TM;
	desc->frame_len = cpu_to_le16(frame_len);
	desc->frame_offset = cpu_to_le16(sizeof(*desc) + pad);
	desc->frame_type = cpu_to_le16(MWL8787_TX_TYPE_802_11);
	/* TODO: AMPDU (fw will override with ampdu queue based on QoS ctl
	 * field TID) */
	desc->priority = mwl8787_ac_to_hwq[skb_get_queue_mapping(skb)];

	if (info->flags & IEEE80211_TX_CTL_ASSIGN_SEQ)
		tx_ctl |= MWL8787_ASSIGN_SEQ;

	if (info->flags & IEEE80211_TX_CTL_REQ_TX_STATUS)
		tx_ctl |= MWL8787_REQ_TX_STATUS;

	if (info->flags & IEEE80211_TX_CTL_AMPDU)
		tx_ctl |= MWL8787_AMPDU;

	desc->tx_control = cpu_to_le32(tx_ctl);
}

static int mwl8787_tx_frame(struct mwl8787_priv *priv,
			    struct sk_buff *skb, bool more_frames)
{
	mwl8787_tx_setup(priv, skb);
	return priv->bus_ops->send_tx(priv, skb, more_frames);
}

void mwl8787_tx_status(struct mwl8787_priv *priv,
		       struct mwl8787_event *tx_status_event)
{
	struct sk_buff *skb;
	struct ieee80211_tx_info *info;
	struct mwl8787_event_tx_status *tx_status =
		&tx_status_event->u.tx_status;
	u8 hw_queue;

	if (WARN_ON(tx_status->hw_queue >= IEEE80211_NUM_ACS))
		return;

	hw_queue = mwl8787_hwq_to_ac[tx_status->hw_queue];
	skb = skb_dequeue(&priv->tx_status_queue[hw_queue]);
	if (!skb)
		return;

	info = IEEE80211_SKB_CB(skb);
	ieee80211_tx_info_clear_status(info);

	info->status.rates[0].idx = tx_status->last_rate;
	info->status.rates[0].count = tx_status->attempts;
	info->status.rates[1].idx = -1;

	if (tx_status->acked)
		info->flags |= IEEE80211_TX_STAT_ACK;

	ieee80211_tx_status_irqsafe(priv->hw, skb);

	if (atomic_dec_return(&priv->tx_pending[hw_queue]) <= MWL8787_TX_CT_LO)
		mwl8787_start_queue(priv, hw_queue);
}

void mwl8787_tx_fail(struct mwl8787_priv *priv,
		     struct mwl8787_event *tx_fail_event)
{
	struct mwl8787_event_tx_fail *tx_fail = &tx_fail_event->u.tx_fail;
	struct ieee80211_sta *sta;

	dev_dbg(priv->dev, "max tx failures reported for %pM\n",
			   tx_fail->addr);

	rcu_read_lock();
	sta = ieee80211_find_sta_by_ifaddr(priv->hw, tx_fail->addr,
					   priv->addr);
	if (sta)
		ieee80211_report_low_ack(sta, priv->tx_fail);
	rcu_read_unlock();
}

void mwl8787_tx_cleanup(struct mwl8787_priv *priv)
{
	struct sk_buff *skb;
	int i;

	while ((skb = skb_dequeue(&priv->tx_queue)))
		ieee80211_free_txskb(priv->hw, skb);

	for (i=0; i < IEEE80211_NUM_ACS; i++) {
		while ((skb = skb_dequeue(&priv->tx_status_queue[i])))
			ieee80211_free_txskb(priv->hw, skb);
	}
}

void mwl8787_tx_work(struct work_struct *work)
{
	struct mwl8787_priv *priv;
	struct sk_buff *skb;
	u8 *data_ptr, hw_queue;
	int ret;
	struct ieee80211_tx_info *info;

	priv = container_of(work, struct mwl8787_priv, tx_work);

	while (!priv->bus_ops->is_tx_busy(priv) &&
	       (skb = skb_dequeue(&priv->tx_queue))) {

		info = IEEE80211_SKB_CB(skb);
		hw_queue = info->hw_queue;

		data_ptr = skb->data;
		ret = mwl8787_tx_frame(priv, skb,
				       !skb_queue_empty(&priv->tx_queue));

		/* move skb->data back to 802.11 header */
		skb_pull(skb, data_ptr - skb->data);

		if (ret == -EBUSY) {
			/*
			 * No free write ports; requeue the frame at the head
			 * then wait until we're rescheduled by tx done irq
			 */
			skb_queue_head(&priv->tx_queue, skb);
			return;
		}

		if (ret) {
			/* on other errors, drop the frame */
			atomic_dec_return(&priv->tx_pending[hw_queue]);
			ieee80211_free_txskb(priv->hw, skb);
			return;
		}

		if (info->flags & IEEE80211_TX_CTL_REQ_TX_STATUS)
			skb_queue_tail(&priv->tx_status_queue[hw_queue], skb);
		else {
			if (atomic_dec_return(&priv->tx_pending[hw_queue]) <=
			    MWL8787_TX_CT_LO)
				mwl8787_start_queue(priv, hw_queue);
			ieee80211_free_txskb(priv->hw, skb);
		}
	}
}

void mwl8787_tx(struct ieee80211_hw *hw,
		struct ieee80211_tx_control *control,
		struct sk_buff *skb)
{
	struct mwl8787_priv *priv = hw->priv;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	u8 hw_queue = info->hw_queue;

	if (atomic_inc_return(&priv->tx_pending[hw_queue]) >= MWL8787_TX_CT_HI)
		mwl8787_stop_queue(priv, hw_queue);

	mwl8787_ampdu_check(priv, control->sta, skb);

	skb_queue_tail(&priv->tx_queue, skb);
	ieee80211_queue_work(priv->hw, &priv->tx_work);
}
