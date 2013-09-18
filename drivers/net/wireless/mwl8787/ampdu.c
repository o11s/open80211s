#include "mwl8787.h"

void mwl8787_ampdu_work(struct work_struct *work)
{
	struct mwl8787_priv *priv;
	struct mwl8787_sta *mwl8787_sta;
	struct ieee80211_sta *sta;
	int tid;

	mwl8787_sta = container_of(work, struct mwl8787_sta, ampdu_work);
	sta = mwl8787_sta->sta;
	priv = mwl8787_sta->priv;

	for (tid=0; tid < IEEE80211_NUM_TIDS; tid++) {
		if (mwl8787_sta->ampdu_state[tid] != MWL8787_AMPDU_INIT)
			continue;

		/* start a new ba session */
		ieee80211_start_tx_ba_session(sta, tid, 5000);
	}
}

/*
 * Check if we can start an a-mpdu session with this station.
 */
void mwl8787_ampdu_check(struct mwl8787_priv *priv,
			 struct ieee80211_sta *sta,
			 struct sk_buff *skb)
{
	struct mwl8787_sta *priv_sta;
	struct ieee80211_hdr *hdr;
	u8 *qc, tid;

	if (!sta || !conf_is_ht(&priv->hw->conf))
		return;

	hdr = (struct ieee80211_hdr *) skb->data;
	if (!ieee80211_is_data_qos(hdr->frame_control))
		return;

	qc = ieee80211_get_qos_ctl(hdr);
	tid = qc[0] & IEEE80211_QOS_CTL_TID_MASK;

	priv_sta = (struct mwl8787_sta *) sta->drv_priv;

	/* TODO make up some decent criteria here... and locking etc */
	if (priv->num_ampdu_sessions < MWL8787_MAX_AMPDU_SESSIONS &&
	    priv_sta->ampdu_state[tid] == MWL8787_AMPDU_NONE) {
		priv->num_ampdu_sessions++;
		priv_sta->ampdu_state[tid] = MWL8787_AMPDU_INIT;
		ieee80211_queue_work(priv->hw, &priv_sta->ampdu_work);
	}
}
