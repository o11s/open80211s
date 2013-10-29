/*
 * Copyright 2012-2013, Marco Porsch <marco.porsch@s2005.tu-chemnitz.de>
 * Copyright 2012-2013, cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "mesh.h"
#include "wme.h"
#include "driver-ops.h"


#define BEACON_TIMEOUT	20000	/* in us units */


static inline void mps_queue_work(struct ieee80211_sub_if_data *sdata,
				  enum mesh_deferred_task_flags flag)
{
	set_bit(flag, &sdata->u.mesh.wrkq_flags);
	ieee80211_queue_work(&sdata->local->hw, &sdata->work);
}


/* mesh PS management */

/**
 * mps_qos_null_get - create pre-addressed QoS Null frame for mesh powersave
 */
static struct sk_buff *mps_qos_null_get(struct sta_info *sta)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_hdr *nullfunc; /* use 4addr header */
	struct sk_buff *skb;
	int size = sizeof(*nullfunc);
	__le16 fc;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + size + 2);
	if (!skb)
		return NULL;
	skb_reserve(skb, local->hw.extra_tx_headroom);

	nullfunc = (struct ieee80211_hdr *) skb_put(skb, size);
	fc = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_NULLFUNC);
	ieee80211_fill_mesh_addresses(nullfunc, &fc, sta->sta.addr,
				      sdata->vif.addr);
	nullfunc->frame_control = fc;
	nullfunc->duration_id = 0;
	/* no address resolution for this frame -> set addr 1 immediately */
	memcpy(nullfunc->addr1, sta->sta.addr, ETH_ALEN);
	memset(skb_put(skb, 2), 0, 2); /* append QoS control field */
	ieee80211_mps_set_frame_flags(sdata, sta, nullfunc);

	return skb;
}

/**
 * mps_qos_null_tx - send a QoS Null to indicate link-specific power mode
 */
static void mps_qos_null_tx(struct sta_info *sta)
{
	struct sk_buff *skb;

	skb = mps_qos_null_get(sta);
	if (!skb)
		return;

	mps_dbg(sta->sdata, "announcing peer-specific power mode to %pM\n",
		sta->sta.addr);

	/* don't unintentionally start a MPSP */
	if (!test_sta_flag(sta, WLAN_STA_PS_STA)) {
		u8 *qc = ieee80211_get_qos_ctl((void *) skb->data);

		qc[0] |= IEEE80211_QOS_CTL_EOSP;
	}

	ieee80211_tx_skb(sta->sdata, skb);
}

/**
 * ieee80211_mps_local_status_update - track status of local link-specific PMs
 *
 * @sdata: local mesh subif
 *
 * sets the non-peer power mode and triggers the driver PS (re-)configuration
 * Return BSS_CHANGED_BEACON if a beacon update is necessary.
 */
u32 ieee80211_mps_local_status_update(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct sta_info *sta;
	bool peering = false;
	int light_sleep_cnt = 0;
	int deep_sleep_cnt = 0;
	u32 changed = 0;
	enum nl80211_mesh_power_mode nonpeer_pm;

	rcu_read_lock();
	list_for_each_entry_rcu(sta, &sdata->local->sta_list, list) {
		if (sdata != sta->sdata)
			continue;

		switch (sta->plink_state) {
		case NL80211_PLINK_OPN_SNT:
		case NL80211_PLINK_OPN_RCVD:
		case NL80211_PLINK_CNF_RCVD:
			peering = true;
			break;
		case NL80211_PLINK_ESTAB:
			if (sta->local_pm == NL80211_MESH_POWER_LIGHT_SLEEP)
				light_sleep_cnt++;
			else if (sta->local_pm == NL80211_MESH_POWER_DEEP_SLEEP)
				deep_sleep_cnt++;
			break;
		default:
			break;
		}
	}
	rcu_read_unlock();

	/*
	 * Set non-peer mode to active during peering/scanning/authentication
	 * (see IEEE802.11-2012 13.14.8.3). The non-peer mesh power mode is
	 * deep sleep if the local STA is in light or deep sleep towards at
	 * least one mesh peer (see 13.14.3.1). Otherwise, set it to the
	 * user-configured default value.
	 */
	if (peering) {
		mps_dbg(sdata, "setting non-peer PM to active for peering\n");
		nonpeer_pm = NL80211_MESH_POWER_ACTIVE;
	} else if (light_sleep_cnt || deep_sleep_cnt) {
		mps_dbg(sdata, "setting non-peer PM to deep sleep\n");
		nonpeer_pm = NL80211_MESH_POWER_DEEP_SLEEP;
	} else {
		mps_dbg(sdata, "setting non-peer PM to user value\n");
		nonpeer_pm = ifmsh->mshcfg.power_mode;
	}

	/* need update if sleep counts move between 0 and non-zero */
	if (ifmsh->nonpeer_pm != nonpeer_pm ||
	    !ifmsh->ps_peers_light_sleep != !light_sleep_cnt ||
	    !ifmsh->ps_peers_deep_sleep != !deep_sleep_cnt)
		changed = BSS_CHANGED_BEACON;

	ifmsh->nonpeer_pm = nonpeer_pm;
	ifmsh->ps_peers_light_sleep = light_sleep_cnt;
	ifmsh->ps_peers_deep_sleep = deep_sleep_cnt;

	mps_queue_work(sdata, MESH_WORK_PS_HW_CONF);

	return changed;
}

/**
 * ieee80211_mps_set_sta_local_pm - set local PM towards a mesh STA
 *
 * @sta: mesh STA
 * @pm: the power mode to set
 * Return BSS_CHANGED_BEACON if a beacon update is in order.
 */
u32 ieee80211_mps_set_sta_local_pm(struct sta_info *sta,
				   enum nl80211_mesh_power_mode pm)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;

	if (sta->local_pm == pm)
		return 0;

	mps_dbg(sdata, "local STA operates in mode %d with %pM\n",
		pm, sta->sta.addr);

	sta->local_pm = pm;

	/*
	 * announce peer-specific power mode transition
	 * (see IEEE802.11-2012 13.14.3.2 and 13.14.3.3)
	 */
	if (sta->plink_state == NL80211_PLINK_ESTAB)
		mps_qos_null_tx(sta);

	return ieee80211_mps_local_status_update(sdata);
}

/**
 * ieee80211_mps_set_frame_flags - set mesh PS flags in FC (and QoS Control)
 *
 * @sdata: local mesh subif
 * @sta: mesh STA
 * @hdr: 802.11 frame header
 *
 * see IEEE802.11-2012 8.2.4.1.7 and 8.2.4.5.11
 *
 * NOTE: sta must be given when an individually-addressed QoS frame header
 * is handled, for group-addressed and management frames it is not used
 */
void ieee80211_mps_set_frame_flags(struct ieee80211_sub_if_data *sdata,
				   struct sta_info *sta,
				   struct ieee80211_hdr *hdr)
{
	enum nl80211_mesh_power_mode pm;
	u8 *qc;

	if (WARN_ON(is_unicast_ether_addr(hdr->addr1) &&
		    ieee80211_is_data_qos(hdr->frame_control) &&
		    !sta))
		return;

	if (is_unicast_ether_addr(hdr->addr1) &&
	    ieee80211_is_data_qos(hdr->frame_control) &&
	    sta->plink_state == NL80211_PLINK_ESTAB)
		pm = sta->local_pm;
	else
		pm = sdata->u.mesh.nonpeer_pm;

	if (pm == NL80211_MESH_POWER_ACTIVE)
		hdr->frame_control &= cpu_to_le16(~IEEE80211_FCTL_PM);
	else
		hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_PM);

	if (!ieee80211_is_data_qos(hdr->frame_control))
		return;

	qc = ieee80211_get_qos_ctl(hdr);

	if ((is_unicast_ether_addr(hdr->addr1) &&
	     pm == NL80211_MESH_POWER_DEEP_SLEEP) ||
	    (is_multicast_ether_addr(hdr->addr1) &&
	     sdata->u.mesh.ps_peers_deep_sleep > 0))
		qc[1] |= (IEEE80211_QOS_CTL_MESH_PS_LEVEL >> 8);
	else
		qc[1] &= ~(IEEE80211_QOS_CTL_MESH_PS_LEVEL >> 8);
}

/**
 * ieee80211_mps_sta_status_update - update buffering status of neighbor STA
 *
 * @sta: mesh STA
 *
 * called after change of peering status or non-peer/peer-specific power mode
 */
void ieee80211_mps_sta_status_update(struct sta_info *sta)
{
	enum nl80211_mesh_power_mode pm;
	bool do_buffer;

	/* For non-assoc STA, prevent buffering or frame transmission */
	if (sta->sta_state < IEEE80211_STA_ASSOC)
		return;

	/*
	 * use peer-specific power mode if peering is established and the
	 * peer's power mode is known
	 */
	if (sta->plink_state == NL80211_PLINK_ESTAB &&
	    sta->peer_pm != NL80211_MESH_POWER_UNKNOWN)
		pm = sta->peer_pm;
	else
		pm = sta->nonpeer_pm;

	do_buffer = (pm != NL80211_MESH_POWER_ACTIVE);

	/* clear the MPSP flags for non-peers or active STA */
	if (sta->plink_state != NL80211_PLINK_ESTAB) {
		clear_sta_flag(sta, WLAN_STA_MPSP_OWNER);
		clear_sta_flag(sta, WLAN_STA_MPSP_RECIPIENT);
	} else if (!do_buffer) {
		clear_sta_flag(sta, WLAN_STA_MPSP_OWNER);
	}

	/* Don't let the same PS state be set twice */
	if (test_sta_flag(sta, WLAN_STA_PS_STA) == do_buffer)
		return;

	if (do_buffer) {
		set_sta_flag(sta, WLAN_STA_PS_STA);
		atomic_inc(&sta->sdata->u.mesh.ps.num_sta_ps);
		mps_dbg(sta->sdata, "start PS buffering frames towards %pM\n",
			sta->sta.addr);
	} else {
		ieee80211_sta_ps_deliver_wakeup(sta);
	}
}

static void mps_set_sta_peer_pm(struct sta_info *sta,
				struct ieee80211_hdr *hdr)
{
	enum nl80211_mesh_power_mode pm;
	u8 *qc = ieee80211_get_qos_ctl(hdr);

	/*
	 * Test Power Management field of frame control (PW) and
	 * mesh power save level subfield of QoS control field (PSL)
	 *
	 * | PM | PSL| Mesh PM |
	 * +----+----+---------+
	 * | 0  |Rsrv|  Active |
	 * | 1  | 0  |  Light  |
	 * | 1  | 1  |  Deep   |
	 */
	if (ieee80211_has_pm(hdr->frame_control)) {
		if (qc[1] & (IEEE80211_QOS_CTL_MESH_PS_LEVEL >> 8))
			pm = NL80211_MESH_POWER_DEEP_SLEEP;
		else
			pm = NL80211_MESH_POWER_LIGHT_SLEEP;
	} else {
		pm = NL80211_MESH_POWER_ACTIVE;
	}

	if (sta->peer_pm == pm)
		return;

	mps_dbg(sta->sdata, "STA %pM enters mode %d\n",
		sta->sta.addr, pm);

	sta->peer_pm = pm;

	ieee80211_mps_sta_status_update(sta);
}

static void mps_set_sta_nonpeer_pm(struct sta_info *sta,
				   struct ieee80211_hdr *hdr)
{
	enum nl80211_mesh_power_mode pm;

	if (ieee80211_has_pm(hdr->frame_control))
		pm = NL80211_MESH_POWER_DEEP_SLEEP;
	else
		pm = NL80211_MESH_POWER_ACTIVE;

	if (sta->nonpeer_pm == pm)
		return;

	mps_dbg(sta->sdata, "STA %pM sets non-peer mode to %d\n",
		sta->sta.addr, pm);

	sta->nonpeer_pm = pm;

	ieee80211_mps_sta_status_update(sta);
}

/**
 * ieee80211_mps_rx_h_sta_process - frame receive handler for mesh powersave
 *
 * @sta: STA info that transmitted the frame
 * @hdr: IEEE 802.11 (QoS) Header
 */
void ieee80211_mps_rx_h_sta_process(struct sta_info *sta,
				    struct ieee80211_hdr *hdr)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;

	if (is_unicast_ether_addr(hdr->addr1) &&
	    ieee80211_is_data_qos(hdr->frame_control)) {
		/*
		 * individually addressed QoS Data/Null frames contain
		 * peer link-specific PS mode towards the local STA
		 */
		mps_set_sta_peer_pm(sta, hdr);

		/* check for mesh Peer Service Period trigger frames */
		ieee80211_mpsp_trigger_process(ieee80211_get_qos_ctl(hdr),
					       sta, false, false);
	} else {
		/*
		 * can only determine non-peer PS mode
		 * (see IEEE802.11-2012 8.2.4.1.7)
		 */
		mps_set_sta_nonpeer_pm(sta, hdr);

		/* resume doze after multicast receipt */
		if (sdata->local->mps_enabled &&
		    is_multicast_ether_addr(hdr->addr1) &&
		    !ieee80211_has_moredata(hdr->frame_control) &&
		    test_and_clear_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_CAB))
			mps_queue_work(sdata, MESH_WORK_PS_DOZE);
	}
}


/* mesh PS frame release */

static void mpsp_trigger_send(struct sta_info *sta, bool rspi, bool eosp)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct sk_buff *skb;
	struct ieee80211_hdr *nullfunc;
	struct ieee80211_tx_info *info;
	u8 *qc;

	skb = mps_qos_null_get(sta);
	if (!skb)
		return;

	nullfunc = (struct ieee80211_hdr *) skb->data;
	if (!eosp)
		nullfunc->frame_control |=
				cpu_to_le16(IEEE80211_FCTL_MOREDATA);
	/*
	 * | RSPI | EOSP |  MPSP triggering   |
	 * +------+------+--------------------+
	 * |  0   |  0   | local STA is owner |
	 * |  0   |  1   | no MPSP (MPSP end) |
	 * |  1   |  0   | both STA are owner |
	 * |  1   |  1   | peer STA is owner  | see IEEE802.11-2012 13.14.9.2
	 */
	qc = ieee80211_get_qos_ctl(nullfunc);
	if (rspi)
		qc[1] |= (IEEE80211_QOS_CTL_RSPI >> 8);
	if (eosp)
		qc[0] |= IEEE80211_QOS_CTL_EOSP;

	info = IEEE80211_SKB_CB(skb);

	info->flags |= IEEE80211_TX_CTL_NO_PS_BUFFER |
		       IEEE80211_TX_CTL_REQ_TX_STATUS;

	mps_dbg(sdata, "sending MPSP trigger%s%s to %pM\n",
		rspi ? " RSPI" : "", eosp ? " EOSP" : "", sta->sta.addr);

	ieee80211_tx_skb(sdata, skb);
}

/**
 * mpsp_qos_null_append - append QoS Null frame to MPSP skb queue if needed
 *
 * To properly end a mesh MPSP the last transmitted frame has to set the EOSP
 * flag in the QoS Control field. In case the current tailing frame is not a
 * QoS Data frame, append a QoS Null to carry the flag.
 */
static void mpsp_qos_null_append(struct sta_info *sta,
				 struct sk_buff_head *frames)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct sk_buff *new_skb, *skb = skb_peek_tail(frames);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	struct ieee80211_tx_info *info;

	if (ieee80211_is_data_qos(hdr->frame_control))
		return;

	new_skb = mps_qos_null_get(sta);
	if (!new_skb)
		return;

	mps_dbg(sdata, "appending QoS Null in MPSP towards %pM\n",
		sta->sta.addr);
	/*
	 * This frame has to be transmitted last. Assign lowest priority to
	 * make sure it cannot pass other frames when releasing multiple ACs.
	 */
	new_skb->priority = 1;
	skb_set_queue_mapping(new_skb, IEEE80211_AC_BK);
	ieee80211_set_qos_hdr(sdata, new_skb);

	info = IEEE80211_SKB_CB(new_skb);
	info->control.vif = &sdata->vif;
	info->flags |= IEEE80211_TX_INTFL_NEED_TXPROCESSING;

	__skb_queue_tail(frames, new_skb);
}

/**
 * mps_frame_deliver - transmit frames during mesh powersave
 *
 * @sta: STA info to transmit to
 * @n_frames: number of frames to transmit. -1 for all
 */
static void mps_frame_deliver(struct sta_info *sta, int n_frames)
{
	struct ieee80211_local *local = sta->sdata->local;
	int ac;
	struct sk_buff_head frames;
	struct sk_buff *skb;
	bool more_data = false;

	skb_queue_head_init(&frames);

	/* collect frame(s) from buffers */
	for (ac = 0; ac < IEEE80211_NUM_ACS; ac++) {
		while (n_frames != 0) {
			skb = skb_dequeue(&sta->tx_filtered[ac]);
			if (!skb) {
				skb = skb_dequeue(
					&sta->ps_tx_buf[ac]);
				if (skb)
					local->total_ps_buffered--;
			}
			if (!skb)
				break;
			n_frames--;
			__skb_queue_tail(&frames, skb);
		}

		if (!skb_queue_empty(&sta->tx_filtered[ac]) ||
		    !skb_queue_empty(&sta->ps_tx_buf[ac]))
			more_data = true;
	}

	/* nothing to send? -> EOSP */
	if (skb_queue_empty(&frames)) {
		mpsp_trigger_send(sta, false, true);
		return;
	}

	/* in a MPSP make sure the last skb is a QoS Data frame */
	if (test_sta_flag(sta, WLAN_STA_MPSP_OWNER))
		mpsp_qos_null_append(sta, &frames);

	mps_dbg(sta->sdata, "sending %d frames to PS STA %pM\n",
		skb_queue_len(&frames), sta->sta.addr);

	/* prepare collected frames for transmission */
	skb_queue_walk(&frames, skb) {
		struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
		struct ieee80211_hdr *hdr = (void *) skb->data;

		/*
		 * Tell TX path to send this frame even though the
		 * STA may still remain is PS mode after this frame
		 * exchange.
		 */
		info->flags |= IEEE80211_TX_CTL_NO_PS_BUFFER;

		if (more_data || !skb_queue_is_last(&frames, skb))
			hdr->frame_control |=
				cpu_to_le16(IEEE80211_FCTL_MOREDATA);
		else
			hdr->frame_control &=
				cpu_to_le16(~IEEE80211_FCTL_MOREDATA);

		if (skb_queue_is_last(&frames, skb) &&
		    ieee80211_is_data_qos(hdr->frame_control)) {
			u8 *qoshdr = ieee80211_get_qos_ctl(hdr);

			/* MPSP trigger frame ends service period */
			*qoshdr |= IEEE80211_QOS_CTL_EOSP;
			info->flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;
		}
	}

	ieee80211_add_pending_skbs(local, &frames);
	sta_info_recalc_tim(sta);
}

/**
 * ieee80211_mpsp_trigger_process - track status of mesh Peer Service Periods
 *
 * @qc: QoS Control field
 * @sta: peer to start a MPSP with
 * @tx: frame was transmitted by the local STA
 * @acked: frame has been transmitted successfully
 *
 * NOTE: active mode STA may only serve as MPSP owner
 */
void ieee80211_mpsp_trigger_process(u8 *qc, struct sta_info *sta,
				    bool tx, bool acked)
{
	struct ieee80211_local *local = sta->sdata->local;
	u8 rspi = qc[1] & (IEEE80211_QOS_CTL_RSPI >> 8);
	u8 eosp = qc[0] & IEEE80211_QOS_CTL_EOSP;

	if (tx) {
		if (rspi && acked)
			set_sta_flag(sta, WLAN_STA_MPSP_RECIPIENT);

		if (eosp)
			clear_sta_flag(sta, WLAN_STA_MPSP_OWNER);
		else if (acked &&
			 test_sta_flag(sta, WLAN_STA_PS_STA) &&
			 !test_and_set_sta_flag(sta, WLAN_STA_MPSP_OWNER))
			mps_frame_deliver(sta, -1);
	} else {
		if (eosp)
			clear_sta_flag(sta, WLAN_STA_MPSP_RECIPIENT);
		else if (sta->local_pm != NL80211_MESH_POWER_ACTIVE)
			set_sta_flag(sta, WLAN_STA_MPSP_RECIPIENT);

		if (rspi && !test_and_set_sta_flag(sta, WLAN_STA_MPSP_OWNER))
			mps_frame_deliver(sta, -1);
	}

	if (!local->mps_enabled)
		return;

	if (!test_sta_flag(sta, WLAN_STA_MPSP_OWNER) &&
	    !test_sta_flag(sta, WLAN_STA_MPSP_RECIPIENT))
		mps_queue_work(sta->sdata, MESH_WORK_PS_DOZE);
}

/**
 * ieee80211_mps_frame_release - release frames buffered due to mesh power save
 *
 * @sta: mesh STA
 * @elems: IEs of beacon or probe response
 *
 * For peers if we have individually-addressed frames buffered or the peer
 * indicates buffered frames, send a corresponding MPSP trigger frame. Since
 * we do not evaluate the awake window duration, QoS Nulls are used as MPSP
 * trigger frames. If the neighbour STA is not a peer, only send single frames.
 */
void ieee80211_mps_frame_release(struct sta_info *sta,
				 struct ieee802_11_elems *elems)
{
	int ac, buffer_local = 0;
	bool has_buffered = false;

	/* TIM map only for LLID <= IEEE80211_MAX_AID */
	if (sta->plink_state == NL80211_PLINK_ESTAB)
		has_buffered = ieee80211_check_tim(elems->tim, elems->tim_len,
				le16_to_cpu(sta->llid) % IEEE80211_MAX_AID);

	if (has_buffered)
		mps_dbg(sta->sdata, "%pM indicates buffered frames\n",
			sta->sta.addr);

	/* only transmit to PS STA with announced, non-zero awake window */
	if (test_sta_flag(sta, WLAN_STA_PS_STA) &&
	    (!elems->awake_window || !le16_to_cpu(*elems->awake_window)))
		return;

	if (!test_sta_flag(sta, WLAN_STA_MPSP_OWNER))
		for (ac = 0; ac < IEEE80211_NUM_ACS; ac++)
			buffer_local += skb_queue_len(&sta->ps_tx_buf[ac]) +
					skb_queue_len(&sta->tx_filtered[ac]);

	if (!has_buffered && !buffer_local)
		return;

	if (sta->plink_state == NL80211_PLINK_ESTAB)
		mpsp_trigger_send(sta, has_buffered, !buffer_local);
	else
		mps_frame_deliver(sta, 1);
}


/* mesh PS driver configuration and doze scheduling */

static bool mps_hw_conf_check(struct ieee80211_local *local)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_mesh *ifmsh;
	bool enable = true;

	if (!local->ops->mesh_ps_doze)
		return false;

	mutex_lock(&local->iflist_mtx);
	list_for_each_entry(sdata, &local->interfaces, list) {
		if (!ieee80211_sdata_running(sdata))
			continue;

		/* disallow PS if an AP or any other non-mesh vif is found */
		if (ieee80211_sdata_running(sdata) &&
		    sdata->vif.type != NL80211_IFTYPE_MESH_POINT) {
			enable = false;
			break;
		}

		ifmsh = &sdata->u.mesh;

		/*
		 * Check for non-peer power mode and links in active mode.
		 * Assume a valid power mode for each established peer link.
		 */
		if (ifmsh->nonpeer_pm == NL80211_MESH_POWER_ACTIVE ||
		    ifmsh->ps_peers_light_sleep + ifmsh->ps_peers_deep_sleep
				< atomic_read(&ifmsh->estab_plinks)) {
			enable = false;
			break;
		}
	}
	mutex_unlock(&local->iflist_mtx);

	return enable;
}

/**
 * ieee80211_mps_hw_conf - check conditions for mesh PS and configure driver
 *
 * @local: mac80211 hw info struct
 */
void ieee80211_mps_hw_conf(struct ieee80211_local *local)
{
	bool enable;

	enable = mps_hw_conf_check(local);

	if (local->mps_enabled == enable)
		return;

	if (enable)
		local->hw.conf.flags |= IEEE80211_CONF_PS;
	else
		local->hw.conf.flags &= ~IEEE80211_CONF_PS;

	ieee80211_hw_config(local, IEEE80211_CONF_CHANGE_PS);
	local->mps_enabled = enable;

	/* we wait for peer beacons before doze */
}

static void mps_sta_nexttbtt_calc(struct sta_info *sta,
				  const struct ieee80211_tim_ie *tim,
				  u64 tsf_local)
{
	u64 tsf_peer;
	int skip = 1;
	u32 nexttbtt_interval;

	/* simple Deep Sleep implementation: only wake up for DTIM beacons */
	if (tim && sta->local_pm == NL80211_MESH_POWER_DEEP_SLEEP)
		skip = tim->dtim_count ? tim->dtim_count : tim->dtim_period;
	/*
	 * determine time to peer TBTT (TSF % beacon_interval = 0).
	 * This approach is robust to delayed beacons.
	 */
	tsf_peer = tsf_local + sta->t_offset;
	nexttbtt_interval = sta->beacon_interval * skip -
			do_div(tsf_peer, sta->beacon_interval * skip);

	mps_dbg(sta->sdata, "updating %pM next TBTT in %dus (%lldus awake)\n",
		sta->sta.addr, nexttbtt_interval,
		(long long) tsf_local - sta->nexttbtt_tsf);

	sta->nexttbtt_tsf = tsf_local + nexttbtt_interval;
	sta->nexttbtt_jiffies = jiffies + usecs_to_jiffies(nexttbtt_interval);
	mod_timer(&sta->nexttbtt_timer, sta->nexttbtt_jiffies +
			usecs_to_jiffies(BEACON_TIMEOUT));
}

/**
 * ieee80211_mps_sta_tbtt_update - update peer beacon wakeup schedule
 *
 * @sta: mesh STA
 * @mgmt: beacon frame
 * @tim: TIM IE of beacon frame
 */
void ieee80211_mps_sta_tbtt_update(struct sta_info *sta,
				   struct ieee80211_mgmt *mgmt,
				   const struct ieee80211_tim_ie *tim)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	u64 tsf_local;

	if (!sdata->local->mps_enabled ||
	    sta->plink_state != NL80211_PLINK_ESTAB)
		return;

	sta->beacon_interval = ieee80211_tu_to_usec(
			le16_to_cpu(mgmt->u.beacon.beacon_int));
	if (tim && tim->bitmap_ctrl & 0x01) /* multicasts after DTIM? */
		set_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_CAB);
	else
		clear_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_CAB);

	tsf_local = mgmt->u.beacon.timestamp - sta->t_offset;
	mps_sta_nexttbtt_calc(sta, tim, tsf_local);

	mps_queue_work(sdata, MESH_WORK_PS_DOZE);
}

/**
 * ieee80211_mps_sta_tbtt_timeout - timer callback for missed peer beacons
 */
void ieee80211_mps_sta_tbtt_timeout(unsigned long data)
{
	struct sta_info *sta = (void *) data;
	struct ieee80211_sub_if_data *sdata = sta->sdata;

	spin_lock_bh(&sta->lock);

	if (!sdata->local->mps_enabled ||
	    sta->plink_state != NL80211_PLINK_ESTAB) {
		spin_unlock_bh(&sta->lock);
		return;
	}

	sta->nexttbtt_tsf += sta->beacon_interval;
	sta->nexttbtt_jiffies += usecs_to_jiffies(sta->beacon_interval);
	mod_timer(&sta->nexttbtt_timer, sta->nexttbtt_jiffies +
			usecs_to_jiffies(BEACON_TIMEOUT));
	mps_queue_work(sdata, MESH_WORK_PS_DOZE);
	mps_dbg(sdata, "beacon miss %pM\n", sta->sta.addr);

	spin_unlock_bh(&sta->lock);
}

/**
 * ieee80211_mps_awake_window_start - start Awake Window on SWBA/PRETBTT
 *
 * @sdata: local mesh subif
 *
 * TODO called from ieee80211_beacon_get_tim as time reference for TBTT,
 * but mac80211 API guarantees neither exact timing nor periodicity
 */
void ieee80211_mps_awake_window_start(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	unsigned long timeout;

	if (!local->mps_enabled)
		return;

	mps_dbg(sdata, "awake window start (%dTU)\n",
		ifmsh->mshcfg.dot11MeshAwakeWindowDuration);

	timeout = jiffies + usecs_to_jiffies(ieee80211_tu_to_usec(
			ifmsh->mshcfg.dot11MeshAwakeWindowDuration));
	mod_timer(&ifmsh->awake_window_end_timer, timeout);
}

/**
 * ieee80211_mps_awake_window_end - timer callback for end of Awake Window
 */
void ieee80211_mps_awake_window_end(unsigned long data)
{
	struct ieee80211_sub_if_data *sdata = (void *) data;

	if (!sdata->local->mps_enabled)
		return;

	mps_dbg(sdata, "awake window end\n");
	mps_queue_work(sdata, MESH_WORK_PS_DOZE);
}

static bool mps_doze_check_vif(struct ieee80211_local *local)
{
	struct ieee80211_sub_if_data *sdata;
	bool allow = true;

	mutex_lock(&local->iflist_mtx);
	list_for_each_entry(sdata, &local->interfaces, list) {
		if (!ieee80211_sdata_running(sdata))
			continue;

		if (!ieee80211_vif_is_mesh(&sdata->vif) ||
		    timer_pending(&sdata->u.mesh.awake_window_end_timer)) {
			allow = false;
			break;
		}
	}
	mutex_unlock(&local->iflist_mtx);

	return allow;
}

static bool mps_doze_check_sta(struct ieee80211_local *local, u64 *nexttbtt)
{
	struct sta_info *sta;
	bool allow = true;
	u64 nexttbtt_min = ULLONG_MAX;

	mutex_lock(&local->sta_mtx);
	list_for_each_entry(sta, &local->sta_list, list) {
		if (!ieee80211_vif_is_mesh(&sta->sdata->vif) ||
		    !ieee80211_sdata_running(sta->sdata) ||
		    sta->plink_state != NL80211_PLINK_ESTAB) {
			continue;
		} else if (test_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_CAB) ||
			   test_sta_flag(sta, WLAN_STA_MPSP_OWNER) ||
			   test_sta_flag(sta, WLAN_STA_MPSP_RECIPIENT) ||
			   !timer_pending(&sta->nexttbtt_timer) ||
			   time_after(jiffies, sta->nexttbtt_jiffies)) {
			allow = false;
			break;
		} else if (sta->nexttbtt_tsf < nexttbtt_min) {
			nexttbtt_min = sta->nexttbtt_tsf;
		}
	}
	mutex_unlock(&local->sta_mtx);

	*nexttbtt = (nexttbtt_min != ULLONG_MAX ? nexttbtt_min : 0);

	return allow;
}

/**
 * ieee80211_mps_doze - trigger radio doze state after checking conditions
 *
 * @local: mac80211 hw info struct
 */
void ieee80211_mps_doze(struct ieee80211_local *local)
{
	u64 nexttbtt;

	if (!local->mps_enabled ||
	    !mps_doze_check_vif(local) ||
	    !mps_doze_check_sta(local, &nexttbtt))
		return;

	drv_mesh_ps_doze(local, nexttbtt);
}
