/*
 * Copyright (c) 2012 cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <asm/unaligned.h>
#include "ieee80211_i.h"
#include "mesh.h"
#include "mesh_11aa.h"


/**
 * ieee80211aa_set_seqnum - Set sequence number
 *
 * @sdata:     subif data
 * @mesh_hdr:  mesh_header
 * @da:        destination multicast address
 *
 * Returns: nothing
 *
 * This function is invoked in locally originated multicast traffic.  The
 * function checks if da is a broadcast or multicast address, and in that case
 * applies the sequence number for that type of traffic.  If not, the main
 * seqnum for unicast traffic is used.
 *
 */
void ieee80211aa_set_seqnum(struct ieee80211_sub_if_data *sdata,
			  struct ieee80211s_hdr *mesh_hdr, u8 *da)
{
	if (is_multicast_ether_addr(da))
		put_unaligned_le32(sdata->u.mesh.mesh_mseqnum++,
				   &mesh_hdr->seqnum);
	else
		put_unaligned_le32(sdata->u.mesh.mesh_seqnum++,
				   &mesh_hdr->seqnum);
}

static void set_mcast_list_on_mgmt(struct sk_buff *skb,
				   struct ieee80211_mgmt *mgmt,
				   struct netdev_hw_addr_list *mc_list)
{
	struct netdev_hw_addr *ha;
	int count = mc_list->count;
	u8 *pos;

	/* skb_put for mc_list */
	pos = skb_put(skb, ETH_ALEN * count);
	mgmt->u.action.u.robust_av_resp.address_count = count;

	list_for_each_entry(ha, &mc_list->list, list) {
		memcpy(pos, ha->addr, ETH_ALEN);
                pos += ETH_ALEN;
	}

}

int ieee80211aa_gcm_frame_tx(struct ieee80211_sub_if_data *sdata,
				    enum ieee80211_robust_av_actioncode action,
				    u8 *da, u8 dialog_token)
{
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;

	if (action == WLAN_AV_ROBUST_ACTION_GM_REQUEST) {
		int hdr_len = offsetof(struct ieee80211_mgmt,
				       u.action.u.robust_av_req) +
				       sizeof(mgmt->u.action.u.robust_av_req);

		skb = dev_alloc_skb(local->tx_headroom + hdr_len);
		if (!skb)
			return -1;

		skb_reserve(skb, local->tx_headroom);
		mgmt = (struct ieee80211_mgmt *) skb_put(skb, hdr_len);
		memset(mgmt, 0, hdr_len);
		mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
						  IEEE80211_STYPE_ACTION);
		memcpy(mgmt->da, da, ETH_ALEN);
		memcpy(mgmt->sa, sdata->vif.addr, ETH_ALEN);
		memcpy(mgmt->bssid, sdata->vif.addr, ETH_ALEN);
		mgmt->u.action.category = WLAN_CATEGORY_ROBUST_AV_STREAMING;
		mgmt->u.action.u.robust_av_req.action = action;

		while (mgmt->u.action.u.robust_av_req.dialog_token == 0)
			get_random_bytes(
				&mgmt->u.action.u.robust_av_req.dialog_token,
				sizeof(u8));

		ieee80211_tx_skb(sdata, skb);
		return 0;

	} else if (action == WLAN_AV_ROBUST_ACTION_GM_RESPONSE) {
		int hdr_len = offsetof(struct ieee80211_mgmt,
				       u.action.u.robust_av_resp) +
				       sizeof(mgmt->u.action.u.robust_av_resp);

		skb = dev_alloc_skb(local->tx_headroom +
				    hdr_len +
				    local->mc_list.count * ETH_ALEN);
		if (!skb)
			return -1;

		skb_reserve(skb, local->tx_headroom);
		mgmt = (struct ieee80211_mgmt *) skb_put(skb, hdr_len);
		memset(mgmt, 0, hdr_len);
		mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
						  IEEE80211_STYPE_ACTION);
		memcpy(mgmt->da, da, ETH_ALEN);
		memcpy(mgmt->sa, sdata->vif.addr, ETH_ALEN);
		memcpy(mgmt->bssid, sdata->vif.addr, ETH_ALEN);
		mgmt->u.action.category = WLAN_CATEGORY_ROBUST_AV_STREAMING;
		mgmt->u.action.u.robust_av_resp.action = action;
		mgmt->u.action.u.robust_av_resp.dialog_token = dialog_token;
		set_mcast_list_on_mgmt(skb, mgmt, &local->mc_list);

		ieee80211_tx_skb(sdata, skb);
		return 0;
	}
	return -1;
}

void ieee80211aa_rx_gcm_frame(struct ieee80211_sub_if_data *sdata,
			      struct ieee80211_mgmt *mgmt,
			      size_t len, struct ieee80211_rx_status *rx_status)
{
	struct sta_info *sta;

	/* need action_code, aux */
	if (len < IEEE80211_MIN_ACTION_SIZE)
		return;

	rcu_read_lock();

	sta = sta_info_get(sdata, mgmt->sa);
	if (!sta) {
		aa_dbg("GCast frame from unknown peer");
		rcu_read_unlock();
		return;
	}

	if (mgmt->u.action.u.robust_av_req.action ==
						WLAN_AV_ROBUST_ACTION_GM_REQUEST) {

		u8 dialog_token = mgmt->u.action.u.robust_av_req.dialog_token;

		/** If non-zero dialog token */
		if (dialog_token > 0)
			ieee80211aa_gcm_frame_tx(sdata,
						 WLAN_AV_ROBUST_ACTION_GM_RESPONSE,
						 sta->sta.addr,
						 dialog_token);
	} else if (mgmt->u.action.u.robust_av_resp.action ==
						WLAN_AV_ROBUST_ACTION_GM_RESPONSE) {
		/** For now just set gcm_enabled to true */
		if (!sta->gcm_enabled) {
			aa_dbg("%pM has GCM enabled", sta->sta.addr);
			sta->gcm_enabled = true;
		}
	}
	rcu_read_unlock();
}

static u16 calculate_window_start(u32 seqnum)
{
	/* By design the values window values are 64s multiples,
	 * so Wstart will be always 0, 64, 128, 192, 254 …
	 */
	int window_start = (seqnum / GCR_WIN_SIZE) * GCR_WIN_SIZE;
	return (u16)(window_start % 65536);
}

void ieee80211aa_set_sender(
		struct ieee80211_sub_if_data *sdata,
		struct rmc_entry *p, u32 seqnum)
{
	u16 window_start = calculate_window_start(seqnum);
	p->sender.s_window_start = window_start;
	p->sender.r_window_start = window_start;
	p->receiver.window_start = window_start;
	/* Fill with 1s*/
	bitmap_fill(p->sender.scoreboard,
		    GCR_WIN_SIZE);
	/* Fill with 0s */
	bitmap_zero(p->receiver.scoreboard,
		    GCR_WIN_SIZE_RCV);
}

void ieee80211_send_bar_gcr(struct ieee80211_sub_if_data *sdata, u8 *ra,
			    u8 *sa, u16 ssn)
{
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb;
	struct ieee80211_bar_gcr *bar;
	u16 bar_control = 0;

	skb = dev_alloc_skb(sizeof(*bar) + local->hw.extra_tx_headroom);
	if (!skb)
		return;

	skb_reserve(skb, local->hw.extra_tx_headroom);
	bar = (struct ieee80211_bar_gcr *)skb_put(skb, sizeof(*bar));
	memset(bar, 0, sizeof(*bar));
	bar->frame_control = cpu_to_le16(IEEE80211_FTYPE_CTL |
					 IEEE80211_STYPE_BACK_REQ);
	memcpy(bar->ra, ra, ETH_ALEN);
	memcpy(bar->ta, sdata->vif.addr, ETH_ALEN);
	bar_control |= (u16)IEEE80211_BAR_CTRL_ACK_POLICY_NORMAL;
	bar_control |= (u16)IEEE80211_BAR_CTRL_CBMTID_COMPRESSED_BA;
	bar_control |= (u16)IEEE80211_BAR_CTRL_GCR;
	bar->control = cpu_to_le16(bar_control);
	bar->start_seq_num = cpu_to_le16(ssn);
	memcpy(bar->gcr_ga, sa, ETH_ALEN);

	IEEE80211_SKB_CB(skb)->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT;
	ieee80211_tx_skb(sdata, skb);
}

void ieee80211_send_ba_gcr(struct ieee80211_sub_if_data *sdata, u8 *ra,
			   u8 *sa, u16 ssn, u64 bitmap)
{
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb;
	struct ieee80211_ba_gcr *ba;
	u16 ba_control = 0;

	skb = dev_alloc_skb(sizeof(*ba) + local->hw.extra_tx_headroom);
	if (!skb)
		return;

	skb_reserve(skb, local->hw.extra_tx_headroom);
	ba = (struct ieee80211_ba_gcr *)skb_put(skb, sizeof(*ba));
	memset(ba, 0, sizeof(*ba));
	ba->frame_control = cpu_to_le16(IEEE80211_FTYPE_CTL |
					 IEEE80211_STYPE_BACK);
	memcpy(ba->ra, ra, ETH_ALEN);
	memcpy(ba->ta, sdata->vif.addr, ETH_ALEN);
	/* TODO BAR -> BA */
	ba_control |= (u16)IEEE80211_BAR_CTRL_ACK_POLICY_NORMAL;
	ba_control |= (u16)IEEE80211_BAR_CTRL_CBMTID_COMPRESSED_BA;
	ba_control |= (u16)IEEE80211_BAR_CTRL_GCR;
	ba->control = cpu_to_le16(ba_control);
	ba->start_seq_num = cpu_to_le16(ssn);
	/* TODO for this first impl we use sa instead of da */
	memcpy(ba->gcr_ga, sa, ETH_ALEN);
	ba->bitmap = bitmap;

	IEEE80211_SKB_CB(skb)->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT;
	ieee80211_tx_skb(sdata, skb);
}

int ieee80211aa_send_bar(struct ieee80211_sub_if_data *sdata,
			  u8 *sa, u16 window_start)
{
	struct sta_info *sta;
	int count = 0;
	/* For each gcr enabled sta */
        rcu_read_lock();
        list_for_each_entry_rcu(sta, &sdata->local->sta_list, list) {
                if (sdata != sta->sdata ||
                    sta->gcm_enabled != true)
                        continue;
		aa_dbg("Sent BAR to %pM with Ws=%d",
			 sta->sta.addr,
			 window_start);

		ieee80211_send_bar_gcr(sdata,
				       sta->sta.addr,
				       sa,
				       window_start);
		count++;
	}
        rcu_read_unlock();
	return count;
}

void ieee80211aa_send_ba(struct ieee80211_sub_if_data *sdata,
			struct ieee80211aa_receiver *r, u8 *ta, u8 *sa)
{
	aa_dbg("BA request %d missing frames",
		 GCR_WIN_SIZE - bitmap_weight(r->scoreboard, GCR_WIN_SIZE));
	//aa_dbg("BA sent to %pM with Ws=%d sb[%lx]", ta, r->window_start, r->scoreboard[0]);
	/* Send a ba frame to the ta */
	ieee80211_send_ba_gcr(sdata, ta, sa, r->window_start, r->scoreboard[0]);
}

/* Data retransmission path */

bool ieee80211aa_retransmit_frame(struct ieee80211_sub_if_data *sdata,
				  u8 *sa, u16 req_sn)
{
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb, *tmp;
	struct ieee80211_hdr *hdr;
	struct ieee80211s_hdr *mesh_hdr;
	unsigned long flags;
	u16 seqnum;

	/* NACK is requesting one of our frames */
	spin_lock_irqsave(&local->mcast_rexmit_skb_queue.lock, flags);
	skb_queue_walk_safe(&local->mcast_rexmit_skb_queue, skb, tmp) {
		hdr = (struct ieee80211_hdr *) skb->data;
		mesh_hdr = (struct ieee80211s_hdr *) (skb->data +
				ieee80211_hdrlen(hdr->frame_control));
		/* TODO Check for errors
		 * we are doing a module 2^16 and
		 * collisions could happen if
		 * seq_num are close enough
		 */
		seqnum = (get_unaligned_le32(&mesh_hdr->seqnum) % 65536);


		/* Only if seqnum and sa matches */
		if (seqnum != req_sn ||
		    memcmp(sa, hdr->addr3, ETH_ALEN))
			continue;

		aa_dbg("*** on rtx: req_sn:%d seqnum:%d seqnun_mod:%d",
			 req_sn, get_unaligned_le32(&mesh_hdr->seqnum), seqnum);
		__skb_unlink(skb, &local->mcast_rexmit_skb_queue);
		ieee80211_tx_skb(sdata, skb);
		spin_unlock_irqrestore(&local->mcast_rexmit_skb_queue.lock, flags);
		return true;
	}
	spin_unlock_irqrestore(&local->mcast_rexmit_skb_queue.lock, flags);
	return false;
}

void ieee80211aa_retransmit(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211aa_sender *s, u8 *ga)
{
	int count;
	// Foreach bit set to 0 ask for retransmission
	int result = find_first_zero_bit(s->scoreboard, GCR_WIN_SIZE);
	count = 0;

	/* Only enter if at least one frame is missing */
	if (result < GCR_WIN_SIZE) {
		aa_dbg("BA contains %d missing frames",
			 GCR_WIN_SIZE - bitmap_weight(s->scoreboard, GCR_WIN_SIZE));

		while (result < GCR_WIN_SIZE) {
			u16 req_sn = s->r_window_start + result;
			if (ieee80211aa_retransmit_frame(sdata, ga, req_sn))
				count++;
			result = find_next_zero_bit(s->scoreboard, GCR_WIN_SIZE, result+1);

		}
		aa_dbg("BA caused %d retransmissions", count);
		/* Only if retransmissions took place */
		/* TODO Merge/Unify this code with the one at data frame tx */
		if (count > 0) {
			/* fill scoreboard with 1s */
			/* send bar to all stations */
			s->rcv_ba_count = 0;
			s->exp_rcv_ba = ieee80211aa_send_bar(
						sdata,
						ga,
						s->r_window_start);

			if (s->exp_rcv_ba > 0) {
				/* Overwrite scoreboard with 1s */
				bitmap_fill(s->scoreboard, GCR_WIN_SIZE);
				s->rtx_sn_thr = s->rtx_sn_thr + GCR_WIN_THRES;
				return;
			}
		}
	} /* No ba received and scoreboard is set to default value */
	else if (s->rcv_ba_count == 0 &&
		   bitmap_weight(s->scoreboard, GCR_WIN_SIZE) == GCR_WIN_SIZE) {
		aa_dbg("BA was lost... we request it again!");
		s->exp_rcv_ba = ieee80211aa_send_bar(
                                                sdata,
                                                ga,
                                                s->r_window_start);
		s->rtx_sn_thr = s->rtx_sn_thr + GCR_WIN_THRES;
		return;
	} /* All frames were received correctly disable expiration threshold */
	else if (s->rcv_ba_count >= s->exp_rcv_ba) {
			aa_dbg("All frames were correctly delivered ws %d",
			       s->r_window_start);
	}
	/* For all other cases we set to a non valid value */
	s->rtx_sn_thr = 0;
}

/* Data frame tx path */

void ieee80211aa_check_expired_rtx(struct ieee80211_sub_if_data *sdata,
				  struct rmc_entry *p, u32 seqnum)
{
	/* Only if threshold is different than 0 and has expired */
	if (p->sender.rtx_sn_thr != 0 &&
	    p->sender.rcv_ba_count < p->sender.exp_rcv_ba &&
	    seqnum > p->sender.rtx_sn_thr) {
		aa_dbg("BA expired sn:%d sn_thr:%d ws:%d thr:%d rcv:%d bitm:%d",
		       seqnum, p->sender.rtx_sn_thr, p->sender.r_window_start,
		       p->sender.exp_rcv_ba, p->sender.rcv_ba_count,
		       bitmap_weight(p->sender.scoreboard, GCR_WIN_SIZE));
		ieee80211aa_retransmit(sdata, &p->sender, p->sa);
	}
}

void ieee80211aa_data_frame_tx(
		struct ieee80211_sub_if_data *sdata,
		struct rmc_entry *p, u32 seqnum)
{
	if (seqnum >= p->sender.s_window_start + GCR_WIN_SIZE) {
		u16 window_start = calculate_window_start(seqnum);

		/* Overwrite info for re-tx */
		p->sender.rcv_ba_count = 0;
		p->sender.exp_rcv_ba = ieee80211aa_send_bar(
					sdata,
					p->sa,
					p->sender.s_window_start);


		if (p->sender.exp_rcv_ba > 0)
			/* We expect the response in less than N frames */
			p->sender.rtx_sn_thr = window_start + GCR_WIN_THRES;
		else
			/* zero is a non-valid threshold value */
			p->sender.rtx_sn_thr = 0;
		/* We expect to receive ba from this bar */
		p->sender.r_window_start = p->sender.s_window_start;
		/* Overwrite scoreboard with 1s*/
		bitmap_fill(p->sender.scoreboard, GCR_WIN_SIZE);
		/* We update sending window to next value */
		p->sender.s_window_start = window_start;
	}
	else {
		ieee80211aa_check_expired_rtx(sdata, p, seqnum);
	}
}

/* Data frame rx path */

void ieee80211aa_flush_scoreboard (struct ieee80211_sub_if_data *sdata,
				   struct ieee80211aa_receiver *r,
				   u16 window_start)
{
	/* |window_start = 0
	 * |W0.........W1..........|
	 * |window_start = 64
	 * |W1.........W2..........|
	 * |window_start = 128
	 * |W2.........W3..........|
	 */

	/* Calculate the number of bits we need shift */
	int shift = window_start - r->window_start;
	/* Should never happen... No shifting for negative values */
	if (shift <= 0)
		return;
	/* Right shift N positions */
	bitmap_shift_right(r->scoreboard, r->scoreboard, shift, GCR_WIN_SIZE_RCV);
	/* Store new window */
	r->window_start = window_start;
}

void ieee80211aa_data_frame_rx(
		struct ieee80211_sub_if_data *sdata,
		struct rmc_entry *p, u32 seqnum)
{

	if (seqnum >= p->receiver.window_start + GCR_WIN_SIZE_RCV) {
		/* Current scoreboard doesn't have access to this bit
 		 * Note:
		 * This is not very nice but in this case want to keep
 		 * at least a window of valuable data, this tries to...
 		 * */
		ieee80211aa_flush_scoreboard(sdata, &p->receiver,
			calculate_window_start(seqnum) - GCR_WIN_SIZE_RCV + GCR_WIN_SIZE);
	}

	set_bit(seqnum - p->receiver.window_start, p->receiver.scoreboard);
	//aa_dbg("sn: %d set bit %d sb:[%lx][%lx]", seqnum, seqnum - p->receiver.window_start, p->receiver.scoreboard[0], p->receiver.scoreboard[1]);
}

/* Handle BAR path */

void ieee80211aa_process_bar(struct ieee80211_sub_if_data *sdata,
				 struct rmc_entry *p, u8 *ta,
				 u8 *sa, u16 window_start)
{

	if (window_start >= p->receiver.window_start + GCR_WIN_SIZE) {
		aa_dbg("BAR received with new window_start %d previous was:%d",
			 window_start, p->receiver.window_start);
		ieee80211aa_flush_scoreboard(sdata, &p->receiver, window_start);
		ieee80211aa_send_ba(sdata, &p->receiver, ta, sa);
	} else if (window_start == p->receiver.window_start) {
		aa_dbg("BAR received in current window_start %d",
			 window_start);
		ieee80211aa_send_ba(sdata, &p->receiver, ta, sa);
	} else {
		aa_dbg("BAR discarded due old window_start: %d expected:%d",
			 window_start, p->receiver.window_start);
	}

}

bool ieee80211aa_handle_bar(struct ieee80211_sub_if_data *sdata,
			struct ieee80211_bar_gcr *bar)
{
	struct mesh_rmc *rmc = sdata->u.mesh.rmc;
	u8 idx;
	struct rmc_entry *p, *n;
	u16 window_start = le16_to_cpu(bar->start_seq_num);

	idx = (bar->gcr_ga[3] ^ bar->gcr_ga[4] ^ bar->gcr_ga[5]) & rmc->idx_mask;

	list_for_each_entry_safe(p, n, &rmc->bucket[idx].list, list) {
		spin_lock_bh(&p->lock);
		if (memcmp(bar->gcr_ga, p->sa, ETH_ALEN) == 0) {
			ieee80211aa_process_bar(sdata, p, bar->ta,
						    bar->gcr_ga, window_start);
			spin_unlock_bh(&p->lock);
			return true;
		}
		spin_unlock_bh(&p->lock);
	}
	return false;
}

/** Handle BA path */

void ieee80211aa_apply_ba_scoreboard(struct ieee80211_sub_if_data *sdata,
				      struct ieee80211aa_sender *s,
				      u8* ga, u64 bitmap)
{
	// XXX we update values here
	bitmap_and(s->scoreboard, s->scoreboard, (unsigned long int*) &bitmap, GCR_WIN_SIZE);
	s->rcv_ba_count++;

	/* Only retranmit if we got all expected ba's */
	if (s->rcv_ba_count >= s->exp_rcv_ba)
		ieee80211aa_retransmit(sdata, s, ga);
}

void ieee80211aa_process_ba(struct ieee80211_sub_if_data *sdata,
			    struct rmc_entry *p,
			    struct ieee80211_ba_gcr *ba,
			    u16 window_start)
{
	if (window_start < p->sender.r_window_start) {
		aa_dbg("BA discarded due old window_start %d expected %d",
			 window_start, p->sender.r_window_start);
		return;
	} else if (window_start > p->sender.r_window_start) {
		aa_dbg("BA discarded due future window_start %d expected %d",
			 window_start, p->sender.r_window_start);
		return;
	}
	aa_dbg("BA received in current window_start %d", window_start);
	ieee80211aa_apply_ba_scoreboard(sdata, &p->sender,
					ba->gcr_ga, ba->bitmap);
}

bool ieee80211aa_handle_ba(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_ba_gcr *ba) {
	struct mesh_rmc *rmc = sdata->u.mesh.rmc;
	u8 idx;
	struct rmc_entry *p, *n;
	u16 window_start = le16_to_cpu(ba->start_seq_num);

	idx = (ba->gcr_ga[3] ^ ba->gcr_ga[4] ^ ba->gcr_ga[5]) & rmc->idx_mask;

	list_for_each_entry_safe(p, n, &rmc->bucket[idx].list, list) {
		spin_lock_bh(&p->lock);
		if (memcmp(ba->gcr_ga, p->sa, ETH_ALEN) == 0) {
			ieee80211aa_process_ba(sdata, p, ba, window_start);
			spin_unlock_bh(&p->lock);
			return true;
		}
		spin_unlock_bh(&p->lock);
	}
	return false;
}
