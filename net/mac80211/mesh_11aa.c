/*
 * Copyright (c) 2012 cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <asm/unaligned.h>
#include "ieee80211_i.h"
#include "mesh.h"
#include "mesh_11aa.h"

bool aa_allocated = false;
static struct kmem_cache *aa_cache;

void ieee80211aa_init(void)
{
	if (!aa_allocated) {
		aa_allocated = true;
		aa_cache = kmem_cache_create("aa_mc", sizeof(struct aa_entry),
					     0, SLAB_POISON | SLAB_RED_ZONE,
					     NULL);
		printk(KERN_DEBUG "aa_mc mem cache created");
	}
}

void ieee80211aa_stop(void)
{
	if (!aa_allocated)
		return;

	kmem_cache_destroy(aa_cache);
	aa_allocated = false;
}

int ieee80211aa_mcc_init(struct ieee80211_sub_if_data *sdata)
{
	int i;

	sdata->u.mesh.aamc = kmalloc(sizeof(struct aa_mc), GFP_KERNEL);
	if (!sdata->u.mesh.aamc) {
		WARN_ON(1);
		return -ENOMEM;
	}
	sdata->u.mesh.aamc->idx_mask = AA_BUCKETS - 1;
	for (i = 0; i < AA_BUCKETS; i++) {
		INIT_LIST_HEAD(&sdata->u.mesh.aamc->bucket[i]);
		spin_lock_init(&sdata->u.mesh.aamc->bucket_lock[i]);
	}
	return 0;

}

void ieee80211aa_mcc_free(struct ieee80211_sub_if_data *sdata)
{
	struct aa_mc *aamc = sdata->u.mesh.aamc;
	struct aa_entry *p, *n;
	int i;

	if(WARN_ON(!aa_allocated || !aamc))
		return;

	for (i = 0; i < AA_BUCKETS; i++)
		list_for_each_entry_safe(p, n, &aamc->bucket[i], list) {
			aa_dbg("baleeting list entry %p in bucket %d", &p->list, i);
			aa_dbg("pointers next: %p, prev: %p", p->list.next, p->list.prev);
			list_del(&p->list);
			kmem_cache_free(aa_cache, p);
		}

	kfree(aamc);
	sdata->u.mesh.aamc = NULL;
}

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
		/* XXX: BA and BARs only have 16 bits for starting seq no. Fix
		 * this properly by handling the translation in the 11aa / 11n
		 * aggregation code. */
		put_unaligned_le32((sdata->u.mesh.mesh_mseqnum++) % 65536,
				   &mesh_hdr->seqnum);
	else
		put_unaligned_le32(sdata->u.mesh.mesh_seqnum++,
				   &mesh_hdr->seqnum);
}

static void ieee80211aa_set_mc_list(struct sk_buff *skb,
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
		ieee80211aa_set_mc_list(skb, mgmt, &local->mc_list);

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

void ieee80211aa_init_struct(struct ieee80211_sub_if_data *sdata,
			     struct aa_entry *p, u32 seqnum)
{
	u16 window_start = calculate_window_start(seqnum);
	p->sender.curr_win = window_start;
	p->sender.prev_win = window_start;
	spin_lock_init(&p->sender.lock);
	/* Fill with 1s*/
	bitmap_fill(p->sender.scoreboard, GCR_WIN_SIZE);

	p->receiver.window_start = window_start;
	/* Fill with 0s */
	bitmap_zero(p->receiver.scoreboard, GCR_WIN_SIZE_RCV);
	aa_dbg("ieee80211aa_init_struct %pM", p->sa);
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

int ieee80211aa_send_bar_to_known_sta(struct ieee80211_sub_if_data *sdata,
				      u8 *sa, u16 window_start)
{
	struct sta_info *sta;
	int count = 0;
	/* For each gcr enabled sta */
        rcu_read_lock();
        list_for_each_entry_rcu(sta, &sdata->local->sta_list, list) {
                if (sdata != sta->sdata ||
                    sta->gcm_enabled != true ||
		    ether_addr_equal(sta->sta.addr, sa))
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

static void ieee80211aa_send_bar(struct ieee80211_sub_if_data *sdata,
				 struct ieee80211aa_sender *s, u8 *sa,
				 u16 window_start, u32 sn_thr)
{
	int exp_bas;

	exp_bas = ieee80211aa_send_bar_to_known_sta(sdata, sa, window_start);

	spin_lock_bh(&s->lock);
	s->rcv_bas = 0;
	s->exp_bas = exp_bas;
	s->ba_expire = sn_thr + GCR_WIN_THRES;

	/* Fill scoreboard with 1s */
	bitmap_fill(s->scoreboard, GCR_WIN_SIZE);
	s->prev_win = window_start;
	spin_unlock_bh(&s->lock);
}

void ieee80211aa_send_ba(struct ieee80211_sub_if_data *sdata,
			 struct ieee80211aa_receiver *r, u8 *ta, u8 *sa)
{
	aa_dbg("BA request %d missing frames",
		 GCR_WIN_SIZE - bitmap_weight(r->scoreboard, GCR_WIN_SIZE));
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
	u16 seqnum;

	/* TODO: Take a current scoreboard and window_start, and queue all
	 * outstanding frames up at once */
	skb_queue_walk_safe(&sdata->mcast_rexmit_skb_queue, skb, tmp) {
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
		    !ether_addr_equal(sa, hdr->addr3))
			continue;

		skb_unlink(skb, &sdata->mcast_rexmit_skb_queue);
		ieee80211_add_pending_skb(local, skb);
		return true;
	}
	return false;
}

/* retransmit outstanding frames from sender */
void ieee80211aa_retransmit(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211aa_sender *s, u8 *ga)
{
	int frames, frame_n;

	/* for each bit set to 0 ask for retransmission */
	frame_n = find_first_zero_bit(s->scoreboard, GCR_WIN_SIZE);
	frames = 0;

	/* will be GCR_WIN_SIZE if no zero bits found */
	if (frame_n < GCR_WIN_SIZE) {
		aa_dbg("BA contains %d missing frames",
		       GCR_WIN_SIZE -
		       bitmap_weight(s->scoreboard, GCR_WIN_SIZE));

		while (frame_n < GCR_WIN_SIZE) {
			u16 req_sn = s->prev_win + frame_n;
			if (ieee80211aa_retransmit_frame(sdata, ga, req_sn))
				frames++;
			frame_n = find_next_zero_bit(s->scoreboard,
						     GCR_WIN_SIZE, frame_n + 1);
		}
	}

	if (frames || s->rcv_bas != s->exp_bas) {
		/* need BAs */
		ieee80211aa_send_bar(sdata, s, ga, s->prev_win, s->ba_expire);
		return;
	} else {
		/* we're done for this window */
		aa_dbg("All frames delivered for window %d", s->prev_win);
		spin_lock_bh(&s->lock);
		s->exp_bas = 0;
		spin_unlock_bh(&s->lock);
	}
}

void ieee80211aa_check_expired_rtx(struct ieee80211_sub_if_data *sdata,
				  struct aa_entry *p, u32 seqnum)
{
	struct ieee80211aa_sender *s = &p->sender;

	/* time to retransmit if necessary */
	if (s->exp_bas && seqnum > s->ba_expire) {
		aa_dbg("BA expired sn:%d sn_thr:%d ws:%d req:%d rcv:%d bitm:%d",
		       seqnum, s->ba_expire, s->prev_win,
		       s->exp_bas, s->rcv_bas,
		       bitmap_weight(s->scoreboard, GCR_WIN_SIZE));
		ieee80211aa_retransmit(sdata, s, p->sa);
	}
}

void ieee80211aa_process_tx_data(struct ieee80211_sub_if_data *sdata,
				 struct aa_entry *p, u32 seqnum)
{
	struct ieee80211aa_sender *s = &p->sender;

	/* did we just finish or roll over a window? */
	if (seqnum >= s->curr_win + GCR_WIN_SIZE ||
	    seqnum + GCR_WIN_SIZE < s->curr_win) {
		u16 window_start = calculate_window_start(seqnum);
		ieee80211aa_send_bar(sdata, s, p->sa,
				     s->curr_win, s->ba_expire);
		/* new window */
		spin_lock_bh(&p->sender.lock);
		s->curr_win = window_start;
		spin_unlock_bh(&p->sender.lock);
	}
}

/* Data frame rx path */
void ieee80211aa_flush_scoreboard(struct ieee80211_sub_if_data *sdata,
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
	/* if the sequence numbers rolled over */
	if (shift <= 0 || shift > GCR_WIN_SIZE_RCV)
		shift = GCR_WIN_SIZE_RCV;

	/* left shift N positions */
	bitmap_shift_left(r->scoreboard, r->scoreboard,
			  shift, GCR_WIN_SIZE_RCV);
	/* Store new window */
	r->window_start = window_start;
}

void ieee80211aa_process_rx_data(struct ieee80211_sub_if_data *sdata,
				 struct aa_entry *p, u32 seqnum)
{
	struct ieee80211aa_receiver *r = &p->receiver;

	if (seqnum >= r->window_start + GCR_WIN_SIZE ||
	    seqnum + GCR_WIN_SIZE < r->window_start) {
		/* shift scoreboard to match the old sender window */
		u16 ws = calculate_window_start(seqnum - GCR_WIN_SIZE);
		ieee80211aa_flush_scoreboard(sdata, r, ws);
	}

	/* shouldn't happen */
	if (WARN_ON(seqnum - r->window_start > GCR_WIN_SIZE_RCV))
		return;

	set_bit(seqnum - r->window_start, r->scoreboard);
}

/* Handle BAR path - process BAR frame
 *
 * return true if BA needs to be sent.
 */
bool ieee80211aa_process_bar(struct ieee80211_sub_if_data *sdata,
			     struct aa_entry *p, u8 *ta,
			     u8 *sa, u16 window_start)
{
	struct ieee80211aa_receiver *r = &p->receiver;

	if (window_start >= r->window_start + GCR_WIN_SIZE ||
	    window_start + GCR_WIN_SIZE < r->window_start) {
		aa_dbg("BAR received with new window_start %d previous was:%d",
			 window_start, r->window_start);
		ieee80211aa_flush_scoreboard(sdata, r, window_start);
		return true;
	} else if (window_start == r->window_start) {
		aa_dbg("BAR received in current window_start %d",
			 window_start);
		return true;
	}
	aa_dbg("BAR discarded due old window_start: %d expected:%d",
	       window_start, r->window_start);
	return false;
}

void ieee80211aa_handle_bar(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_bar_gcr *bar)
{
	struct aa_mc *aamc = sdata->u.mesh.aamc;
	u8 idx;
	struct aa_entry *p;
	bool tx = false;
	u16 window_start = le16_to_cpu(bar->start_seq_num);

	if (WARN_ON(!aamc))
		return;

	idx = (bar->gcr_ga[3] ^ bar->gcr_ga[4] ^ bar->gcr_ga[5]) & aamc->idx_mask;

	spin_lock_bh(&aamc->bucket_lock[idx]);
	list_for_each_entry(p, &aamc->bucket[idx], list) {
		if (!ether_addr_equal(bar->gcr_ga, p->sa))
			continue;

		tx = ieee80211aa_process_bar(sdata, p, bar->ta,
					    bar->gcr_ga, window_start);
		if (tx)
			ieee80211aa_send_ba(sdata, &p->receiver, bar->ta,
					    bar->gcr_ga);
		break;
	}
	spin_unlock_bh(&aamc->bucket_lock[idx]);
}

/** Handle BA path */

/**
 * ieee80211aa_apply_ba_scoreboard - Applies recieved BA scoreboard
 *
 * @sdata:     subif data
 * @s:	       802.1aa sender info
 * @ga:        group address
 * @bitmap:    BA scoreboard
 *
 * Returns: true if all expected ba have been received, false if not.
 *
 * This function is invoked after the reception of a BA. The
 * function applies the given scoreboard and checks if all requested
 * BA's have been received.
 *
 */
bool ieee80211aa_apply_ba_scoreboard(struct ieee80211_sub_if_data *sdata,
				     struct ieee80211aa_sender *sender,
				     u8* ga, u64 bitmap)
{
	spin_lock_bh(&sender->lock);
	bitmap_and(sender->scoreboard, sender->scoreboard,
		   (unsigned long *) &bitmap, GCR_WIN_SIZE);
	sender->rcv_bas++;
	spin_unlock_bh(&sender->lock);

	/* all BAs received, retx */
	if (sender->rcv_bas == sender->exp_bas)
		return true;
	return false;
}

/* returns true if all BAs were received */
bool ieee80211aa_process_ba(struct ieee80211_sub_if_data *sdata,
			    struct aa_entry *p,
			    struct ieee80211_ba_gcr *ba,
			    u16 window_start)
{
	if (window_start < p->sender.prev_win) {
		aa_dbg("BA discarded due old window_start %d expected %d",
			 window_start, p->sender.prev_win);
		return false;
	} else if (window_start > p->sender.prev_win) {
		aa_dbg("BA discarded due future window_start %d expected %d",
			 window_start, p->sender.prev_win);
		return false;
	}
	aa_dbg("BA received in current window_start %d", window_start);
	return ieee80211aa_apply_ba_scoreboard(sdata, &p->sender,
					ba->gcr_ga, ba->bitmap);
}

void ieee80211aa_handle_ba(struct ieee80211_sub_if_data *sdata,
			   struct ieee80211_ba_gcr *ba)
{
	struct aa_mc *aamc = sdata->u.mesh.aamc;
	u8 idx;
	struct aa_entry *p;
	u16 window_start = le16_to_cpu(ba->start_seq_num);
	bool retx = false;

	if (WARN_ON(!aamc))
		return;

	idx = (ba->gcr_ga[3] ^ ba->gcr_ga[4] ^ ba->gcr_ga[5]) & aamc->idx_mask;

	spin_lock_bh(&aamc->bucket_lock[idx]);
	list_for_each_entry(p, &aamc->bucket[idx], list) {
		if (!ether_addr_equal(ba->gcr_ga, p->sa))
			continue;

		retx = ieee80211aa_process_ba(sdata, p, ba, window_start);
		/* After process the bar, retx if necessary  */
		if (retx)
			ieee80211aa_retransmit(sdata, &p->sender, ba->gcr_ga);
		break;
	}
	spin_unlock_bh(&aamc->bucket_lock[idx]);
}

void ieee80211aa_check_tx(struct ieee80211_sub_if_data *sdata,
			  u8 *sa, u32 seqnum)
{
	struct aa_mc *aamc = sdata->u.mesh.aamc;
	u8 idx;
	struct aa_entry *p;

	if (WARN_ON(!aamc))
		return;

	idx = (sa[3] ^ sa[4] ^ sa[5]) & aamc->idx_mask;

	spin_lock_bh(&aamc->bucket_lock[idx]);
	list_for_each_entry(p, &aamc->bucket[idx], list) {
		if (!ether_addr_equal(sa, p->sa))
			continue;
		ieee80211aa_process_tx_data(sdata, p, seqnum);
		ieee80211aa_check_expired_rtx(sdata, p, seqnum);
		goto unlock;
	}
	/* If it doesn't exist just create the entry */
	p = kmem_cache_alloc(aa_cache, GFP_ATOMIC);
	if (!p)
		goto unlock;

	memcpy(p->sa, sa, ETH_ALEN);
	ieee80211aa_init_struct(sdata, p, seqnum);
	list_add(&p->list, &aamc->bucket[idx]);
unlock:
	spin_unlock_bh(&aamc->bucket_lock[idx]);
}

void ieee80211aa_check_rx(struct ieee80211_sub_if_data *sdata,
		       u8 *sa, u32 seqnum) {
	struct aa_mc *aamc = sdata->u.mesh.aamc;
	u8 idx;
	struct aa_entry *p;

	if (WARN_ON(!aamc))
		return;

	idx = (sa[3] ^ sa[4] ^ sa[5]) & aamc->idx_mask;

	spin_lock_bh(&aamc->bucket_lock[idx]);
	list_for_each_entry(p, &aamc->bucket[idx], list) {
		if (!ether_addr_equal(sa, p->sa))
			continue;

		ieee80211aa_process_rx_data(sdata, p, seqnum);
		goto unlock;
	}
	/* If it doesn't exist just create the entry */
	p = kmem_cache_alloc(aa_cache, GFP_ATOMIC);
	if (!p)
		goto unlock;

	memcpy(p->sa, sa, ETH_ALEN);
	ieee80211aa_init_struct(sdata, p, seqnum);
	list_add(&p->list, &aamc->bucket[idx]);
unlock:
	spin_unlock_bh(&aamc->bucket_lock[idx]);
}

/**
 * ieee80211aa_handle_tx_skb - queue frame for retransmission
 *
 * Will clone and enqueue the given skb for retransmission, and bump off any
 * old frames if the queue grows too long.
 */
void ieee80211aa_handle_tx_skb(struct ieee80211_local *local,
			       struct sk_buff *skb)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_tx_info *info;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	__le16 fc = hdr->frame_control;
	int hdrlen = ieee80211_hdrlen(hdr->frame_control);
	struct ieee80211s_hdr *mesh_hdr = (struct ieee80211s_hdr *) (skb->data + hdrlen);

	if (!(ieee80211aa_enabled() && skb->dev && skb->dev->ieee80211_ptr &&
	    skb->dev->ieee80211_ptr->iftype == NL80211_IFTYPE_MESH_POINT &&
	    is_multicast_ether_addr(hdr->addr1) && ieee80211_is_data_qos(fc) &&
	    !is_broadcast_ether_addr(hdr->addr1)))
		return;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (WARN_ON(!skb))
		return;
	info = IEEE80211_SKB_CB(skb);

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &local->interfaces, list) {
		if (!ieee80211_sdata_running(sdata) ||
		    !ieee80211_vif_is_mesh(&sdata->vif) ||
		    !ether_addr_equal(hdr->addr2, sdata->vif.addr))
			continue;
		/* This will be called only on the original tx */
		if (!(info->flags & IEEE80211_TX_INTFL_RETRANSMISSION)) {
			ieee80211aa_check_tx(sdata, hdr->addr3,
				     le32_to_cpu(get_unaligned(&mesh_hdr->seqnum)));
			info->flags |= IEEE80211_TX_INTFL_RETRANSMISSION;
		}
		break;
	}

	/* huh? */
	if (WARN_ON(!sdata))
		goto out;

	/* XXX: garbage, the txinfo.control was overwritten by status, so
	 * proper fix is to call this function from the tx path. */
	memset(&info->control, 0, sizeof(info->control));
	info->control.jiffies = jiffies;
	info->control.vif = &sdata->vif;
	info->flags |= IEEE80211_TX_INTFL_NEED_TXPROCESSING;

	/* re-queue it in either case since even a retransmission might fail */
	skb_queue_tail(&sdata->mcast_rexmit_skb_queue, skb);
	if (sdata->mcast_rexmit_skb_queue.qlen > sdata->mcast_rexmit_skb_max_size) {
		skb = skb_dequeue(&sdata->mcast_rexmit_skb_queue);
		dev_kfree_skb(skb);
	}
out:
	rcu_read_unlock();
}
