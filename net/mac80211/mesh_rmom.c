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
#include "mesh_rmom.h"

/**
 * is_rmom_range_addr - Check if addr is RMoM range addr
 *
 * @addr:	Checked mac address
 *
 * Returns: true if is a RMoM address, false if not.
 *
 * This function checks for a valid RMoM address.
 */
bool is_rmom_range_addr(const u8 *addr)
{
	return !(addr[3] | addr[4] | addr[5]);
}

/**
 * mesh_rmom_setseqnum - Set sequence number
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
void mesh_rmom_set_seqnum(struct ieee80211_sub_if_data *sdata,
			  struct ieee80211s_hdr *mesh_hdr, u8 *da)
{
	if (is_multicast_ether_addr(da))
		put_unaligned_le32(sdata->u.mesh.mesh_mseqnum++,
				   &mesh_hdr->seqnum);
	else
		put_unaligned_le32(sdata->u.mesh.mesh_seqnum++,
				   &mesh_hdr->seqnum);
}

/**
 * mesh_rmom_tx_nack - TX a NAK frame for given seqnum
 *
 * @sdata: 	ieee80211 interface data
 * @hdr:	frame header for missing frame source
 * @seqnum:	sequence number of missing frame requested on the nak
 * @retry:	NACK retry value
 *
 * This function creates a NAK frame with given parameters.
 *
 */
static int mesh_rmom_tx_nack(struct ieee80211_sub_if_data *sdata,
			     struct ieee80211_hdr *hdr, u32 seqnum, u8 retry)
{
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	int len = offsetof(struct ieee80211_mgmt, u.action.u.mesh_rmom_nak) +
		sizeof(mgmt->u.action.u.mesh_rmom_nak);

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + len);

	if (!skb)
		return -1;

	skb_reserve(skb, local->hw.extra_tx_headroom);
	mgmt = (struct ieee80211_mgmt *) skb_put(skb, len);
	memset(mgmt, 0, len);
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					  IEEE80211_STYPE_ACTION_NO_ACK);
	memcpy(mgmt->da, hdr->addr1, ETH_ALEN);
	memcpy(mgmt->sa, sdata->vif.addr, ETH_ALEN);
	memcpy(mgmt->bssid, sdata->vif.addr, ETH_ALEN);
	mgmt->u.action.category = WLAN_CATEGORY_VENDOR_SPECIFIC;
	mgmt->u.action.u.mesh_rmom_nak.oid[0] = 0x4C;
	mgmt->u.action.u.mesh_rmom_nak.oid[1] = 0x22;
	mgmt->u.action.u.mesh_rmom_nak.oid[2] = 0x58;
	mgmt->u.action.u.mesh_rmom_nak.eid = 0xff;
	mgmt->u.action.u.mesh_rmom_nak.len = 0x11;
	mgmt->u.action.u.mesh_rmom_nak.missed_sn = cpu_to_le32(seqnum);
	mgmt->u.action.u.mesh_rmom_nak.retry = retry;
	memcpy(mgmt->u.action.u.mesh_rmom_nak.sa, hdr->addr3, ETH_ALEN);
	memcpy(mgmt->u.action.u.mesh_rmom_nak.ta, hdr->addr2, ETH_ALEN);

	ieee80211_tx_skb(sdata, skb);
	return 0;
}

/**
 * process_incoming_nack - Process an incoming NACK
 *
 * @sdata: 	ieee80211 interface data
 * @p:		rmc_entry for this sa
 * @seqnum:	sequence number of missing frame requested on the nak
 * @count:	retry counter for incoming NACK
 *
 * Returns:
 *	-1: duplicate NACK
 *	 0: OK, NACK tracked.
 *	 1: NACK retry limit reached
 *
 * This function is called everytime a nack is received, if entry exists it
 * gets updated, if not it's created and stored on the incoming nack list.
 */
static int process_incoming_nack(struct ieee80211_sub_if_data *sdata,
				 struct rmc_entry *p, u32 seqnum, u8 count)
{
	struct rmom_nack *nack;
	int ret = 0;
	u8 rmom_max_nack = sdata->u.mesh.mshcfg.dot11MeshRmomMaxRetries;

	spin_lock_bh(&p->in_nack_lock);
	list_for_each_entry(nack, &p->rmom.in.list, list) {
		if (nack->seqnum != seqnum)
			continue;

		if (count <= nack->count) {
			/* Old nack counter, ignore */
			ret = -1;
			goto out;
		}

		nack->count = count;
		if (nack->count == rmom_max_nack) {
			/* final transmission, stop tracking this */
			list_del(&nack->list);
			kfree(nack);
			ret = 1;
		}
		/* Retransmit and store frame */
		goto out;
	}
	spin_unlock_bh(&p->in_nack_lock);

	/* Nack seqnum not found: create new incoming nack */
	nack = kmalloc(sizeof(struct rmom_nack), GFP_ATOMIC);
	if (!nack)
		return -ENOMEM;
	nack->seqnum = seqnum;
	nack->count = count;

	/** Add the entry at the first position */
	spin_lock_bh(&p->in_nack_lock);
	list_add(&nack->list, &p->rmom.in.list);
out:
	spin_unlock_bh(&p->in_nack_lock);
	return ret;
}

/**
 * remove_incoming_nack - Removes an incoming nack entry
 *
 * @sdata: 	ieee80211 interface data
 * @p:		rmc_entry for this sa
 * @seqnum:	sequence number of missing frame requested on the nak
 *
 * Returns: True if removed, false if not
 *
 * Iterates the incoming nack list to remove any incoming
 * nack entry with given sequence number.
 */
bool remove_incoming_nack(struct ieee80211_sub_if_data *sdata,
			  struct rmc_entry *p, u32 seqnum)
{
	struct rmom_nack *nack;
	bool removed = false;

	spin_lock_bh(&p->in_nack_lock);
	list_for_each_entry(nack, &p->rmom.in.list, list) {
		if (nack->seqnum == seqnum) {
			list_del(&nack->list);
			kfree(nack);
			rmom_dbg("Removed an in nack entry in sn %x", seqnum);
			removed = true;
			break;
		}
	}
	spin_unlock_bh(&p->in_nack_lock);
	return removed;
}

/**
 * mesh_rmom_rx_nack - Process an incoming NACK for this stream
 *
 * @sdata: 	ieee80211 interface data
 * @p:		rmc_entry for this sa
 * @seqnum:	sequence number of missing frame requested on the nak
 *
 * Returns: Nothing
 *
 * This function is called when a NACK is received by a mesh interface,
 * if frame is saved on rmom queue, frames is dequeued and sent over the air.
 * If NACK is not for this TA, is expired, or we don't have the frame queued,
 * ignore it.
 */
void mesh_rmom_rx_nack(struct ieee80211_sub_if_data *sdata,
		       struct ieee80211_mgmt *mgmt,
		       struct rmc_entry *p)
{
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb, *tmp;
	struct ieee80211_hdr *hdr;
	struct ieee80211s_hdr *mesh_hdr;
	u32 nak_sn, seqnum;
	u8 retry;
	int ret;
	unsigned long flags;


	/* TODO: check for buffer (truncated frame) out of bounds access */
	nak_sn = le32_to_cpu(mgmt->u.action.u.mesh_rmom_nak.missed_sn);
	retry = mgmt->u.action.u.mesh_rmom_nak.retry;

	if (memcmp(mgmt->u.action.u.mesh_rmom_nak.ta, sdata->vif.addr, ETH_ALEN))
		/* If NAK is for another TA, just ignore it for now */
		return;

	/* NACK is requesting one of our frames */
	spin_lock_irqsave(&local->mcast_rexmit_skb_queue.lock, flags);
	skb_queue_walk_safe(&local->mcast_rexmit_skb_queue, skb, tmp) {
		struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
		hdr = (struct ieee80211_hdr *) skb->data;
		mesh_hdr = (struct ieee80211s_hdr *) (skb->data +
				ieee80211_hdrlen(hdr->frame_control));
		seqnum = get_unaligned_le32(&mesh_hdr->seqnum);

		/* Only if seqnum and sa matches */
		if (seqnum != nak_sn ||
		    memcmp(mgmt->u.action.u.mesh_rmom_nak.sa,
			   hdr->addr3, ETH_ALEN))
			continue;

		/* This frame is already waiting on final rexmit */
		if (info->flags & IEEE80211_TX_INTFL_RETRANSMISSION)
			break;

		ret = process_incoming_nack(sdata, p, seqnum, retry);

		/* old nack */
		if (ret < 0)
			break;

		if (ret == 1) {
			/* Retransmit the skb over the air
			 * but don't enqueue it anymore */
			IEEE80211_SKB_CB(skb)->flags |=
				IEEE80211_TX_INTFL_RETRANSMISSION;
		}
		rmom_dbg("Re-tx frame %x on retry %d (ret=%d)",
			 seqnum, retry, ret);
		__skb_unlink(skb, &local->mcast_rexmit_skb_queue);
		ieee80211_tx_skb(sdata, skb);
		break;
	}
	spin_unlock_irqrestore(&local->mcast_rexmit_skb_queue.lock, flags);
}

/*
 * add_outgoing_nack - Adds a nack entry to the queue
 *
 * @sdata: 	ieee80211 interface data
 * @p:		rmc_entry for this sa
 * @seqnum:	sequence number of missing frame requested on the nak
 *
 * Returns: 0 if correctly added.
 *
 * Adds an outgoing nack to the nack list
 */
static int add_outgoing_nack(struct ieee80211_sub_if_data *sdata,
			     struct rmc_entry *p, u32 seqnum)
{
	struct rmom_nack *nack;
	u8 rmom_expiry = sdata->u.mesh.mshcfg.dot11MeshRmomExpiryWindow;

	nack = kmalloc(sizeof(struct rmom_nack), GFP_ATOMIC);
	if (!nack)
		return -ENOMEM;
	/** TODO look for a valid offset for expiration */
	nack->seqnum = seqnum;
	nack->expiry_sn = p->rmom.exp_seqnum + rmom_expiry;
	nack->count = 1;

	/** Add the entry at the last position */
	list_add_tail(&nack->list, &p->rmom.out.list);

	return 0;
}

/**
 * process_outgoing_nack - Process an outgoing nack
 *
 * @sdata: 	ieee80211 interface data
 * @p:		rmc_entry for this sa
 * @hdr:	ieee80211 header
 *
 * Returns: Nothing
 *
 * Traverse the outgoing nack list, resend or remove NACKs as needed.
 */
static void process_outgoing_nack(struct ieee80211_sub_if_data *sdata,
				  struct rmc_entry *p,
				  struct ieee80211_hdr *hdr)
{
	struct rmom_nack *nack, *tmp;
	u8 rmom_max_nack = sdata->u.mesh.mshcfg.dot11MeshRmomMaxRetries;
	u8 rmom_expiry = sdata->u.mesh.mshcfg.dot11MeshRmomExpiryWindow;

	list_for_each_entry_safe(nack, tmp, &p->rmom.out.list, list) {
		/* As frames are ordered by expiration once we find
		 * the first non expired, we stop traversing the list */
		if (nack->expiry_sn > p->rmom.exp_seqnum)
			return;

		/* TODO: constant / mesh parameter */
		if (nack->count >= rmom_max_nack) {
			list_del(&nack->list);
			kfree(nack);
			continue;
		}

		/* Move expiry window */
		nack->expiry_sn = p->rmom.exp_seqnum + rmom_expiry;
		nack->count++;
		rmom_dbg("Sending retry NACK %d for sn %x",
			 nack->count, nack->seqnum);
		mesh_rmom_tx_nack(sdata, hdr, nack->seqnum, nack->count);
		list_move_tail(&nack->list, &p->rmom.out.list);
	}
}

/**
 * remove_outgoing_nack - removes a nack entry by seqnum
 *
 * @sdata: 	ieee80211 interface data
 * @p:		rmc_entry for this sa
 * @seqnum:	sequence number of missing frame requested on the nak
 *
 * Returns: Nothing
 *
 * Traverses the outgoing nack list and removes any entry that matches
 * the given sequence number.
 */
static void remove_outgoing_nack(struct ieee80211_sub_if_data *sdata,
				 struct rmc_entry *p, u32 seqnum)
{
	struct rmom_nack *nack;

	list_for_each_entry(nack, &p->rmom.out.list, list) {
		if (nack->seqnum != seqnum)
			continue;

		list_del(&nack->list);
		kfree(nack);
		rmom_dbg("Removed an out nack entry for sn %x", seqnum);
		return;
	}
}

/**
 * iterate_nack_range - Send NACKs for the range of missing seq numbers
 *
 * @sdata: 	ieee80211 interface data
 * @p:		RMC entry of mcast source
 * @hdr:	802.11 header
 * @range:	range of sequence numbers representing missing frames
 *
 * This function is invoked when frame loss is detected. The function
 * will requeste a NAK frame TX for each lost frame.
 */
static void iterate_nack_range(struct ieee80211_sub_if_data *sdata,
			       struct rmc_entry *p, struct ieee80211_hdr *hdr,
			       u32 *range)
{
	int i;

	for (i = range[0]; i <= range[1] ; i++) {
		add_outgoing_nack(sdata, p, i);
		mesh_rmom_tx_nack(sdata, hdr, i, 1);
	}
}

/*  updates exp seqnum and returns next values:
 *
 * @p:		RMC entry for this mcast source
 * @seqnum:	current frame sequence number
 * @range:	range of lost sequence numbers. Filled if nacks are required.
 *
 *  	0 if no losses or big jump detected (no further action).
 *  	1 losses are detected, nacks required.
 *  	2 old seqnum detected, update nack queue.
 *	-1 if any error
 */
static int update_exp_seqnum(struct ieee80211_sub_if_data *sdata,
			     struct rmc_entry *p, u32 seqnum, u32 *range)
{
	int ret = -1;
	u32 exp_seqnum = p->rmom.exp_seqnum;
	u8 rmom_max_jump = sdata->u.mesh.mshcfg.dot11MeshRmomMaxJump;

	if ((s32) (seqnum - exp_seqnum) < 0) {
		/* this is an old seqnum, don't update expected seqnum */
		rmom_dbg("old seqnum: %x < %x", seqnum, exp_seqnum);
		ret = 2;
	} else if (seqnum == exp_seqnum ||
		   (s32) (seqnum - exp_seqnum) > rmom_max_jump) {
		exp_seqnum = seqnum + 1;
		ret = 0;
	} else if ((s32) (seqnum - exp_seqnum) <= rmom_max_jump) {
		rmom_dbg("missed range: %x:%x", exp_seqnum, seqnum - 1);
		if (range) {
			range[0] = exp_seqnum;
			range[1] = seqnum - 1;
		}
		exp_seqnum = seqnum + 1;
		ret = 1;
	}

	p->rmom.exp_seqnum = exp_seqnum;
	BUG_ON(ret < 0);
	return ret;
}

/**
 * mesh_rmom_handle_frame - Detect losses and send NAKs
 *
 * @p:		RMC entry for frame mcast source
 * @hdr:	802.11 header of current frame
 * @mesh_hdr:	802.11 mesh header of current frame
 *
 * Detect sequence number jumps, and, if small trigger NACKs for the missing
 * frames.
 */
void mesh_rmom_handle_frame(struct ieee80211_sub_if_data *sdata,
			    struct rmc_entry *p, struct ieee80211_hdr *hdr,
		            struct ieee80211s_hdr *mesh_hdr)
{
	int ret;
	u32 seqnum;
	u32 range[2] = {};
	seqnum = get_unaligned_le32(&mesh_hdr->seqnum);

	ret = update_exp_seqnum(sdata, p, seqnum, range);

	/* If we detect missing frames */
	if (ret == 1 && is_rmom_range_addr(hdr->addr1))
		iterate_nack_range(sdata, p, hdr, range);
	/* If old frames are received */
	else if (ret == 2)
		remove_outgoing_nack(sdata, p, seqnum);

	/* We always check for any expired nack entry*/
	process_outgoing_nack(sdata, p, hdr);
}

static void set_mcast_list_on_mgmt(struct sk_buff *skb,
				   struct ieee80211_mgmt *mgmt,
				   struct netdev_hw_addr_list *mc_list)
{
	struct netdev_hw_addr *ha;
	int count = mc_list->count;
	u8 *pos;

	printk(KERN_DEBUG "mc_list=%d\n", count);

	/* skb_put for mc_list */
	pos = skb_put(skb, ETH_ALEN * count);
	mgmt->u.action.u.robust_av_resp.address_count = count;

	list_for_each_entry(ha, &mc_list->list, list) {
		printk(KERN_DEBUG "HW:%pM\n", ha->addr);
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
		printk(KERN_DEBUG "GCast frame from unknown peer\n");
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
			printk(KERN_DEBUG "%pM has GCM enabled\n", sta->sta.addr);
			sta->gcm_enabled = true;
		}
	}
	rcu_read_unlock();
}
