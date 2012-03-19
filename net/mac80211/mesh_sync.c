/*
 * Copyright 2011-2012, Pavel Zubarev <pavel.zubarev@gmail.com>
 * Copyright 2011-2012, Marco Porsch <marco.porsch@s2005.tu-chemnitz.de>
 * Copyright 2011-2012, cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "ieee80211_i.h"
#include "mesh.h"
#include "driver-ops.h"


struct sync_method {
	u8 method;
	struct ieee80211_mesh_sync_ops ops;
};

/**
 * mesh_peer_tbtt_adjusting - check if an mp is currently adjusting its TBTT
 *
 * @ie: information elements of a management frame from the mesh peer
 */
bool mesh_peer_tbtt_adjusting(struct ieee802_11_elems *ie)
{
	return (ie->mesh_config->meshconf_cap &
	    MESHCONF_CAPAB_TBTT_ADJUSTING) != 0;
}

void mesh_sync_offset_rx_bcn_presp(struct ieee80211_sub_if_data *sdata,
				   u16 stype,
				   struct ieee80211_mgmt *mgmt,
				   struct ieee802_11_elems *elems,
				   struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct ieee80211_local *local = sdata->local;
	struct sta_info *sta;
	u64 t_t, t_r;
	s64 t_offset;

	WARN_ON(ifmsh->mesh_sp_id != IEEE80211_SYNC_METHOD_NEIGHBOR_OFFSET);

	/* standard mentions only beacons */
	if (stype != IEEE80211_STYPE_BEACON)
		return;

	rcu_read_lock(); /* TODO use rcu_read_lock() or spin_lock(&sta->lock)? */
	sta = sta_info_get(sdata, mgmt->sa);
	if (!sta)
		goto no_sync;

	/* check offset sync conditions (11C.12.2.2.1)
	 *
	 * TODO also sync to
	 * dot11MeshNbrOffsetMaxNeighbor non-peer MBSS neighbors and
	 * dot11MeshNbrOffsetMaxNeighbor non-peer non-MBSS neighbors
	 */
	if (sta_plink_state(sta) != NL80211_PLINK_ESTAB) /* neighbor peer mesh STA */
		goto no_sync;

	if (elems->mesh_config && mesh_peer_tbtt_adjusting(elems)) { /* 11C.12.2.2.3 a) */
		printk(KERN_DEBUG "STA %pM : is adjusting TBTT",
			sta->sta.addr);

		goto no_sync;
	}

	/* get t_r, copied from ibss.c : ieee80211_rx_bss_info(...) */
	if (rx_status->flag & RX_FLAG_MACTIME_MPDU && rx_status->mactime) { /* bugfix: mactime is zero */
		/*
		 * Since mactime is defined as the time the first data symbol
		 * of the frame hits the PHY, and the timestamp of the beacon
		 * is defined as "the time that the data symbol containing the
		 * first bit of the timestamp is transmitted to the PHY plus
		 * the transmitting STA's delays through its local PHY from the
		 * MAC-PHY interface to its interface with the WM" (802.11
		 * 11.1.2)
		 * - equals the time this bit arrives at the receiver - we have
		 *   to take into account the offset between the two.
		 *
		 * E.g. at 1 MBit that means mactime is 192 usec earlier
		 * (=24 bytes * 8 usecs/byte) than the beacon timestamp.
		 */
		int rate;

		if (rx_status->flag & RX_FLAG_HT)
			rate = 65; /* TODO: HT rates */
		else
			rate = local->hw.wiphy->bands[rx_status->band]->
				bitrates[rx_status->rate_idx].bitrate;

		t_r = rx_status->mactime + (24 * 8 * 10 / rate);

		printk(KERN_DEBUG "STA %pM : calculated t_r=%lld, rate=%d, rx_status->mactime=%lld",
			sta->sta.addr,
			(unsigned long long) t_r,
			rate,
			(unsigned long long) rx_status->mactime);
	} else {
		/*
		 * second best option: get current TSF
		 * (will return -1 if not supported)
		 */
		t_r = drv_get_tsf(local, sdata);
	}

	/* Timing offset calculation (see 11C.12.2.2.2) */
	t_t = le64_to_cpu(mgmt->u.beacon.timestamp);
	t_offset = t_t - t_r;

	if (test_sta_flag(sta, WLAN_STA_TOFFSET_KNOWN)) { /* 11C.12.2.2.3 b) */
		s64 t_clockdrift = sta->t_offset - t_offset; /* 11C.12.2.2.3 c) */

		spin_lock_bh(&ifmsh->sync_offset_lock);
		if (t_clockdrift > ifmsh->sync_offset_clockdrift_max) /* 11C.12.2.2.3 d) */
			ifmsh->sync_offset_clockdrift_max = t_clockdrift;
		spin_unlock_bh(&ifmsh->sync_offset_lock);

		printk(KERN_DEBUG "STA %pM : t_r=%lld, t_t=%llu, t_offset=%lld, sta->t_offset=%lld, t_clockdrift=%lld",
			sta->sta.addr,
			(unsigned long long) t_r,
			(unsigned long long) t_t,
			(long long) t_offset,
			(long long) sta->t_offset,
			(long long) t_clockdrift);
	} else
		printk(KERN_DEBUG "STA %pM : offset was invalid, t_r=%lld, t_t=%llu, t_offset=%lld",
			sta->sta.addr,
			(unsigned long long) t_r,
			(unsigned long long) t_t,
			(long long) t_offset);

	/* store STA parameters for next beacon receipt */
	sta->t_offset = t_offset;
	set_sta_flag(sta, WLAN_STA_TOFFSET_KNOWN);

no_sync:
	rcu_read_unlock();
}

/**
 * see 11C.12.2.2.3
 *
 * called from beacon_get interrupt -> locking of
 * ifmsh->sync_offset_clockdrift_max needed
 */
void mesh_sync_offset_adjust_tbtt(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	u64 beacon_int_fraction = sdata->vif.bss_conf.beacon_int * 1024 / 2500; /* sdata->vif.bss_conf.beacon_int in 1024us units, 0.04% */
	u64 tsf;

	WARN_ON(ifmsh->mesh_sp_id != IEEE80211_SYNC_METHOD_NEIGHBOR_OFFSET);

	spin_lock_bh(&ifmsh->sync_offset_lock);

	if (ifmsh->sync_offset_clockdrift_max <= 0) {
		printk(KERN_DEBUG "TBTT : max clockdrift=%lld; no need to adjust",
			(long long) ifmsh->sync_offset_clockdrift_max);
		ifmsh->sync_offset_clockdrift_max = 0;
		spin_unlock_bh(&ifmsh->sync_offset_lock);
		ifmsh->adjusting_tbtt = false;
		return;
	}

	tsf = drv_get_tsf(local, sdata);

	if (ifmsh->sync_offset_clockdrift_max < beacon_int_fraction) {
		printk(KERN_DEBUG "TBTT : max clockdrift=%lld; adjusting",
			(long long) ifmsh->sync_offset_clockdrift_max);
		tsf += ifmsh->sync_offset_clockdrift_max;
		ifmsh->sync_offset_clockdrift_max = 0;
	} else {
		printk(KERN_DEBUG "TBTT : max clockdrift=%lld; adjusting by %llu",
			(long long) ifmsh->sync_offset_clockdrift_max,
			(unsigned long long) beacon_int_fraction);
		tsf += beacon_int_fraction;
		ifmsh->sync_offset_clockdrift_max -= beacon_int_fraction;
	}

	drv_set_tsf(local, sdata, tsf);
	ifmsh->adjusting_tbtt = true;
	spin_unlock_bh(&ifmsh->sync_offset_lock);
}

void mesh_sync_offset_add_vendor_ie(struct sk_buff *skb, struct ieee80211_sub_if_data *sdata)
{
	WARN_ON(sdata->u.mesh.mesh_sp_id != IEEE80211_SYNC_METHOD_NEIGHBOR_OFFSET);
	/* neighbor offset sync does not need an additional IE */
}

void mesh_sync_vendor_rx_bcn_presp(struct ieee80211_sub_if_data *sdata,
				   u16 stype,
				   struct ieee80211_mgmt *mgmt,
				   struct ieee802_11_elems *elems,
				   struct ieee80211_rx_status *rx_status)
{
	WARN_ON(sdata->u.mesh.mesh_sp_id != IEEE80211_SYNC_METHOD_VENDOR);
	printk(KERN_DEBUG "called mesh_sync_vendor_rx_bcn_presp");
}

void mesh_sync_vendor_adjust_tbtt(struct ieee80211_sub_if_data *sdata)
{
	WARN_ON(sdata->u.mesh.mesh_sp_id != IEEE80211_SYNC_METHOD_VENDOR);
	printk(KERN_DEBUG "called mesh_sync_vendor_adjust_tbtt");
}

void mesh_sync_vendor_add_vendor_ie(struct sk_buff *skb, struct ieee80211_sub_if_data *sdata)
{
	WARN_ON(sdata->u.mesh.mesh_sp_id != IEEE80211_SYNC_METHOD_VENDOR);
	printk(KERN_DEBUG "called mesh_sync_vendor_add_vendor_ie");
}

/* global variable */
static struct sync_method sync_methods[] = {
	{
		.method = IEEE80211_SYNC_METHOD_NEIGHBOR_OFFSET,
		.ops = {
			.rx_bcn_presp = &mesh_sync_offset_rx_bcn_presp,
			.adjust_tbtt = &mesh_sync_offset_adjust_tbtt,
			.add_vendor_ie = &mesh_sync_offset_add_vendor_ie,
		}
	},
	{
		.method = IEEE80211_SYNC_METHOD_VENDOR,
		.ops = {
			.rx_bcn_presp = &mesh_sync_vendor_rx_bcn_presp,
			.adjust_tbtt = &mesh_sync_vendor_adjust_tbtt,
			.add_vendor_ie = &mesh_sync_vendor_add_vendor_ie,
		}
	},
};

struct ieee80211_mesh_sync_ops *ieee80211_mesh_sync_ops_get(u8 method)
{
	struct ieee80211_mesh_sync_ops *ops = NULL;
	u8 i;

	for (i = 0 ; i < ARRAY_SIZE(sync_methods); ++i) {
		if (sync_methods[i].method == method) {
			ops = &sync_methods[i].ops;
			break;
		}
	}
	return ops;
}
