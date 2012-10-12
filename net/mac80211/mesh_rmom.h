/*
 * Copyright (c) 2012 cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef MESH_RMOM_H
#define MESH_RMOM_H

#ifdef CONFIG_MAC80211_RMOM_DEBUG
#define rmom_dbg(fmt, args...) \
	printk(KERN_DEBUG "RMoM (%s): " fmt "\n", sdata->name, ##args)
#else
#define rmom_dbg(fmt, args...)   do { (void)(0); } while (0)
#endif

/*
#define RMOM_MAX_FLOWS 8
#define RMOM_MAX_JUMP 8
#define RMOM_MAX_FIFO_SIZE ( RMOM_MAX_JUMP * RMOM_MAX_FLOWS )
#define RMOM_MAX_NACK_RETRIES 5
#define RMOM_EXPIRY_WINDOW_SIZE 8
*/


int mesh_rmom_cache_init(struct ieee80211_sub_if_data *sdata);
bool is_rmom_range_addr(const u8 *da);
void mesh_rmom_set_seqnum(struct ieee80211_sub_if_data *sdata,
			  struct ieee80211s_hdr *mesh_hdr, u8 *da);
void mesh_rmom_handle_frame(struct ieee80211_sub_if_data *sdata,
			    struct rmc_entry *p, struct ieee80211_hdr *hdr,
			    struct ieee80211s_hdr *mesh_hdr);
bool remove_incoming_nack(struct ieee80211_sub_if_data *sdata,
			  struct rmc_entry *p, u32 seqnun);
void mesh_rmom_rx_nack(struct ieee80211_sub_if_data *sdata,
		       struct ieee80211_mgmt *mgmt, struct rmc_entry *p);
#endif /* MESH_RMOM_H */
