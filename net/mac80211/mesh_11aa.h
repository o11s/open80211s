/*
 * Copyright (c) 2012 cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef MESH_11AA_H
#define MESH_11AA_H

#include "ieee80211_i.h"

#ifdef CONFIG_MAC80211_11AA_DEBUG
#define aa_dbg(fmt, args...) \
	printk(KERN_DEBUG "11aa (%s): " fmt "\n", sdata->name, ##args)
#else
#define aa_dbg(fmt, args...)   do { (void)(0); } while (0)
#endif

/* ieee80211aa definitions */
#ifdef CONFIG_MAC80211_MESH_11AA
static inline bool ieee80211aa_enabled(void)
{
	return true;
}

int ieee80211aa_gcm_frame_tx(struct ieee80211_sub_if_data *sdata,
			     enum ieee80211_robust_av_actioncode action,
			     u8 *da, u8 dialog_token);
void ieee80211aa_rx_gcm_frame(struct ieee80211_sub_if_data *sdata,
			      struct ieee80211_mgmt *mgmt,
			      size_t len, struct ieee80211_rx_status *rx_status);
void ieee80211aa_init_struct(struct ieee80211_sub_if_data *sdata,
			    struct rmc_entry *p,
			    u32 seqnum);
bool ieee80211aa_handle_bar(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_bar_gcr *bar);
bool ieee80211aa_handle_ba(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_ba_gcr *ba);
void ieee80211aa_process_tx_data(struct ieee80211_sub_if_data *sdata,
			       struct rmc_entry *p, u32 seqnum);
void ieee80211aa_process_rx_data(struct ieee80211_sub_if_data *sdata,
			       struct rmc_entry *p, u32 seqnum);
void ieee80211aa_set_seqnum(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211s_hdr *mesh_hdr, u8 *da);
void ieee80211aa_check_expired_rtx(struct ieee80211_sub_if_data *sdata,
				   struct rmc_entry *p, u32 seqnum);
#else /* !CONFIG_MAC80211_MESH_11AA */
static inline bool ieee80211aa_enabled(void)
{
	return false;
}
static inline int ieee80211aa_gcm_frame_tx(struct ieee80211_sub_if_data *sdata,
			     enum ieee80211_robust_av_actioncode action,
			     u8 *da, u8 dialog_token)
{
	return 0;
}
static void ieee80211aa_rx_gcm_frame(struct ieee80211_sub_if_data *sdata,
			      struct ieee80211_mgmt *mgmt,
			      size_t len, struct ieee80211_rx_status *rx_status)
{
	return;
}
static inline void ieee80211aa_init_struct(struct ieee80211_sub_if_data *sdata,
			    struct rmc_entry *p,
			    u32 seqnum)
{
	return;
}
static inline bool ieee80211aa_handle_bar(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_bar_gcr *bar)
{
	return false;
}
static inline bool ieee80211aa_handle_ba(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_ba_gcr *ba)
{
	return false;
}
static inline void ieee80211aa_process_data_tx(struct ieee80211_sub_if_data *sdata,
			       struct rmc_entry *p, u32 seqnum)
{
	return;
}
static inline void ieee80211aa_process_data_rx(struct ieee80211_sub_if_data *sdata,
			       struct rmc_entry *p, u32 seqnum)
{
	return;
}
static inline void ieee80211aa_set_seqnum(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211s_hdr *mesh_hdr, u8 *da)
{
	return;
}
static inline void ieee80211aa_check_expired_rtx(
				struct ieee80211_sub_if_data *sdata,
				struct rmc_entry *p, u32 seqnum)
{
	return;
}
#endif /* !CONFIG_MAC80211_MESH_11AA */
#endif /* MESH_11AA_H */
