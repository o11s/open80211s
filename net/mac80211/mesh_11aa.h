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

/* time before which last outstanding BA must be received or retrigger BAR */
#define AA_BA_TIMEOUT	500	/* us */
/* 11aa multicast cache */
/* AA_BUCKETS must be a power of 2, maximum 256 */
#define AA_BUCKETS		256

/* ieee80211aa required fields */

#define GCR_WIN_SIZE 64 /* Fixed to 64 positions by protocol */
#define GCR_WIN_SIZE_RCV GCR_WIN_SIZE*2 /* Fixed to 64*N positions by protocol */
#define GCR_WIN_THRES 24 /* Arbitrary value for the BA threshold */

struct ieee80211aa_sender {
	struct list_head list;
	struct ieee80211_sub_if_data *sdata;
	bool need_retx;
	u8 sa[ETH_ALEN];
	spinlock_t lock;
	u16 curr_win; /* sn marking start of current window */
	u16 prev_win; /* sn marking start of previous window */
	struct hrtimer ba_timer;
	int exp_bas; /* Number of BA expected */
	int rcv_bas; /* Number of BA received */
	unsigned long scoreboard [BITS_TO_LONGS(GCR_WIN_SIZE)];
};

struct ieee80211aa_receiver {
	struct list_head list;
	u8 sa[ETH_ALEN];
	/* info for rx */
	u32 window_start; // current seq_num when the window has started
	unsigned long scoreboard [BITS_TO_LONGS(GCR_WIN_SIZE_RCV)];
};

struct aa_mc {
	struct list_head bucket[AA_BUCKETS];
	u32 idx_mask;
};

/* ieee80211aa definitions */
#ifdef CONFIG_MAC80211_MESH_11AA
static inline bool ieee80211aa_enabled(void)
{
	return true;
}

void ieee80211aa_init(void);
void ieee80211aa_stop(void);

int ieee80211aa_mcc_init(struct ieee80211_sub_if_data *sdata);
void ieee80211aa_mcc_free(struct ieee80211_sub_if_data *sdata);

int ieee80211aa_gcm_frame_tx(struct ieee80211_sub_if_data *sdata,
			     enum ieee80211_robust_av_actioncode action,
			     u8 *da, u8 dialog_token);
void ieee80211aa_rx_gcm_frame(struct ieee80211_sub_if_data *sdata,
			      struct ieee80211_mgmt *mgmt,
			      size_t len, struct ieee80211_rx_status *rx_status);
void ieee80211aa_handle_bar(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_bar_gcr *bar);
void ieee80211aa_handle_ba(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_ba_gcr *ba);
void ieee80211aa_set_seqnum(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211s_hdr *mesh_hdr, u8 *da);
void ieee80211aa_handle_tx_skb(struct ieee80211_sub_if_data *sdata,
			       struct sk_buff *skb);
void ieee80211aa_check_tx(struct ieee80211_sub_if_data *sdata,
			  u8 *sa, u32 seqnum);
void ieee80211aa_check_rx(struct ieee80211_sub_if_data *sdata,
			  u8 *sa, u32 seqnum);
void ieee80211_send_bar_gcr(struct ieee80211_sub_if_data *sdata, u8 *ra,
			    u8 *sa, u16 ssn);
#else /* !CONFIG_MAC80211_MESH_11AA */
static inline bool ieee80211aa_enabled(void)
{
	return false;
}

static inline void ieee80211aa_init(void)
{
	return;
}

static inline void ieee80211aa_stop(void)
{
	return;
}

static inline int ieee80211aa_mcc_init(struct ieee80211_sub_if_data *sdata)
{
	return 0;
}

static inline int ieee80211aa_mcc_free(struct ieee80211_sub_if_data *sdata)
{
	return 0;
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
static inline void ieee80211aa_handle_bar(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_bar_gcr *bar)
{
	return;
}
static inline void ieee80211aa_handle_ba(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_ba_gcr *ba)
{
	return;
}
static inline void ieee80211aa_set_seqnum(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211s_hdr *mesh_hdr, u8 *da)
{
	return;
}
static inline void ieee80211_send_bar_gcr(struct ieee80211_sub_if_data *sdata, u8 *ra,
			    u8 *sa, u16 ssn)
{
	return;
}
static inline void ieee80211aa_check_rx(struct ieee80211_sub_if_data *sdata,
					u8 *sa, u32 seqnum)
{
	return;
}
static inline void
ieee80211aa_handle_tx_skb(struct ieee80211_sub_if_data *sdata,
			  struct sk_buff *skb)
{
	return;
}
#endif /* !CONFIG_MAC80211_MESH_11AA */
#endif /* MESH_11AA_H */
