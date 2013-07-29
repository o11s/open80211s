/*
 * Copyright 2013 cozybit, inc.
 *
 * All rights reserved.
 */
#include <linux/types.h>

#ifndef _MWL8787_FW_H_
#define _MWL8787_FW_H_

#define MAX_POLL_TRIES			100

#define MAX_MULTI_INTERFACE_POLL_TRIES  1000

#define MAX_FIRMWARE_POLL_TRIES			100

#define FIRMWARE_READY_SDIO				0xfedc
#define FIRMWARE_READY_PCIE				0xfedcba00

#define CAL_SNR(RSSI, NF)		((s16)((s16)(RSSI)-(s16)(NF)))
#define CAL_RSSI(SNR, NF)		((s16)((s16)(SNR)+(s16)(NF)))

#define UAP_BSS_PARAMS_I			0
#define UAP_CUSTOM_IE_I				1
#define MWIFIEX_AUTO_IDX_MASK			0xffff
#define MWIFIEX_DELETE_MASK			0x0000
#define MGMT_MASK_ASSOC_REQ			0x01
#define MGMT_MASK_REASSOC_REQ			0x04
#define MGMT_MASK_ASSOC_RESP			0x02
#define MGMT_MASK_REASSOC_RESP			0x08
#define MGMT_MASK_PROBE_REQ			0x10
#define MGMT_MASK_PROBE_RESP			0x20
#define MGMT_MASK_BEACON			0x100

#define MWL8787_MAX_MULTICAST_LIST_SIZE		32
#define MWL8787_MAX_BEACON_SIZE			440

#define MWL8787_ACT_GET				0
#define MWL8787_ACT_SET				1

#define MWL8787_CMD_RET_BIT			0x8000

#define MWL8787_CMD_SUCCESS			0x0
#define MWL8787_CMD_FAIL			0x1

#define MWL8787_ACTIVE_SCAN_TIME		30
#define MWL8787_PASSIVE_SCAN_TIME		110

#define MWL8787_BSS_MODE_ANY			3

#define MWL8787_MONITOR_MODE_ALL		7

#define SEQ_NO_BSS_INFO(seq, num, type) {   \
	(((seq) & 0x00ff) |                             \
	 (((num) & 0x000f) << 8)) |                     \
	(((type) & 0x000f) << 12);                  }

enum mwl8787_bss_type {
	MWL8787_BSS_TYPE_CLIENT		= 0x00,
	MWL8787_BSS_TYPE_AP		= 0x01,
	MWL8787_BSS_TYPE_WFD		= 0x02,
	MWL8787_BSS_TYPE_TM		= 0x03,
};

enum mwl8787_tx_type {
	MWL8787_TX_TYPE_802_3		= 0x00,
	MWL8787_TX_TYPE_802_11		= 0x05,
	MWL8787_TX_TYPE_MGMT		= 0xe5,
	MWL8787_TX_TYPE_UAPSD		= 0xe6,
};

enum mwl8787_tx_flags {
	MWL8787_NULL_DATA		= BIT(0),
	MWL8787_LAST_FRAME		= BIT(3),
};

enum mwl8787_rx_ht_info {
	MWL8787_RX_HT_RATE		= BIT(0),
	MWL8787_RX_HT_40		= BIT(1),
	MWL8787_RX_HT_SHORT_GI		= BIT(2),
};

enum mwl8787_scan_ssid_type {
	MWL8787_SCAN_SSID		= 0,
	MWL8787_SCAN_WILDCARD		= 32,
};

enum mwl8787_scan_type {
	MWL8787_SCAN_TYPE_UNCHANGED	= 0,
	MWL8787_SCAN_TYPE_ACTIVE	= 1,
	MWL8787_SCAN_TYPE_PASSIVE	= 2,
};

enum mwl8787_filter_flags {
	MWL8787_FIF_ENABLE_RX		= BIT(0),
	MWL8787_FIF_ENABLE_TX		= BIT(1),
	MWL8787_FIF_ENABLE_WEP		= BIT(3),
	MWL8787_FIF_ENABLE_ETHERNETII	= BIT(4),
	MWL8787_FIF_ENABLE_PROMISC	= BIT(7),
	MWL8787_FIF_ENABLE_ALLMULTI	= BIT(8),
	MWL8787_FIF_ENABLE_80211	= BIT(12),
	MWL8787_FIF_ENABLE_MGMT		= BIT(14),
};

enum mwl8787_cmd_id {
	MWL8787_CMD_HW_SPEC		= 0x0003,
	MWL8787_CMD_RESET		= 0x0005,
	MWL8787_CMD_SCAN		= 0x0006,
	MWL8787_CMD_MULTICAST_ADDR	= 0x0010,
	MWL8787_CMD_RF_CHANNEL		= 0x001d,
	MWL8787_CMD_RADIO_CTRL		= 0x001c,
	MWL8787_CMD_MAC_ADDR		= 0x004d,
	MWL8787_CMD_MAC_CTRL		= 0x0028,
	MWL8787_CMD_BEACON_SET		= 0x00cb,
	MWL8787_CMD_FUNC_INIT		= 0x00a9,
	MWL8787_CMD_MONITOR		= 0x0102,
};

enum mwl8787_tlv_type {
	MWL8787_TYPE_CHANLIST		= 0x0101,
	MWL8787_TYPE_NUM_PROBES		= 0x0102,
	MWL8787_TYPE_WILDCARD_SSID	= 0x0112,
	MWL8787_TYPE_BAND_CHAN		= 0x012A,
};

struct mwl8787_cmd_hw_spec {
	__le16 hw_if_version;
	__le16 version;
	__le16 reserved;
	__le16 num_mcast;
	u8 perm_addr[ETH_ALEN];
	__le16 region_code;
	__le16 num_ant;
	__le32 fw_version;
	__le32 reserved_2[3];
	__le32 fw_cap_info;
	__le32 dot_11n_dev_cap;
	u8 dev_mcs_support;
	__le16 mp_end_port;
	__le16 mgmt_buf_count;
	__le32 reserved_3[2];
	__le32 dot_11ac_dev_cap;
	__le32 dot_11ac_mcs_support;
} __packed;

struct mwl8787_cmd_reset {
	__le16 action;
} __packed;

struct mwl8787_cmd_multicast_addr {
	__le16 action;
	__le16 num;
	u8 mac_list[MWL8787_MAX_MULTICAST_LIST_SIZE][ETH_ALEN];
} __packed;

struct mwl8787_cmd_radio_ctrl {
	__le16 action;
	__le16 control;
} __packed;

struct mwl8787_cmd_rf_channel {
	__le16 action;
	__le16 current_channel;
	__le16 rftype;
	u8 reserved[34];
} __packed;

struct mwl8787_cmd_mac_ctrl {
	__le16 control;
	__le16 reserved;
} __packed;

struct mwl8787_cmd_mac_addr {
	__le16 action;
	u8 addr[ETH_ALEN];
} __packed;

struct mwl8787_cmd_beacon_ctrl {
	__le16 action;
	__le16 beacon_enable;
	__le16 beacon_period;
} __packed;

struct mwl8787_cmd_beacon_set {
	__le16 len;
	u8 beacon[0];
} __packed;

struct mwl8787_cmd_mode {
	__le16 mode;
} __packed;

struct mwl8787_cmd_bssid {
	u8 bssid[6];
	u8 activate;
} __packed;

struct mwl8787_cmd_header {
	__le16 id;
	__le16 len;
	__le16 seq;
	__le16 result;
} __packed;

struct mwl8787_tlv_header {
	__le16 type;
	__le16 len;
} __packed;

struct mwl8787_ssid_item {
	struct mwl8787_tlv_header hdr;
	u8 ssid[0];
} __packed;


struct mwl8787_tlv_wildcard_ssid {
	struct mwl8787_tlv_header hdr;
	u8 scan_ssid_type;
	u8 ssid[0];
} __packed;

struct mwl8787_tlv_num_probes {
	struct mwl8787_tlv_header hdr;
	__le16 num_probes;
} __packed;

struct mwl8787_tlv_supp_rates {
	struct mwl8787_tlv_header hdr;
	u8 rates[0];
} __packed;

struct mwl8787_tlv_ht_cap {
	struct mwl8787_tlv_header hdr;
	struct ieee80211_ht_cap ht_cap;
} __packed;

struct mwl8787_band_channel {
	u8 band;
	u8 channel;
} __packed;

struct mwl8787_tlv_band_channel {
	struct mwl8787_tlv_header hdr;
	struct mwl8787_band_channel bc[0];
} __packed;

struct mwl8787_channel_param {
	u8 radio_type;
	u8 channel;
	u8 channel_scan_mode;
	__le16 min_scan_time;
	__le16 max_scan_time;
} __packed;

struct mwl8787_channel_list {
	struct mwl8787_tlv_header hdr;
	struct mwl8787_channel_param channels[0];
} __packed;

struct mwl8787_cmd_scan {
	u8 bss_mode;
	u8 bssid[ETH_ALEN];

	/* bag of mwl8787_ssid_item and mwl8787_channel_list structs */
	u8 data[0];
} __packed;

struct mwl8787_cmd_scan_resp {
	__le16 bss_size;
	u8 num;
	u8 data[0];
} __packed;

struct mwl8787_cmd_monitor {
	__le16 action;
	__le16 enable;
	__le16 flags;
	struct mwl8787_tlv_band_channel channel;
} __packed;

struct mwl8787_tx_desc {
	u8 bss_type;
	u8 bss_num;
	__le16 frame_len;
	__le16 frame_offset;
	__le16 frame_type;
	__le32 res1;
	u8 priority;
	u8 flags;
	u8 delay;
	u8 res2;
} __packed;

struct mwl8787_rx_desc {
	u8 bss_type;
	u8 bss_num;
	__le16 frame_len;
	__le16 frame_offset;
	__le16 frame_type;
	__le16 seq_num;
	u8 priority;
	u8 rx_rate;
	s8 snr;
	s8 nf;
	u8 ht_info;
	u8 reserved;
} __packed;

struct mwl8787_cmd {
	struct mwl8787_cmd_header hdr;
	union {
		struct mwl8787_cmd_hw_spec hw_spec;
		struct mwl8787_cmd_reset reset;
		struct mwl8787_cmd_multicast_addr multicast_addr;
		struct mwl8787_cmd_radio_ctrl radio_ctrl;
		struct mwl8787_cmd_rf_channel rf_channel;
		struct mwl8787_cmd_mac_ctrl mac_ctrl;
		struct mwl8787_cmd_mac_addr mac_addr;
		struct mwl8787_cmd_beacon_ctrl beacon_ctrl;
		struct mwl8787_cmd_beacon_set beacon_set;
		struct mwl8787_cmd_mode mode;
		struct mwl8787_cmd_bssid bssid;
		struct mwl8787_cmd_scan scan;
		struct mwl8787_cmd_scan_resp scan_resp;
		struct mwl8787_cmd_monitor monitor;
		u8 data[0];
	} u;
} __packed;

struct mwl8787_sdio_header {
	__le16 len;
	__le16 type;
} __packed;

#endif /* _MWL8787_FW_H_ */
