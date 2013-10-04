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
#define MWL8787_ACT_BITWISE_SET			2
#define MWL8787_ACT_BITWISE_CLR			3

#define MWL8787_CMD_RET_BIT			0x8000

#define MWL8787_CMD_SUCCESS			0x0
#define MWL8787_CMD_FAIL			0x1

#define MWL8787_ACTIVE_SCAN_TIME		30
#define MWL8787_PASSIVE_SCAN_TIME		110

#define MWL8787_BSS_MODE_ANY			3

#define SEQ_NO_BSS_INFO(seq, num, type) {   \
	(((seq) & 0x00ff) |                             \
	 (((num) & 0x000f) << 8)) |                     \
	(((type) & 0x000f) << 12);                  }

#define MRVL_RATEID_DBPSK1Mbps		0
#define MRVL_RATEID_DQPSK2Mbps		1
#define MRVL_RATEID_CCK5_5Mbps		2
#define MRVL_RATEID_CCK11Mbps		3
#define MRVL_RATEID_CCK22Mbps		4
#define MRVL_RATEID_OFDM6Mbps		5
#define MRVL_RATEID_OFDM9Mbps		6
#define MRVL_RATEID_OFDM12Mbps		7
#define MRVL_RATEID_OFDM18Mbps		8
#define MRVL_RATEID_OFDM24Mbps		9
#define MRVL_RATEID_OFDM36Mbps		10
#define MRVL_RATEID_OFDM48Mbps		11
#define MRVL_RATEID_OFDM54Mbps		12
#define MRVL_RATEID_OFDM72Mbps		13

#define MRVL_RATEID_MCS0_6d5Mbps	14
#define MRVL_RATEID_MCS1_13Mbps		15
#define MRVL_RATEID_MCS2_19d5Mbps	16
#define MRVL_RATEID_MCS3_26Mbps		17
#define MRVL_RATEID_MCS4_39Mbps		18
#define MRVL_RATEID_MCS5_52Mbps		19
#define MRVL_RATEID_MCS6_58d5Mbps	20
#define MRVL_RATEID_MCS7_65Mbps		21

#define MRVL_RATEID_MCS32BW40_6Mbps	22
#define MRVL_RATEID_MCS0BW40_13d5Mbps	23
#define MRVL_RATEID_MCS1BW40_27Mbps	24
#define MRVL_RATEID_MCS2BW40_40d5Mbps	25
#define MRVL_RATEID_MCS3BW40_54Mbps	26
#define MRVL_RATEID_MCS4BW40_81Mbps	27
#define MRVL_RATEID_MCS5BW40_108Mbps	28
#define MRVL_RATEID_MCS6BW40_121d5Mbps	29
#define MRVL_RATEID_MCS7BW40_135Mbps	30

#define MRVL_MCS_SHIFT			14

#define MWL8787_DEFAULT_TX_POWER	30	/* dBm */

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

enum mwl8787_tx_ctl {
	MWL8787_ASSIGN_SEQ		= BIT(16),
	MWL8787_REQ_TX_STATUS		= BIT(17),
	MWL8787_AMPDU			= BIT(18),
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

enum mwl8787_dev_cap {
	MWL8787_DEV_HT_CAP_40MHZ_INTOLERANT	= BIT(8),
	MWL8787_DEV_HT_CAP_SUP_WIDTH_20_40	= BIT(17),
	MWL8787_DEV_HT_CAP_LDPC_CODING		= BIT(22),
	MWL8787_DEV_HT_CAP_SGI_20		= BIT(23),
	MWL8787_DEV_HT_CAP_SGI_40		= BIT(24),
	MWL8787_DEV_HT_CAP_TX_STBC		= BIT(25),
	MWL8787_DEV_HT_CAP_RX_STBC		= BIT(26),
	MWL8787_DEV_HT_CAP_GRN_FLD		= BIT(29),
};

enum mwl8787_mac_ctrl_flags {
	MWL8787_MAC_ENABLE_RX		= BIT(0),
	MWL8787_MAC_ENABLE_ALL_UNICAST	= BIT(1),
	MWL8787_MAC_ENABLE_WEP		= BIT(3),
	MWL8787_MAC_ENABLE_ETHERNETII	= BIT(4),
	MWL8787_MAC_ENABLE_BCAST	= BIT(6),
	MWL8787_MAC_ENABLE_PROMISC	= BIT(7),
	MWL8787_MAC_ENABLE_ALLMULTI	= BIT(8),
	MWL8787_MAC_ENABLE_CTS		= BIT(9),
	MWL8787_MAC_ENABLE_80211	= BIT(12),
	MWL8787_MAC_ENABLE_MGMT		= BIT(14),
	MWL8787_MAC_ENABLE_OTHER_BSS	= BIT(16),
	MWL8787_MAC_ENABLE_OTHER_BCN	= BIT(17),
	MWL8787_MAC_ENABLE_OTHER_PRESP	= BIT(18),
};

enum mwl8787_oid {
	MWL8787_OID_RTS_THRESHOLD	= 0x05,
	MWL8787_OID_SHORT_RETRY_LIMIT	= 0x06,
	MWL8787_OID_LONG_RETRY_LIMIT	= 0x07,
	MWL8787_OID_FRAG_THRESHOLD	= 0x08,
	MWL8787_OID_MCAST_RATE		= 0x0b,
};

enum mwl8787_cmd_id {
	MWL8787_CMD_HW_SPEC		= 0x0003,
	MWL8787_CMD_SCAN		= 0x0006,
	MWL8787_CMD_LOG			= 0x000b,
	MWL8787_CMD_MULTICAST_ADDR	= 0x0010,
	MWL8787_CMD_SNMP_MIB		= 0x0016,
	MWL8787_CMD_RF_CHANNEL		= 0x001d,
	MWL8787_CMD_RADIO_CTRL		= 0x001c,
	MWL8787_CMD_MAC_ADDR		= 0x004d,
	MWL8787_CMD_MAC_CTRL		= 0x0028,
	MWL8787_CMD_SUBSCRIBE_EVENTS	= 0x0075,
	MWL8787_CMD_TX_RATE_QUERY	= 0x007f,
	MWL8787_CMD_GET_TSF		= 0x0080,
	MWL8787_CMD_BEACON_SET		= 0x00cb,
	MWL8787_CMD_11N_CFG		= 0x00cd,
	MWL8787_CMD_FUNC_INIT		= 0x00a9,
	MWL8787_CMD_ADDBA_REQ		= 0x00ce,
	MWL8787_CMD_ADDBA_RSP		= 0x00cf,
	MWL8787_CMD_DELBA		= 0x00d0,
	MWL8787_CMD_TX_POWER		= 0x00d1,
	MWL8787_CMD_BEACON_CTRL		= 0x010e,
	MWL8787_CMD_SET_TSF		= 0x010f,
	MWL8787_CMD_SET_PEER		= 0x0110,
	MWL8787_CMD_DEL_PEER		= 0x0111,
};

enum mwl8787_ba_status {
	MWL8787_BA_SUCCESS		= 0,
	MWL8787_BA_EXEC_FAILURE		= 1,
	MWL8787_BA_TIMEOUT		= 2,
	MWL8787_BA_DATA_INVALID		= 3,
};

enum mwl8787_event_id {
	MWL8787_EVT_WAKEUP		= 0x0001,
	MWL8787_EVT_TX_FAIL		= 0x001b,
	MWL8787_EVT_TX_STATUS		= 0x0067,
};

enum mwl8787_event_sub_flags {
	MWL8787_EVT_SUB_BCN_RSSI_LO	= BIT(0),
	MWL8787_EVT_SUB_BCN_SNR_LO	= BIT(1),
	MWL8787_EVT_SUB_TX_FAIL		= BIT(2),
	MWL8787_EVT_SUB_BCN_LOSS	= BIT(3),
	MWL8787_EVT_SUB_TX_STATUS	= BIT(12),
};

enum mwl8787_modulation_class {
	MWL8787_MOD_DSSS		= 0x03,
	MWL8787_MOD_OFDM		= 0x07,
	MWL8787_MOD_HT			= 0x08,
};

enum mwl8787_modulation_max_rate {
	MWL8787_MAX_RATE_DSSS		= 0x03,
	MWL8787_MAX_RATE_OFDM		= 0x07,
	MWL8787_MAX_RATE_HT		= 0x20,
};

enum mwl8787_tlv_type {
	MWL8787_TYPE_CHANLIST		= 0x0101,
	MWL8787_TYPE_NUM_PROBES		= 0x0102,
	MWL8787_TYPE_TX_FAIL		= 0x0106,
	MWL8787_TYPE_WILDCARD_SSID	= 0x0112,
	MWL8787_TYPE_BAND_CHAN		= 0x012A,
	MWL8787_TLV_POWER_GROUP		= 0x0154,
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
	u8 tx_rx_chains;
	__le16 mp_end_port;
	__le16 mgmt_buf_count;
	__le32 reserved_3[2];
	__le32 dot_11ac_dev_cap;
	__le32 dot_11ac_mcs_support;
} __packed;

struct mwl8787_cmd_log {
	__le32 dot11MulticastTransmittedFrameCount;
	__le32 dot11FailedCount;
	__le32 dot11RetryCount;
	__le32 dot11MultipleRetryCount;
	__le32 dot11FrameDuplicateCount;
	__le32 dot11RTSSuccessCount;
	__le32 dot11RTSFailureCount;
	__le32 dot11ACKFailureCount;
	__le32 dot11ReceivedFragmentCount;
	__le32 dot11MulticastReceivedFrameCount;
	__le32 dot11FCSErrorCount;
	__le32 dot11TransmittedFragmentCount;
	__le32 res;
	__le32 dot11WepIcvErrorCount[4];
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


struct mwl8787_cmd_11n_cfg {
	__le16 action;
	__le16 ht_cap;
	__le16 ht_info;
	__le16 misc;
} __packed;

/*
 * band, channel, and secondary offset are all combined into rftype field.
 */
enum mwl8787_band {
	MWL8787_BAND_2GHZ	= 0,
	MWL8787_BAND_5GHZ	= 1,
	MWL8787_BAND_4GHZ	= 2
};

#define MWL8787_CHAN_WIDTH_SHIFT	2
enum mwl8787_chan_width {
	MWL8787_CHAN_WIDTH_20	= 0 << MWL8787_CHAN_WIDTH_SHIFT,
	MWL8787_CHAN_WIDTH_40	= 2 << MWL8787_CHAN_WIDTH_SHIFT,
};

#define MWL8787_SEC_OFF_SHIFT		4
enum mwl8787_secondary_offset {
	MWL8787_SEC_OFF_NONE	= 0 << MWL8787_SEC_OFF_SHIFT,
	MWL8787_SEC_OFF_ABOVE	= 1 << MWL8787_SEC_OFF_SHIFT,
	MWL8787_SEC_OFF_BELOW	= 3 << MWL8787_SEC_OFF_SHIFT,
};

struct mwl8787_cmd_rf_channel {
	__le16 action;
	__le16 current_channel;
	u8 reserved0;
	u8 rftype;
	u8 reserved1[34];
} __packed;

struct mwl8787_cmd_mac_ctrl {
	__le32 control;
	__le16 reserved;
} __packed;

struct mwl8787_cmd_mac_addr {
	__le16 action;
	u8 addr[ETH_ALEN];
} __packed;

struct mwl8787_cmd_subscribe_events {
	__le16 action;
	__le16 events;
	u8 tlvs[0];
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

struct mwl8787_cmd_snmp_mib {
	__le16 action;
	__le16 oid;
	__le16 payload_size;
	u8 payload[0];
} __packed;

struct mwl8787_cmd_get_tsf {
	__le64 tsf;
} __packed;

struct mwl8787_cmd_set_peer {
	u8 addr[ETH_ALEN];
	__le32 supp_rate_map; /* MRVL_RATEIDs */
} __packed;

struct mwl8787_cmd_del_peer {
	u8 addr[ETH_ALEN];
} __packed;

struct mwl8787_cmd_addba_req {
	u8 add_req_result;
	u8 addr[ETH_ALEN];
	u8 token;
	__le16 ba_param_set;
	__le16 ba_timeout;
	__le16 ssn;
} __packed;

struct mwl8787_cmd_delba {
	u8 del_result;
	u8 addr[ETH_ALEN];
	__le16 ba_param_set;
	u16 reason_code;
} __packed;

struct mwl8787_cmd_tx_power {
	__le16 action;
	__le16 cfg_index;
	__le32 user_defined;
	u8 power_group_tlv[0];
} __packed;

struct mwl8787_cmd_header {
	__le16 id;
	__le16 len;
	__le16 seq;
	__le16 result;
} __packed;

struct mwl8787_cmd_rate_query {
	u8 tx_rate;
	u8 ht_info;
	u8 addr[ETH_ALEN];
	__le32 tx_err;
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

struct mwl8787_tlv_tx_fail {
	u8 fail_threshold;
	u8 reporting_freq;
} __packed;

struct mwl8787_power_group {
	u8 mod_class;
	u8 start_rate;
	u8 end_rate;
	u8 power_step;
	u8 power_min;
	u8 power_max;
	u8 ht40;
	u8 reserved;
} __packed;

struct mwl8787_tlv_power_group {
	struct mwl8787_power_group groups[4];
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

struct mwl8787_tx_desc {
	u8 bss_type;
	u8 bss_num;
	__le16 frame_len;
	__le16 frame_offset;
	__le16 frame_type;
	__le32 tx_control;
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
	__le64 mactime;
	u8 reserved;
} __packed;

struct mwl8787_cmd {
	struct mwl8787_cmd_header hdr;
	union {
		struct mwl8787_cmd_hw_spec hw_spec;
		struct mwl8787_cmd_log log;
		struct mwl8787_cmd_multicast_addr multicast_addr;
		struct mwl8787_cmd_radio_ctrl radio_ctrl;
		struct mwl8787_cmd_rf_channel rf_channel;
		struct mwl8787_cmd_mac_ctrl mac_ctrl;
		struct mwl8787_cmd_mac_addr mac_addr;
		struct mwl8787_cmd_subscribe_events subscribe_events;
		struct mwl8787_cmd_beacon_ctrl beacon_ctrl;
		struct mwl8787_cmd_beacon_set beacon_set;
		struct mwl8787_cmd_mode mode;
		struct mwl8787_cmd_bssid bssid;
		struct mwl8787_cmd_scan scan;
		struct mwl8787_cmd_scan_resp scan_resp;
		struct mwl8787_cmd_snmp_mib snmp_mib;
		struct mwl8787_cmd_get_tsf get_tsf;
		struct mwl8787_cmd_get_tsf set_tsf;
		struct mwl8787_cmd_set_peer set_peer;
		struct mwl8787_cmd_del_peer del_peer;
		struct mwl8787_cmd_addba_req addba_req;
		struct mwl8787_cmd_delba delba;
		struct mwl8787_cmd_rate_query rate_query;
		struct mwl8787_cmd_tx_power tx_power;
		struct mwl8787_cmd_11n_cfg dot11n;
		u8 data[0];
	} u;
} __packed;

struct mwl8787_tlv {
	struct mwl8787_tlv_header hdr;
	union {
		struct mwl8787_tlv_tx_fail tx_fail;
		struct mwl8787_tlv_power_group power_group;
		u8 data[0];
	} u;
} __packed;

struct mwl8787_sdio_header {
	__le16 len;
	__le16 type;
} __packed;


struct mwl8787_event_tx_status {
	u8 acked;
	u8 last_rate;
	u8 attempts;
	u8 hw_queue;
} __packed;

struct mwl8787_event_tx_fail {
	u8 addr[ETH_ALEN];
} __packed;

struct mwl8787_event_header {
	__le16 id;
	u8 bss_num;
	u8 bss_type;
} __packed;

struct mwl8787_event {
	struct mwl8787_event_header hdr;
	union {
		struct mwl8787_event_tx_status tx_status;
		struct mwl8787_event_tx_fail tx_fail;
		u8 data[0];
	} u;
} __packed;

#endif /* _MWL8787_FW_H_ */
