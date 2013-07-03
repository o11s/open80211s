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
/* FIXME ? */
#define MWL8787_MAX_BEACON_SIZE			1024

#define MWL8787_ACT_SET				1

struct mwl8787_cmd_header {
	__le16 id;
	__le16 size;
	__le16 seq;
	__le16 result;
} __packed;

#define MWL8787_CMD_RESET			0x0003
struct mwl8787_cmd_reset {
	struct mwl8787_cmd_header header;
	__le16 action;
} __packed;

struct mwl8787_cmd_multicast_addr {
	struct mwl8787_cmd_header header;
	__le16 action;
	__le16 num;
	u8 mac_list[MWL8787_MAX_MULTICAST_LIST_SIZE][ETH_ALEN];
} __packed;

struct mwl8787_cmd_radio_ctrl {
	struct mwl8787_cmd_header header;
	__le16 action;
	__le16 control;
} __packed;

struct mwl8787_cmd_rf_channel {
	struct mwl8787_cmd_header header;
	__le16 action;
	__le16 current_channel;
	__le16 rftype;
	u8 reserved[34];
} __packed;

struct mwl8787_cmd_mac_ctrl {
	struct mwl8787_cmd_header header;
	__le16 control;
	__le16 reserved;
} __packed;

struct mwl8787_cmd_mac_addr {
	struct mwl8787_cmd_header header;
	__le16 action;
	u8 addr[ETH_ALEN];
} __packed;

struct mwl8787_cmd_beacon_ctrl {
	struct mwl8787_cmd_header header;
	__le16 action;
	__le16 beacon_enable;
	__le16 beacon_period;
} __packed;

struct mwl8787_cmd_beacon_set {
	struct mwl8787_cmd_header header;
	__le16 len;
	u8 beacon[MWL8787_MAX_BEACON_SIZE];
} __packed;

struct mwl8787_cmd_set_mode {
	struct mwl8787_cmd_header header;
	__le16 mode;
} __packed;

struct mwl8787_cmd_set_bssid {
	struct mwl8787_cmd_header header;
	u8 bssid[6];
	u8 activate;
} __packed;

#endif /* _MWL8787_FW_H_ */
