/*
 * Copyright 2013 cozybit, inc.
 *
 * All rights reserved.
 */
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

/* TODO: supported mwl8787tf commands and events go here */
#endif /* _MWL8787_FW_H_ */
