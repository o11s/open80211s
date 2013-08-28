#include "mwl8787.h"

int mwl8787_cmd_scan(struct mwl8787_priv *priv,
		     struct cfg80211_scan_request *request)
{
	struct mwl8787_cmd *cmd;

	struct mwl8787_tlv_wildcard_ssid *ssid;
	struct mwl8787_tlv_num_probes *probes;
	struct ieee80211_channel *chan;
	struct mwl8787_channel_list *chanlist;
	struct mwl8787_channel_param *param;

	u16 scan_time;
	u8 *ptr;
	u16 chan_size;
	size_t tlv_len = 0;
	int i, ret;

	tlv_len += sizeof(struct mwl8787_tlv_wildcard_ssid) *
		   request->n_ssids;

	for (i=0; i < request->n_ssids; i++)
		tlv_len += request->ssids[i].ssid_len;

	/* number of probes */
	tlv_len += sizeof(struct mwl8787_tlv_num_probes);

#if 0
	/* TODO rates & caps */
	struct mwl8787_tlv_supp_rates *rates;
	struct mwl8787_tlv_ht_caps *ht_caps;

	/* supported rates */
	tlv_len += sizeof(struct mwl8787_tlv_supp_rates) +
		   rates_size;

	/* HT capabilities */
	tlv_len += sizeof(struct mwl8787_tlv_ht_caps);
#endif

	/* channels */
	chan_size = sizeof(struct mwl8787_channel_param) * request->n_channels;
	if (request->n_channels)
		tlv_len += sizeof(struct mwl8787_channel_list) + chan_size;

	cmd = mwl8787_cmd_alloc(priv,
				MWL8787_CMD_SCAN,
				sizeof(struct mwl8787_cmd_scan) + tlv_len,
				GFP_KERNEL);

	cmd->u.scan.bss_mode = MWL8787_BSS_MODE_ANY;

	/* scan ssids */
	ptr = cmd->u.scan.data;
	ssid = (struct mwl8787_tlv_wildcard_ssid *) ptr;
	for (i=0; i < request->n_ssids; i++) {
		ssid->hdr.type = cpu_to_le16(MWL8787_TYPE_WILDCARD_SSID);
		ssid->hdr.len = cpu_to_le16(sizeof(*ssid) -
					    sizeof(ssid->hdr) +
					    request->ssids[i].ssid_len);
		memcpy(ssid->ssid, request->ssids[i].ssid,
		       request->ssids[i].ssid_len);

		if (request->ssids[i].ssid_len)
			ssid->scan_ssid_type = 0;
		else
			ssid->scan_ssid_type = MWL8787_SCAN_WILDCARD;

		ptr += sizeof(ssid->hdr) + le16_to_cpu(ssid->hdr.len);
		ssid = (struct mwl8787_tlv_wildcard_ssid *) ptr;
	}

	/* num probes */
	probes = (struct mwl8787_tlv_num_probes *) ptr;
	probes->hdr.type = cpu_to_le16(MWL8787_TYPE_NUM_PROBES);
	probes->hdr.len =
		cpu_to_le16(sizeof(*probes) - sizeof(probes->hdr));
	probes->num_probes = cpu_to_le16(1);
	ptr += sizeof(probes->hdr) + le16_to_cpu(probes->hdr.len);

	chanlist = (struct mwl8787_channel_list *) ptr;
	if (request->n_channels) {
		chanlist->hdr.type = cpu_to_le16(MWL8787_TYPE_CHANLIST);
		chanlist->hdr.len = cpu_to_le16(chan_size);

		for (i=0; i < request->n_channels; i++) {
			chan = request->channels[i];
			param = &chanlist->channels[i];

			param->radio_type = chan->band;
			param->channel = chan->hw_value;
			if (chan->flags & IEEE80211_CHAN_PASSIVE_SCAN) {
				param->channel_scan_mode =
					MWL8787_SCAN_TYPE_PASSIVE;
				scan_time = MWL8787_PASSIVE_SCAN_TIME;
			} else {
				param->channel_scan_mode =
					MWL8787_SCAN_TYPE_ACTIVE;
				scan_time = MWL8787_ACTIVE_SCAN_TIME;
			}
			param->min_scan_time = cpu_to_le16(scan_time);
			param->max_scan_time = param->min_scan_time;
		}
		ptr += sizeof(*chanlist) + chan_size;
	}

	ret = mwl8787_send_cmd(priv, cmd);

	mwl8787_cmd_free(priv, cmd);
	return ret;
}

