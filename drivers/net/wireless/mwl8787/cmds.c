#include "mwl8787.h"
#include "fw.h"

int mwl8787_reset(struct mwl8787_priv *priv)
{
	struct mwl8787_cmd_reset reset_cmd = {
		.header.id = MWL8787_CMD_RESET,
		.header.size = sizeof(struct mwl8787_cmd_reset),
		.header.seq = 0,
		.header.result = 0,
		.action = MWL8787_ACT_SET
	};

	return mwl8787_send_cmd(priv, reset_cmd.header.id, (u8 *) &reset_cmd,
				sizeof(reset_cmd));
}
