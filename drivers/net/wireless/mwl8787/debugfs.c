#include <linux/debugfs.h>
#include "mwl8787.h"
#include "sdio.h"

static ssize_t
mwl8787_scratch_read(struct file *file, char __user *ubuf,
		     size_t count, loff_t *ppos)
{
	struct mwl8787_priv *priv =
		(struct mwl8787_priv *) file->private_data;

	char buf[17] = {};
	int pos = 0, ret = 0;
	u64 reg_value;

	/* read scratch reg */
	ret = mwl8787_read_scratch_area(priv, &reg_value);

	if (ret) {
		ret = -EINVAL;
		goto done;
	}

	pos += snprintf(buf, sizeof(buf), "%016llx\n", reg_value);

	ret = simple_read_from_buffer(ubuf, count, ppos, buf, pos);
done:
	return ret;
}

#define MWL8787_DFS_ADD_FILE(name) \
	debugfs_create_file(#name, 0644, priv->dfs_dev_dir,		\
			priv, &mwl8787_dfs_##name##_fops);		\


#define MWL8787_DFS_FILE_READ_OPS(name)                                 \
static const struct file_operations mwl8787_dfs_##name##_fops = {       \
	.read = mwl8787_##name##_read,                                  \
	.open = simple_open,                                            \
};

MWL8787_DFS_FILE_READ_OPS(scratch);

/*
 * This function creates the debugfs directory and files.
 */
void
mwl8787_dev_debugfs_init(struct mwl8787_priv *priv)
{
	if (!priv)
		return;

	priv->dfs_dev_dir = debugfs_create_dir("mwl8787",
		priv->hw->wiphy->debugfsdir);

	MWL8787_DFS_ADD_FILE(scratch);
}

/*
 * This function removes the debugfs directory and files
 */
void
mwl8787_dev_debugfs_remove(struct mwl8787_priv *priv)
{
	if (!priv)
		return;

	debugfs_remove_recursive(priv->dfs_dev_dir);
}
