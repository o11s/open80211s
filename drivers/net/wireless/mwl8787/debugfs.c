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

	pos += scnprintf(buf, sizeof(buf), "%016llx\n", reg_value);

	ret = simple_read_from_buffer(ubuf, count, ppos, buf, pos);
done:
	return ret;
}

static ssize_t
mwl8787_reset_write(struct file *file,
		      const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct mwl8787_priv *priv =
		(struct mwl8787_priv *) file->private_data;

	priv->bus_ops->card_reset(priv);

	return count;
}

static const struct file_operations mwl8787_reset_fops = {
	.write = mwl8787_reset_write,
	.open = simple_open,
};

#define MWL8787_DFS_ADD_FILE(name) \
	debugfs_create_file(#name, 0644, priv->dfs_dev_dir,		\
			priv, &mwl8787_dfs_##name##_fops);		\


#define MWL8787_DFS_FILE_WRITE_OPS(name) \
static const struct file_operations mwl8787_dfs_##name##_fops = {	\
	.write = mwl8787_##name##_write,				\
	.open = simple_open,						\
};

#define MWL8787_DFS_FILE_READ_OPS(name)                                 \
static const struct file_operations mwl8787_dfs_##name##_fops = {       \
	.read = mwl8787_##name##_read,                                  \
	.open = simple_open,                                            \
};

#define MWL8787_DFS_ADD_MODE(name, mode)				\
	debugfs_create_file(#name, mode, priv->dfs_dev_dir,		\
			priv, &mwl8787_##name##_fops);

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

	if (!priv->dfs_dev_dir)
		return;

	MWL8787_DFS_ADD_FILE(scratch);
	MWL8787_DFS_ADD_MODE(reset, 0200);
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
