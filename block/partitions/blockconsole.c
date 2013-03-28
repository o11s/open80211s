#include <linux/blockconsole.h>

#include "check.h"

int blockconsole_partition(struct parsed_partitions *state)
{
	Sector sect;
	void *data;
	int err = 0;

	data = read_part_sector(state, 0, &sect);
	if (!data)
		return -EIO;
	if (!bcon_magic_present(data))
		goto out;

	bcon_add(state->name);
	err = 1;
out:
	put_dev_sector(sect);
	return err;
}
