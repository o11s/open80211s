/*
 * Read flash partition table from command line
 *
 * Copyright © 2002      SYSGO Real-Time Solutions GmbH
 * Copyright © 2002-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * The format for the command line is as follows:
 *
 * mtdparts=<mtddef>[;<mtddef]
 * <mtddef>  := <mtd-id>:<partdef>[,<partdef>]
 * <partdef> := <size>[@<offset>][<name>][ro][lk]
 * <mtd-id>  := unique name used in mapping driver/device (mtd->name)
 * <size>    := standard linux memsize OR "-" to denote all remaining space
 *              size is automatically truncated at end of device
 *              if specified or trucated size is 0 the part is skipped
 * <offset>  := standard linux memsize
 *              if omitted the part will immediately follow the previous part
 *              or 0 if the first part
 * <name>    := '(' NAME ')'
 *              NAME will appear in /proc/mtd
 *
 * <size> and <offset> can be specified such that the parts are out of order
 * in physical memory and may even overlap.
 *
 * The parts are assigned MTD numbers in the order they are specified in the
 * command line regardless of their order in physical memory.
 *
 * Examples:
 *
 * 1 NOR Flash, with 1 single writable partition:
 * edb7312-nor:-
 *
 * 1 NOR Flash with 2 partitions, 1 NAND with one
 * edb7312-nor:256k(ARMboot)ro,-(root);edb7312-nand:-(home)
 */
 /*
  * Copyright © 2013 Cai Zhiyong <caizhiyong@huawei.com>
  * Rewrite the cmdline parser code, adjust it to a library-style code.
  * this module only use the cmdline parser lib.
  */

#include <linux/kernel.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/cmdline-parser.h>

static char *mtdparts;
static struct cmdline_parts *mtd_cmdline_parts;

static int add_part(int slot, struct cmdline_subpart *subpart, void *param)
{
	struct mtd_partition *mtdpart = &((struct mtd_partition *)param)[slot];

	mtdpart->offset = subpart->from;
	mtdpart->size = subpart->size;
	mtdpart->name = subpart->name;
	mtdpart->mask_flags = 0;

	if (subpart->flags & PF_RDONLY)
		mtdpart->mask_flags |= MTD_WRITEABLE;

	if (subpart->flags & PF_POWERUP_LOCK)
		mtdpart->mask_flags |= MTD_POWERUP_LOCK;

	return 0;
}

static int __init mtdpart_setup(char *s)
{
	mtdparts = s;
	return 1;
}
__setup("mtdparts=", mtdpart_setup);

static int parse_cmdline_partitions(struct mtd_info *master,
				    struct mtd_partition **pparts,
				    struct mtd_part_parser_data *data)
{
	struct cmdline_parts *parts;

	if (mtdparts) {
		if (mtd_cmdline_parts)
			cmdline_parts_free(&mtd_cmdline_parts);

		if (cmdline_parts_parse(&mtd_cmdline_parts, mtdparts)) {
			mtdparts = NULL;
			return -EINVAL;
		}
		mtdparts = NULL;
	}

	if (!mtd_cmdline_parts)
		return 0;

	parts = cmdline_parts_find(mtd_cmdline_parts, master->name);
	if (!parts)
		return 0;

	*pparts = kzalloc(sizeof(**pparts) * parts->nr_subparts, GFP_KERNEL);
	if (!*pparts)
		return -ENOMEM;

	return cmdline_parts_set(parts, master->size, 0, add_part,
				 (void *)*pparts);
}

static struct mtd_part_parser cmdline_parser = {
	.owner = THIS_MODULE,
	.parse_fn = parse_cmdline_partitions,
	.name = "cmdlinepart",
};

static int __init cmdline_parser_init(void)
{
	return register_mtd_parser(&cmdline_parser);
}

static void __exit cmdline_parser_exit(void)
{
	deregister_mtd_parser(&cmdline_parser);
}

module_init(cmdline_parser_init);
module_exit(cmdline_parser_exit);

MODULE_PARM_DESC(mtdparts, "Partitioning specification");
module_param(mtdparts, charp, 0);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marius Groeger <mag@sysgo.de>");
MODULE_DESCRIPTION("Command line configuration of MTD partitions");
