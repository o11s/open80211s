/*
 * Copyright (c) 2012 cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef MESH_RMOM_H
#define MESH_RMOM_H

#ifdef CONFIG_MAC80211_RMOM_DEBUG
#define rmom_dbg(fmt, args...) \
	printk(KERN_DEBUG "RMoM (%s): " fmt "\n", sdata->name, ##args)
#else
#define rmom_dbg(fmt, args...)   do { (void)(0); } while (0)
#endif

/*
#define RMOM_MAX_FLOWS 8
#define RMOM_MAX_JUMP 8
#define RMOM_MAX_FIFO_SIZE ( RMOM_MAX_JUMP * RMOM_MAX_FLOWS )
#define RMOM_MAX_NACK_RETRIES 5
#define RMOM_EXPIRY_WINDOW_SIZE 8
*/

#endif /* MESH_RMOM_H */
