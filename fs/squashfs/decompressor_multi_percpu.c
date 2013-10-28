/*
 * Copyright (c) 2013
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See
 * the COPYING file in the top-level directory.
 */

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "decompressor.h"
#include "squashfs.h"

/*
 * This file implements multi-threaded decompression using percpu
 * variables, one thread per cpu core.
 */

struct squashfs_stream {
	void		*stream;
};

void *squashfs_decompressor_create(struct squashfs_sb_info *msblk,
						void *comp_opts)
{
	struct squashfs_stream *stream;
	struct squashfs_stream __percpu *percpu;
	int err, cpu, cpu0;

	percpu = alloc_percpu(struct squashfs_stream);
	if (percpu == NULL) {
		err = -ENOMEM;
		goto out2;
	}

	for_each_possible_cpu(cpu) {
		stream = per_cpu_ptr(percpu, cpu);
		stream->stream = msblk->decompressor->init(msblk, comp_opts);
		if (IS_ERR(stream->stream)) {
			err = PTR_ERR(stream->stream);
			goto out;
		}
	}

	kfree(comp_opts);
	return (__force void *) percpu;

out:
	for_each_possible_cpu(cpu0) {
		if (cpu0 == cpu)
			break;
		stream = per_cpu_ptr(percpu, cpu0);
		msblk->decompressor->free(stream->stream);
	}
	free_percpu(percpu);
out2:
	kfree(comp_opts);
	return ERR_PTR(err);
}

void squashfs_decompressor_destroy(struct squashfs_sb_info *msblk)
{
	struct squashfs_stream __percpu *percpu =
			(struct squashfs_stream __percpu *) msblk->stream;
	struct squashfs_stream *stream;
	int cpu;

	if (msblk->stream) {
		for_each_possible_cpu(cpu) {
			stream = per_cpu_ptr(percpu, cpu);
			msblk->decompressor->free(stream->stream);
		}
		free_percpu(percpu);
	}
}

int squashfs_decompress(struct squashfs_sb_info *msblk, struct buffer_head **bh,
	int b, int offset, int length, struct squashfs_page_actor *output)
{
	int res;
	struct squashfs_stream __percpu *percpu =
			(struct squashfs_stream __percpu *) msblk->stream;
	struct squashfs_stream *stream = get_cpu_ptr(percpu);

	res = msblk->decompressor->decompress(msblk, stream->stream, bh, b,
		offset, length, output);
	put_cpu_ptr(stream);

	if (res < 0)
		ERROR("%s decompression failed, data probably corrupt\n",
			msblk->decompressor->name);

	return res;
}

int squashfs_max_decompressors(void)
{
	return num_possible_cpus();
}
