#ifndef _LINUX_BATCH_COMPLETE_H
#define _LINUX_BATCH_COMPLETE_H

#include <linux/rbtree.h>

/*
 * Common stuff to the aio and block code for batch completion. Everything
 * important is elsewhere:
 */

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct batch_complete {
	struct bio_list		bio;
	struct rb_root		kiocb;
};

#endif
