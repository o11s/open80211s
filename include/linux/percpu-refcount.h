/*
 * Dynamic percpu refcounts:
 * (C) 2012 Google, Inc.
 * Author: Kent Overstreet <koverstreet@google.com>
 *
 * This implements a refcount with similar semantics to atomic_t - atomic_inc(),
 * atomic_dec_and_test() - but potentially percpu.
 *
 * There's one important difference between percpu refs and normal atomic_t
 * refcounts; you have to keep track of your initial refcount, and then when you
 * start shutting down you call percpu_ref_kill() _before_ dropping the initial
 * refcount.
 *
 * Before you call percpu_ref_kill(), percpu_ref_put() does not check for the
 * refcount hitting 0 - it can't, if it was in percpu mode. percpu_ref_kill()
 * puts the ref back in single atomic_t mode, collecting the per cpu refs and
 * issuing the appropriate barriers, and then marks the ref as shutting down so
 * that percpu_ref_put() will check for the ref hitting 0.  After it returns,
 * it's safe to drop the initial ref.
 *
 * BACKGROUND:
 *
 * Percpu refcounts are quite useful for performance, but if we blindly
 * converted all refcounts to percpu counters we'd waste quite a bit of memory.
 *
 * Think about all the refcounts embedded in kobjects, files, etc. most of which
 * aren't used much. These start out as simple atomic counters - a little bigger
 * than a bare atomic_t, 16 bytes instead of 4 - but if we exceed some arbitrary
 * number of gets in one second, we then switch to percpu counters.
 *
 * This heuristic isn't perfect because it'll fire if the refcount was only
 * being used on one cpu; ideally we'd be able to count the number of cache
 * misses on percpu_ref_get() or something similar, but that'd make the non
 * percpu path significantly heavier/more complex. We can count the number of
 * gets() without any extra atomic instructions on arches that support
 * atomic64_t - simply by changing the atomic_inc() to atomic_add_return().
 *
 * USAGE:
 *
 * See fs/aio.c for some example usage; it's used there for struct kioctx, which
 * is created when userspaces calls io_setup(), and destroyed when userspace
 * calls io_destroy() or the process exits.
 *
 * In the aio code, kill_ioctx() is called when we wish to destroy a kioctx; it
 * calls percpu_ref_kill(), then hlist_del_rcu() and sychronize_rcu() to remove
 * the kioctx from the proccess's list of kioctxs - after that, there can't be
 * any new users of the kioctx (from lookup_ioctx()) and it's then safe to drop
 * the initial ref with percpu_ref_put().
 *
 * Code that does a two stage shutdown like this often needs some kind of
 * explicit synchronization to ensure the initial refcount can only be dropped
 * once - percpu_ref_kill() does this for you, it returns true once and false if
 * someone else already called it. The aio code uses it this way, but it's not
 * necessary if the code has some other mechanism to synchronize teardown.
 *
 * As mentioned previously, we decide when to convert a ref to percpu counters
 * in percpu_ref_get(). However, since percpu_ref_get() will often be called
 * with rcu_read_lock() held, it's not done there - percpu_ref_get() returns
 * true if the ref should be converted to percpu counters.
 *
 * The caller should then call percpu_ref_alloc() after dropping
 * rcu_read_lock(); if there is an uncommonly used codepath where it's
 * inconvenient to call percpu_ref_alloc() after get(), it may be safely skipped
 * and percpu_ref_get() will return true again the next time the counter wraps
 * around.
 */

#ifndef _LINUX_PERCPU_REFCOUNT_H
#define _LINUX_PERCPU_REFCOUNT_H

#include <linux/atomic.h>
#include <linux/percpu.h>

struct percpu_ref {
	atomic64_t		count;
	unsigned long		pcpu_count;
};

void percpu_ref_init(struct percpu_ref *ref);
void __percpu_ref_get(struct percpu_ref *ref, bool alloc);
int percpu_ref_put(struct percpu_ref *ref);

int percpu_ref_kill(struct percpu_ref *ref);
int percpu_ref_dead(struct percpu_ref *ref);

/**
 * percpu_ref_get - increment a dynamic percpu refcount
 *
 * Increments @ref and possibly converts it to percpu counters. Must be called
 * with rcu_read_lock() held, and may potentially drop/reacquire rcu_read_lock()
 * to allocate percpu counters - if sleeping/allocation isn't safe for some
 * other reason (e.g. a spinlock), see percpu_ref_get_noalloc().
 *
 * Analagous to atomic_inc().
  */
static inline void percpu_ref_get(struct percpu_ref *ref)
{
	__percpu_ref_get(ref, true);
}

/**
 * percpu_ref_get_noalloc - increment a dynamic percpu refcount
 *
 * Increments @ref, to be used when it's not safe to allocate percpu counters.
 * Must be called with rcu_read_lock() held.
 *
 * Analagous to atomic_inc().
  */
static inline void percpu_ref_get_noalloc(struct percpu_ref *ref)
{
	__percpu_ref_get(ref, false);
}

#endif
