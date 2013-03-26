#define pr_fmt(fmt) "%s: " fmt "\n", __func__

#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/percpu-refcount.h>
#include <linux/rcupdate.h>

/*
 * A percpu refcount can be in 4 different modes. The state is tracked in the
 * low two bits of percpu_ref->pcpu_count:
 *
 * PCPU_REF_NONE - the initial state, no percpu counters allocated.
 *
 * PCPU_REF_PTR - using percpu counters for the refcount.
 *
 * PCPU_REF_DYING - we're shutting down so get()/put() should use the embedded
 * atomic counter, but we're not finished updating the atomic counter from the
 * percpu counters - this means that percpu_ref_put() can't check for the ref
 * hitting 0 yet.
 *
 * PCPU_REF_DEAD - we've finished the teardown sequence, percpu_ref_put() should
 * now check for the ref hitting 0.
 *
 * In PCPU_REF_NONE mode, we need to count the number of times percpu_ref_get()
 * is called; this is done with the high bits of the raw atomic counter. We also
 * track the time, in jiffies, when the get count last wrapped - this is done
 * with the remaining bits of percpu_ref->percpu_count.
 *
 * So, when percpu_ref_get() is called it increments the get count and checks if
 * it wrapped; if it did, it checks if the last time it wrapped was less than
 * one second ago; if so, we want to allocate percpu counters.
 *
 * PCPU_COUNT_BITS determines the threshold where we convert to percpu: of the
 * raw 64 bit counter, we use PCPU_COUNT_BITS for the refcount, and the
 * remaining (high) bits to count the number of times percpu_ref_get() has been
 * called. It's currently (completely arbitrarily) 16384 times in one second.
 *
 * Percpu mode (PCPU_REF_PTR):
 *
 * In percpu mode all we do on get and put is increment or decrement the cpu
 * local counter, which is a 32 bit unsigned int.
 *
 * Note that all the gets() could be happening on one cpu, and all the puts() on
 * another - the individual cpu counters can wrap (potentially many times).
 *
 * But this is fine because we don't need to check for the ref hitting 0 in
 * percpu mode; before we set the state to PCPU_REF_DEAD we simply sum up all
 * the percpu counters and add them to the atomic counter. Since addition and
 * subtraction in modular arithmatic is still associative, the result will be
 * correct.
 */

#define PCPU_COUNT_BITS		50
#define PCPU_COUNT_MASK		((1LL << PCPU_COUNT_BITS) - 1)

#define PCPU_STATUS_BITS	2
#define PCPU_STATUS_MASK	((1 << PCPU_STATUS_BITS) - 1)

#define PCPU_REF_PTR		0
#define PCPU_REF_NONE		1
#define PCPU_REF_DYING		2
#define PCPU_REF_DEAD		3

#define REF_STATUS(count)	(count & PCPU_STATUS_MASK)

/**
 * percpu_ref_init - initialize a dynamic percpu refcount
 *
 * Initializes the refcount in single atomic counter mode with a refcount of 1;
 * analagous to atomic_set(ref, 1).
 */
void percpu_ref_init(struct percpu_ref *ref)
{
	unsigned long now = jiffies;

	atomic64_set(&ref->count, 1);

	now <<= PCPU_STATUS_BITS;
	now |= PCPU_REF_NONE;

	ref->pcpu_count = now;
}

static void percpu_ref_alloc(struct percpu_ref *ref, unsigned long pcpu_count)
{
	unsigned long new, now = jiffies;

	now <<= PCPU_STATUS_BITS;
	now |= PCPU_REF_NONE;

	if (now - pcpu_count <= HZ << PCPU_STATUS_BITS) {
		rcu_read_unlock();
		new = (unsigned long) alloc_percpu(unsigned);
		rcu_read_lock();

		if (!new)
			goto update_time;

		BUG_ON(new & PCPU_STATUS_MASK);

		if (cmpxchg(&ref->pcpu_count, pcpu_count, new) != pcpu_count)
			free_percpu((void __percpu *) new);
		else
			pr_debug("created");
	} else {
update_time:
		new = now;
		cmpxchg(&ref->pcpu_count, pcpu_count, new);
	}
}

void __percpu_ref_get(struct percpu_ref *ref, bool alloc)
{
	unsigned long pcpu_count;
	uint64_t v;

	pcpu_count = ACCESS_ONCE(ref->pcpu_count);

	if (REF_STATUS(pcpu_count) == PCPU_REF_PTR) {
		/* for rcu - we're not using rcu_dereference() */
		smp_read_barrier_depends();
		__this_cpu_inc(*((unsigned __percpu *) pcpu_count));
	} else {
		v = atomic64_add_return(1 + (1ULL << PCPU_COUNT_BITS),
					&ref->count);

		if (!(v >> PCPU_COUNT_BITS) &&
		    REF_STATUS(pcpu_count) == PCPU_REF_NONE && alloc)
			percpu_ref_alloc(ref, pcpu_count);
	}
}

/**
 * percpu_ref_put - decrement a dynamic percpu refcount
 *
 * Returns true if the result is 0, otherwise false; only checks for the ref
 * hitting 0 after percpu_ref_kill() has been called. Analagous to
 * atomic_dec_and_test().
 */
int percpu_ref_put(struct percpu_ref *ref)
{
	unsigned long pcpu_count;
	uint64_t v;
	int ret = 0;

	rcu_read_lock();

	pcpu_count = ACCESS_ONCE(ref->pcpu_count);

	switch (REF_STATUS(pcpu_count)) {
	case PCPU_REF_PTR:
		/* for rcu - we're not using rcu_dereference() */
		smp_read_barrier_depends();
		__this_cpu_dec(*((unsigned __percpu *) pcpu_count));
		break;
	case PCPU_REF_NONE:
	case PCPU_REF_DYING:
		atomic64_dec(&ref->count);
		break;
	case PCPU_REF_DEAD:
		v = atomic64_dec_return(&ref->count);
		v &= PCPU_COUNT_MASK;

		ret = v == 0;
		break;
	}

	rcu_read_unlock();

	return ret;
}

/**
 * percpu_ref_kill - prepare a dynamic percpu refcount for teardown
 *
 * Must be called before dropping the initial ref, so that percpu_ref_put()
 * knows to check for the refcount hitting 0. If the refcount was in percpu
 * mode, converts it back to single atomic counter mode.
 *
 * Returns true the first time called on @ref and false if @ref is already
 * shutting down, so it may be used by the caller for synchronizing other parts
 * of a two stage shutdown.
 */
int percpu_ref_kill(struct percpu_ref *ref)
{
	unsigned long old, new, status, pcpu_count;

	pcpu_count = ACCESS_ONCE(ref->pcpu_count);

	do {
		status = REF_STATUS(pcpu_count);

		switch (status) {
		case PCPU_REF_PTR:
			new = PCPU_REF_DYING;
			break;
		case PCPU_REF_NONE:
			new = PCPU_REF_DEAD;
			break;
		case PCPU_REF_DYING:
		case PCPU_REF_DEAD:
			return 0;
		}

		old = pcpu_count;
		pcpu_count = cmpxchg(&ref->pcpu_count, old, new);
	} while (pcpu_count != old);

	if (status == PCPU_REF_PTR) {
		unsigned count = 0, cpu;

		synchronize_rcu();

		for_each_possible_cpu(cpu)
			count += *per_cpu_ptr((unsigned __percpu *) pcpu_count, cpu);

		pr_debug("global %lli pcpu %i",
			 atomic64_read(&ref->count) & PCPU_COUNT_MASK,
			 (int) count);

		atomic64_add((int) count, &ref->count);
		smp_wmb();
		/* Between setting global count and setting PCPU_REF_DEAD */
		ref->pcpu_count = PCPU_REF_DEAD;

		free_percpu((unsigned __percpu *) pcpu_count);
	}

	return 1;
}

/**
 * percpu_ref_dead - check if a dynamic percpu refcount is shutting down
 *
 * Returns true if percpu_ref_kill() has been called on @ref, false otherwise.
 */
int percpu_ref_dead(struct percpu_ref *ref)
{
	unsigned status = REF_STATUS(ref->pcpu_count);

	return status == PCPU_REF_DYING ||
		status == PCPU_REF_DEAD;
}
