/*
 * Blockconsole - write kernel console to a block device
 *
 * Copyright (C) 2012  Joern Engel <joern@logfs.org>
 */
#include <linux/bio.h>
#include <linux/blockconsole.h>
#include <linux/console.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/ctype.h>

#define BLOCKCONSOLE_MAGIC	"\nLinux blockconsole version 1.1\n"
#define BCON_UUID_OFS		(32)
#define BCON_ROUND_OFS		(41)
#define BCON_TILE_OFS		(50)
#define BCON_HEADERSIZE		(50)
#define BCON_LONG_HEADERSIZE	(59) /* with tile index */

#define PAGE_COUNT		(256)
#define SECTOR_COUNT		(PAGE_COUNT * (PAGE_SIZE >> 9))
#define CACHE_PAGE_MASK		(PAGE_COUNT - 1)
#define CACHE_SECTOR_MASK	(SECTOR_COUNT - 1)
#define CACHE_SIZE		(PAGE_COUNT << PAGE_SHIFT)
#define CACHE_MASK		(CACHE_SIZE - 1)
#define SECTOR_SHIFT		(9)
#define SECTOR_SIZE		(1 << SECTOR_SHIFT)
#define SECTOR_MASK		(~(SECTOR_SIZE-1))
#define PG_SECTOR_MASK		((PAGE_SIZE >> 9) - 1)

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

struct bcon_bio {
	struct bio bio;
	struct bio_vec bvec;
	void *sector;
	int in_flight;
};

struct blockconsole {
	char devname[32];
	spinlock_t end_io_lock;
	struct timer_list pad_timer;
	int error_count;
	struct kref kref;
	u64 console_bytes;
	u64 write_bytes;
	u64 max_bytes;
	u32 round;
	u32 uuid;
	struct bcon_bio bio_array[SECTOR_COUNT];
	struct page *pages;
	struct bcon_bio zero_bios[PAGE_COUNT];
	struct page *zero_page;
	struct block_device *bdev;
	struct console console;
	struct work_struct unregister_work;
	struct work_struct release_work;
	struct task_struct *writeback_thread;
	struct notifier_block panic_block;
};

static void bcon_get(struct blockconsole *bc)
{
	kref_get(&bc->kref);
}

static void __bcon_release(struct work_struct *work)
{
	struct blockconsole *bc = container_of(work, struct blockconsole,
			release_work);

	__free_pages(bc->zero_page, 0);
	__free_pages(bc->pages, 8);
	invalidate_mapping_pages(bc->bdev->bd_inode->i_mapping, 0, -1);
	blkdev_put(bc->bdev, FMODE_READ|FMODE_WRITE);
	kfree(bc);
}

static void bcon_release(struct kref *kref)
{
	struct blockconsole *bc = container_of(kref, struct blockconsole, kref);

	/* bcon_release can be called from atomic context */
	schedule_work(&bc->release_work);
}

static void bcon_put(struct blockconsole *bc)
{
	kref_put(&bc->kref, bcon_release);
}

static int __bcon_console_ofs(u64 console_bytes)
{
	return console_bytes & ~SECTOR_MASK;
}

static int bcon_console_ofs(struct blockconsole *bc)
{
	return __bcon_console_ofs(bc->console_bytes);
}

static int __bcon_console_sector(u64 console_bytes)
{
	return (console_bytes >> SECTOR_SHIFT) & CACHE_SECTOR_MASK;
}

static int bcon_console_sector(struct blockconsole *bc)
{
	return __bcon_console_sector(bc->console_bytes);
}

static int bcon_write_sector(struct blockconsole *bc)
{
	return (bc->write_bytes >> SECTOR_SHIFT) & CACHE_SECTOR_MASK;
}

static void clear_sector(void *sector)
{
	memset(sector, ' ', 511);
	memset(sector + 511, 10, 1);
}

static void bcon_init_first_page(struct blockconsole *bc)
{
	char *buf = page_address(bc->pages);
	size_t len = strlen(BLOCKCONSOLE_MAGIC);
	u32 tile = bc->console_bytes >> 20; /* We overflow after 4TB - fine */

	clear_sector(buf);
	memcpy(buf, BLOCKCONSOLE_MAGIC, len);
	sprintf(buf + BCON_UUID_OFS, "%08x", bc->uuid);
	sprintf(buf + BCON_ROUND_OFS, "%08x", bc->round);
	sprintf(buf + BCON_TILE_OFS, "%08x", tile);
	/* replace NUL with newline */
	buf[BCON_UUID_OFS + 8] = 10;
	buf[BCON_ROUND_OFS + 8] = 10;
	buf[BCON_TILE_OFS + 8] = 10;
}

static void bcon_advance_console_bytes(struct blockconsole *bc, int bytes)
{
	u64 old, new;

	do {
		old = bc->console_bytes;
		new = old + bytes;
		if (new >= bc->max_bytes)
			new = 0;
		if ((new & CACHE_MASK) == 0) {
			bcon_init_first_page(bc);
			new += BCON_LONG_HEADERSIZE;
		}
	} while (cmpxchg64(&bc->console_bytes, old, new) != old);
}

static void request_complete(struct bio *bio, int err)
{
	complete((struct completion *)bio->bi_private);
}

static int sync_read(struct blockconsole *bc, u64 ofs)
{
	struct bio bio;
	struct bio_vec bio_vec;
	struct completion complete;

	bio_init(&bio);
	bio.bi_io_vec = &bio_vec;
	bio_vec.bv_page = bc->pages;
	bio_vec.bv_len = SECTOR_SIZE;
	bio_vec.bv_offset = 0;
	bio.bi_vcnt = 1;
	bio.bi_idx = 0;
	bio.bi_size = SECTOR_SIZE;
	bio.bi_bdev = bc->bdev;
	bio.bi_sector = ofs >> SECTOR_SHIFT;
	init_completion(&complete);
	bio.bi_private = &complete;
	bio.bi_end_io = request_complete;

	submit_bio(READ, &bio);
	wait_for_completion(&complete);
	return test_bit(BIO_UPTODATE, &bio.bi_flags) ? 0 : -EIO;
}

static void bcon_erase_segment(struct blockconsole *bc)
{
	int i;

	for (i = 0; i < PAGE_COUNT; i++) {
		struct bcon_bio *bcon_bio = bc->zero_bios + i;
		struct bio *bio = &bcon_bio->bio;

		/*
		 * If the last erase hasn't finished yet, just skip it.  The log
		 * will look messy, but that's all.
		 */
		rmb();
		if (bcon_bio->in_flight)
			continue;
		bio_init(bio);
		bio->bi_io_vec = &bcon_bio->bvec;
		bio->bi_vcnt = 1;
		bio->bi_size = PAGE_SIZE;
		bio->bi_bdev = bc->bdev;
		bio->bi_private = bc;
		bio->bi_idx = 0;
		bio->bi_sector = (bc->write_bytes + i * PAGE_SIZE) >> 9;
		bcon_bio->in_flight = 1;
		wmb();
		/* We want the erase to go to the device first somehow */
		submit_bio(WRITE | REQ_SOFTBARRIER, bio);
	}
}

static void bcon_advance_write_bytes(struct blockconsole *bc, int bytes)
{
	bc->write_bytes += bytes;
	if (bc->write_bytes >= bc->max_bytes) {
		bc->write_bytes = 0;
		bcon_init_first_page(bc);
		bc->round++;
	}
}

static int bcon_find_end_of_log(struct blockconsole *bc)
{
	u64 start = 0, end = bc->max_bytes, middle;
	void *sec0 = bc->bio_array[0].sector;
	void *sec1 = bc->bio_array[1].sector;
	int err, version;

	err = sync_read(bc, 0);
	if (err)
		return err;
	/* Second sanity check, out of sheer paranoia */
	version = bcon_magic_present(sec0);
	if (!version)
		return -EINVAL;

	bc->uuid = simple_strtoull(sec0 + BCON_UUID_OFS, NULL, 16);
	bc->round = simple_strtoull(sec0 + BCON_ROUND_OFS, NULL, 16);

	memcpy(sec1, sec0, BCON_HEADERSIZE);
	for (;;) {
		middle = (start + end) / 2;
		middle &= ~CACHE_MASK;
		if (middle == start)
			break;
		err = sync_read(bc, middle);
		if (err)
			return err;
		if (memcmp(sec1, sec0, BCON_HEADERSIZE)) {
			/* If the two differ, we haven't written that far yet */
			end = middle;
		} else {
			start = middle;
		}
	}
	bc->console_bytes = bc->write_bytes = end;
	bcon_advance_console_bytes(bc, 0); /* To skip the header */
	bcon_advance_write_bytes(bc, 0); /* To wrap around, if necessary */
	bcon_erase_segment(bc);
	return 0;
}

static void bcon_unregister(struct work_struct *work)
{
	struct blockconsole *bc = container_of(work, struct blockconsole,
			unregister_work);

	atomic_notifier_chain_unregister(&panic_notifier_list, &bc->panic_block);
	unregister_console(&bc->console);
	del_timer_sync(&bc->pad_timer);
	kthread_stop(bc->writeback_thread);
	/* No new io will be scheduled anymore now */
	bcon_put(bc);
}

#define BCON_MAX_ERRORS	10
static void bcon_end_io(struct bio *bio, int err)
{
	struct bcon_bio *bcon_bio = container_of(bio, struct bcon_bio, bio);
	struct blockconsole *bc = bio->bi_private;
	unsigned long flags;

	/*
	 * We want to assume the device broken and free this console if
	 * we accumulate too many errors.  But if errors are transient,
	 * we also want to forget about them once writes succeed again.
	 * Oh, and we only want to reset the counter if it hasn't reached
	 * the limit yet, so we don't bcon_put() twice from here.
	 */
	spin_lock_irqsave(&bc->end_io_lock, flags);
	if (err) {
		if (bc->error_count++ == BCON_MAX_ERRORS) {
			pr_info("no longer logging to %s\n", bc->devname);
			schedule_work(&bc->unregister_work);
		}
	} else {
		if (bc->error_count && bc->error_count < BCON_MAX_ERRORS)
			bc->error_count = 0;
	}
	/*
	 * Add padding (a bunch of spaces and a newline) early so bcon_pad
	 * only has to advance a pointer.
	 */
	clear_sector(bcon_bio->sector);
	bcon_bio->in_flight = 0;
	spin_unlock_irqrestore(&bc->end_io_lock, flags);
	bcon_put(bc);
}

static void bcon_writesector(struct blockconsole *bc, int index)
{
	struct bcon_bio *bcon_bio = bc->bio_array + index;
	struct bio *bio = &bcon_bio->bio;

	rmb();
	if (bcon_bio->in_flight)
		return;
	bcon_get(bc);

	bio_init(bio);
	bio->bi_io_vec = &bcon_bio->bvec;
	bio->bi_vcnt = 1;
	bio->bi_size = SECTOR_SIZE;
	bio->bi_bdev = bc->bdev;
	bio->bi_private = bc;
	bio->bi_end_io = bcon_end_io;

	bio->bi_idx = 0;
	bio->bi_sector = bc->write_bytes >> 9;
	bcon_bio->in_flight = 1;
	wmb();
	submit_bio(WRITE, bio);
}

static int bcon_writeback(void *_bc)
{
	struct blockconsole *bc = _bc;
	struct sched_param(sp);

	sp.sched_priority = MAX_RT_PRIO - 1; /* Highest realtime prio */
	sched_setscheduler_nocheck(current, SCHED_FIFO, &sp);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		if (kthread_should_stop())
			break;
		while (bcon_write_sector(bc) != bcon_console_sector(bc)) {
			bcon_writesector(bc, bcon_write_sector(bc));
			bcon_advance_write_bytes(bc, SECTOR_SIZE);
			if (bcon_write_sector(bc) == 0)
				bcon_erase_segment(bc);
		}
	}
	return 0;
}

static void bcon_pad(unsigned long data)
{
	struct blockconsole *bc = (void *)data;
	unsigned int n;

	/*
	 * We deliberately race against bcon_write here.  If we lose the race,
	 * our padding is no longer where we expected it to be, i.e. it is
	 * no longer a bunch of spaces with a newline at the end.  There could
	 * not be a newline at all or it could be somewhere in the middle.
	 * Either way, the log corruption is fairly obvious to spot and ignore
	 * for human readers.
	 */
	n = SECTOR_SIZE - bcon_console_ofs(bc);
	if (n != SECTOR_SIZE) {
		bcon_advance_console_bytes(bc, n);
		wake_up_process(bc->writeback_thread);
	}
}

static void bcon_write(struct console *console, const char *msg,
		unsigned int len)
{
	struct blockconsole *bc = container_of(console, struct blockconsole,
			console);
	unsigned int n;
	u64 console_bytes;
	int i;

	while (len) {
		console_bytes = bc->console_bytes;
		i = __bcon_console_sector(console_bytes);
		rmb();
		if (bc->bio_array[i].in_flight)
			break;
		n = min_t(int, len, SECTOR_SIZE -
				__bcon_console_ofs(console_bytes));
		memcpy(bc->bio_array[i].sector +
				__bcon_console_ofs(console_bytes), msg, n);
		len -= n;
		msg += n;
		bcon_advance_console_bytes(bc, n);
	}
	wake_up_process(bc->writeback_thread);
	mod_timer(&bc->pad_timer, jiffies + HZ);
}

static void bcon_init_bios(struct blockconsole *bc)
{
	int i;

	for (i = 0; i < SECTOR_COUNT; i++) {
		int page_index = i >> (PAGE_SHIFT - SECTOR_SHIFT);
		struct page *page = bc->pages + page_index;
		struct bcon_bio *bcon_bio = bc->bio_array + i;
		struct bio_vec *bvec = &bcon_bio->bvec;

		bcon_bio->in_flight = 0;
		bcon_bio->sector = page_address(bc->pages + page_index)
			+ SECTOR_SIZE * (i & PG_SECTOR_MASK);
		clear_sector(bcon_bio->sector);
		bvec->bv_page = page;
		bvec->bv_len = SECTOR_SIZE;
		bvec->bv_offset = SECTOR_SIZE * (i & PG_SECTOR_MASK);
	}
}

static void bcon_init_zero_bio(struct blockconsole *bc)
{
	int i;

	memset(page_address(bc->zero_page), 0, PAGE_SIZE);
	for (i = 0; i < PAGE_COUNT; i++) {
		struct bcon_bio *bcon_bio = bc->zero_bios + i;
		struct bio_vec *bvec = &bcon_bio->bvec;

		bcon_bio->in_flight = 0;
		bvec->bv_page = bc->zero_page;
		bvec->bv_len = PAGE_SIZE;
		bvec->bv_offset = 0;
	}
}

static int blockconsole_panic(struct notifier_block *this, unsigned long event,
		void *ptr)
{
	struct blockconsole *bc = container_of(this, struct blockconsole,
			panic_block);
	unsigned int n;

	n = SECTOR_SIZE - bcon_console_ofs(bc);
	if (n != SECTOR_SIZE)
		bcon_advance_console_bytes(bc, n);
	bcon_writeback(bc);
	return NOTIFY_DONE;
}

static int bcon_create(const char *devname)
{
	const fmode_t mode = FMODE_READ | FMODE_WRITE;
	struct blockconsole *bc;
	int err;

	bc = kzalloc(sizeof(*bc), GFP_KERNEL);
	if (!bc)
		return -ENOMEM;
	memset(bc->devname, ' ', sizeof(bc->devname));
	strlcpy(bc->devname, devname, sizeof(bc->devname));
	spin_lock_init(&bc->end_io_lock);
	strcpy(bc->console.name, "bcon");
	bc->console.flags = CON_PRINTBUFFER | CON_ENABLED | CON_ALLDATA;
	bc->console.write = bcon_write;
	bc->bdev = blkdev_get_by_path(devname, mode, NULL);
#ifndef MODULE
	if (IS_ERR(bc->bdev)) {
		dev_t devt = name_to_dev_t(devname);
		if (devt)
			bc->bdev = blkdev_get_by_dev(devt, mode, NULL);
	}
#endif
	if (IS_ERR(bc->bdev))
		goto out;
	bc->pages = alloc_pages(GFP_KERNEL, 8);
	if (!bc->pages)
		goto out;
	bc->zero_page = alloc_pages(GFP_KERNEL, 0);
	if (!bc->zero_page)
		goto out1;
	bcon_init_bios(bc);
	bcon_init_zero_bio(bc);
	setup_timer(&bc->pad_timer, bcon_pad, (unsigned long)bc);
	bc->max_bytes = bc->bdev->bd_inode->i_size & ~CACHE_MASK;
	err = bcon_find_end_of_log(bc);
	if (err)
		goto out2;
	kref_init(&bc->kref); /* This reference gets freed on errors */
	bc->writeback_thread = kthread_run(bcon_writeback, bc, "bcon_%s",
			devname);
	if (IS_ERR(bc->writeback_thread))
		goto out2;
	INIT_WORK(&bc->unregister_work, bcon_unregister);
	INIT_WORK(&bc->release_work, __bcon_release);
	register_console(&bc->console);
	bc->panic_block.notifier_call = blockconsole_panic;
	bc->panic_block.priority = INT_MAX;
	atomic_notifier_chain_register(&panic_notifier_list, &bc->panic_block);
	pr_info("now logging to %s at %llx\n", devname, bc->console_bytes >> 20);

	return 0;

out2:
	__free_pages(bc->zero_page, 0);
out1:
	__free_pages(bc->pages, 8);
out:
	kfree(bc);
	/* Not strictly correct, be the caller doesn't care */
	return -ENOMEM;
}

static void bcon_create_fuzzy(const char *name)
{
	char *longname;
	int err;

	err = bcon_create(name);
	if (err) {
		longname = kzalloc(strlen(name) + 6, GFP_KERNEL);
		if (!longname)
			return;
		strcpy(longname, "/dev/");
		strcat(longname, name);
		bcon_create(longname);
		kfree(longname);
	}
}

static DEFINE_SPINLOCK(bcon_device_lock);
static char scanned_devices[80];

static void bcon_do_add(struct work_struct *work)
{
	char local_devices[80], *name, *remainder = local_devices;

	spin_lock(&bcon_device_lock);
	memcpy(local_devices, scanned_devices, sizeof(local_devices));
	memset(scanned_devices, 0, sizeof(scanned_devices));
	spin_unlock(&bcon_device_lock);

	while (remainder && remainder[0]) {
		name = strsep(&remainder, ",");
		bcon_create_fuzzy(name);
	}
}

static DECLARE_WORK(bcon_add_work, bcon_do_add);

void bcon_add(const char *name)
{
	/*
	 * We add each name to a small static buffer and ask for a workqueue
	 * to go pick it up asap.  Once it is picked up, the buffer is empty
	 * again, so hopefully it will suffice for all sane users.
	 */
	spin_lock(&bcon_device_lock);
	if (scanned_devices[0])
		strncat(scanned_devices, ",", sizeof(scanned_devices));
	strncat(scanned_devices, name, sizeof(scanned_devices));
	spin_unlock(&bcon_device_lock);
	schedule_work(&bcon_add_work);
}

/*
 * Check if we have an 8-digit hex number followed by newline
 */
static bool is_four_byte_hex(const void *data)
{
	const char *str = data;
	int len = 0;

	while (isxdigit(*str) && len++ < 9)
		str++;

	if (len != 8)
		return false;

	/* str should point to a \n now */
	if (*str != 0xa)
		return false;

	return true;
}

int bcon_magic_present(const void *data)
{
	size_t len = strlen(BLOCKCONSOLE_MAGIC);

	if (memcmp(data, BLOCKCONSOLE_MAGIC, len))
		return 0;
	if (!is_four_byte_hex(data + BCON_UUID_OFS))
		return 0;
	if (!is_four_byte_hex(data + BCON_ROUND_OFS))
		return 0;
	if (!is_four_byte_hex(data + BCON_TILE_OFS))
		return 0;
	return 11;
}
