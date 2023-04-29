#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/bvec.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/spinlock_types.h>

#include <linux/fs.h>
#include <linux/blkdev.h>

#define SBDD_SECTOR_SHIFT      9
#define SBDD_SECTOR_SIZE       (1 << SBDD_SECTOR_SHIFT)
#define SBDD_MIB_SECTORS       (1 << (20 - SBDD_SECTOR_SHIFT))
#define SBDD_NAME              "sbdd"

enum dev_mode {
	RAMDRIVE,
	BLKDEV
};

struct sbdd {
	wait_queue_head_t       exitwait;
	spinlock_t              datalock;
	atomic_t                deleting;
	atomic_t                refs_cnt;
	sector_t                capacity;
	u8                      *data;
	struct gendisk          *gd;
	struct request_queue    *q;
	void (*process_bio)(struct bio *bio);
	struct block_device		*blk_dev;
	sector_t 				start_sect;
};

static struct sbdd      __sbdd;
static int              __sbdd_major = 0;
static unsigned long    __sbdd_capacity_mib = 100;
static char *__devname  = NULL;
static int dev_mode 	= RAMDRIVE;

static void sbdd_xfer_bio_ram(struct bio *bio);
static void sbdd_xfer_bio_blkdev(struct bio *bio);
static void __dealloc_ramdrive(void);
static int __alloc_ramdrive(void);


static int devmode_op_write_handler(const char *val, const struct kernel_param *kp) {

	//TODO: Add On the fly mode change
	char valcp[16];
	char *s;

	strncpy(valcp, val, 16);
	valcp[15] = '\0';
	
	s = strstrip(valcp);

	if (strcmp(s, "ram") == 0)
	{
		if(dev_mode == BLKDEV)
		{
			dev_mode = RAMDRIVE;
		}
		return 0;
	}
	else if (strcmp(s, "blkdev") == 0)
	{
		if(dev_mode == RAMDRIVE)
		{
			dev_mode = BLKDEV;
		}
		return 0;
	}
	else
		return -EINVAL;
};

static int devmode_op_read_handler(char *buffer, const struct kernel_param *kp) {
	switch (dev_mode) {
	case RAMDRIVE:
		strcpy(buffer, "ram");
		break;

	case BLKDEV:
		strcpy(buffer, "blkdev");
		break;

	default:
		strcpy(buffer, "error");
		break;
	}
	return strlen(buffer);
}

static int __acquire_blkdev(void) {
	if (__devname == NULL)
	{
		pr_err("No name for block device provided");
		return -EINVAL;
	}
	__sbdd.blk_dev = blkdev_get_by_path(__devname, FMODE_READ | FMODE_WRITE | FMODE_EXCL, THIS_MODULE);
	if (IS_ERR(__sbdd.blk_dev))
	{
		pr_err("Error occured during opening of block_device");
		return -EINVAL;
	}
	pr_info("acquired block device %s", __sbdd.blk_dev->bd_disk->disk_name);
	pr_info("with partition number %d", __sbdd.blk_dev->bd_partno);
	return 0;
}

static void __release_blkdev(void) {
	blkdev_put(__sbdd.blk_dev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
}

static void __dealloc_ramdrive(void) {
	if (__sbdd.data) {
		pr_info("freeing data\n");
		vfree(__sbdd.data);
	}
}

static int __alloc_ramdrive(void) {
	__sbdd.data = vzalloc(__sbdd.capacity << SBDD_SECTOR_SHIFT);
	if (!__sbdd.data) {
		pr_err("unable to alloc data\n");
		return -ENOMEM;
	}
	pr_info("allocated RAMdisk");
	return 0;
}

static sector_t sbdd_xfer(struct bio_vec* bvec, sector_t pos, int dir)
{
	void *buff = page_address(bvec->bv_page) + bvec->bv_offset;
	sector_t len = bvec->bv_len >> SBDD_SECTOR_SHIFT;
	size_t offset;
	size_t nbytes;

	if (pos + len > __sbdd.capacity)
		len = __sbdd.capacity - pos;

	offset = pos << SBDD_SECTOR_SHIFT;
	nbytes = len << SBDD_SECTOR_SHIFT;

	spin_lock(&__sbdd.datalock);
	if (dir)
		memcpy(__sbdd.data + offset, buff, nbytes);
	else
		memcpy(buff, __sbdd.data + offset, nbytes);
	spin_unlock(&__sbdd.datalock);

	pr_info("pos=%6llu len=%4llu %s\n", pos, len, dir ? "written" : "read");

	return len;
}

static void blkdev_end_io(struct bio *bio) {
	struct bio *b = bio->bi_private;
	pr_info("Ended BIO request (I suppose?)");
	bio_put(bio);
	pr_info("Put done BIO");
	bio_endio(b);
	pr_info("Ended initial BIO");
}

static void sbdd_xfer_bio_blkdev(struct bio *bio) {
	struct bio *new_bio = bio_clone_fast(bio, GFP_NOIO, &fs_bio_set);
	bio_set_dev(new_bio, __sbdd.blk_dev);
	pr_info("New BIO start and length %d %d", new_bio->bi_iter.bi_sector, new_bio->bi_iter.bi_size >> SBDD_SECTOR_SHIFT);
	pr_info("BIOs op flags: old %X, new %X", bio->bi_opf, new_bio->bi_opf);
	new_bio->bi_private = bio;
	new_bio->bi_end_io = blkdev_end_io;
	submit_bio(new_bio);
	pr_info("Submitted new BIO");
}

static void sbdd_xfer_bio_ram(struct bio *bio)
{
	struct bvec_iter iter;
	struct bio_vec bvec;
	int dir = bio_data_dir(bio);
	sector_t pos = bio->bi_iter.bi_sector;

	bio_for_each_segment(bvec, bio, iter)
		pos += sbdd_xfer(&bvec, pos, dir);
	
	bio_endio(bio);
}

static blk_qc_t sbdd_make_request(struct request_queue *q, struct bio *bio)
{
	if (atomic_read(&__sbdd.deleting)) {
		pr_err("unable to process bio while deleting\n");
		bio_io_error(bio);
		return BLK_STS_IOERR;
	}

	atomic_inc(&__sbdd.refs_cnt);

	__sbdd.process_bio(bio);

	if (atomic_dec_and_test(&__sbdd.refs_cnt))
		wake_up(&__sbdd.exitwait);

	return BLK_STS_OK;
}

/*
There are no read or write operations. These operations are performed by
the request() function associated with the request queue of the disk.
*/
static struct block_device_operations const __sbdd_bdev_ops = {
	.owner = THIS_MODULE,
};

static int sbdd_create(void)
{
	int ret = 0;

	/*
	This call is somewhat redundant, but used anyways by tradition.
	The number is to be displayed in /proc/devices (0 for auto).
	*/
	pr_info("registering blkdev\n");
	__sbdd_major = register_blkdev(0, SBDD_NAME);
	if (__sbdd_major < 0) {
		pr_err("call register_blkdev() failed with %d\n", __sbdd_major);
		return -EBUSY;
	}

	memset(&__sbdd, 0, sizeof(struct sbdd));
	
	pr_info("allocating data\n");
	if (dev_mode == RAMDRIVE)
	{
		__sbdd.capacity = (sector_t)__sbdd_capacity_mib * SBDD_MIB_SECTORS;
		int ret_alloc_ram = __alloc_ramdrive();
		if(ret_alloc_ram)
		{
			pr_err("__alloc_ramdrive returned %d", ret_alloc_ram);
			return -EINVAL;
		}
		__sbdd.process_bio = sbdd_xfer_bio_ram;
	}
	else if (dev_mode == BLKDEV) {
		int ret_acq_blkdev = __acquire_blkdev();
		if(ret_acq_blkdev) {
			pr_err("__acquire_blkdev returned %d", ret_acq_blkdev);
			return -EINVAL;
		}
		__sbdd.process_bio = sbdd_xfer_bio_blkdev;
		__sbdd.capacity = disk_get_part(__sbdd.blk_dev->bd_disk, __sbdd.blk_dev->bd_partno)->nr_sects;
		__sbdd.start_sect = disk_get_part(__sbdd.blk_dev->bd_disk, __sbdd.blk_dev->bd_partno)->start_sect;
	}
	else
		{
			pr_err("Unknown device mode");
			return -EINVAL;
		}

	spin_lock_init(&__sbdd.datalock);
	init_waitqueue_head(&__sbdd.exitwait);

	pr_info("allocating queue\n");
	__sbdd.q = blk_alloc_queue(GFP_KERNEL);
	if (!__sbdd.q) {
		pr_err("call blk_alloc_queue() failed\n");
		return -EINVAL;
	}
	blk_queue_make_request(__sbdd.q, sbdd_make_request);

	/* Configure queue */
	blk_queue_logical_block_size(__sbdd.q, SBDD_SECTOR_SIZE);

	/* A disk must have at least one minor */
	pr_info("allocating disk\n");
	__sbdd.gd = alloc_disk(1);

	/* Configure gendisk */
	__sbdd.gd->queue = __sbdd.q;
	__sbdd.gd->major = __sbdd_major;
	__sbdd.gd->first_minor = 0;
	__sbdd.gd->fops = &__sbdd_bdev_ops;
	/* Represents name in /proc/partitions and /sys/block */
	scnprintf(__sbdd.gd->disk_name, DISK_NAME_LEN, SBDD_NAME);
	set_capacity(__sbdd.gd, __sbdd.capacity);

	/*
	Allocating gd does not make it available, add_disk() required.
	After this call, gd methods can be called at any time. Should not be
	called before the driver is fully initialized and ready to process reqs.
	*/
	pr_info("adding disk\n");
	add_disk(__sbdd.gd);

	return ret;
}

static void sbdd_delete(void)
{
	atomic_set(&__sbdd.deleting, 1);

	wait_event(__sbdd.exitwait, !atomic_read(&__sbdd.refs_cnt));

	/* gd will be removed only after the last reference put */
	if (__sbdd.gd) {
		pr_info("deleting disk\n");
		del_gendisk(__sbdd.gd);
	}

	if (__sbdd.q) {
		pr_info("cleaning up queue\n");
		blk_cleanup_queue(__sbdd.q);
	}

	if (__sbdd.gd)
		put_disk(__sbdd.gd);

	if (dev_mode == RAMDRIVE)
		__dealloc_ramdrive();
	else if (dev_mode == BLKDEV) {
		__release_blkdev();
	}

	memset(&__sbdd, 0, sizeof(struct sbdd));

	if (__sbdd_major > 0) {
		pr_info("unregistering blkdev\n");
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		__sbdd_major = 0;
	}
}

/*
Note __init is for the kernel to drop this function after
initialization complete making its memory available for other uses.
There is also __initdata note, same but used for variables.
*/
static int __init sbdd_init(void)
{
	int ret = 0;

	pr_info("starting initialization...\n");
	ret = sbdd_create();

	if (ret) {
		pr_warn("initialization failed\n");
		sbdd_delete();
	} else {
		pr_info("initialization complete\n");
	}

	return ret;
}

/*
Note __exit is for the compiler to place this code in a special ELF section.
Sometimes such functions are simply discarded (e.g. when module is built
directly into the kernel). There is also __exitdata note.
*/
static void __exit sbdd_exit(void)
{
	pr_info("exiting...\n");
	sbdd_delete();
	pr_info("exiting complete\n");
}


static const struct kernel_param_ops devmode_op_ops = {
	.set = devmode_op_write_handler,
	.get = devmode_op_read_handler
};

/* Called on module loading. Is mandatory. */
module_init(sbdd_init);

/* Called on module unloading. Unloading module is not allowed without it. */
module_exit(sbdd_exit);

/* Set desired capacity with insmod */
module_param_named(capacity_mib, __sbdd_capacity_mib, ulong, 0444);
module_param_named(block_device, __devname, charp, 0444);
module_param_cb(device_mode, &devmode_op_ops, NULL, 0664);

/* Note for the kernel: a free license module. A warning will be outputted without it. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple Block Device Driver");
