/*
 * Kernel Device Mapper for abstracting ZAC/ZBC devices as normal
 * block devices for linux file systems.
 *
 * Copyright (C) 2015 Seagate Technology PLC
 *
 * Written by:
 * Shaun Tancheff <shaun.tancheff@seagate.com>
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "dm.h"
#include <linux/dm-io.h>
#include <linux/init.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/crc32c.h>
#include <linux/crc16.h>
#include <linux/sort.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/blk-zoned-ctrl.h>
#include <linux/timer.h>
#include <linux/delay.h>

#include "dm-zoned.h"

/*
 * FUTURE FIXME:
 * Current sd.c does not swizzle on report zones and no
 * scsi native drives exists so ... therefore all results are
 * little endian ...
 * When sd.c translates the output of report zones
 * then remove the 'everything is little endian' assumption.
 */
#define REPORT_ZONES_LE_ONLY 1

#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRId32 "d"

static inline char *_zdisk(struct zoned *znd)
{
	return znd->bdev_name;
}

#define Z_ERR(znd, fmt, arg...) \
	pr_err("dm-zoned(%s): " fmt "\n", _zdisk(znd), ## arg)

#define Z_INFO(znd, fmt, arg...) \
	pr_info("dm-zoned(%s): " fmt "\n", _zdisk(znd), ## arg)

#define Z_DBG(znd, fmt, arg...) \
	pr_debug("dm-zoned(%s): " fmt "\n", _zdisk(znd), ## arg)

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
static int dev_is_congested(struct dm_dev *dev, int bdi_bits);
static int zoned_is_congested(struct dm_target_callbacks *cb, int bdi_bits);
static int zoned_ctr(struct dm_target *ti, unsigned argc, char **argv);
static void do_io_work(struct work_struct *work);
static int block_io(struct zoned *, enum dm_io_mem_type, void *, sector_t,
		    unsigned int, int, int);
static int zoned_map_write(struct megazone*, struct bio*, struct map_addr*);
static int zoned_map_read(struct zoned *znd, struct bio *bio);
static int zoned_map(struct dm_target *ti, struct bio *bio);
static sector_t get_dev_size(struct dm_target *ti);
static int zoned_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data);
static int zoned_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
		       struct bio_vec *biovec, int max_size);
static void zoned_io_hints(struct dm_target *ti, struct queue_limits *limits);
static int is_zoned_inquiry(struct zoned *znd, int trim, int ata);
static int dmz_reset_wp(struct megazone *megaz, u64 z_id);
static int dmz_open_zone(struct megazone *megaz, u64 z_id);
static int dmz_close_zone(struct megazone *megaz, u64 z_id);
static u32 dmz_report_count(struct zoned *znd, void *report, size_t bufsz);
static int dmz_report_zones(struct zoned *znd, u64 z_id,
			    struct bdev_zone_report *report, size_t bufsz);
static void activity_timeout(unsigned long data);
static void zoned_destroy(struct zoned *);
static int gc_can_cherrypick(struct megazone *megaz);
static void bg_work_task(struct work_struct *work);
static void on_timeout_activity(struct zoned *znd, int mempurge);

/**
 * get_bdev_bd_inode() - Get primary backing device inode
 * @param znd
 *
 * Return: backing device inode
 */
static inline struct inode *get_bdev_bd_inode(struct zoned *znd)
{
	return znd->dev->bdev->bd_inode;
}

#include "libzoned.c"

static int dev_is_congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_is_congested(struct dm_target_callbacks *cb, int bdi_bits)
{
	struct zoned *zoned = container_of(cb, struct zoned, callbacks);
	int backing = dev_is_congested(zoned->dev, bdi_bits);

	if (zoned->gc_backlog > 1) {
		/*
		 * Was BDI_async_congested;
		 * Was BDI_sync_congested;
		 */
		backing |= 1 << WB_async_congested;
		backing |= 1 << WB_sync_congested;
	}
	return backing;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void set_discard_support(struct zoned *znd, int trim)
{
	struct mapped_device *md = dm_table_get_md(znd->ti->table);
	struct queue_limits *limits = dm_get_queue_limits(md);
	struct gendisk *disk = znd->dev->bdev->bd_disk;

	Z_INFO(znd, "Discard Support: %s", trim ? "on" : "off");
	if (limits) {
		limits->logical_block_size =
			limits->physical_block_size =
			limits->io_min = Z_C4K;
		if (trim) {
			limits->discard_alignment = Z_C4K;
			limits->discard_granularity = Z_C4K;
			limits->max_discard_sectors = 1 << 16;
			limits->discard_zeroes_data = 1;
		}
	}
	/* fixup stacked queue limits so discard zero's data is honored */
	if (trim && disk->queue) {
		limits = &disk->queue->limits;
		limits->discard_alignment = Z_C4K;
		limits->discard_granularity = Z_C4K;
		limits->max_discard_sectors = 1 << 16;
		limits->discard_zeroes_data = 1;
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int is_zoned_inquiry(struct zoned *znd, int trim, int ata)
{
	struct gendisk *disk = znd->dev->bdev->bd_disk;

	if (disk->queue) {
		u8 extended = 1;
		u8 page_op = 0xb1;
		u8 *buf = NULL;
		u16 sz = 64;
		int wp_err;

		set_discard_support(znd, trim);

#ifdef CONFIG_BLK_ZONED_CTRL
		if (ata) {
			struct zoned_identity ident;

			wp_err = blk_zoned_identify_ata(disk, &ident);
			if (!wp_err) {
				if (ident.type_id == HOST_AWARE) {
					znd->zinqtype = Z_TYPE_SMR_HA;
					znd->ata_passthrough = 1;
				}
			}
			return 0;
		}

		buf = ZDM_ALLOC(znd, Z_C4K, PG_01); /* zoned inq */
		if (!buf)
			return -ENOMEM;

		wp_err = blk_zoned_inquiry(disk, extended, page_op, sz, buf);
		if (!wp_err) {
			znd->zinqtype = buf[Z_VPD_INFO_BYTE] >> 4 & 0x03;
			if (znd->zinqtype != Z_TYPE_SMR_HA &&
			    buf[4] == 0x17 && buf[5] == 0x5c) {
				Z_ERR(znd, "Forcing ResetWP capability ... ");
				znd->zinqtype = Z_TYPE_SMR_HA;
				znd->ata_passthrough = 0;
			}
		}
#else
	#warning "CONFIG_BLK_ZONED_CTRL required."
#endif
		if (buf)
			ZDM_FREE(znd, buf, Z_C4K, PG_01);
	}

	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_map_discard(struct zoned *znd, struct bio *bio)
{
	u64 lba     = 0;
	int rcode   = DM_MAPIO_SUBMITTED;
	u64 s_up    = bio->bi_iter.bi_sector >> 3;
	u64 blks    = bio->bi_iter.bi_size / Z_C4K;
	u64 count;
	struct map_addr maddr;
	struct megazone *megaz = NULL;
	int err;

	if (znd->is_empty)
		goto out;

	for (count = 0; count < blks; count++) {
		u64 s_map = s_up + count;

		map_addr_to_zdm(znd, s_map, &maddr);
		megaz = &znd->z_mega[maddr.mz_id];

		mutex_lock(&megaz->mz_io_mutex);
		lba = z_lookup(megaz, &maddr);
		if (lba) {
			Z_DBG(znd, "TRIM: FS: %llx -> dm_s: %llx lba: %llx",
				s_map, maddr.dm_s, lba);
			err = z_mapped_discard(megaz, maddr.dm_s, lba);
		}
		mutex_unlock(&megaz->mz_io_mutex);

		if (err) {
			rcode = err;
			goto out;
		}

		if ((count & 0xFFFFF) == 0) {
			if (test_bit(DO_JOURNAL_MOVE, &megaz->flags) ||
			    test_bit(DO_MEMPOOL, &megaz->flags)) {
				if (!test_bit(DO_METAWORK_QD, &megaz->flags)) {

					Z_ERR(znd, "Large discard ...");

					set_bit(DO_METAWORK_QD, &megaz->flags);
					queue_work(znd->meta_wq,
						&megaz->meta_work);
					flush_workqueue(znd->meta_wq);

					Z_ERR(znd, " continue large discard");
				}
			}
		}
	}
out:
	if (rcode == DM_MAPIO_SUBMITTED)
		bio_endio(bio, 0);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int dmz_reset_wp(struct megazone *megaz, u64 z_id)
{
	int wp_err = 0;

	if (megaz->z_ptrs[z_id] & Z_WP_NON_SEQ)
		return wp_err;

#ifdef CONFIG_BLK_ZONED_CTRL
	if (megaz->znd->zinqtype == Z_TYPE_SMR_HA) {
		struct gendisk *disk = megaz->znd->dev->bdev->bd_disk;
		u64 z_offset = z_id + megaz->znd->zdstart;
		u64 lba = Z_BLKSZ * ((megaz->mega_nr * 1024) + z_offset);
		u64 s_addr = lba * Z_BLOCKS_PER_DM_SECTOR;
		int retry = 5;

		wp_err = -1;
		while (wp_err && --retry > 0) {
			if (megaz->znd->ata_passthrough)
				wp_err = blk_zoned_reset_wp_ata(disk, s_addr);
			else
				wp_err = blk_zoned_reset_wp(disk, s_addr);
		}

		if (wp_err) {
			Z_ERR(megaz->znd, "Reset WP: LBA: %" PRIx64
			      " [%u.%" PRIu64" - Z:%" PRIu64
			      "] -> %d failed.", s_addr,
			      megaz->mega_nr, z_id, z_offset, wp_err);
			Z_ERR(megaz->znd, "ZAC/ZBC support disabled.");
			megaz->znd->zinqtype = 0;
			wp_err = -ENOTSUPP;
		}
	}
#endif /* CONFIG_BLK_ZONED_CTRL */
	return wp_err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int dmz_open_zone(struct megazone *megaz, u64 z_id)
{
	int wp_err = 0;

	if (megaz->z_ptrs[z_id] & Z_WP_NON_SEQ)
		return wp_err;

#ifdef CONFIG_BLK_ZONED_CTRL
	if (megaz->znd->zinqtype == Z_TYPE_SMR_HA) {
		struct gendisk *disk = megaz->znd->dev->bdev->bd_disk;
		u64 z_offset = z_id + megaz->znd->zdstart;
		u64 lba = Z_BLKSZ * ((megaz->mega_nr * 1024) + z_offset);
		u64 s_addr = lba * Z_BLOCKS_PER_DM_SECTOR;
		int retry = 5;

		wp_err = -1;
		while (wp_err && --retry > 0) {
			if (megaz->znd->ata_passthrough)
				wp_err = blk_zoned_open_ata(disk, s_addr);
			else
				wp_err = blk_zoned_open(disk, s_addr);
		}

		if (wp_err) {
			Z_ERR(megaz->znd, "Open Zone: LBA: %" PRIx64
			      " [%u.%" PRIu64" - Z:%" PRIu64
			      " -> %d failed.", s_addr,
			      megaz->mega_nr, z_id, z_offset, wp_err);
			Z_ERR(megaz->znd, "ZAC/ZBC support disabled.");
			megaz->znd->zinqtype = 0;
			wp_err = -ENOTSUPP;
		}
	}
#endif /* CONFIG_BLK_ZONED_CTRL */

	return wp_err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int dmz_close_zone(struct megazone *megaz, u64 z_id)
{
	int wp_err = 0;

	if (megaz->z_ptrs[z_id] & Z_WP_NON_SEQ)
		return wp_err;

#ifdef CONFIG_BLK_ZONED_CTRL
	if (megaz->znd->zinqtype == Z_TYPE_SMR_HA) {
		struct gendisk *disk = megaz->znd->dev->bdev->bd_disk;
		u64 z_offset = z_id + megaz->znd->zdstart;
		u64 lba = Z_BLKSZ * ((megaz->mega_nr * 1024) + z_offset);
		u64 s_addr = lba * Z_BLOCKS_PER_DM_SECTOR;
		int retry = 5;

		wp_err = -1;
		while (wp_err && --retry > 0) {
			if (megaz->znd->ata_passthrough)
				wp_err = blk_zoned_close_ata(disk, s_addr);
			else
				wp_err = blk_zoned_close(disk, s_addr);
		}

		if (wp_err) {
			Z_ERR(megaz->znd, "Close Zone: LBA: %" PRIx64
			      " [%u.%" PRIu64" - Z:%" PRIu64
			      " -> %d failed.", s_addr,
			      megaz->mega_nr, z_id, z_offset, wp_err);
			Z_ERR(megaz->znd, "ZAC/ZBC support disabled.");
			megaz->znd->zinqtype = 0;
			wp_err = -ENOTSUPP;
		}
	}
#endif /* CONFIG_BLK_ZONED_CTRL */
	return wp_err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u32 dmz_report_count(struct zoned *znd, void *rpt_in, size_t bufsz)
{
	u32 count;
	u32 max_count = (bufsz - sizeof(struct bdev_zone_report))
		      /	 sizeof(struct bdev_zone_descriptor);

	if (REPORT_ZONES_LE_ONLY || znd->ata_passthrough) {
		struct bdev_zone_report_le *report = rpt_in;

		/* ZAC: ata results are little endian */
		if (max_count > le32_to_cpu(report->descriptor_count))
			report->descriptor_count = cpu_to_le32(max_count);
		count = le32_to_cpu(report->descriptor_count);
	} else {
		struct bdev_zone_report *report = rpt_in;

		/* ZBC: scsi results are big endian */
		if (max_count > be32_to_cpu(report->descriptor_count))
			report->descriptor_count = cpu_to_be32(max_count);
		count = be32_to_cpu(report->descriptor_count);
	}
	return count;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * dmz_report_zones() - issue report zones from z_id zones after zdstart
 * @param: znd: ZDM Target
 * @param: z_id: Zone past zdstart
 * @param: report: structure filled
 * @param: bufsz: kmalloc()'d space reserved for report
 *
 * Return: -ENOTSUPP or 0 on success
 */
static int dmz_report_zones(struct zoned *znd, u64 z_id,
			    struct bdev_zone_report *report, size_t bufsz)
{
	int wp_err = -ENOTSUPP;

#ifdef CONFIG_BLK_ZONED_CTRL
	if (znd->zinqtype == Z_TYPE_SMR_HA) {
		struct gendisk *disk = znd->dev->bdev->bd_disk;
		u64 s_addr = (z_id + znd->zdstart) << 19;
		u8  opt = ZOPT_NON_SEQ_AND_RESET;
		int retry = 5;

		wp_err = -1;
		while (wp_err && --retry > 0) {
			if (znd->ata_passthrough)
				wp_err = blk_zoned_report_ata(disk, s_addr, opt,
							      report, bufsz);
			else
				wp_err = blk_zoned_report(disk, s_addr, opt,
							  report, bufsz);
		}

		if (wp_err) {
			Z_ERR(znd, "Report Zones: LBA: %" PRIx64
			      " [Z:%" PRIu64 " -> %d failed.",
			      s_addr, z_id + znd->zdstart, wp_err);
			Z_ERR(znd, "ZAC/ZBC support disabled.");
			znd->zinqtype = 0;
			wp_err = -ENOTSUPP;
		}
	}
#endif /* CONFIG_BLK_ZONED_CTRL */
	return wp_err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int is_zone_reset(struct bdev_zone_descriptor *dentry)
{
	u8 type = dentry->type & 0x0F;
	u8 cond = (dentry->flags & 0xF0) >> 4;

	return (ZCOND_ZC1_EMPTY == cond || ZTYP_CONVENTIONAL == type) ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline u32 get_wp_from_descriptor(struct zoned *znd, void *dentry_in)
{
	u32 wp = 0;

	/*
	 * If passthrough then ZAC results are little endian.
	 * otherwise ZBC results are big endian.
	 */

	if (REPORT_ZONES_LE_ONLY || znd->ata_passthrough) {
		struct bdev_zone_descriptor_le *lil = dentry_in;

		wp = le64_to_cpu(lil->lba_start) - le64_to_cpu(lil->lba_wptr);
	} else {
		struct bdev_zone_descriptor *big = dentry_in;

		wp = be64_to_cpu(big->lba_start) - be64_to_cpu(big->lba_wptr);
	}
	return wp;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int is_conventional(struct bdev_zone_descriptor *dentry)
{
	return (ZTYP_CONVENTIONAL == (dentry->type & 0x0F)) ? 1 : 0;
}

static int megazone_wp_sync(struct zoned *znd, int reset_non_empty)
{
	int rcode = 0;
	u32 rcount = 0;
	u32 iter;
	size_t bufsz = REPORT_BUFFER * Z_C4K;
	struct bdev_zone_report *report = kmalloc(bufsz, GFP_KERNEL);

	if (!report) {
		rcode = -ENOMEM;
		goto out;
	}

	Z_ERR(znd, "%s: reset_non_empty: %d", __func__, reset_non_empty);

	for (iter = 0; iter < znd->mz_count; iter++) {
		struct megazone *megaz = &znd->z_mega[iter];
		int entry = (iter % 4) * 1024;
		int z_nr;

		if (entry == 0) {
			u64 from = megaz->mega_nr * 1024;
			int err = dmz_report_zones(znd, from, report, bufsz);

			if (err) {
				Z_ERR(znd, "report zones-> %d", err);
				if (err != -ENOTSUPP)
					rcode = err;
				goto out;
			}
			rcount = dmz_report_count(znd, report, bufsz);
		}

		for (z_nr = 0;
		     z_nr < megaz->z_count && entry < rcount;
		     z_nr++, entry++) {
			struct bdev_zone_descriptor *dentry
				= &report->descriptors[entry];
			u32 wp_at;
			u32 wp;

			if (reset_non_empty && !is_conventional(dentry)) {
				int err = 0;

				if (!is_zone_reset(dentry))
					err = dmz_reset_wp(megaz, z_nr);

				if (err) {
					Z_ERR(znd, "reset wp-> %d", err);
					if (err != -ENOTSUPP)
						rcode = err;
					goto out;
				}
				wp = wp_at = 0;
				megaz->z_ptrs[z_nr] = 0;
				megaz->zfree_count[z_nr] = Z_BLKSZ;
				continue;
			}

			wp = get_wp_from_descriptor(znd, dentry);
			wp >>= 3; /* 512 sectors to 4k sectors */
			wp_at = megaz->z_ptrs[z_nr] & Z_WP_VALUE_MASK;

			if (is_conventional(dentry)) {
				wp = wp_at; /* There is no WP for this zone. */
				megaz->z_ptrs[z_nr] |= Z_WP_NON_SEQ;
			} else {
				megaz->z_ptrs[z_nr] &= ~Z_WP_NON_SEQ;
			}

			if (wp > wp_at) {
				u32 wp_flgs;
				u32 lost = wp - wp_at;

				wp_flgs = megaz->z_ptrs[z_nr] & Z_WP_FLAGS_MASK;
				megaz->z_ptrs[z_nr] = wp & wp_flgs;
				megaz->zfree_count[z_nr] += lost;

				Z_ERR(znd,
				     "MZ#%u z:%x [wp:%x rz:%x] lost %u blocks.",
				     megaz->mega_nr, z_nr, wp_at, wp, lost);
			}
		}
	}

out:
	kfree(report);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void zoned_actual_size(struct dm_target *ti, struct zoned *znd)
{
	znd->nr_blocks = i_size_read(get_bdev_bd_inode(znd)) / Z_C4K;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_integrity_check(struct zoned *znd)
{
	int rc = 0;

	if (znd->z_mega) {
		u32 iter;

		for (iter = 0; iter < znd->mz_count; iter++) {
			struct megazone *megaz = &znd->z_mega[iter];

			set_bit(DO_META_CHECK, &megaz->flags);
			queue_work(znd->meta_wq, &megaz->meta_work);
		}

		flush_workqueue(znd->meta_wq);

		for (iter = 0; iter < znd->mz_count; iter++) {
			struct megazone *megaz = &znd->z_mega[iter];

			if (megaz->meta_result)
				rc = megaz->meta_result;
		}
	}
	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * <data dev> <format|check|force>
 */
static int zoned_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	const int reset_non_empty = 0;
	int create = 0;
	int force = 0;
	int check = 0;
	int zbc_probe = 1;
	int zac_probe = 1;
	int trim = 1;
	int r;
	struct zoned *zoned;
	long long first_data_zone = 0;
	long long mz_md_provision = MZ_METADATA_ZONES;

	BUILD_BUG_ON(Z_C4K != (sizeof(struct map_sect_to_lba) * Z_UNSORTED));
	BUILD_BUG_ON(Z_C4K != (sizeof(struct io_4k_block)));
	BUILD_BUG_ON(Z_C4K != (sizeof(struct mz_superkey)));
	BUILD_BUG_ON(SYNC_IO_SZ < (sizeof(struct mz_state)));

	if (argc < 1) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	for (r = 1; r < argc; r++) {
		if (isdigit(*argv[r])) {
			int krc = kstrtoll(argv[r], 0, &first_data_zone);

			if (krc != 0) {
				DMERR("Failed to parse %s: %d", argv[r], krc);
				first_data_zone = 0;
			}
		}
		if (!strcasecmp("create", argv[r]))
			create = 1;
		if (!strcasecmp("load", argv[r]))
			create = 0;
		if (!strcasecmp("check", argv[r]))
			check = 1;
		if (!strcasecmp("force", argv[r]))
			force = 1;
		if (!strcasecmp("nozbc", argv[r]))
			zbc_probe = 0;
		if (!strcasecmp("nozac", argv[r]))
			zac_probe = 0;
		if (!strcasecmp("discard", argv[r]))
			trim = 1;
		if (!strcasecmp("nodiscard", argv[r]))
			trim = 0;

		if (!strncasecmp("reserve=", argv[r], 8)) {
			long long mz_resv;
			int krc = kstrtoll(argv[r] + 8, 0, &mz_resv);

			if (krc == 0) {
				if (mz_resv > mz_md_provision)
					mz_md_provision = mz_resv;
			} else {
				DMERR("Reserved 'FAILED TO PARSE.' %s: %d",
					argv[r]+8, krc);
				mz_resv = 0;
			}
		}
	}

	zoned = ZDM_ALLOC(NULL, sizeof(*zoned), KM_00);
	if (!zoned) {
		ti->error = "Error allocating zoned structure";
		return -ENOMEM;
	}

	zoned->ti = ti;
	ti->private = zoned;
	zoned->zdstart = first_data_zone;
	zoned->mz_provision = mz_md_provision;

	r = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &zoned->dev);
	if (r) {
		ti->error = "Error opening backing device";
		zoned_destroy(zoned);
		return -EINVAL;
	}

	if (zoned->dev->bdev) {
		bdevname(zoned->dev->bdev, zoned->bdev_name);
		zoned->start_sect = get_start_sect(zoned->dev->bdev) / 8;
	}

	/*
	 * Set if this target needs to receive flushes regardless of
	 * whether or not its underlying devices have support.
	 */
	ti->flush_supported = true;

	/*
	 * Set if this target needs to receive discards regardless of
	 * whether or not its underlying devices have support.
	 */
	ti->discards_supported = true;

	/*
	 * Set if the target required discard bios to be split
	 * on max_io_len boundary.
	 */
	ti->split_discard_bios = false;

	/*
	 * Set if this target does not return zeroes on discarded blocks.
	 */
	ti->discard_zeroes_data_unsupported = false;
	/*
	 * Set if this target wants discard bios to be sent.
	 */
	ti->num_discard_bios = 1;

	if (!trim) {
		ti->discards_supported = false;
		ti->num_discard_bios = 0;
	}

	zoned_actual_size(ti, zoned);
	zoned->callbacks.congested_fn = zoned_is_congested;
	dm_table_add_target_callbacks(ti->table, &zoned->callbacks);
	r = zoned_init(ti, zoned);
	if (r) {
		ti->error = "Error in zoned init";
		zoned_destroy(zoned);
		return -EINVAL;
	}
	if (zbc_probe) {
		Z_ERR(zoned, "Checking for ZONED support %s",
			trim ? "with trim" : "");
		is_zoned_inquiry(zoned, trim, 0);
	} else if (zac_probe) {
		Z_ERR(zoned, "Checking for ZONED [ATA PASSTHROUGH] support %s",
			trim ? "with trim" : "");
		is_zoned_inquiry(zoned, trim, 1);
	} else {
		Z_ERR(zoned, "No PROBE");
		set_discard_support(zoned, trim);
	}

	r = megazone_init(zoned);
	if (r) {
		ti->error = "Error in zoned init megazone";
		zoned_destroy(zoned);
		return -EINVAL;
	}
	r = zoned_init_disk(ti, zoned, create, check, force);
	if (r) {
		ti->error = "Error in zoned init from disk";
		zoned_destroy(zoned);
		return -EINVAL;
	}
	r = megazone_wp_sync(zoned, reset_non_empty);
	if (r) {
		ti->error = "Error in zoned re-sync WP";
		zoned_destroy(zoned);
		return -EINVAL;
	}

	/*
	 * for each megaz,
	 *    for each non-zero entry in the crc_md table,
	 *	load the page  (and check the crc).
	 */
	if (check)
		zoned_integrity_check(zoned);

	mod_timer(&zoned->timer, jiffies + msecs_to_jiffies(5000));

	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void zoned_dtr(struct dm_target *ti)
{
	struct zoned *znd = ti->private;

	if (znd->z_superblock) {
		struct mz_superkey *key_blk = znd->z_superblock;
		struct zdm_superblock *sblock = &key_blk->sblock;

		sblock->flags = cpu_to_le32(0);
		sblock->csum = sb_crc32(sblock);
	}

	megazone_destroy(znd);
	zoned_destroy(znd);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * Read or write a chunk aligned and sized block of data from a device.
 */
static void do_io_work(struct work_struct *work)
{
	struct z_io_req_t *req = container_of(work, struct z_io_req_t, work);
	struct dm_io_request *io_req = req->io_req;
	unsigned long error_bits = 0;

	req->result = dm_io(io_req, 1, req->where, &error_bits);
	if (error_bits)
		DMERR("ERROR: dm_io error: %lx", error_bits);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int block_io(struct zoned *znd,
		    enum dm_io_mem_type dtype,
		    void *data,
		    sector_t block, unsigned int nDMsect, int rw, int queue)
{
	unsigned long error_bits = 0;
	int rcode;
	struct dm_io_region where = {
		.bdev = znd->dev->bdev,
		.sector = block,
		.count = nDMsect,
	};
	struct dm_io_request io_req = {
		.bi_rw = rw,
		.mem.type = dtype,
		.mem.offset = 0,
		.mem.ptr.vma = data,
		.client = znd->io_client,
		.notify.fn = NULL,
		.notify.context = NULL,
	};

	switch (dtype) {
	case DM_IO_KMEM:
		io_req.mem.ptr.addr = data;
		break;
	case DM_IO_BIO:
		io_req.mem.ptr.bio = data;
		where.count = nDMsect;
		break;
	case DM_IO_VMA:
		io_req.mem.ptr.vma = data;
		break;
	default:
		Z_ERR(znd, "page list not handled here ..  see dm-io.");
		break;
	}

	if (queue) {
		struct z_io_req_t req;

		/*
		 * Issue the synchronous I/O from a different thread
		 * to avoid generic_make_request recursion.
		 */
		INIT_WORK_ONSTACK(&req.work, do_io_work);
		req.where = &where;
		req.io_req = &io_req;
		queue_work(znd->io_wq, &req.work);
		flush_workqueue(znd->io_wq);
		destroy_work_on_stack(&req.work);

		return req.result;
	}

	rcode = dm_io(&io_req, 1, &where, &error_bits);
	if (error_bits)
		Z_ERR(znd, "ERROR: dm_io error: %lx", error_bits);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * count -> count in 4k sectors.
 */
static int read_block(struct dm_target *ti, enum dm_io_mem_type dtype,
		      void *data, u64 lba, unsigned int count, int queue)
{
	struct zoned *znd = ti->private;
	sector_t block = lba * Z_BLOCKS_PER_DM_SECTOR;
	unsigned int nDMsect = count * Z_BLOCKS_PER_DM_SECTOR;
	int rc;

	if (lba >= znd->nr_blocks) {
		Z_ERR(znd, "Error reading past end of media: %llx.", lba);
		rc = -EIO;
		return rc;
	}

	rc = block_io(znd, dtype, data, block, nDMsect, READ, queue);
	if (rc) {
		Z_ERR(znd, "read error: %d -- R: %llx [%u dm sect] (Q:%d)",
			rc, lba, nDMsect, queue);
		dump_stack();
	}

	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * count -> count in 4k sectors.
 */
static int write_block(struct dm_target *ti, enum dm_io_mem_type dtype,
		       void *data, u64 lba, unsigned int count, int queue)
{
	struct zoned *znd = ti->private;
	sector_t block = lba * Z_BLOCKS_PER_DM_SECTOR;
	unsigned int nDMsect = count * Z_BLOCKS_PER_DM_SECTOR;
	int rc;

	rc = block_io(znd, dtype, data, block, nDMsect, WRITE, queue);
	if (rc) {
		Z_ERR(znd, "write error: %d W: %llx [%u dm sect] (Q:%d)",
			rc, lba, nDMsect, queue);
		dump_stack();
	}

	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zm_cow(struct megazone *megaz, struct bio *bio,
		  struct map_addr *maddr, u32 blks, u64 origin)
{
	struct dm_target *ti = megaz->znd->ti;
	int count = 1;
	int use_wq = 1;
	unsigned int bytes = bio_cur_bytes(bio);
	u8 *data = bio_data(bio);
	u8 *io = NULL;
	u16 ua_off = bio->bi_iter.bi_sector & 0x0007;
	u16 ua_size = bio->bi_iter.bi_size & 0x0FFF;	/* in bytes */
	u32 mapped = 0;
	u64 disk_lba = 0;

	if (!megaz->cow_block)
		megaz->cow_block = ZDM_ALLOC(megaz->znd, Z_C4K, PG_02);

	io = megaz->cow_block;
	if (!io)
		return -EIO;

	disk_lba = z_acquire(megaz, Z_AQ_NORMAL, blks, &mapped);
	if (!disk_lba || !mapped)
		return -ENOSPC;

	while (bytes) {
		int rd;
		unsigned int iobytes = Z_C4K;

		/* ---------------------------------------------------------- */
		if (origin) {
			if (maddr->dm_s != megaz->cow_addr) {
				Z_ERR(megaz->znd,
					"Copy block from %llx <= %llx",
					origin, maddr->dm_s);
				rd = read_block(ti, DM_IO_KMEM, io, origin,
						count, use_wq);
				if (rd)
					return -EIO;

				megaz->cow_addr = maddr->dm_s;
			} else {
				Z_ERR(megaz->znd,
					"Cached block from %llx <= %llx",
					origin, maddr->dm_s);
			}
		} else {
			memset(io, 0, Z_C4K);
		}

		if (ua_off)
			iobytes -= ua_off * 512;

		if (bytes < iobytes)
			iobytes = bytes;

		Z_ERR(megaz->znd, "Moving %u bytes from origin [offset:%u]",
		      iobytes, ua_off * 512);

		memcpy(io + (ua_off * 512), data, iobytes);

		/* ---------------------------------------------------------- */

		rd = write_block(ti, DM_IO_KMEM, io, disk_lba, count, use_wq);
		if (rd)
			return -EIO;

		rd = z_mapped_addmany(megaz, maddr->dm_s, disk_lba, mapped);
		if (rd) {
			Z_ERR(megaz->znd, "%s: Journal MANY failed.", __func__);
			return -EIO;
		}

		data += iobytes;
		bytes -= iobytes;
		ua_size -= (ua_size > iobytes) ? iobytes : ua_size;
		ua_off = 0;
		disk_lba++;

		if (bytes && (ua_size || ua_off)) {
			map_addr_calc(megaz->znd, maddr->dm_s + 1, maddr);
			origin = z_lookup(megaz, maddr);
		}
	}
	bio_endio(bio, 0);

	return DM_MAPIO_SUBMITTED;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

#define BIO_CACHE_SECTORS (IO_VCACHE_PAGES * Z_BLOCKS_PER_DM_SECTOR)

/**
 * Write 4k blocks from cache to lba.
 * Move any remaining 512 byte blocks to the start of cache and update
 * the @param _blen count is update
 */
static int zm_write_cache(struct zoned *znd, struct io_dm_block *dm_vbuf,
			  u64 lba, u32 *_blen)
{
	int use_wq    = 1;
	int cached    = *_blen;
	int blks      = cached / 8;
	int sectors   = blks * 8;
	int remainder = cached - sectors;
	int err;

	err = write_block(znd->ti, DM_IO_VMA, dm_vbuf, lba, blks, use_wq);
	if (!err) {
		if (remainder)
			memcpy(dm_vbuf[0].data,
			       dm_vbuf[sectors].data, remainder * 512);
		*_blen = remainder;
	}
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zm_write_pages(struct megazone *megaz, struct bio *bio,
			  struct map_addr *maddr)
{
	struct zoned *znd = megaz->znd;
	u64 sect_ori = maddr->dm_s;
	u32 blks     = dm_div_up(bio->bi_iter.bi_size, Z_C4K);
	u64 lba      = 0;
	u32 blen     = 0; /* total: IO_VCACHE_PAGES * 8 */
	u32 written  = 0;
	int avail    = 0;
	int err;
	struct bvec_iter start;
	struct bvec_iter iter;
	struct bio_vec bv;
	struct io_4k_block *io_vcache;
	struct io_dm_block *dm_vbuf = NULL;

	mutex_lock(&megaz->vcio_lock);
	io_vcache = get_io_vcache(megaz);
	if (!io_vcache) {
		Z_ERR(megaz->znd, "%s: FAILED to get SYNC CACHE.", __func__);
		err = -ENOMEM;
		goto out;
	}

	dm_vbuf = (struct io_dm_block *)io_vcache;

	/* USE: dm_vbuf for dumping bio pages to disk ... */
	start = bio->bi_iter; /* struct implicit copy */
	do {
		u64 alloc_ori = 0;
		u32 mcount = 0;
		u32 mapped = 0;

reacquire:
		/*
		 * When lba is zero no blocks were not allocated.
		 * Retry with the smaller request
		 */
		lba = z_acquire(megaz, Z_AQ_NORMAL, blks - written, &mapped);
		if (!lba && mapped)
			lba = z_acquire(megaz, Z_AQ_NORMAL, mapped, &mapped);

		if (!lba) {
			if (znd->gc_throttle.counter == 0) {
				err = -ENOSPC;
				goto out;
			}

			Z_ERR(znd, "Throttle input ... Mandatory GC.");
			if (delayed_work_pending(&znd->gc_work)) {
				mod_delayed_work(znd->gc_wq, &znd->gc_work, 0);
				mutex_unlock(&megaz->mz_io_mutex);
				flush_delayed_work(&znd->gc_work);
				mutex_lock(&megaz->mz_io_mutex);
			}
			goto reacquire;
		}

		/* this may be redundant .. if we have lba we have mapped > 0 */
		if (lba && mapped)
			avail += mapped * 8; /* claimed pages in dm blocks */

		alloc_ori = lba;

		/* copy [upto mapped] pages to buffer */
		__bio_for_each_segment(bv, bio, iter, start) {
			int issue_write = 0;
			unsigned int boff;
			void *src;

			if (avail <= 0) {
				Z_ERR(megaz->znd, "%s: TBD: Close Z# %llu",
					__func__, alloc_ori >> 16);
				start = iter;
				break;
			}

			src = kmap_atomic(bv.bv_page);
			boff = bv.bv_offset;
			memcpy(dm_vbuf[blen].data, src + boff, bv.bv_len);
			kunmap_atomic(src);
			blen   += bv.bv_len / 512;
			avail  -= bv.bv_len / 512;

			if ((blen >= (mapped * 8)) ||
			    (blen >= (BIO_CACHE_SECTORS - 8)))
				issue_write = 1;

			/*
			 * If there is less than 1 4k block in out cache,
			 * send the available blocks to disk
			 */
			if (issue_write) {
				int blks = blen / 8;

				err = zm_write_cache(megaz->znd, dm_vbuf,
						     lba, &blen);
				if (err) {
					Z_ERR(megaz->znd, "%s: bio-> %" PRIx64
					      " [%d of %d blks] -> %d",
					      __func__, lba, blen, blks, err);
					bio_endio(bio, err);
					goto out;
				}
				lba     += blks;
				written += blks;
				mcount  += blks;
				mapped  -= blks;

				if (mapped == 0) {
					bio_advance_iter(bio, &iter, bv.bv_len);
					start = iter;
					break;
				}
				if (mapped < 0) {
					Z_ERR(megaz->znd, "ERROR: Bad write %"
					      PRId32 " beyond alloc'd space",
					      mapped);
				}
			}
		}
		if ((mapped > 0) && ((blen / 8) > 0)) {
			int blks = blen / 8;

			err = zm_write_cache(megaz->znd, dm_vbuf, lba, &blen);
			if (err) {
				Z_ERR(megaz->znd, "%s: bio-> %" PRIx64
				      " [%d of %d blks] -> %d",
				      __func__, lba, blen, blks, err);
				bio_endio(bio, err);
				goto out;
			}
			lba     += blks;
			written += blks;
			mcount  += blks;
			mapped  -= blks;

			if (mapped < 0) {
				Z_ERR(megaz->znd, "ERROR: [2] Bad write %"
				      PRId32 " beyond alloc'd space",
				      mapped);
			}
		}
		err = z_mapped_addmany(megaz, maddr->dm_s, alloc_ori, mcount);
		if (err) {
			Z_ERR(megaz->znd, "%s: Journal MANY failed.", __func__);
			err = DM_MAPIO_REQUEUE;
			/*
			 * FIXME:
			 * Ending the BIO here is causing a GFP:
			 -       DEBUG_PAGEALLOC
			 -    in Workqueue:
			 -        writeback bdi_writeback_workfn (flush-252:0)
			 -    backtrace:
			 -      __map_bio+0x7a/0x280
			 -      __split_and_process_bio+0x2e3/0x4e0
			 -      ? __split_and_process_bio+0x22/0x4e0
			 -      ? generic_start_io_acct+0x5/0x210
			 -      dm_make_request+0x6b/0x100
			 -      generic_make_request+0xc0/0x110
			 -      ....

			 - bio_endio(bio, err);
			 */
			goto out;
		}

		if (written < blks)
			map_addr_calc(znd, sect_ori + written, maddr);

		if (written == blks && blen > 0)
			Z_ERR(megaz->znd, "%s: blen: %d un-written blocks!!",
			      __func__, blen);
	} while (written < blks);
	bio_endio(bio, 0);
	err = DM_MAPIO_SUBMITTED;

out:
	put_io_vcache(megaz, io_vcache);
	mutex_unlock(&megaz->vcio_lock);

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_map_write(struct megazone *megaz, struct bio *bio,
			   struct map_addr *maddr)
{
	u32 blks     = dm_div_up(bio->bi_iter.bi_size, Z_C4K);
	u16 ua_off   = bio->bi_iter.bi_sector & 0x0007;
	u16 ua_size  = bio->bi_iter.bi_size & 0x0FFF;	/* in bytes */

	if (ua_size || ua_off) {
		u64 origin = z_lookup(megaz, maddr);

		if (origin)
			return zm_cow(megaz, bio, maddr, blks, origin);
	}
	return zm_write_pages(megaz, bio, maddr);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_map_read(struct zoned *znd, struct bio *bio)
{
	int rcode = DM_MAPIO_REMAPPED;
	u64 ua_off = bio->bi_iter.bi_sector & 0x0007;
	u64 ua_size = bio->bi_iter.bi_size & 0x0FFF;	/* in bytes */
	u64 s_up = bio->bi_iter.bi_sector >> 3;
	u64 blks = dm_div_up(bio->bi_iter.bi_size, Z_C4K);
	struct map_addr maddr;
	u64 start_lba;
	struct megazone *megaz = NULL;

	map_addr_to_zdm(znd, s_up, &maddr);
	megaz = &znd->z_mega[maddr.mz_id];
	start_lba = z_lookup(megaz, &maddr);

	if (start_lba) {
		u64 sz;

		bio->bi_iter.bi_sector = start_lba << 3;
		if (ua_off)
			bio->bi_iter.bi_sector += ua_off;

		for (sz = 1; sz < blks; sz++) {
			u64 next_lba;

			map_addr_to_zdm(znd, s_up+sz, &maddr);
			megaz = &znd->z_mega[maddr.mz_id];
			next_lba = z_lookup(megaz, &maddr);
			if (next_lba != (start_lba + sz)) {
				unsigned nsect = sz * 8;

				if (ua_size) {
					unsigned ua_blocks = ua_size / 512;

					nsect -= 8;
					nsect += ua_blocks;
				}
				Z_DBG(megaz->znd,
					"NON SEQ @ %llx + %llu [%llx] [%llx]",
					 maddr.dm_s, sz, start_lba, next_lba);

				dm_accept_partial_bio(bio, nsect);
				return rcode;
			}
		}

		if (ua_off || ua_size)
			Z_ERR(megaz->znd, "(R): bio: sector: %lx bytes: %u",
			      bio->bi_iter.bi_sector, bio->bi_iter.bi_size);

		generic_make_request(bio);
		rcode = DM_MAPIO_SUBMITTED;
	} else {
		zero_fill_bio(bio);
		bio_endio(bio, 0);
		return DM_MAPIO_SUBMITTED;
	}
	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u64 mz_final(struct zoned *znd, struct bio *bio)
{
	u64 blks = dm_div_up(bio->bi_iter.bi_size, Z_C4K);
	u64 s_up = bio->bi_iter.bi_sector >> 3;
	struct map_addr maddr;

	if (blks > 0)
		s_up += (blks - 1);

	map_addr_to_zdm(znd, s_up, &maddr);

	return maddr.mz_id;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/*
 * Return the number of 4k sectors available
 */
static u32 mz_bio_blocks(struct zoned *znd, struct bio *bio, u64 mz_id)
{
	u64 s_up = bio->bi_iter.bi_sector >> 3;
	u32 blks = dm_div_up(bio->bi_iter.bi_size, Z_C4K);
	u32 count;
	struct map_addr maddr;

	for (count = 0; count < blks; count++) {
		map_addr_to_zdm(znd, s_up+count, &maddr);
		if (mz_id != maddr.mz_id)
			break;
	}
	return count;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_map(struct dm_target *ti, struct bio *bio)
{
	struct zoned *znd = ti->private;
	bool is_write = (bio_data_dir(bio) == WRITE);
	sector_t sector_nr = bio->bi_iter.bi_sector / Z_BLOCKS_PER_DM_SECTOR;
	int rcode = DM_MAPIO_REMAPPED;
	struct map_addr maddr;
	struct request_queue *q;
	struct megazone *megaz = NULL;
	int force_sync_now = 0;
	struct block_device *bdev = bio->bi_bdev;

	/* map to backing device ... NOT dm-zoned device */
	bio->bi_bdev = znd->dev->bdev;

	q = bdev_get_queue(bio->bi_bdev);
	q->queue_flags |= QUEUE_FLAG_NOMERGES;

	/* sector is from the upper layer (fs, gparted, etc) */
	map_addr_to_zdm(znd, sector_nr, &maddr);

	if (maddr.dm_s >= znd->nr_blocks) {
		Z_ERR(znd,
		      "%s requested %lu -> %llu is too large for device (%llu)",
		      __func__, sector_nr, maddr.dm_s, znd->nr_blocks);
		return -ENOSPC;
	}

	megaz = &znd->z_mega[maddr.mz_id];
	if (is_write && megaz->meta_result)
		return megaz->meta_result;

	mutex_lock(&megaz->mz_io_mutex);

	/* check for SYNC flag */
	if (bio->bi_rw & REQ_SYNC) {
		set_bit(DO_SYNC, &megaz->flags);
		force_sync_now = 1;
	}

	Z_DBG(znd, "%s: s:%lu sz:%u -> %s [%llu]", __func__,
		 sector_nr, bio->bi_iter.bi_size,
		 is_write ? "W" : "R", maddr.mz_id);

	if (bio->bi_iter.bi_size) {
		if (bio->bi_rw & REQ_DISCARD) {
			znd->gc_mz_pref = maddr.mz_id;
			mutex_unlock(&megaz->mz_io_mutex);
			rcode = zoned_map_discard(znd, bio);
			mutex_lock(&megaz->mz_io_mutex);
		} else if (is_write) {
			znd->is_empty = 0;
			znd->gc_mz_pref = maddr.mz_id;
			if (mz_final(znd, bio) != maddr.mz_id) {
				u32 accept;

				accept = mz_bio_blocks(znd, bio, maddr.mz_id);
				/*
				 * accept number of 4k blocks -> 512 blocks
				 * and have the upper layer remap them back
				 * to ZDM.
				 */
				bio->bi_bdev = bdev;
				dm_accept_partial_bio(bio, accept << 3);
				rcode = DM_MAPIO_REMAPPED;
				Z_ERR(znd, "ReMap to self [crossing MZ] %u",
					accept);
				mutex_unlock(&megaz->mz_io_mutex);
				return rcode;
			}
			rcode = zoned_map_write(megaz, bio, &maddr);
		} else {
			rcode = zoned_map_read(znd, bio);
		}
		megaz->age = jiffies;
	}

	if (test_bit(DO_SYNC, &megaz->flags) ||
	    test_bit(DO_JOURNAL_MOVE, &megaz->flags) ||
	    test_bit(DO_MEMPOOL, &megaz->flags)) {
		if (!test_bit(DO_METAWORK_QD, &megaz->flags)) {
			set_bit(DO_METAWORK_QD, &megaz->flags);
			queue_work(znd->meta_wq, &megaz->meta_work);
		}
	}

	if (megaz->z_gc_free < 5) {
		Z_ERR(znd, "... issue gc low on free space.");
		gc_immediate(megaz);
	}
	mutex_unlock(&megaz->mz_io_mutex);

	if (force_sync_now)
		flush_workqueue(znd->meta_wq);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int _do_mem_purge(struct megazone *megaz)
{
	int do_work = 0;

	if (megaz->incore_count > 3) {
		set_bit(DO_MEMPOOL, &megaz->flags);
		if (!work_pending(&megaz->meta_work))
			do_work = 1;
	}
	return do_work;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int gc_can_cherrypick(struct megazone *megaz)
{
	int delay = 1;
	int z_gc = megaz->z_data - 1;

	for (; z_gc < megaz->z_count; z_gc++) {
		int is_ready = is_ready_for_gc(megaz, z_gc);
		const u32 wp = megaz->z_ptrs[z_gc] & Z_WP_VALUE_MASK;
		const u32 nfree = megaz->zfree_count[z_gc];

/* Maybe 'nfree > GC_PRIO_DEFAULT' ? */
		if (is_ready && (wp == Z_BLKSZ) && (nfree == Z_BLKSZ)) {
			if (gc_compact_check(megaz, delay))
				return 1;
		}
	}

	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void on_timeout_activity(struct zoned *znd, int mempurge)
{
	int gc_idle = 0;
	int delay = 1;
	unsigned long flags;
	struct megazone *megaz;
	u32 itr;

	spin_lock_irqsave(&znd->gc_lock, flags);
	gc_idle = !znd->gc_active;
	spin_unlock_irqrestore(&znd->gc_lock, flags);

	if (!znd->z_mega)
		return;

	if (test_bit(ZF_FREEZE, &znd->flags))
		return;

	/*
	 * sort on discard ratio:
	 *   - discard / zone count
	 *
	 * 1. Highest ratio gets first check for cherrypick
	 * 2. otherwise: Scan all for cherrypick.
	 * 3. otherwise: Highest ratio gets normal GC
	 * 4. otherwise: Scan all for normal GC.
	 * 5. For all issue memory purge.
	 */

	if (gc_idle) {
		int pref_ratio;
		int ratio;

		/* sort on discard ratio */
		megaz = &znd->z_mega[0];
		znd->gc_mz_pref = 0;
		pref_ratio = megaz->discard_count / megaz->z_count;
		for (itr = 1; itr < znd->mz_count; itr++) {
			megaz = &znd->z_mega[itr];
			ratio = megaz->discard_count / megaz->z_count;
			if (ratio > pref_ratio) {
				znd->gc_mz_pref = itr;
				pref_ratio = ratio;
			}
		}

		/* 1. cherrypick highest */
		megaz = &znd->z_mega[znd->gc_mz_pref];
		if (gc_idle && gc_can_cherrypick(megaz))
			gc_idle = 0;

		/* 2. Scan MZs for cherrypick candidate */
		for (itr = 0; gc_idle && itr < znd->mz_count; itr++) {
			megaz = &znd->z_mega[itr];
			if (gc_idle && gc_can_cherrypick(megaz))
				gc_idle = 0;
		}

		/* 3. Normal GC on highest */
		megaz = &znd->z_mega[znd->gc_mz_pref];
		if (gc_idle && gc_compact_check(megaz, delay))
			gc_idle = 0;

		/* 4. Scan all for normal GC. */
		for (itr = 0; gc_idle && itr < znd->mz_count; itr++) {
			megaz = &znd->z_mega[itr];
			if (gc_idle && gc_compact_check(megaz, delay))
				gc_idle = 0;
		}
	}

	if (mempurge) {
		/* 5. For all issue memory purge. */
		for (itr = 0; itr < znd->mz_count; itr++) {
			megaz = &znd->z_mega[itr];
			if (_do_mem_purge(megaz))
				queue_work(znd->meta_wq, &megaz->meta_work);
		}
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void bg_work_task(struct work_struct *work)
{
	struct zoned *znd;

	if (!work)
		return;

	znd = container_of(work, struct zoned, bg_work);
	on_timeout_activity(znd, 1);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void activity_timeout(unsigned long data)
{
	struct zoned *znd = (struct zoned *) data;

	if (!work_pending(&znd->bg_work))
		queue_work(znd->bg_wq, &znd->bg_work);

	if (!test_bit(ZF_FREEZE, &znd->flags))
		mod_timer(&znd->timer, jiffies + msecs_to_jiffies(2500));
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static sector_t get_dev_size(struct dm_target *ti)
{
	struct zoned *znd = ti->private;
	u64 sz = i_size_read(get_bdev_bd_inode(znd));	/* size in bytes. */
	u64 lut_resv;

	lut_resv = (znd->mz_count * znd->mz_provision);

	Z_DBG(znd, "%s size: %llu (/8) -> %llu blks -> zones -> %llu mz: %llu",
		 __func__, sz, sz / 4096, (sz / 4096) / 65536,
		 ((sz / 4096) / 65536) / 1024);

	sz -= (lut_resv * Z_SMR_SZ_BYTES);

	Z_DBG(znd, "%s backing device size: %llu (4k blocks)", __func__, sz);

	/*
	 * NOTE: `sz` should match `ti->len` when the dm_table
	 *       is setup correctly
	 */

	return to_sector(sz);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	struct zoned *zoned = ti->private;
	int rc = fn(ti, zoned->dev, 0, get_dev_size(ti), data);

	Z_DBG(zoned, "%s: %p -> rc: %d", __func__, fn, rc);

	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * Follow the backing device limits for READ [and DISCARD].
 * Limit WRITE requests to the current zone max [Enforced in ->map()]
 */
static int zoned_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
		       struct bio_vec *biovec, int max_size)
{
	struct zoned *znd = ti->private;
	struct request_queue *q = bdev_get_queue(znd->dev->bdev);
	sector_t sector_nr = bvm->bi_sector / Z_BLOCKS_PER_DM_SECTOR;
	struct megazone *megaz = NULL;
	struct map_addr maddr;
	u32 wptr = 0;
	u32 avail = 0;
	int zmax = 4096;
	int bdev_max = 4096;

	map_addr_to_zdm(znd, sector_nr, &maddr);
	bvm->bi_bdev = znd->dev->bdev;
	bvm->bi_sector = maddr.dm_s * Z_BLOCKS_PER_DM_SECTOR;

	if (q->merge_bvec_fn) {
		bdev_max = q->merge_bvec_fn(q, bvm, biovec);
		if (max_size > bdev_max)
			max_size = bdev_max;
	}

	megaz = &znd->z_mega[maddr.mz_id];
	wptr = megaz->z_ptrs[megaz->z_current];

	if (wptr < Z_BLKSZ)
		avail = Z_BLKSZ - wptr;

	if (avail > 25)
		avail = 25; /* arbitrary I/O limit in 4k blocks.*/

	avail *= 4096;
	if (avail)
		zmax = avail;

	if (max_size > zmax)
		max_size = zmax;

	return max_size;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void zoned_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	u64 io_opt_sectors = limits->io_opt >> SECTOR_SHIFT;

	/*
	 * If the system-determined stacked limits are compatible with the
	 * zoned device's blocksize (io_opt is a factor) do not override them.
	 */
	if (io_opt_sectors < 8 || do_div(io_opt_sectors, 8)) {
		blk_limits_io_min(limits, 0);
		blk_limits_io_opt(limits, 8 << SECTOR_SHIFT);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void zoned_status(struct dm_target *ti, status_type_t type,
			 unsigned status_flags, char *result, unsigned maxlen)
{
	struct zoned *znd = (struct zoned *) ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		scnprintf(result, maxlen, "%s Z#%llu", znd->dev->name,
			 znd->zdstart);
		break;
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_ioctl_fwd(struct dm_dev *dev, unsigned int cmd,
			   unsigned long arg)
{
	int r = scsi_verify_blk_ioctl(NULL, cmd);

	if (r == 0)
		r = __blkdev_driver_ioctl(dev->bdev, dev->mode, cmd, arg);

	return r;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int do_ioc_wpstat(struct zoned *znd, unsigned long arg, int what)
{
	void __user *parg = (void __user *)arg;
	int error = -EFAULT;
	struct zdm_ioc_request *req;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		error = -ENOMEM;
		goto out;
	}

	if (copy_from_user(req, parg, sizeof(*req)))
		goto out;

	if (req->megazone_nr < znd->mz_count) {
		struct megazone *megaz = &znd->z_mega[req->megazone_nr];
		u32 reply_sz =
		    req->result_size < Z_C4K ? req->result_size : Z_C4K;
		void *send_what = what ? megaz->z_ptrs : megaz->zfree_count;

		if (copy_to_user(parg, send_what, reply_sz))
			error = -EFAULT;

		error = 0;
	}
out:
	kfree(req);

	return error;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void fill_ioc_status(struct megazone *megaz,
			    struct zdm_ioc_status *status)
{
	int entry;

	memset(status, 0, sizeof(*status));
	status->mc_entries = megaz->mc_entries;

	for (entry = megaz->z_data; entry < megaz->z_count; entry++) {
		u32 used = megaz->z_ptrs[entry] & Z_WP_VALUE_MASK;

		status->b_used += used;
		status->b_available += Z_BLKSZ - used;
	}
	status->b_discard = megaz->discard_count;

	/*  fixed array of ->sectortm and ->reversetm */
	status->m_used = 2 * ((sizeof(struct map_pg *) * Z_BLKSZ) / 4096);
	status->memstat = megaz->znd->memstat;
	memcpy(status->bins, megaz->znd->bins, sizeof(status->bins));
	status->mlut_blocks = megaz->incore_count;

	for (entry = 0; entry < MZKY_NCRC; entry++) {
		if (megaz->stm_crc[entry].cdata)
			status->crc_blocks++;
		if (megaz->rtm_crc[entry].cdata)
			status->crc_blocks++;
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int do_ioc_status(struct zoned *znd, unsigned long arg)
{
	void __user *parg = (void __user *)arg;
	int error = -EFAULT;
	struct zdm_ioc_request *req;
	struct zdm_ioc_status *stats;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	stats = kzalloc(sizeof(*stats), GFP_KERNEL);

	if (!req || !stats) {
		error = -ENOMEM;
		goto out;
	}

	if (copy_from_user(req, parg, sizeof(*req)))
		goto out;

	if (req->megazone_nr < znd->mz_count) {
		struct megazone *megaz = &znd->z_mega[req->megazone_nr];

		if (req->result_size < sizeof(*stats)) {
			error = -EBADTYPE;
			goto out;
		}
		fill_ioc_status(megaz, stats);
		if (copy_to_user(parg, stats, sizeof(*stats))) {
			error = -EFAULT;
			goto out;
		}
		error = 0;
	}

out:
	kfree(req);
	kfree(stats);
	return error;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_ioctl(struct dm_target *ti, unsigned int cmd,
		       unsigned long arg)
{
	int rcode = 0;
	struct zoned *znd = (struct zoned *) ti->private;

	switch (cmd) {
	case ZDM_IOC_MZCOUNT:
		rcode = znd->mz_count;
		break;
	case ZDM_IOC_WPS:
		do_ioc_wpstat(znd, arg, 1);
		break;
	case ZDM_IOC_FREE:
		do_ioc_wpstat(znd, arg, 0);
		break;
	case ZDM_IOC_STATUS:
		do_ioc_status(znd, arg);
		break;
#if 0
	case BLKFLSBUF:
		Z_ERR(znd, "Ign BLKFLSBUF (ZDM: flush backing store) %u %lu\n",
		      cmd, arg);
		rcode = 0;
		break;
#endif
	default:
		rcode = zoned_ioctl_fwd(znd->dev, cmd, arg);
		break;
	}
	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void start_worker(struct zoned *znd)
{
	clear_bit(ZF_FREEZE, &znd->flags);
	atomic_set(&znd->suspended, 0);
	mod_timer(&znd->timer, jiffies + msecs_to_jiffies(5000));
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void stop_worker(struct zoned *znd)
{
	set_bit(ZF_FREEZE, &znd->flags);
	atomic_set(&znd->suspended, 1);
	megazone_flush_all(znd);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void zoned_postsuspend(struct dm_target *ti)
{
	struct zoned *zoned = ti->private;

	stop_worker(zoned);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zoned_preresume(struct dm_target *ti)
{
	struct zoned *zoned = ti->private;

	start_worker(zoned);
	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct target_type zoned_target = {
	.name = "zoned",
	.module = THIS_MODULE,
	.version = {1, 0, 0},
	.ctr = zoned_ctr,
	.dtr = zoned_dtr,
	.map = zoned_map,

	.postsuspend = zoned_postsuspend,
	.preresume = zoned_preresume,
	.status = zoned_status,
		/*  .message = zoned_message, */
	.ioctl = zoned_ioctl,

	.iterate_devices = zoned_iterate_devices,
	.merge = zoned_merge,
	.io_hints = zoned_io_hints
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int __init dm_zoned_init(void)
{
	int rcode = dm_register_target(&zoned_target);

	if (rcode)
		DMERR("zoned target registration failed: %d", rcode);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
static void __exit dm_zoned_exit(void)
{
	dm_unregister_target(&zoned_target);
}

module_init(dm_zoned_init);
module_exit(dm_zoned_exit);

MODULE_DESCRIPTION(DM_NAME " zoned target for Host Aware/Managed drives.");
MODULE_AUTHOR("Shaun Tancheff <shaun.tancheff@seagate.com>");
MODULE_LICENSE("GPL");
