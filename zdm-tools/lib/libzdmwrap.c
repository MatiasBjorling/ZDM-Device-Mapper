/*
 * Kernel Device Mapper for abstracting ZAC/ZBC devices as normal
 * block devices for linux file systems.
 *
 * Copyright (C) 2015 Seagate Technology PLC
 *
 * Written by:
 * Shaun Tancheff <shaun.tancheff@seagate.com>
 *
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>


#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <linux/fs.h>
#include <errno.h>
#include <string.h> // strdup

#include "libzdmwrap.h"
#include "zbc-ctrl.h"

int zdm_reset_wp_wrap(struct zdm * znd, u64 z_id);

static int __debug_state = 0;

int _debug(void)
{
	return __debug_state;
}

void set_debug(int state)
{
	__debug_state = state;
}

static inline int zndone_wp_sync(struct zdm *znd, int reset_non_empty)
{
	(void)znd;
	(void)reset_non_empty;
	return 0;
}

static inline struct inode * get_bdev_bd_inode(struct zdm *znd)
{
	(void)znd;
	return NULL;
}

static inline void dump_stack(void) {}

static int read_block(struct dm_target *ti, enum dm_io_mem_type dtype,
                      void *data, u64 lba,
                      unsigned int count, int queue);
static int write_block(struct dm_target *ti, enum dm_io_mem_type dtype,
                       void *data, u64 lba,
                       unsigned int count, int queue);

static int is_zoned_inquiry(struct zdm *znd)
{
	return zdm_zoned_inq(znd);
}

static int dmz_reset_wp(struct zdm * znd, u64 z_id)
{
	return zdm_reset_wp_wrap(znd, z_id);
}

static int dmz_open_zone(struct zdm * znd, u64 z_id)
{
	return 0;
}

static int dmz_close_zone(struct zdm * znd, u64 z_id)
{
	return 0;
}

static void on_timeout_activity(struct zdm * znd, int delay)
{
	(void)znd;
	(void)delay;
}

struct zdm * zoned_alloc(int fd, char * name);
int read_superblock(struct zdm * znd);

#include "libzdm.c"

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void activity_timeout(unsigned long data)
{
	(void)data;
}

static void bg_work_task(struct work_struct *work)
{
	(void) work;
}

/* -------------------------------------------------------------------------- */

void _zdm_free(struct zdm * znd, void *p, size_t sz, u32 code)
{
	zdm_free(znd, p, sz, code);
}

void * _zdm_alloc(struct zdm * znd, size_t sz, int code, gfp_t gfp)
{
	return zdm_alloc(znd, sz, code, gfp);
}

void * _zdm_calloc(struct zdm * znd, size_t n, size_t sz, int code, gfp_t gfp)
{
	return zdm_calloc(znd, n, sz, code, gfp);
}

void * alloc_pages(gfp_t mask, int order)
{
	return malloc(4096 << order);
}

void __free_pages(void *pgs, int order)
{
	(void) order;
	if (pgs)
		free(pgs);
}

/* -------------------------------------------------------------------------- */

static u64 mcache_greatest_gen(struct zdm *, int, u64 *, u64 *);
static u64 mcache_find_gen(struct zdm *, u64 base, int, u64 * out);
static void activity_timeout(unsigned long data);

u64 zdm_mcache_greatest_gen(struct zdm * mz, int at, u64 *_a, u64 *_b)
{
	return mcache_greatest_gen(mz, at, _a, _b);
}

u64 zdm_mcache_find_gen(struct zdm *mz, u64 base, int opt, u64 * out)
{
	return zdm_mcache_find_gen(mz, base, opt, out);
}

int zdm_reset_wp_wrap(struct zdm * znd, u64 z_id)
{
	int wp_err = 0;
	int fd = znd->ti->fd;

	if (znd->bdev_is_zoned) {
		u64 mapped_zoned = z_id + znd->zdstart;
		u64 lba = Z_BLKSZ * mapped_zoned;
		u64 s_addr = lba * Z_BLOCKS_PER_DM_SECTOR;

		wp_err = zdm_zone_reset_wp(fd, s_addr);
		if (wp_err) {
			Z_ERR(znd, "Reset WP: %" PRIx64 " -> %d failed.",
			       s_addr, wp_err);
			Z_ERR(znd, "Disabling Reset WP capability");
			znd->bdev_is_zoned = 0;
		}
	}
	return wp_err;
}

int zdm_zoned_inq(struct zdm *znd)
{
	int is_host_aware = 0;
	int fd = znd->ti->fd;
	int do_ata = znd->ata_passthrough;
	uint32_t inq = zdm_device_inquiry(fd, do_ata);
	if (inq) {
		is_host_aware = zdm_is_ha_device(inq, 0);
	}
	znd->bdev_is_zoned = is_host_aware;
	return 0;
}

struct zdm * zoned_alloc(int fd, char * name);

struct zdm * zdm_acquire(int fd, char * name)
{
	return zoned_alloc(fd, name);
}

// void zdm_release(struct zdm *znd)
// {
// //	if (znd->super_block) {
// //		struct mz_superkey *key_blk = znd->super_block;
// //		struct zdm_superblock *sblock = &key_blk->sblock;
// //
// //		sblock->flags = cpu_to_le32(0);
// //		sblock->csum = sb_crc32(sblock);
// //	}
// 
// 	zoned_destroy(znd);
// }
// 
int zdm_read(struct zdm *znd, void * data, u64 lba, int count)
{
	return read_block(znd->ti, DM_IO_KMEM, data, lba, count, 0);
}

int zdm_write(struct zdm *znd, void * data, u64 lba, int count)
{
	return write_block(znd->ti, DM_IO_KMEM, data, lba, count, 0);
}

/* -------------------------------------------------------------------------- */

struct zdm * zoned_alloc(int fd, char * name)
{
	struct zdm * znd = calloc(1, sizeof(*znd));
	if (znd) {
		u64 mzcount;
		u64 remainder;
		u64 nbytes = 0ul;
		int rcode = ioctl(fd, BLKGETSIZE64, &nbytes);
		if (rcode < 0) {
			perror("BLKGETSIZE64");
		}

		znd->ti = calloc(1, sizeof(*znd->ti));;
		znd->ti->fd = fd;
		znd->ti->private = znd;
		znd->nr_blocks = nbytes / 4096;


/* MUST do report zones against parition start to determine zdstart !! */

		znd->data_zones = (znd->nr_blocks >> Z_BLKBITS) - znd->zdstart;

/* FIXME: zones, data_zones, mz_count et. all */

		znd->gc_io_buf = vmalloc(GC_MAX_STRIPE * Z_C4K);
		znd->io_wq = create_singlethread_workqueue("kzoned");
		znd->super_block = vzalloc(Z_C4K);

		is_zoned_inquiry(znd);

		if (0 == strncmp("/dev/", name, 5)) {
			name += 5;
		}

		if (0 == strncmp("mapper/", name, 7)) {
			name += 7;
		}

		strncpy(znd->bdev_name, name, BDEVNAME_SIZE-1);

	}
	return znd;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

int zdm_superblock(struct zdm * znd)
{
	int rcode = -1;
        int n4kblks = 1;
        int use_worker = 1;
        int rc = 0;
	u64 sb_lba = 0;

	if (find_superblock(znd, use_worker, 1)) {
//		u64 generation;

// FIXME

//		generation = mcache_greatest_gen(znd, use_worker, &sb_lba, NULL);
//		pr_debug("Generation: %" PRIu64 " @ %" PRIx64 "\n", generation, sb_lba);
//
//		rc = read_block(znd->ti, DM_IO_VMA, key_blk,
//				sb_lba, n4kblks, use_worker);
//		if (rc) {
//			znd->ti->error = "Superblock read error.";
//			return rc;
//		}
//
//		znd->super_block = &key_blk->sblock;
//		rcode = 0;
	} else {
		fprintf(stderr, "Failed to find superblock\n");
	}

        return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int read_block(struct dm_target *ti, enum dm_io_mem_type dtype,
                      void *data, u64 lba, unsigned int count, int queue)
{
        off_t block = lba * Z_BLOCKS_PER_DM_SECTOR * 512ul;
        unsigned int c4k = count * Z_BLOCKS_PER_DM_SECTOR * 512ul;
        int rc = pread64(ti->fd, data, c4k, block);
        if (rc != c4k) {
                fprintf(stderr, "read error: %d reading %"
			PRIx64 "\n", rc, lba);
        } else {
		rc = 0;
        }
	(void)dtype;
	(void)queue;
        return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int write_block(struct dm_target *ti, enum dm_io_mem_type dtype,
                       void *data, u64 lba, unsigned int count, int queue)
{
        off_t block = lba * Z_BLOCKS_PER_DM_SECTOR * 512ul;
        unsigned int c4k = count * Z_BLOCKS_PER_DM_SECTOR  * 512ul;

        int rc = pwrite64(ti->fd, data, c4k, block);
        if (rc != c4k) {
                fprintf(stderr, "write error: %d writing %"
			PRIx64 "\n", rc, lba);
        } else {
		rc = 0;
        }
	(void)dtype;
	(void)queue;

        return rc;
}

int writef_block(struct dm_target *ti, enum dm_io_mem_type dtype,
			void *data, u64 lba, unsigned int op_flags,
			unsigned int count, int queue)
{
	(void) op_flags;
	return write_block(ti, dtype, data, lba, count, queue);
}


int znd_async_io(struct zdm *znd, enum dm_io_mem_type dtype,
		 void *data, sector_t block, unsigned int nDMsect,
		 u8 bi_op, unsigned int bi_flags, int queue,
		 io_notify_fn callback, void *context)
{
	unsigned long rc;

	if (bi_op == REQ_OP_READ)
		rc = read_block(znd->ti, dtype, data, block, nDMsect, queue);
	else
		rc = write_block(znd->ti, dtype, data, block, nDMsect, queue);
	if (!rc && callback)
		callback(rc, context);
}




int dmz_report_zones(struct zdm *znd, u64 z_id, void *pgs, size_t bufsz)
{
	int wp_err = 0;
	int fd = znd->ti->fd;
	struct blk_zone_report *report = pgs;

	if (znd->bdev_is_zoned) {
		u64 mapped_zoned = z_id + znd->zdstart;
		u64 lba = Z_BLKSZ * mapped_zoned;
		u64 s_addr = lba * Z_BLOCKS_PER_DM_SECTOR;

		report->nr_zones = (bufsz - sizeof(struct blk_zone_report)) >> 19;
		report->sector = s_addr;

		wp_err = zdm_report_zones(fd, report);
		if (wp_err) {
			Z_ERR(znd, "Zone Report: %" PRIx64 " -> %d failed.",
			       s_addr, wp_err);
			Z_ERR(znd, "Disabling Reset WP capability");
			znd->bdev_is_zoned = 0;
		}
	}
	return wp_err;
}

int zdm_superblock_check(struct zdm_superblock * sblock)
{
	return sb_check(sblock);
}

int zdm_map_addr(struct zdm * znd, u64 dm_s, struct map_addr * out)
{
	return map_addr_calc(znd, dm_s, out);
}

int zdm_sync_tables(struct zdm * znd, int sync, int drop)
{
	return do_sync_metadata(znd, sync, drop);
}

// int zdm_sync_crc_pages(struct zdm * znd)
// {
// 	return sync_crc_pages(znd);
// }

int zdm_unused_phy(struct zdm * znd, u64 block_nr, u64 orig, gfp_t gfp)
{
	return unused_phy(znd, block_nr, orig, gfp);
}

// int zdm_unused_addr(struct zdm * znd, u64 dm_s)
// {
// 	return unused_addr(znd, dm_s);
// }

int zdm_mapped_addmany(struct zdm * znd, u64 dm_s, u64 lba, u64 count, gfp_t gfp)
{
	return z_mapped_addmany(znd, dm_s, lba, count, gfp);
}

int zdm_mapped_discard(struct zdm * znd, u64 dm_s, u64 lba, gfp_t gfp)
{
	return z_mapped_discard(znd, dm_s, lba, gfp);
}

int zdm_mapped_sync(struct zdm * znd)
{
	return z_mapped_sync(znd);
}

int zdm_mapped_init(struct zdm * znd)
{
	return z_mapped_init(znd);
}

int zdm_write_if_dirty(struct zdm * znd, struct map_pg * oldest, int use_wq, int sync)
{
	return write_if_dirty(znd, oldest, use_wq, sync);
}

void zdm_release_table_pages(struct zdm * znd)
{
	release_table_pages(znd);
}

int zdm_zoned_wp_sync(struct zdm *znd, int reset_non_empty)
{
	return zoned_wp_sync(znd, reset_non_empty);
}

// int zdm_sync(struct zdm * znd)
// {
// 	return _znd_sync_to_disk(znd);
// }

u32 zdm_sb_crc32(struct zdm_superblock *sblock)
{
	return sb_crc32(sblock);
}

u64 zdm_reserve_blocks(struct zdm * znd, u32 flags, u32 count, u32 *avail)
{
	return z_acquire(znd, flags, count, avail);
}

int zdm_move_to_map_tables(struct zdm * znd, struct map_cache * jrnl)
{
	return move_to_map_tables(znd, jrnl);
}

struct map_pg *zdm_get_map_entry(struct zdm *znd, u64 lba, gfp_t gfp)
{
	return get_map_entry(znd, lba, gfp);
}

// int zdm_free_unused(struct zdm * znd, int allowed_pages)
// {
// 	return keep_active_pages(znd, allowed_pages);
// }

u16 zdm_crc16_le16(void const *data, size_t len)
{
	return crc_md_le16(data, len);
}

u64 zdm_map_value(struct zdm * znd, u32 delta)
{
	return map_value(znd, delta);
}

u64 zdm_map_encode(struct zdm * znd, u64 to_addr, u32 * value)
{
	return map_encode(znd, to_addr, value);
}

u64 zdm_lookup_cache(struct zdm *znd, u64 addr, int type)
{
	return z_lookup_cache(znd, addr, type);
}

u64 zdm_locate_sector(struct zdm *znd, u64 addr, gfp_t gfp)
{
	return current_mapping(znd, addr, gfp);
}

int zdm_read_pg(struct zdm *znd, struct map_pg *pg, u64 lba48, gfp_t gfp, struct mpinfo *mpi)
{
	return read_pg(znd, pg, lba48, gfp, mpi);
}




// static int load_page(struct zdm *, struct map_pg *, u64 lba, int);

// static u64 locate_sector(struct zdm * znd, struct map_addr * maddr);
// static int z_zone_gc_chunk(struct gc_state * gc_entry);
// static int z_zone_gc_grab_empty_zone(struct gc_state * gc_entry);

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
// static int zoned_init(struct dm_target *ti, struct zdm *znd);
// static int fpages(struct zdm * znd, int allowed_pages);
// static int zoned_create_disk(struct dm_target *ti, struct zdm * znd);

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
// static int zoned_init_disk(struct dm_target *ti, struct zdm * znd,
// 			   int create, int check, int force);
// static sector_t jentry_value(struct map_sect_to_lba * e, bool is_block);
// static u64 z_lookup_cache(struct zdm * znd, struct map_addr * sm);


int zdm_meta_test(struct zdm * znd)
{
	u64 dm_s;
	u64 lba;
	u64 mz = 0;
	int verbose = 1;

	// REDUX.

	return 0;
}

int zdm_sb_test_flag(struct zdm_superblock * sb, int bit_no)
{
	return sb_test_flag(sb, bit_no);
}

void zdm_sb_set_flag(struct zdm_superblock * sb, int bit_no)
{
	sb_set_flag(sb, bit_no);
}

int zdm_do_something(struct zdm * znd)
{
	int rcode;
	struct zdm_superblock * sblock = znd->super_block;
	char uuid_str[40];

	uuid_unparse(sblock->uuid, uuid_str);

	rcode = zdm_superblock_check(sblock);
	printf("sb check -> %d %s\n", rcode, rcode ? "error" : "okay");

	// do whatever
	printf("UUID    : %s\n",   uuid_str);
	printf("Magic   : %"PRIx64"\n",   le64_to_cpu(sblock->magic) );
	printf("Version : %08x\n", le32_to_cpu(sblock->version) );
	printf("N# Zones: %d\n",   le32_to_cpu(sblock->nr_zones) );
	printf("First Zn: %"PRIx64"\n",   le64_to_cpu(sblock->zdstart) );
	printf("Flags   : %08x\n", le32_to_cpu(sblock->flags) );
	printf("          %s\n",
	       zdm_sb_test_flag(sblock, SB_DIRTY) ? "dirty" : "clean");

	znd->zdstart  = le64_to_cpu(sblock->zdstart);
	zdm_meta_test(znd);

	return 0;

}


/**
 * ilog2 - log of base 2 of 32-bit or a 64-bit unsigned value
 * @n - parameter
 *
 * constant-capable log of base 2 calculation
 * - this can be used to initialise global variables from constant data, hence
 *   the massive ternary operator construction
 *
 * selects the appropriately-sized optimised version depending on sizeof(n)
 */
int ilog2(u64 n)
{
	return 	(n) < 1 ? -1 :
		(n) & (1ULL << 63) ? 63 :
		(n) & (1ULL << 62) ? 62 :
		(n) & (1ULL << 61) ? 61 :
		(n) & (1ULL << 60) ? 60 :
		(n) & (1ULL << 59) ? 59 :
		(n) & (1ULL << 58) ? 58 :
		(n) & (1ULL << 57) ? 57 :
		(n) & (1ULL << 56) ? 56 :
		(n) & (1ULL << 55) ? 55 :
		(n) & (1ULL << 54) ? 54 :
		(n) & (1ULL << 53) ? 53 :
		(n) & (1ULL << 52) ? 52 :
		(n) & (1ULL << 51) ? 51 :
		(n) & (1ULL << 50) ? 50 :
		(n) & (1ULL << 49) ? 49 :
		(n) & (1ULL << 48) ? 48 :
		(n) & (1ULL << 47) ? 47 :
		(n) & (1ULL << 46) ? 46 :
		(n) & (1ULL << 45) ? 45 :
		(n) & (1ULL << 44) ? 44 :
		(n) & (1ULL << 43) ? 43 :
		(n) & (1ULL << 42) ? 42 :
		(n) & (1ULL << 41) ? 41 :
		(n) & (1ULL << 40) ? 40 :
		(n) & (1ULL << 39) ? 39 :
		(n) & (1ULL << 38) ? 38 :
		(n) & (1ULL << 37) ? 37 :
		(n) & (1ULL << 36) ? 36 :
		(n) & (1ULL << 35) ? 35 :
		(n) & (1ULL << 34) ? 34 :
		(n) & (1ULL << 33) ? 33 :
		(n) & (1ULL << 32) ? 32 :
		(n) & (1ULL << 31) ? 31 :
		(n) & (1ULL << 30) ? 30 :
		(n) & (1ULL << 29) ? 29 :
		(n) & (1ULL << 28) ? 28 :
		(n) & (1ULL << 27) ? 27 :
		(n) & (1ULL << 26) ? 26 :
		(n) & (1ULL << 25) ? 25 :
		(n) & (1ULL << 24) ? 24 :
		(n) & (1ULL << 23) ? 23 :
		(n) & (1ULL << 22) ? 22 :
		(n) & (1ULL << 21) ? 21 :
		(n) & (1ULL << 20) ? 20 :
		(n) & (1ULL << 19) ? 19 :
		(n) & (1ULL << 18) ? 18 :
		(n) & (1ULL << 17) ? 17 :
		(n) & (1ULL << 16) ? 16 :
		(n) & (1ULL << 15) ? 15 :
		(n) & (1ULL << 14) ? 14 :
		(n) & (1ULL << 13) ? 13 :
		(n) & (1ULL << 12) ? 12 :
		(n) & (1ULL << 11) ? 11 :
		(n) & (1ULL << 10) ? 10 :
		(n) & (1ULL <<  9) ?  9 :
		(n) & (1ULL <<  8) ?  8 :
		(n) & (1ULL <<  7) ?  7 :
		(n) & (1ULL <<  6) ?  6 :
		(n) & (1ULL <<  5) ?  5 :
		(n) & (1ULL <<  4) ?  4 :
		(n) & (1ULL <<  3) ?  3 :
		(n) & (1ULL <<  2) ?  2 :
		(n) & (1ULL <<  1) ?  1 :
		(n) & (1ULL <<  0) ?  0 :
		-1;
}



#if 0
int main(int argc, char *argv[])
{
	int opt;
	int index;
	int loglevel;
	int exCode = 0;

	/* Parse command line */
	errno = EINVAL; // Assume invalid Argument if we die
	while ((opt = getopt(argc, argv, "l:")) != -1) {
		switch (opt) {
		case 'l':
			loglevel = atoi(optarg);
			break;
		default:
			printf("USAGE:\n"
			       "    verify -l loglevel files...\n"
			       "Defaults are: -l 0\n");
			break;
		} /* switch */
	} /* while */

	for (index = optind; index < argc; index++) {
		int fd;

		printf("Do something with %s\n", argv[index] );
		fd = open(argv[index], O_RDONLY);
		if (fd) {
			struct zdm * znd = zdm_acquire(fd, argv[index]);
			int rcode = zdm_superblock(znd);

			printf("read sb? fd: %d -> %d\n", fd, rcode);
			if (0 == rcode) {
				zdm_do_something(znd);
			} else {
				printf("Unable to find/load superblock\n");
			}
		} else {
			perror("Failed to open file");
			fprintf(stderr, "file: %s", argv[index]);
		}
	}

	(void) loglevel;

	return exCode;
}

#endif
