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

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/major.h>

#include <errno.h>
#include <string.h> // strdup

#include "libzdmwrap.h"
#include "libzdm-compat.h"
#include "zbc-ctrl.h"
#include "is_mounted.h"
#include "zdm_version.h"

#ifndef MAJOR
  #define MAJOR(dev)	((dev)>>8)
  #define MINOR(dev)	((dev) & 0xff)
#endif

#ifndef SCSI_BLK_MAJOR
  #ifdef SCSI_DISK0_MAJOR
    #ifdef SCSI_DISK8_MAJOR
      #define SCSI_DISK_MAJOR(M) ((M) == SCSI_DISK0_MAJOR || \
	((M) >= SCSI_DISK1_MAJOR && (M) <= SCSI_DISK7_MAJOR) || \
	((M) >= SCSI_DISK8_MAJOR && (M) <= SCSI_DISK15_MAJOR))
    #else
      #define SCSI_DISK_MAJOR(M) ((M) == SCSI_DISK0_MAJOR || \
	((M) >= SCSI_DISK1_MAJOR && (M) <= SCSI_DISK7_MAJOR))
    #endif /* defined(SCSI_DISK8_MAJOR) */
    #define SCSI_BLK_MAJOR(M) (SCSI_DISK_MAJOR((M)) || (M) == SCSI_CDROM_MAJOR)
  #else
    #define SCSI_BLK_MAJOR(M)  ((M) == SCSI_DISK_MAJOR || (M) == SCSI_CDROM_MAJOR)
  #endif /* defined(SCSI_DISK0_MAJOR) */
#endif /* defined(SCSI_BLK_MAJOR) */

#define ZDMADM_CREATE 1
#define ZDMADM_RESTORE 2
#define ZDMADM_CHECK 3
#define ZDMADM_PROBE 4
#define ZDMADM_UNLOAD 5
#define ZDMADM_WIPE 6


#define ZDM_SBLK_VER_MAJOR 1
#define ZDM_SBLK_VER_MINOR 0
#define ZDM_SBLK_VER_POINT 0

#define ZDM_SBLK_VER   (ZDM_SBLK_VER_MAJOR << 16) | \
                       (ZDM_SBLK_VER_MINOR << 8) | \
                        ZDM_SBLK_VER_POINT

#define MEDIA_ZBC 0x01
#define MEDIA_ZAC 0x02

#define MEDIA_HOST_AWARE    (0x01 << 16)
#define MEDIA_HOST_MANAGED  (0x01 << 17)

#define ZONE_SZ_IN_SECT 0x80000 /* 1 << 19 */

/**
 * A large randomish number to identify a ZDM partition
 */
static const char zdm_magic[] = {
	0x7a, 0x6f, 0x6e, 0x65, 0x63, 0x44, 0x45, 0x56,
	0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81
};

/**
 * A superblock stored at the 0-th block of a deivce used to
 * re-create identify and manipulate a ZDM instance.
 * Contains enough information to repeat the dmsetup magic create/restore
 * an instance.
 */
struct zdm_super_block {
	uint32_t crc32;
	uint32_t reserved;
	uint8_t magic[ARRAY_SIZE(zdm_magic)];
	uuid_t  uuid;
	uint32_t version;     /* 0xMMMMmmpt */
	uint64_t sect_start;
	uint64_t sect_size;
	uint32_t mz_metadata_zones;     /* 3 (default) */
	uint32_t mz_over_provision;     /* 5 (minimum) */
	uint64_t zdm_blocks;  /* 0 -> <zdm_blocks> for dmsetup table entry */
	uint32_t discard;     /* if discard support is enabled */
	uint32_t disk_type;   /* HA | HM */
	uint32_t zac_zbc;     /* if ZAC / ZBC is supported on backing device */
	char label[64];
	uint64_t data_start;  /* zone # of first *DATA* zone */
	uint64_t zone_size;   /* zone size in 512 byte blocks */
};
typedef struct zdm_super_block zdm_super_block_t;

/**
 * A 64bit CRC. Overkill but it looked nice,
 *   inspired by btrfs-tools via util-linux
 */
static uint64_t zdm_crc32(zdm_super_block_t *sblk)
{
	uint32_t icrc = sblk->crc32;
	uint8_t *data = (uint8_t *) sblk;
	size_t sz = sizeof(*sblk);
	uint32_t calc;

	sblk->crc32 = 0u;
	calc = crc32(~0u, data, sz) ^ ~0u;
	sblk->crc32 = icrc;

	return calc;
}

/**
 * Decode the ZDM superblock to a more user-friendly representation.
 */
static void zdmadm_show(const char * dname, zdm_super_block_t *sblk)
{
	char uuid_str[40];

	uuid_unparse(sblk->uuid, uuid_str);

	printf("Device %s is configured for ZDM:\n", dname );
	printf("crc     - %" PRIx32 "\n", sblk->crc32 );
	printf("magic   - %02x%02x%02x%02x%02x%02x%02x%02x "
			 "%02x%02x%02x%02x%02x%02x%02x%02x\n",
			sblk->magic[0],
			sblk->magic[1],
			sblk->magic[2],
			sblk->magic[3],
			sblk->magic[4],
			sblk->magic[5],
			sblk->magic[6],
			sblk->magic[7],
			sblk->magic[8],
			sblk->magic[9],
			sblk->magic[10],
			sblk->magic[11],
			sblk->magic[12],
			sblk->magic[13],
			sblk->magic[14],
			sblk->magic[15]);
	printf("uuid    - %s\n", uuid_str );
	printf("version - %d.%d.%d\n",
	                (sblk->version >> 16) & 0xFFFF,
			(sblk->version >>  8) & 0xFF,
			(sblk->version >>  0) & 0xFF );

	if (strlen(sblk->label) > 0) {
		printf("label   - %s\n", sblk->label );
	}
	printf("start   - %"PRIu64"\n", sblk->sect_start);
	printf("data    - %"PRIx64" [zone %" PRIu64 " @ %"PRIx64"]\n",
		sblk->data_start * sblk->zone_size,
		sblk->data_start, sblk->data_start << 16);
	printf("size    - %"PRIu64"\n", sblk->sect_size);
	printf("zdm sz  - %"PRIu64"\n", sblk->zdm_blocks);
	printf("resv    - %u [%u: metadata + %u: over provision]\n",
			sblk->mz_metadata_zones +  sblk->mz_over_provision,
			sblk->mz_metadata_zones,
			sblk->mz_over_provision);
	printf("trim    - %s\n", sblk->discard ? "ON" : "OFF");
	printf("ha/hm   - HostAware %s / HostManaged %s\n",
		sblk->disk_type & MEDIA_HOST_AWARE   ? "Yes" : "No",
		sblk->disk_type & MEDIA_HOST_MANAGED ? "Yes" : "No");

	printf("zac/zbc - ZAC: %s / ZBC: %s\n",
		sblk->zac_zbc & MEDIA_ZAC ? "Yes" : "No",
		sblk->zac_zbc & MEDIA_ZBC ? "Yes" : "No" );
}

/**
 * Use device major/minor to determine if whole device or partition is specified.
 */
static int is_part(const char *dname)
{
	int is_partition = 1;
	struct stat st_buf;
	if (stat(dname, &st_buf) == 0) {
		if ( ((MAJOR(st_buf.st_rdev) == HD_MAJOR &&
		      (MINOR(st_buf.st_rdev) % 64) == 0))
		           ||
		     ((SCSI_BLK_MAJOR(MAJOR(st_buf.st_rdev)) &&
		                     (MINOR(st_buf.st_rdev) % 16) == 0))
		) {
			printf("%s is entire device, not just one partition!\n", dname);
			is_partition = 0;
		}
	}
	return is_partition;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zdm_mentry_page(struct zdm *znd, struct map_pg *mapped, u64 lba, int mt)
{
	int rc = -ENOMEM;

//	REF(mapped->refcount);
//	mutex_lock(&mapped->md_lock);
//	mapped->mdata = ZDM_ALLOC(megaz->znd, Z_C4K, PG_27);
//	if (mapped->mdata) {
//		memset(mapped->mdata, 0xFF, Z_C4K);
//	}
//	mutex_unlock(&mapped->md_lock);
//
//	if (!mapped->mdata) {
//		Z_ERR(megaz->znd, "%s: Out of memory.", __func__);
//		goto out;
//	}
//
//	rc = load_page(megaz, mapped, lba, mt);
//	if (rc < 0) {
//		Z_ERR(megaz->znd, "%s: load_page from %" PRIx64
//		      " [to? %d] error: %d", __func__, lba,
//		      mt, rc);
//		goto out;
//	}
//	mapped->age = jiffies_64;
//out:
//	DEREF(mapped->refcount);
	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_pg *zdm_get_mentry(struct zdm *znd, struct map_addr * maddr, int is_map_to)
{
//	u64 lba = is_map_to ? maddr->lut_s : maddr->lut_r;
//	struct map_pg *mapped = get_map_table_entry(megaz, lba, is_map_to);
//	if (mapped) {
//		if (!mapped->mdata) {
//			int rc = zdm_mentry_page(megaz, mapped, lba, is_map_to);
//			if (rc < 0) {
//				megaz->meta_result = rc;
//			}
//		}
//	} else {
//		Z_ERR(megaz->znd, "%s: No table for %" PRIx64 " page# %" PRIx64 ".",
//		      __func__, maddr->dm_s, lba);
//	}
//	return mapped;
	return NULL;
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_pg *load_map_entry(struct zdm *znd, u64 lba, int is_map_to)
{
//	struct map_pg *mapped = get_map_table_entry(megaz, lba, is_map_to);
//	if (mapped) {
//		if (!mapped->mdata) {
//			int rc = zdm_mentry_page(megaz, mapped, lba, is_map_to);
//			if (rc < 0) {
//				megaz->meta_result = rc;
//			}
//		}
//	} else {
//		Z_ERR(megaz->znd, "%s: No table for page# %" PRIx64 ".",
//		      __func__, lba);
//	}
//	return mapped;
	return NULL;
}

#define E_NF MZTEV_NF

static void _all_nf(struct map_pg *mapped)
{
//	int entry;
//	for (entry = 0; entry < 1024; entry++) {
//		mapped->mdata[entry] = E_NF;
//	}
}

static int _test_nf(struct map_pg *mapped, int dont_fix)
{
//	int entry;
//	for (entry = 0; entry < 1024; entry++) {
//		if (E_NF == mapped->mdata[entry]) {
//			if (dont_fix) {
//				printf("Bad entry %d [%x]\n", entry, mapped->mdata[entry] );
//				return -1; /* E: Corrupt */
//			}
//			mapped->mdata[entry] = MZTEV_UNUSED;
//		}
//	}
	return 0;
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

int __btf(struct zdm *znd, struct map_pg *mapped, u64 b_lba, int is_to)
{
//	int rcode = 0;
//	u32 enc = 0;
//	int entry;
//	struct map_pg * lba_map;
//	struct map_addr maddr;
//	u64 lba_addr;
//	u64 addr = (b_lba & 0xFFFF) * 1024;
//
//	for (entry = 0; entry < 1024; entry++) {
//		u64 dm_s = addr + entry
//			 + (megaz->mega_nr * Z_BLKSZ * 1024ul);
//
//		enc = mapped->mdata[entry];
//		if ( enc > 0x03ffFFFFu ) {
//			if ( MZTEV_UNUSED != enc ) {
//				mapped->mdata[entry] = E_NF;
//				rcode = 1;
//			}
//		} else {
//			int err;
//			u32 value;
//			u32 lba_enc = 0;
//			u64 r_sect = 0;
//			u64 lba = map_value(megaz, enc); // phy of dm_s
//
//			if (!lba) {
//				printf("Un-possible!! %d\n", __LINE__);
//				mapped->mdata[entry] = E_NF;
//				rcode = 1;
//				continue;
//			}
//
//			map_addr_calc(megaz->znd, lba, &maddr);
//			lba_addr = !is_to ? maddr.lut_s : maddr.lut_r;
//			lba_map = get_map_table_entry(megaz, lba_addr, !is_to);
//			if (lba_map && lba_map->mdata) {
//				lba_enc = lba_map->mdata[maddr.offentry];
//				r_sect = map_value(megaz, lba_enc);
//			}
//
//			/* if lba_enc == MZTEV_NF (or othersise invalid) */
//			/* correct the broken reverse map value */
//			if (r_sect != dm_s) {
//				printf("b2f: %s %" PRIx64 " --> %" PRIx64
//				       " (%s) [dms_enc: %x]...",
//					is_to ? "dms" : "lba",
//					dm_s, lba, is_to ? "lba" : "dms", enc);
//
//				err = map_encode(megaz, dm_s, &value);
//				if (!err) {
//					printf("Fix %" PRIx64 " %x <-- "
//					       "[value: %x] %" PRIx64, lba,
//					       lba_map->mdata[maddr.offentry],
//					       value, r_sect );
//					lba_map->mdata[maddr.offentry] = value;
//					set_bit(IS_DIRTY, &lba_map->flags);
//				}
//				printf("\n");
//			}
//		}
//	}
//	return rcode;
	return 0;
}

/**
 * An initial check and repair the lookup tables.
 */
int zmz_car_rlut(struct zdm *znd)
{
//	struct mzlam * lam = &megaz->logical_map;
//	u64 lba;
//	u64 dm_s;
//	int is_to = 0;
//	int need_repair = 1;
//	int fwd_corrupt = 0;
//	int rev_corrupt = 0;
//
//	/*
//	 * Check and repair:
//	 *   - load reverse map entries.
//	 *   - load foward map entries.
//	 */
//
//
//	printf("e");
//	fflush(stdout);
//
//	for (lba = lam->r_base; lba < (lam->r_base + Z_BLKSZ); lba++) {
//		struct map_pg *mapped = get_map_table_entry(megaz, lba, is_to);
//		if (mapped) {
//			if (!mapped->mdata) {
//				int err;
//				err = zdm_mentry_page(megaz, mapped, lba, is_to);
//				if (-ENOSPC == err) {
//					printf("Out of memory!! %d\n", __LINE__);
//					rev_corrupt = 1;
//				} else if (err < 0) {
//					printf("Loaded %" PRIx64 " Corrupt page.\n", lba );
//					_all_nf(mapped);
//					rev_corrupt = 1;
//				} else {
//					if (_test_nf(mapped, 1)) {
//						printf("Repair failed: Bad entries in %"
//							PRIx64 ".\n", lba);
//					}
//				}
//			}
//		} else {
//			printf("Out of memory!! %d\n", __LINE__ );
//		}
//	}
//
//	printf("p");
//	fflush(stdout);
//
//	is_to = 1;
//	for (dm_s = lam->s_base; dm_s < (lam->s_base + Z_BLKSZ); dm_s++) {
//		struct map_pg *mapped = get_map_table_entry(megaz, dm_s, is_to);
//		if (mapped) {
//			if (!mapped->mdata) {
//				int err;
//				err = zdm_mentry_page(megaz, mapped, dm_s, is_to);
//				if (-ENOSPC == err) {
//					printf("%" PRIx64 " -- Out of memory!!"
//					        " %d\n", dm_s, __LINE__);
//					fwd_corrupt = 1;
//				} else if (err < 0) {
//					printf("%" PRIx64 " -- Corrupt Entry!!"
//					        " %d\n", dm_s, __LINE__);
//					_all_nf(mapped);
//					fwd_corrupt = 1;
//				} else {
//					if (_test_nf(mapped, 1)) {
//						printf("Repair failed: Bad entries in %"
//							PRIx64 ".\n", lba);
//					}
//				}
//			}
//			__btf(megaz, mapped, dm_s, is_to);
//		} else {
//			printf("Out of memory!! %d\n", __LINE__ );
//		}
//	}
//
////printf("Fixing Forward mapping table\n");
//	printf("a");
//	fflush(stdout);
//
//	is_to = 0;
//	for (lba = lam->r_base; lba < (lam->r_base + Z_BLKSZ); lba++) {
//		struct map_pg *mapped = get_map_table_entry(megaz, lba, is_to);
//		if (mapped) {
//			if (!mapped->mdata) {
//				int err;
//
//printf("Loading %"PRIx64 " ?? \n", lba );
//				err = zdm_mentry_page(megaz, mapped, lba, 0);
//				if (-ENOSPC == err) {
//					printf("%" PRIx64 " -- Out of memory!!"
//					        " %d\n", lba, __LINE__);
//				} else if (err < 0) {
//					printf("%" PRIx64 " -- Corrupt Entry!!"
//					        " %d\n", lba, __LINE__);
////					_all_nf(mapped);
//				}
//				rev_corrupt = 1;
//			}
//			__btf(megaz, mapped, lba, is_to);
//		} else {
//			printf("Out of memory!! %d\n", __LINE__ );
//		}
//	}
//
//// printf("Verify Forward mapping table entries\n");
//	printf("i");
//	fflush(stdout);
//
//	is_to = 1;
//	for (dm_s = lam->s_base; dm_s < (lam->s_base + Z_BLKSZ); dm_s++) {
//		struct map_pg *mapped = get_map_table_entry(megaz, dm_s, is_to);
//		if (mapped) {
//			if (!mapped->mdata) {
//				int err;
//				err = zdm_mentry_page(megaz, mapped, dm_s, is_to);
//				if (err < 0) {
//					printf("Repair failed dm_s %" PRIx64
//						" Err %d.\n", dm_s, err );
//					goto out;
//				}
//			}
//			if (!mapped->mdata) {
//				printf("Repair failed: No page for %"
//					PRIx64 ".\n", dm_s);
//				goto out;
//			}
//			if (_test_nf(mapped, rev_corrupt)) {
//				printf("Repair failed: Bad entries in %"
//					PRIx64 ".\n", dm_s);
//				goto out;
//			}
//		} else {
//			printf("Out of memory!! %d\n", __LINE__ );
//		}
//	}
//
//// printf("Verify Reverse mapping table entries\n");
//	printf("r");
//	fflush(stdout);
//
//	is_to = 0;
//	for (lba = lam->r_base; lba < (lam->r_base + Z_BLKSZ); lba++) {
//		struct map_pg *mapped = get_map_table_entry(megaz, lba, is_to);
//		if (mapped) {
//			if (!mapped->mdata) {
//				int err;
//				err = zdm_mentry_page(megaz, mapped, lba, 0);
//				if (err < 0) {
//					printf("Repair failed lba %" PRIx64
//						" Err %d.\n", lba, err );
//					goto out;
//				}
//			}
//			if (!mapped->mdata) {
//				printf("Repair failed: No page for %"
//					PRIx64 ".\n", lba);
//				goto out;
//			}
//			if (_test_nf(mapped, fwd_corrupt)) {
//				printf("Repair failed: Bad entries in %"
//					PRIx64 ".\n", lba);
//				goto out;
//			}
//		} else {
//			printf("Out of memory!! %d\n", __LINE__ );
//		}
//	}
//	need_repair = 0;
//
//	printf(".");
//	fflush(stdout);
//
//out:
//	return need_repair;
	return 0;
}

/**
 * An initial 'check' and 'repair' ZDM metadata on a Megazone
 */
int zdm_mz_check_and_repair(struct zdm *znd)
{
	int err = 0;
//	int entry;
//
//	printf("R");
//	fflush(stdout);
//
//	err = zmz_car_rlut(megaz);
//	if (err) {
//		/* repair is still needed */
//		goto out;
//	}
//
//	/* on clean: */
//	for (entry = 0; entry < Z_BLKSZ; entry++) {
//		if (megaz->sectortm[entry]) {
//			write_if_dirty(megaz, megaz->sectortm[entry], 1);
//		}
//		if (megaz->reversetm[entry]) {
//			write_if_dirty(megaz, megaz->reversetm[entry], 1);
//		}
//	}
//
//out:
//	release_table_pages(megaz);
//
	return err;
}

/**
 * An initial 'check' and 'repair' ZDM metadata ...
 */
int zdm_check_and_repair(struct zdm * znd)
{
//	int err = 0;
//	u64 mz = 0;
//	int all_good = 1;
//
//	printf("Loading MZ ");
//	fflush(stdout);
//	for (mz = 0; mz < znd->mz_count; mz++) {
//		printf("%"PRIu64".", mz);
//		fflush(stdout);
//
//		err = zdm_mapped_init(&znd->z_mega[mz]);
//		if (err) {
//			printf("MZ #%"PRIu64" Init failed -> %d\n", mz, err);
//			goto out;
//		}
//	}
//
//	printf("done.\nZDM Check ");
//	fflush(stdout);
//
//	for (mz = 0; mz < znd->mz_count; mz++) {
//		printf("%"PRIu64".", mz);
//		fflush(stdout);
//
//		err = zdm_mz_check_and_repair(&znd->z_mega[mz]);
//		if (err) {
//			printf("MZ #%"PRIu64" Check failed -> %d\n", mz, err);
//			goto out;
//		}
//	}
//
//	if (all_good) {
//		printf("Write clean SB\n");
//		if (znd->z_superblock) {
//			struct mz_superkey *key_blk = znd->z_superblock;
//			struct zdm_superblock *sblock = &key_blk->sblock;
//
//			sblock->flags = cpu_to_le32(0);
//			sblock->csum = sb_crc32(sblock);
//		}
//		printf("Sync ... SB\n");
//
//		for (mz = 0; mz < znd->mz_count; mz++) {
//			zdm_sync(&znd->z_mega[mz]);
//		}
//	}
//
//out:
	return 0;
}

/**
 * An initial 'check' and 'repair' ZDM metadata ...
 */
int my_alt_test(struct zdm * znd, int verbose)
{
//	u64 dm_s;
//	u64 lba;
//	struct zdm *znd = &znd->z_mega[0];
//
//	for (dm_s = 0x20000; dm_s < 0x60000; dm_s++) {
//		struct map_addr maddr;
//
//		zdm_map_addr(znd, dm_s, &maddr);
//		lba = zdm_lookup(megaz, &maddr);
//		if (lba && verbose) {
//			fprintf(stderr, "%"PRIx64" -> %"PRIx64"\n", dm_s, lba);
//		}
//	}
	return 0;
}

/**
 * Find and verify the actual ZDM superblock(s) and key metadata.
 *
 * Return 1 if superblock is flagged as dirty.
 */
int zdm_metadata_check(struct zdm * znd)
{
//	int rcode = 0;
//	struct zdm_superblock * sblock = znd->super_block;
//	char uuid_str[40];
//
//	uuid_unparse(sblock->uuid, uuid_str);
//
//	rcode = zdm_superblock_check(sblock);
//	printf("sb check -> %d %s\n", rcode, rcode ? "error" : "okay");
//	if (rcode) {
//		return rcode;
//	}
//
//	rcode = zdm_sb_test_flag(sblock, SB_DIRTY) ? 1 : 0;
//
//	// do whatever
//	printf("UUID    : %s\n",   uuid_str);
//	printf("Magic   : %"PRIx64"\n",   le64_to_cpu(sblock->magic) );
//	printf("Version : %08x\n", le32_to_cpu(sblock->version) );
//	printf("N# Zones: %d\n",   le32_to_cpu(sblock->nr_zones) );
//	printf("First Zn: %"PRIx64"\n",   le64_to_cpu(sblock->zdstart) );
//	printf("Flags   : %08x\n", le32_to_cpu(sblock->flags) );
//	printf("          %s\n", zdm_sb_test_flag(sblock, SB_DIRTY) ? "dirty" : "clean");
//
//	znd->zdstart  = le64_to_cpu(sblock->zdstart);
//	return rcode;
	return 0;
}


/**
 * Get the starting block of the partition.
 * Currently using HDIO_GETGEO and start is a long ...
 * Q: Is there better way to get this? Preferably an API
 *    returning the a full u64. Other option is to poke
 *    around in sysfs (/sys/block/sdX/sdXn/start)
 *
 * FUTURE: Do this better ...
 */
int blkdev_get_start(int fd, unsigned long *start)
{
	struct hd_geometry geometry;

	if (ioctl(fd, HDIO_GETGEO, &geometry) == 0) {
		*start = geometry.start;
		return 0;
	}
	return -1;
}


/**
 * Get the full size of a partition/block device.
 */
int blkdev_get_size(int fd, u64 *sz)
{
	if (ioctl(fd, BLKGETSIZE64, sz) >= 0) {
		return 0;
	}
	return -1;
}


/**
 * User requested the ZDM be checked ...
 * TODO: Add fix support, switch to RW, etc.
 */
int zdmadm_check(const char *dname, int fd, zdm_super_block_t * sblock, int do_fix)
{
	struct zdm * znd;
	char * zname;
	int rcode;

	if (strlen(sblock->label) > 0) {
		zname = sblock->label;
	} else {
		zname = strrchr(dname, '/');
		if (zname) {
			if (*zname == '/') {
				zname++;
			}
		} else {
			rcode = -1;
			printf("Invalid argument. Need valid dname or zname\n");
			goto out;
		}
	}

	znd = zoned_alloc(fd, zname);
	rcode = zdm_superblock(znd);
	if (0 == rcode) {
		int is_dirty = zdm_metadata_check(znd);
		if (is_dirty ||	do_fix) {
			int err = zdm_check_and_repair(znd);
			if (err) {
				printf("ERROR: check/repair failed!\n");
				rcode = err;
			}
		}

	} else {
		printf("Unable to find/load superblock\n");
	}

out:
	return rcode;
}

int zaczbc_probe_media(int fd, zdm_super_block_t * sblk, int verbose)
{
	int do_ata = 0;
	int rcode = -1;

	uint32_t inq = zdm_device_inquiry(fd, do_ata);
	if (inq) {
		if (zdm_is_ha_device(inq, 0)) {
			sblk->zac_zbc |= MEDIA_ZBC;
			sblk->disk_type |= MEDIA_HOST_AWARE;
			if (verbose > 0) {
				printf(" ... HA device supports ZBC access.\n");
			}
			rcode = 0;
		}
	}

	do_ata = 1;
	inq = zdm_device_inquiry(fd, do_ata);
	if (inq) {
		if (zdm_is_ha_device(inq, 0)) {
			sblk->disk_type |= MEDIA_HOST_AWARE;
			sblk->zac_zbc   |= MEDIA_ZAC;
			if (verbose > 0) {
				printf(" ... HA device supports ZAC access.\n");
			}
			rcode = 0;
		}
	}

	if (0 == sblk->disk_type && 0 == sblk->zac_zbc) {
		if (verbose > 0) {
			printf(" ... No ZAC/ZAC support detected.\n");
		}
		rcode = 0;
	}

	return rcode;
}

static inline int is_conv_or_relaxed(unsigned int type)
{
	return (type == 1 || type == 3) ? 1 : 0;
}

/* assuming 4k sectors aka ssize < 16TB */
/**
 * Here we attempt to report the amount of metadata we need to reserve
 * @ssize: Total size of partition.
 * @zonesz: Size of zones (256MiB)
 * @mzc: # of zones needed for Forward Lookup Tables.
 * @cache: # of blocks needed for super block and accounting/journaling etc.
 * @min: # Minimum reservation [FWD Lookup + cache (sized at 1 zone)]
 * @pref: # FWD/REV + CRC blks (in zones) + cache blocks (in zones).
 *
 * NOTE: cache blocks and CRC blocks are rounded up and reported as # of zones.
 * 
 */
static int minimums(u64 ssize, u64 zonesz, u64 *mzc, u64 * cache, u64 * min, u64 * pref)
{
	u64 zonesz_4k   = zonesz / 8;
	u64 full_zones  = ssize / zonesz;
	u64 blks        = full_zones * zonesz_4k;
	u64 cache_syncs = WB_JRNL_BASE + WB_JRNL_MIN;
	u64 lut_blocks  = blks / 1024;
	u64 lut_zones   = (lut_blocks + zonesz_4k - 1) / zonesz_4k;

	*mzc = lut_zones;
	*cache = cache_syncs;
	*min = lut_zones + 1; /* forward LUT + Super block [Z0] reservation */
	*pref = (lut_zones * 2) + 2; /* cache(1) + fwd(N) + rev(N) + crcs(1) */

	return 0;
}

int zdmadm_probe_zones(int fd, zdm_super_block_t * sblk, int verbose)
{
	int rcode = 0;
	size_t size = 128 * 4096;
	struct bdev_zone_report_io *report = malloc(size);
	if (report) {
		int opt = ZOPT_NON_SEQ_AND_RESET;
		u64 lba = sblk->sect_start;
		int do_ata = (sblk->zac_zbc & MEDIA_ZAC) ? 1 : 0;

		memset(report, 0, size);
		rcode = zdm_report_zones(fd, report, size, opt, lba, do_ata);
		if (rcode < 0) {
			printf("report zones failure: %d\n", rcode);
		} else  {
			int zone = 0;
			int zone_absolute_start = 0;
			struct bdev_zone_report *info = &report->data.out;
			struct bdev_zone_descriptor *entry = &info->descriptors[zone];
			int is_be = zdm_is_big_endian_report(info);
			u64 fz_at = is_be ? be64toh(entry->lba_start) : entry->lba_start;
			u64 fz_sz = is_be ? be64toh(entry->length) : entry->length;
			unsigned int type = entry->type & 0xF;
			u64 cache, need, pref;
			u64 mdzcount = 0;
			u64 nmegaz = 0;

			minimums(sblk->sect_size, fz_sz, &nmegaz, &cache, &need, &pref);
			if ( !is_conv_or_relaxed(type) ) {
				printf("Unsupported device: ZDM first zone must be conventional"
				       " or sequential-write preferred\n");
				rcode = -1;
				goto out;
			}
			zone_absolute_start = fz_at / fz_sz;
			if (verbose) {
				printf("LBA start of first zone: %6" PRIx64 " Z# %d\n", fz_at, zone);
				printf("LBA start of partition:  %6" PRIx64 "\n", sblk->sect_start);
				printf("LBA partition is in zone #%d\n", zone_absolute_start);
				printf(" ... Min cache needed before data starts: %" PRIx64 "\n", (cache * 8));
			}
			while (fz_at < sblk->sect_start) {
				if (verbose)
					printf("Finding first zone *AFTER START OF PARTITION*\n");
				entry = &info->descriptors[++zone];
				fz_at = is_be ? be64toh(entry->lba_start) : entry->lba_start;
				fz_sz = is_be ? be64toh(entry->length) : entry->length;
			}
			if (verbose) {
				printf("LBA start of first zone: %6" PRIx64 " Z# %d\n", fz_at, zone);
				printf("LBA start of partition:  %6" PRIx64 "\n", sblk->sect_start);
				printf(" ... Min cache needed before data starts: %" PRIx64 "\n", (cache * 8));
			}
			while (sblk->sect_start >= fz_at) {
				if (verbose)
					printf("Skipping forward\n");
				entry = &info->descriptors[++zone];
				fz_at = is_be ? be64toh(entry->lba_start) : entry->lba_start;
				fz_sz = is_be ? be64toh(entry->length) : entry->length;
			}
			if (verbose) {
				printf("LBA start of first zone: %6" PRIx64 " Z# %d\n", fz_at, zone);
				printf("LBA start of partition:  %6" PRIx64 "\n", sblk->sect_start);
			}


// printf("Using non-aligned space start of partition for metadata.*\n");


			if ((fz_at - sblk->sect_start) > (cache * 8))
				mdzcount++; /* really pref-- */

			/*
			 * using an 'Sanity' cut off of 200.
			 * This is probably just paranoia and could be removed.
			 */
			for (; mdzcount < pref && zone < 200; zone++) {
				u64 length;

				entry = &info->descriptors[zone];
				length = is_be ? be64toh(entry->length) : entry->length;
				type = entry->type & 0xF;

				if ( !is_conv_or_relaxed(type) ) {
					printf("Unsupported device: ZDM first zone must be conventional"
					       " or sequential-write preferred\n");
					rcode = -1;
					goto out;
				}
				if ( length != fz_sz ) {
					printf("Unsupported device: all zones must be same size"
					       " excluding last zone on the drive!\n");
					rcode = -1;
					goto out;
				}
				mdzcount++;
			}
			sblk->data_start = zone + zone_absolute_start;
			sblk->zone_size = fz_sz;
		}
	}
out:
	if (report)
		free(report);

	return rcode;
}

int zdmadm_format_initmd(int fd, zdm_super_block_t * sblk, int use_force, int verbose)
{
 	struct io_4k_block *io_vcache = NULL;
 	void *data = NULL;
 	int locations;
 	int iter;
 	int err = 0;
 	int rc;
 	u64 pool_lba;
 	u64 cache, need, pref;
 	u64 fz_sz = 1 << 19; /* in 512 byte sectors */
 	u64 zone = ((sblk->sect_start + fz_sz - 1) / fz_sz);
 	u64 fz_at = zone * fz_sz;
 	u64 mdzcount = 0;
 	u64 mz_count;
 	u64 lba = LBA_SB_START;
 	unsigned long wchunk = (Z_C4K*IO_VCACHE_PAGES);
 
 	io_vcache = calloc(IO_VCACHE_PAGES, Z_C4K);
 	data = calloc(1, Z_C4K);
 	if (!data || !io_vcache) {
 		err = -ENOMEM;
 		goto out;
 	}
 
 	/* pass through conventional ... no ZAC/ZBC report to check */
 	minimums(sblk->sect_size, fz_sz, &mz_count, &cache, &need, &pref);
 
 	lba = LBA_SB_START;
 	memset(data, 0, Z_C4K);
 	locations = mz_count * CACHE_COPIES;
 
 	printf("ZDM: Initialize Metadata pool\n");
 	printf(" ... initializing cache blocks from %" PRIx64 " - 0x%"
 		PRIx64 "\n", lba, lba + WB_JRNL_BASE );
 
 	for (iter = 0; iter < WB_JRNL_BASE; iter++) {
 		rc = pwrite64(fd, data, Z_C4K, lba << 12);
 		if (rc != Z_C4K) {
 			fprintf(stderr, "write error: %d writing %"
 				PRIx64 "\n", rc, lba);
 			err = -1;
 			goto out;
 		}
 		lba++;
 	}
 
 	pool_lba = fz_sz >> 3;
 	if ( (fz_at - sblk->sect_start) > (cache << 3) ) {
 		/* number of blocks until next zone begins */
 		pool_lba = (fz_at - sblk->sect_start) >> 3;
 		mdzcount++;
 		printf(" ... used 0x%" PRIx64 " 4k blocks for"
 		       " zone-alignment\n", pool_lba);
 	}
 
 	printf(" ... clearing %" PRIu64 " ZTL zones from %"
 		PRIx64 " - %" PRIx64 "\n",
 		pref - 2, pool_lba, pool_lba + ((pref - 2) << 16) );
 
 	memset(io_vcache, 0xFF, wchunk);
 	locations = (mz_count << 16) / IO_VCACHE_PAGES;
 	if ( (pref - mdzcount) <= sblk->data_start) {
 		locations *= 2;
 		if (verbose)
 			printf(" ... including reverse ZTL zones\n");
 	}
 
 	printf(" ... %d writes of %d 4k blocks [%ld bytes]\n",
 		locations, IO_VCACHE_PAGES, wchunk);
 	printf("         lba of partition | drive\n");
 	lba = pool_lba;
 	for (iter = 0; iter < locations; iter++) {
 		rc = pwrite64(fd, io_vcache, wchunk, lba << 12);
 		if (rc != wchunk) {
 			printf("%s: clear sb @ %" PRIx64
 			       " failed:  %d\b", __func__, lba, rc);
 		}
 
 		if (0 == (iter % 256)) {
 			printf("    ... writing .. %6"PRIx64" | %6"PRIx64"\n",
 				lba, lba + (sblk->sect_start >> 3));
 		}
 
 		lba += IO_VCACHE_PAGES;
 	}
 
 	if ( (pref - mdzcount) <= sblk->data_start) {
 		__le16 crc;
 		__le16 *crcs = data;
 
 		printf(" ... inititalize Meta CRCs %6"PRIx64" - %6"PRIx64"\n",
 			lba, lba + (0x40 * mz_count));
 		printf(" ...              absolute %6"PRIx64" - %6"PRIx64"\n",
 			lba + (sblk->sect_start >> 3),
 			lba + (0x40 * mz_count) + (sblk->sect_start >> 3));
 
 		memset(data, 0xFF, Z_C4K);
 		crc = crc_md_le16(data, Z_CRC_4K);
 
 		if (verbose)
 			printf(" ... Initial MetaCRC %04x\n", le16_to_cpu(crc));
 
 		/* make page of CRCs */
 		for (iter = 0; iter < 2048; iter++) {
 			crcs[iter] = crc;
 		}
 
 		/* make IO_VCACHE_PAGES of CRCs */
 		for (iter = 0; iter < IO_VCACHE_PAGES; iter++) {
 			memcpy(io_vcache[iter].data, crcs, Z_C4K);
 		}
 
 		if (verbose)
 			printf(" ... Initial MetaMetaCRC %04x\n",
 				le16_to_cpu(crc_md_le16(crcs, Z_CRC_4K)));
 
 		locations = dm_div_up((0x40 * mz_count), IO_VCACHE_PAGES);
 		for (iter = 0; iter < locations; iter++) {
 			rc = pwrite64(fd, io_vcache, wchunk, lba << 12);
 			if (rc != wchunk) {
 				printf("%s: clear sb @ %" PRIx64
 					" failed:  %d\n", __func__,
 				lba, rc);
 			}
 			lba += IO_VCACHE_PAGES;
 		}
 	}
 	printf("Metadata pool initialized.\n");
 out:
 
 	if (io_vcache) free(io_vcache);
 	if (data) free(data);
 
 	return err;
}


int zdmadm_create(const char *dname, char *zname_opt,
		  int fd, zdm_super_block_t * sblk, int use_force, int verbose)
{
	int rc = 0;
	off_t lba = 0ul;
	zdm_super_block_t * data = malloc(Z_C4K);
	char cmd[1024];
	char * zname;

	if (zname_opt) {
		snprintf(sblk->label, sizeof(sblk->label), "%s", zname_opt);
		sblk->crc32 = zdm_crc32(sblk);
		zname = zname_opt;
	} else {
		zname = strrchr(dname, '/');
		if (zname) {
			if (*zname == '/') {
				zname++;
			}
		} else {
			rc = -1;
			printf("Invalid argument. Need valid dname or zname\n");
			goto out;
		}
	}

	if (!data) {
		fprintf(stderr, "Failed to allocate 4k\n");
		rc = -2;
		goto out;
	}

	zdmadm_format_initmd(fd, sblk, use_force, verbose);

	memset(data, 0, Z_C4K);
	memcpy(data, sblk, sizeof(*sblk));

	rc = pwrite64(fd, data, Z_C4K, lba);
	if (rc != Z_C4K) {
		fprintf(stderr, "write error: %d writing %"
			PRIx64 "\n", rc, lba);
		rc = -1;
		goto out;
	}

	fsync(fd);
	close(fd);

	snprintf(cmd, sizeof(cmd),
		"dmsetup create \"zdm_%s\" "
			"--table \"0 %" PRIu64 " zdm %s %"PRIu64
			        " create %s %s %s %s reserve=%d\"",
		zname,
		sblk->zdm_blocks,
		dname,
		sblk->data_start,
		use_force ? "force" : "",
		sblk->discard ? "discard" : "nodiscard",
		sblk->zac_zbc & MEDIA_ZAC ? "zac" : "nozac",
		sblk->zac_zbc & MEDIA_ZBC ? "zbc" : "nozbc",
		sblk->mz_metadata_zones + sblk->mz_over_provision);
	if (verbose) {
		printf("%s\n", cmd);
	}
	rc = system(cmd);
	if (rc != 0) {
		printf("** ERROR: Create ZDM instance failed: %d\n", rc);
	}
	zdmadm_show(dname, sblk);

out:
	if (data) {
		free(data);
	}
	return rc;
}

int zdmadm_restore(const char *dname, int fd, zdm_super_block_t * sblock)
{
	int rc = 0;
	char cmd[1024];
	char * zname;

	if (strlen(sblock->label) > 0) {
		zname = sblock->label;
	} else {
		zname = strrchr(dname, '/');
		if (zname) {
			if (*zname == '/') {
				zname++;
			}
		} else {
			rc = -1;
			printf("Invalid argument. Need valid dname or zname\n");
			goto out;
		}
	}

	close(fd);

	snprintf(cmd, sizeof(cmd),
		"dmsetup create \"zdm_%s\" --table "
			"\"0 %" PRIu64 " zdm %s %"
		                PRIu64 " load %s %s %s reserve=%d\"",
		zname,
		sblock->zdm_blocks,
		dname,
		sblock->data_start,
		sblock->discard ? "discard" : "nodiscard",
		sblock->zac_zbc & MEDIA_ZAC ? "zac" : "nozac",
		sblock->zac_zbc & MEDIA_ZBC ? "zbc" : "nozbc",
		sblock->mz_metadata_zones + sblock->mz_over_provision );

	printf("%s\n", cmd);
	rc = system(cmd);
	if (rc != 0) {
		printf("Restore ZDM instance failed: %d\n", rc);
	}

out:
	return rc;
}


int zdmadm_wipe(int fd, zdm_super_block_t * sblock)
{
	int rc = 0;
	off_t lba = 0ul;
	zdm_super_block_t * data = malloc(Z_C4K);

	memset(data, 0, Z_C4K);

	do {
		rc = pwrite64(fd, data, Z_C4K, lba);
		if (rc != Z_C4K) {
			fprintf(stderr, "write error: %d writing %"
				PRIx64 "\n", rc, lba);
			rc = -1;
			goto out;
		}
	} while (lba++ < 2048);

out:
	if (data) {
		free(data);
	}
	return rc;
}

int zdmadm_unload(const char *dname, int fd, zdm_super_block_t * sblock)
{
	int rc = 0;
	char cmd[1024];
	char * zname;

	if (strlen(sblock->label) > 0) {
		zname = sblock->label;
	} else {
		zname = strrchr(dname, '/');
		if (zname) {
			if (*zname == '/') {
				zname++;
			}
		} else {
			rc = -1;
			printf("Invalid argument. Need valid dname or zname\n");
			goto out;
		}
	}

	snprintf(cmd, sizeof(cmd), "dmsetup remove \"zdm_%s\"", zname );

	printf("%s\n", cmd);
	rc = system(cmd);
	if (rc != 0) {
		printf("ZDM Unload failed: %d\n", rc);
	}

out:
	return rc;
}


int zdmadm_probe_existing(int fd, zdm_super_block_t * sblock, int verbose)
{
	int rc = 0;
	off_t lba = 0ul;
	zdm_super_block_t * data = malloc(Z_C4K);
	u32 crc;

	if (!data) {
		fprintf(stderr, "Failed to allocate 4k\n");
		rc = -2;
		goto out;
	}

	rc = pread64(fd, data, Z_C4K, lba);
	if (rc != Z_C4K) {
		fprintf(stderr, "read error: %d reading %" PRIx64 "\n", rc, lba);
		rc = -1;
		goto out;
	}

	crc = zdm_crc32(data);
	if (crc != data->crc32) {
		if (verbose > 0) {
			fprintf(stderr, "ZDM CRC: %" PRIx32 " != %" PRIx32
				" on device.\n", crc, data->crc32 );
		}
		rc = -1;
		goto out;
	}

	if (0 != memcmp(data->magic, zdm_magic, ARRAY_SIZE(zdm_magic)) ) {
		if (verbose > 0) {
			fprintf(stderr, "ZDM Magic not found on device.\n");
		}
		rc = -1;
		goto out;
	}

	memcpy(sblock, data, sizeof(*sblock));

out:
	if (data) {
		free(data);
	}
	return rc;
}

static void calculate_zdm_blocks(zdm_super_block_t * sblk, int verbose)
{
	u64 mz_resv      = sblk->mz_metadata_zones + sblk->mz_over_provision;
	u64 zone_count   = sblk->sect_size >> 19;
	u64 megaz_count  = (zone_count + 1023) >> 10;
	u64 zdm_reserved = mz_resv * megaz_count;
	u64 blocks       = (zone_count - zdm_reserved) << 19;
	u64 part_sz      = (sblk->sect_size / 0x80000) * 0x80000;

	if (sblk->data_start > 0) {
		blocks -= (sblk->data_start - 1) << 19;
		if (verbose)
			printf("Reserved zones %"PRIu64" for metadata\n",
				sblk->data_start - 1);
	} else {
		printf("Data Start is 0. Must be WHOLE DRIVE!!\n");
	}
	sblk->zdm_blocks = blocks;

	if (verbose)
		printf("%" PRIu64 " blocks on ZDM - %"
			   PRIu64" blocks on part\n",
			sblk->zdm_blocks / 8,  (part_sz / 8) );

}

int zdmadm_probe_default(const char * dname, int fd, zdm_super_block_t * sblk,
			 u32 resv, u32 oprov, u32 trim, int verbose)
{
	unsigned long start; /* in 512 byte sectors */
	u64 sz;
	int exCode = 0;

	sblk->version = ZDM_SBLK_VER;
	sblk->discard = 1;
	memcpy(sblk->magic, zdm_magic, sizeof(sblk->magic));
	uuid_generate(sblk->uuid);
	sblk->mz_metadata_zones = resv;
	sblk->mz_over_provision = oprov;
	sblk->discard = trim;

	if (verbose > 0) {
		printf("Scanning device %s\n", dname );
	}

	if (blkdev_get_start(fd, &start) < 0) {
		printf("Failed to determine partition starting sector!!\n");
		exCode = 1;
		goto out;
	}
	sblk->sect_start = start; /* in 512 byte sectors */

	if (blkdev_get_size(fd, &sz) < 0) {
		printf("Failed to determine partition size!!\n");
		exCode = 2;
		goto out;
	}
	sblk->sect_size = sz >> 9; /* in 512 byte sectors */

	if (zaczbc_probe_media(fd, sblk, verbose) < 0) {
		exCode = 3;
		goto out;
	}
	if (verbose > 0) {
		printf(" ... partition %lx, len %"PRIu64" (512 byte sectors)\n",
			sblk->sect_start, sblk->sect_size);
	}

	if (sblk->zac_zbc) {
		/* test 'size' for sanity */
		if (zdmadm_probe_zones(fd, sblk, verbose) < 0) {
			exCode = 4;
			goto out;
		}
	} else {
		u64 cache, need, pref;
		u64 fz_sz = 0x80000;
		u64 zone = ((sblk->sect_start + fz_sz - 1) / fz_sz);
		u64 fz_at = zone * fz_sz;
		u64 mdzcount = 0;
		u64 nmegaz = 0;

		/* pass through conventional ... no ZAC/ZBC report to check */
		minimums(sblk->sect_size, fz_sz, &nmegaz, &cache, &need, &pref);

		if ( (fz_at - sblk->sect_start) > (cache * 8) ) {
			mdzcount++;
			printf("Using non-aligned space start of partition for metadata.\n");
		}
		zone += (pref - mdzcount);

		if (sblk->sect_start == 0) /* whole drive fixup. */
			zone++;

		sblk->zone_size = fz_sz;
		sblk->data_start = zone;
	}
	calculate_zdm_blocks(sblk, verbose);
	sblk->crc32 = zdm_crc32(sblk);

out:
	return exCode;
}

void usage(void)
{
	printf("USAGE:\n"
	       "    zdmadm [options] device\n"
	       "Options:\n"
	       "    -c create zdm on device\n"
	       "    -F force used with create or wipe \n"
	       "    -k check zdm instance\n"
	       "    -l specify zdm 'label' (default is zdm_sdXn)\n"
	       "    -p probe device for superblock. (default)\n"
	       "    -r restore zdm instance\n"
	       "    -R <N> over-provision <N> zones per Megazone (minimum=8)\n"
	       "    -t <0|1> trim on/off, default is on.\n"
	       "    -u unload zdm instance\n"
	       "    -v verbosity. More v's more verbose.\n"
	       "    -w wipe an existing zdm instance. Requires -F\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int index;
	char * label = NULL;
	int exCode = 0;

	u32 reserved_zones  = 3;
	u32 over_provision  = 5;
	u32 discard_default = 1;
	u32 resv;
	int command = ZDMADM_PROBE;
	int use_force = 0;
	int verbose = 0;

	printf("zdmadm %d.%d\n", zdm_VERSION_MAJOR, zdm_VERSION_MINOR );

	/* Parse command line */
	errno = EINVAL; // Assume invalid Argument if we die
	while ((opt = getopt(argc, argv, "t:R:l:Fpcrkuwv")) != -1) {
		switch (opt) {
		case 'p':
			command = ZDMADM_PROBE;
			break;
		case 'c':
			command = ZDMADM_CREATE;
			break;
		case 'R':
			resv = strtoul(optarg, NULL, 0);
			if (8 < resv && resv < 1024) {
				over_provision = resv - reserved_zones;
			}
			break;
		case 'r':
			command = ZDMADM_RESTORE;
			break;
		case 'k':
			command = ZDMADM_CHECK;
			break;
		case 'w':
			command = ZDMADM_WIPE;
			break;
		case 'u':
			command = ZDMADM_UNLOAD;
			break;
		case 'F':
			use_force = 1;
			break;
		case 'l':
			if (strlen(optarg) < 64) {
				label = optarg;
			} else {
				printf("Label: '%s' is too long. Max is 63\n",
					optarg);
			}
			break;
		case 't':
			discard_default = atoi(optarg) ? 1 : 0;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
			break;
		} /* switch */
	} /* while */

	if (verbose > 0) {
		set_debug(verbose);
	}

	for (index = optind; index < argc; ) {
		int fd;
		char *dname = argv[index];
		int is_busy;
		char buf[80];
		int flags;
		int need_rw = 0;
		int o_flags = O_RDONLY;

		is_busy = is_anypart_mounted(dname, &flags, buf, sizeof(buf));
		if (is_busy || flags) {
			if (ZDMADM_CREATE == command || ZDMADM_WIPE == command ) {
				need_rw = 1;
			}
			if (use_force && ZDMADM_CHECK == command) {
				need_rw = 1;
			}

			if (need_rw) {
				printf("%s is busy/mounted: %d:%x\n",
					dname, is_busy, flags );
				printf("refusing to proceed\n");
				exCode = 1;
				goto out;
			}
		}

		if (ZDMADM_CREATE == command || ZDMADM_WIPE == command ) {
			if (0 == is_part(dname)) {
				if (!use_force) {
					printf("Whole disk .. use -F to force\n");
					goto out;
				}
			}
		}


		if (need_rw) {
			o_flags = O_RDWR;
		}

		fd = open(dname, o_flags);
		if (fd) {
			int zdm_exists = 1;
			zdm_super_block_t sblk_def;
			zdm_super_block_t sblk;

			memset(&sblk_def, 0, sizeof(sblk_def));

			exCode = zdmadm_probe_default(dname, fd, &sblk_def,
						      reserved_zones,
						      over_provision,
						      discard_default,
						      verbose );
			if (exCode) {
				goto out;
			}

			exCode = zdmadm_probe_existing(fd, &sblk, verbose);
			if (exCode < 0) {
				zdm_exists = 0;
			}

			switch(command) {
			case ZDMADM_CREATE:
				if (zdm_exists && ! use_force) {
					printf("ZDM Already on disk. Use -F to force\n");
					exCode = 1;
					goto out;
				}
				close(fd);
				fd = open(dname, O_RDWR);
				if (fd < 0) {
					perror("Failed to open device for RW");
					printf("ZDM disk re-open RDWR failed: %s\n", dname);
					exCode = 1;
					goto out;
				}

				/* does a lot of writing to fd and closes before
				 * starting ZDM instance */
				exCode = zdmadm_create(dname, label, fd, &sblk_def,
							use_force, verbose);
				if (exCode < 0) {
					printf("ZDM Create failed.\n");
					exCode = 1;
					goto out;
				}
			break;
			case ZDMADM_RESTORE:
				if (! zdm_exists) {
					printf("ZDM No found. Nothing to restore.\n");
					goto next;
				}

				/* closes fd before
				 * starting ZDM instance */
				exCode = zdmadm_restore(dname, fd, &sblk);
				if (exCode < 0) {
					printf("ZDM Restore failed.\n");
					exCode = 1;
					goto next;
				}
			break;
			case ZDMADM_UNLOAD:
				if (! zdm_exists) {
					printf("ZDM No found. Nothing to unload.\n");
					goto next;
				}
				exCode = zdmadm_unload(dname, fd, &sblk);
				if (exCode < 0) {
					printf("ZDM Restore failed.\n");
					exCode = 1;
					goto next;
				}
			break;
			case ZDMADM_WIPE:
				if (! zdm_exists) {
					printf("ZDM No found. Nothing to wipe.\n");
					exCode = 1;
					goto out;
				}
				if (! use_force) {
					printf("Wipe must use -F to force\n");
					exCode = 1;
					goto out;
				}
				close(fd);
				fd = open(dname, O_RDWR);
				if (fd < 0) {
					perror("Failed to open device for RW");
					printf("ZDM disk re-open RDWR failed: %s\n", dname);
					exCode = 1;
					goto out;
				}
				exCode = zdmadm_wipe(fd, &sblk);
				if (exCode < 0) {
					printf("ZDM Wipe failed.\n");
					exCode = 1;
					goto out;
				}
			break;
			case ZDMADM_CHECK:
				if (! zdm_exists) {
					printf("No ZDM found on %s device.\n",
						dname);
					goto next;
				}
				if (use_force) {
					close(fd);
					fd = open(dname, O_RDWR);
				}
				exCode = zdmadm_check(dname, fd, &sblk, use_force);
				if (exCode < 0) {
					printf("ZDM check failed.\n");
					exCode = 1;
					goto next;
				}
			break;
			case ZDMADM_PROBE:
				if (! zdm_exists) {
					if (verbose > 0) {
						printf("No ZDM found on %s device.\n",
							dname);
					}
					goto next;
				}
				zdmadm_show(dname, &sblk);
				goto next;
			break;
			default:
				printf("Unknown command\n");
				exCode = 1;
				goto out;
			break;
			}
		} else {
			perror("Failed to open device");
			fprintf(stderr, "device: %s", dname);
		}
next:
		index++;

	} /* end: for each device on cli */

	if (optind >= argc) {
		usage();
	}

out:
	return exCode;
}
