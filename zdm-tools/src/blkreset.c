/*
 * blkreport.c -- request a zone report on part (or all) of the block device.
 *
 * Copyright (C) 2015,2016 Seagate Technology PLC
 * Written by Shaun Tancheff <shaun.tancheff@seagate.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * This program uses BLKREPORT ioctl to query zone information about part of
 * or a whole block device, if the device supports it.
 * You can specify range (start and length) to be queried.
 */

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <limits.h>
#include <getopt.h>
#include <time.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/ioctl.h>

#ifdef HAVE_BLKZONED_H
#include <linux/blkzoned.h>
#endif

#include <errno.h>

#ifndef HAVE_BLKZONED_H
/**
 * enum blk_zone_type - Types of zones allowed in a zoned device.
 *
 * @BLK_ZONE_TYPE_CONVENTIONAL: The zone has no write pointer and can be writen
 *                              randomly. Zone reset has no effect on the zone.
 * @BLK_ZONE_TYPE_SEQWRITE_REQ: The zone must be written sequentially
 * @BLK_ZONE_TYPE_SEQWRITE_PREF: The zone can be written non-sequentially
 *
 * Any other value not defined is reserved and must be considered as invalid.
 */
enum blk_zone_type {
	BLK_ZONE_TYPE_CONVENTIONAL	= 0x1,
	BLK_ZONE_TYPE_SEQWRITE_REQ	= 0x2,
	BLK_ZONE_TYPE_SEQWRITE_PREF	= 0x3,
};

/**
 * enum blk_zone_cond - Condition [state] of a zone in a zoned device.
 *
 * @BLK_ZONE_COND_NOT_WP: The zone has no write pointer, it is conventional.
 * @BLK_ZONE_COND_EMPTY: The zone is empty.
 * @BLK_ZONE_COND_IMP_OPEN: The zone is open, but not explicitly opened.
 * @BLK_ZONE_COND_EXP_OPEN: The zones was explicitly opened by an
 *                          OPEN ZONE command.
 * @BLK_ZONE_COND_CLOSED: The zone was [explicitly] closed after writing.
 * @BLK_ZONE_COND_FULL: The zone is marked as full, possibly by a zone
 *                      FINISH ZONE command.
 * @BLK_ZONE_COND_READONLY: The zone is read-only.
 * @BLK_ZONE_COND_OFFLINE: The zone is offline (sectors cannot be read/written).
 *
 * The Zone Condition state machine in the ZBC/ZAC standards maps the above
 * deinitions as:
 *   - ZC1: Empty         | BLK_ZONE_EMPTY
 *   - ZC2: Implicit Open | BLK_ZONE_COND_IMP_OPEN
 *   - ZC3: Explicit Open | BLK_ZONE_COND_EXP_OPEN
 *   - ZC4: Closed        | BLK_ZONE_CLOSED
 *   - ZC5: Full          | BLK_ZONE_FULL
 *   - ZC6: Read Only     | BLK_ZONE_READONLY
 *   - ZC7: Offline       | BLK_ZONE_OFFLINE
 *
 * Conditions 0x5 to 0xC are reserved by the current ZBC/ZAC spec and should
 * be considered invalid.
 */
enum blk_zone_cond {
	BLK_ZONE_COND_NOT_WP	= 0x0,
	BLK_ZONE_COND_EMPTY	= 0x1,
	BLK_ZONE_COND_IMP_OPEN	= 0x2,
	BLK_ZONE_COND_EXP_OPEN	= 0x3,
	BLK_ZONE_COND_CLOSED	= 0x4,
	BLK_ZONE_COND_READONLY	= 0xD,
	BLK_ZONE_COND_FULL	= 0xE,
	BLK_ZONE_COND_OFFLINE	= 0xF,
};

/**
 * struct blk_zone - Zone descriptor for BLKREPORTZONE ioctl.
 *
 * @start: Zone start in 512 B sector units
 * @len: Zone length in 512 B sector units
 * @wp: Zone write pointer location in 512 B sector units
 * @type: see enum blk_zone_type for possible values
 * @cond: see enum blk_zone_cond for possible values
 * @non_seq: Flag indicating that the zone is using non-sequential resources
 *           (for host-aware zoned block devices only).
 * @reset: Flag indicating that a zone reset is recommended.
 * @reserved: Padding to 64 B to match the ZBC/ZAC defined zone descriptor size.
 *
 * start, len and wp use the regular 512 B sector unit, regardless of the
 * device logical block size. The overall structure size is 64 B to match the
 * ZBC/ZAC defined zone descriptor and allow support for future additional
 * zone information.
 */
struct blk_zone {
	__u64	start;		/* Zone start sector */
	__u64	len;		/* Zone length in number of sectors */
	__u64	wp;		/* Zone write pointer position */
	__u8	type;		/* Zone type */
	__u8	cond;		/* Zone condition */
	__u8	non_seq;	/* Non-sequential write resources active */
	__u8	reset;		/* Reset write pointer recommended */
	__u8	reserved[36];
};

/**
 * struct blk_zone_report - BLKREPORTZONE ioctl request/reply
 *
 * @sector: starting sector of report
 * @nr_zones: IN maximum / OUT actual
 * @reserved: padding to 16 byte alignment
 * @zones: Space to hold @nr_zones @zones entries on reply.
 *
 * The array of at most @nr_zones must follow this structure in memory.
 */
struct blk_zone_report {
	__u64		sector;
	__u32		nr_zones;
	__u8		reserved[4];
	struct blk_zone zones[0];
} __attribute__((packed));

/**
 * struct blk_zone_range - BLKRESETZONE ioctl request
 * @sector: starting sector of the first zone to issue reset write pointer
 * @nr_sectors: Total number of sectors of 1 or more zones to reset
 */
struct blk_zone_range {
	__u64		sector;
	__u64		nr_sectors;
};

/**
 * Zoned block device ioctl's:
 *
 * @BLKREPORTZONE: Get zone information. Takes a zone report as argument.
 *                 The zone report will start from the zone containing the
 *                 sector specified in the report request structure.
 * @BLKRESETZONE: Reset the write pointer of the zones in the specified
 *                sector range. The sector range must be zone aligned.
 */
#define BLKREPORTZONE	_IOWR(0x12, 130, struct blk_zone_report)
#define BLKRESETZONE	_IOW(0x12, 131, struct blk_zone_range)
#endif /* HAVE_BLKZONED_API_H */

#define ZONE_ACTION_RESET	1

#define warn(...)        fprintf(stdout, __VA_ARGS__)
#define warnx(...)       fprintf(stdout, __VA_ARGS__), exit(EXIT_FAILURE)
#define err(code, ...)   fprintf(stderr, __VA_ARGS__)
#define errx(code, ...)  fprintf(stderr, __VA_ARGS__), exit(code)

static void __attribute__((__noreturn__)) usage(FILE *out)
{
	fprintf(out,
	      " %s [options] <device>\n", "blkreset\n");
	fputs("Reset a Zone per ZBC from on a device.\n\n", out);

	fprintf(out,
	      " %s [options] <device>\n", "zdm-report\n");
	fputs("Report on Zone information per ZBC from a device.\n\n", out);
	fputs("Usage:", out);

	fputs(  " -z, --zone <num>  lba of start of zone to act upon\n"
		" -r, --reset       reset zone\n"
		" -l, --length <num>  range of reset\n"
		" -v, --verbose     print aligned length and offset",
		out);
	fputs("\n\n", out);
	exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	char *path;
	int c, fd, verbose = 0, secsize;
	uint64_t blksize;
	struct stat sb;
	struct blk_zone_range za;
	uint64_t zone_lba = 0ul;
	uint32_t act = ZONE_ACTION_RESET;
	uint32_t length = 1ul << 19;
	int rc = 0;

	static const struct option longopts[] = {
	    { "help",      0, 0, 'h' },
	    { "version",   0, 0, 'V' },
	    { "zone",      1, 0, 'z' },
	    { "length",    1, 0, 'l' },
	    { "reset",     0, 0, 'r' },
	    { "verbose",   0, 0, 'v' },
	    { NULL,        0, 0, 0 }
	};

//	setlocale(LC_ALL, "");
	while ((c = getopt_long(argc, argv, "hVvrz:l:", longopts, NULL)) != -1) {
		switch(c) {
		case 'h':
			usage(stdout);
			break;
		case 'V':
			printf("0.119\n");
			return EXIT_SUCCESS;
		case 'z':
			zone_lba = strtoull(optarg, NULL, 0);
			break;
		case 'r':
			act = ZONE_ACTION_RESET;
			break;
		case 'l':
			length = strtoull(optarg, NULL, 0);
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(stderr);
			break;
		}
	}

	if (optind == argc)
		errx(EXIT_FAILURE, "no device specified\n");

	path = argv[optind++];

	if (optind != argc) {
		warnx("unexpected number of arguments\n");
		usage(stderr);
	}

	fd = open(path, O_RDWR);
	if (fd < 0)
		err(EXIT_FAILURE, "cannot open %s\n", path);

	if (fstat(fd, &sb) == -1)
		err(EXIT_FAILURE, "stat of %s failed\n", path);
	if (!S_ISBLK(sb.st_mode))
		errx(EXIT_FAILURE, "%s: not a block device\n", path);

	if (ioctl(fd, BLKGETSIZE64, &blksize))
		err(EXIT_FAILURE, "%s: BLKGETSIZE64 ioctl failed\n", path);
	if (ioctl(fd, BLKSSZGET, &secsize))
		err(EXIT_FAILURE, "%s: BLKSSZGET ioctl failed\n", path);

	/* is the range end behind the end of the device ?*/
	if (zone_lba > blksize)
		errx(EXIT_FAILURE, "%s: zone_lba is greater than device size\n", path);

	switch (act) {
	case ZONE_ACTION_RESET:
		za.sector = zone_lba;
		za.nr_sectors = length;

		rc = ioctl(fd, BLKRESETZONE, &za);
		if (rc == -1)
			err(EXIT_FAILURE, "%s: BLKRESETZONE ioctl failed", path);
		break;
	default:
		err(EXIT_FAILURE, "%s: Unknown zone action %d", path, act);
		break;
	}

	close(fd);
	return EXIT_SUCCESS;
}
