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


#define ZBC_REPORT_OPTION_MASK  0x3f
#define ZBC_REPORT_ZONE_PARTIAL 0x80

/**
 * enum zone_report_option - Report Zones types to be included.
 *
 * @ZBC_ZONE_REPORTING_OPTION_ALL: Default (all zones).
 * @ZBC_ZONE_REPORTING_OPTION_EMPTY: Zones which are empty.
 * @ZBC_ZONE_REPORTING_OPTION_IMPLICIT_OPEN:
 *	Zones open but not explicitly opened
 * @ZBC_ZONE_REPORTING_OPTION_EXPLICIT_OPEN: Zones opened explicitly
 * @ZBC_ZONE_REPORTING_OPTION_CLOSED: Zones closed for writing.
 * @ZBC_ZONE_REPORTING_OPTION_FULL: Zones that are full.
 * @ZBC_ZONE_REPORTING_OPTION_READONLY: Zones that are read-only
 * @ZBC_ZONE_REPORTING_OPTION_OFFLINE: Zones that are offline
 * @ZBC_ZONE_REPORTING_OPTION_NEED_RESET_WP: Zones with Reset WP Recommended
 * @ZBC_ZONE_REPORTING_OPTION_RESERVED: Zones that with Non-Sequential
 *	Write Resources Active
 * @ZBC_ZONE_REPORTING_OPTION_NON_WP: Zones that do not have Write Pointers
 *	(conventional)
 * @ZBC_ZONE_REPORTING_OPTION_RESERVED: Undefined
 * @ZBC_ZONE_REPORTING_OPTION_PARTIAL: Modifies the definition of the Zone List
 *	Length field.
 *
 * Used by Report Zones in bdev_zone_get_report: report_option
 */
enum zbc_zone_reporting_options {
	ZBC_ZONE_REPORTING_OPTION_ALL = 0,
	ZBC_ZONE_REPORTING_OPTION_EMPTY,
	ZBC_ZONE_REPORTING_OPTION_IMPLICIT_OPEN,
	ZBC_ZONE_REPORTING_OPTION_EXPLICIT_OPEN,
	ZBC_ZONE_REPORTING_OPTION_CLOSED,
	ZBC_ZONE_REPORTING_OPTION_FULL,
	ZBC_ZONE_REPORTING_OPTION_READONLY,
	ZBC_ZONE_REPORTING_OPTION_OFFLINE,
	ZBC_ZONE_REPORTING_OPTION_NEED_RESET_WP = 0x10,
	ZBC_ZONE_REPORTING_OPTION_NON_SEQWRITE,
	ZBC_ZONE_REPORTING_OPTION_NON_WP = 0x3f,
	ZBC_ZONE_REPORTING_OPTION_RESERVED = 0x40,
	ZBC_ZONE_REPORTING_OPTION_PARTIAL = ZBC_REPORT_ZONE_PARTIAL
};


static const char * same_text[] = {
	"all zones are different",
	"all zones are same size",
	"last zone differs by size",
	"all zones same size - different types",
};

static const char * type_text[] = {
	"RESERVED",
	"CONVENTIONAL",
	"SEQ_WRITE_REQUIRED",
	"SEQ_WRITE_PREFERRED",
};

#define ARRAY_COUNT(x) (sizeof((x))/sizeof((*x)))

static int is_big_endian = 0;

const char * condition_str[] = {
	"cv", /* conventional zone */
	"e0", /* empty */
	"Oi", /* open implicit */
	"Oe", /* open explicit */
	"Cl", /* closed */
	"x5", "x6", "x7", "x8", "x9", "xA", "xB", /* xN: reserved */
	"ro", /* read only */
	"fu", /* full */
	"OL"  /* offline */
	};

static const char * zone_condition_str(uint8_t cond)
{
	return condition_str[cond & 0x0f];
}

static void print_zones(struct blk_zone *info, uint32_t count)
{
	uint32_t iter;
	const char *fmtx = "  start: %9lx, len %7lx, wptr %8lx"
		           " reset:%u non-seq:%u, zcond:%2u(%s) [type: %u(%s)]\n";

	fprintf(stdout, "  count: %u\n", count);

	for (iter = 0; iter < count; iter++ ) {
		struct blk_zone * entry = &info[iter];
		unsigned int type  = entry->type;
		unsigned int flags = entry->cond;
		uint64_t start = entry->start;
		uint64_t wp = entry->wp;
		uint8_t cond = entry->cond;
		uint64_t len = entry->len;
		const char *fmt = fmtx;

		if (!len) {
			break;
		}

		fprintf(stdout, fmt, start, len, wp,
			entry->reset, entry->non_seq,
			cond, zone_condition_str(cond),
			type, type_text[type]);
	}
}

static inline int is_report_option_valid(uint64_t ropt)
{
	uint8_t _opt = ropt & ZBC_REPORT_OPTION_MASK;

	if (_opt <= ZBC_ZONE_REPORTING_OPTION_OFFLINE)
		return 1;
	
	switch (_opt) {
	case ZBC_ZONE_REPORTING_OPTION_NEED_RESET_WP:
	case ZBC_ZONE_REPORTING_OPTION_NON_SEQWRITE:
	case ZBC_ZONE_REPORTING_OPTION_NON_WP:
		return 1;
	default:
		fprintf(stderr, "Illegal report option %x is unknown.\n",
			ZBC_ZONE_REPORTING_OPTION_RESERVED);
		return 0;
	}
}

static int do_report(int fd, uint64_t lba, uint64_t len, int fua, uint8_t ropt, int verbose)
{
	int rc = -4;
	struct blk_zone_report *zone_info;

	zone_info = malloc(len + sizeof(struct blk_zone_report));
	if (zone_info) {
		zone_info->nr_zones = len / sizeof(struct blk_zone);
		zone_info->sector = lba; /* maybe shift 4Kn -> 512e */
		rc = ioctl(fd, BLKREPORTZONE, zone_info);
		if (rc != -1) {
			if (verbose)
				fprintf(stdout, "Found %d zones\n", zone_info->nr_zones);

			print_zones(zone_info->zones, zone_info->nr_zones);
		} else {
			fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
		}
		free(zone_info);
	}

	return rc;
}

#define warn(...)        fprintf(stdout, __VA_ARGS__)
#define warnx(...)       fprintf(stdout, __VA_ARGS__), exit(EXIT_FAILURE)
#define err(code, ...)   fprintf(stderr, __VA_ARGS__)
#define errx(code, ...)  fprintf(stderr, __VA_ARGS__), exit(code)

static void __attribute__((__noreturn__)) usage(FILE *out)
{
	fprintf(out,
	      " %s [options] <device>\n", "zdm-report\n");
	fputs("Report on Zone information per ZBC from a device.\n\n", out);
	fputs("Usage:", out);
	fputs(" -z, --zone <num>  zone lba in bytes to report from\n"
		" -l, --length <num>  length of report (512 bytes to 512k bytes)\n"
		" -r, --option <report> report option\n"
		"    report is the numeric value from \"enum zone_report_option\".\n"
		"             0 - non seq. and reset (default)\n"
		"             1 - empty\n"
		"             2 - open implicit\n"
		"             3 - open explicit\n"
		"             4 - closed\n"
		"             5 - full\n"
		"             6 - read only\n"
		"             7 - offline\n"
		"          0x10 - reset\n"
		"          0x11 - non sequential\n"
		"          0x3f - non write pointer zones\n"
		" -S  --sat           use ATA16 (implies force w/o zone cache update)\n"
		" -F, --force         force zone report to query media\n"
		" -e, --endian <num>  Results is 0=little or 1=big endian\n"
		" -v, --verbose       print aligned length and offset",
		out);
	fputs("\n\n", out);
	exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}


#define MAX_REPORT_LEN		(1 << 19) /* 512k */
#define MAX_REPORT_LEN_SAT	(1 << 18) /* 512k */

int main(int argc, char **argv)
{
	char *path;
	int c;
	int fd;
	int secsize;
	uint64_t blksize;
	struct stat sb;
	int verbose = 0;
	uint64_t ropt = ZBC_ZONE_REPORTING_OPTION_ALL;
	uint64_t offset = 0ul;
	uint32_t length = MAX_REPORT_LEN;
	int fua = 0;
	int sat = 0;

	static const struct option longopts[] = {
	    { "help",      0, 0, 'h' },
	    { "version",   0, 0, 'V' },
	    { "zone",      1, 0, 'z' }, /* starting LBA */
	    { "length",    1, 0, 'l' }, /* max #of bytes for result */
	    { "option",    1, 0, 'r' }, /* report option */
	    { "endian",    1, 0, 'e' },
	    { "force",     0, 0, 'F' },
	    { "sat",       0, 0, 'S' },
	    { "verbose",   0, 0, 'v' },
	    { NULL,        0, 0, 0 }
	};

//	setlocale(LC_ALL, "");

	while ((c = getopt_long(argc, argv, "hVSFvz:l:r:e:", longopts, NULL)) != -1) {
		switch(c) {
		case 'h':
			usage(stdout);
			break;
		case 'V':
			printf("0.119\n");
			return EXIT_SUCCESS;
		case 'F':
			fua = 1;
			break;
		case 'S':
			sat = 1;
			break;
		case 'l':
			length = strtoull(optarg, NULL, 0);
			break;
		case 'z':
			offset = strtoull(optarg, NULL, 0);
			break;
		case 'r':
			ropt = strtoull(optarg, NULL, 0);
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

	/* check offset alignment to the sector size */
	if (offset % secsize)
		errx(EXIT_FAILURE, "%s: offset %lu is not aligned "
			 "to sector size %i\n", path, offset, secsize);

	/* is the range end behind the end of the device ?*/
	if (offset > blksize)
		errx(EXIT_FAILURE, "%s: offset is greater than device size\n", path);

	length = (length / 512) * 512;
	if (length < 512)
		length = 512;
	if (length > MAX_REPORT_LEN)
		length = MAX_REPORT_LEN;

	if (!is_report_option_valid(ropt))
		errx(EXIT_FAILURE, "%s: invalid report option for device\n", path);

	if (do_report(fd, offset, length, fua, ropt & 0xFF, verbose))
		 err(EXIT_FAILURE, "%s: BLKREPORTZONE ioctl failed\n", path);
	close(fd);

	return EXIT_SUCCESS;
}
