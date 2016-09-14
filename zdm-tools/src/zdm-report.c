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
#include <inttypes.h>
#include <locale.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/fs.h>

#ifdef HAVE_BLKZONED_API_H
#include <linux/blkzoned_api.h>
#endif

#include <scsi/sg_lib.h>
#include <scsi/sg_cmds_basic.h>
#include <scsi/sg_cmds_extra.h>

#ifndef HAVE_BLKZONED_API_H

#define ZBC_REPORT_OPTION_MASK  0x3f
#define ZBC_REPORT_ZONE_PARTIAL 0x80

/**
 * enum zone_report_option - Report Zones types to be included.
 *
 * @ZOPT_NON_SEQ_AND_RESET: Default (all zones).
 * @ZOPT_ZC1_EMPTY: Zones which are empty.
 * @ZOPT_ZC2_OPEN_IMPLICIT: Zones open but not explicitly opened
 * @ZOPT_ZC3_OPEN_EXPLICIT: Zones opened explicitly
 * @ZOPT_ZC4_CLOSED: Zones closed for writing.
 * @ZOPT_ZC5_FULL: Zones that are full.
 * @ZOPT_ZC6_READ_ONLY: Zones that are read-only
 * @ZOPT_ZC7_OFFLINE: Zones that are offline
 * @ZOPT_RESET: Zones with Reset WP Recommended
 * @ZOPT_NON_SEQ: Zones that with Non-Sequential Write Resources Active
 * @ZOPT_NON_WP_ZONES: Zones that do not have Write Pointers (conventional)
 * @ZOPT_PARTIAL_FLAG: Modifies the definition of the Zone List Length field.
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

/**
 * enum blk_zone_type - Types of zones allowed in a zoned device.
 *
 * @BLK_ZONE_TYPE_RESERVED: Reserved.
 * @BLK_ZONE_TYPE_CONVENTIONAL: Zone has no WP. Zone commands are not available.
 * @BLK_ZONE_TYPE_SEQWRITE_REQ: Zone must be written sequentially
 * @BLK_ZONE_TYPE_SEQWRITE_PREF: Zone may be written non-sequentially
 *
 * TBD: Move to blkzoned_api - we don't need pointless duplication
 * and user space needs to handle the same information in the
 * same format -- so lets make it easy
 */
enum blk_zone_type {
	BLK_ZONE_TYPE_RESERVED,
	BLK_ZONE_TYPE_CONVENTIONAL,
	BLK_ZONE_TYPE_SEQWRITE_REQ,
	BLK_ZONE_TYPE_SEQWRITE_PREF,
	BLK_ZONE_TYPE_UNKNOWN,
};

/**
 * enum blk_zone_state - State [condition] of a zone in a zoned device.
 *
 * @BLK_ZONE_NO_WP: Zone has not write pointer it is CMR/Conventional
 * @BLK_ZONE_EMPTY: Zone is empty. Write pointer is at the start of the zone.
 * @BLK_ZONE_OPEN: Zone is open, but not explicitly opened by a zone open cmd.
 * @BLK_ZONE_OPEN_EXPLICIT: Zones was explicitly opened by a zone open cmd.
 * @BLK_ZONE_CLOSED: Zone was [explicitly] closed for writing.
 * @BLK_ZONE_UNKNOWN: Zone states 0x5 through 0xc are reserved by standard.
 * @BLK_ZONE_FULL: Zone was [explicitly] marked full by a zone finish cmd.
 * @BLK_ZONE_READONLY: Zone is read-only.
 * @BLK_ZONE_OFFLINE: Zone is offline.
 * @BLK_ZONE_BUSY: [INTERNAL] Kernel zone cache for this zone is being updated.
 *
 * The Zone Condition state machine also maps the above deinitions as:
 *   - ZC1: Empty         | BLK_ZONE_EMPTY
 *   - ZC2: Implicit Open | BLK_ZONE_OPEN
 *   - ZC3: Explicit Open | BLK_ZONE_OPEN_EXPLICIT
 *   - ZC4: Closed        | BLK_ZONE_CLOSED
 *   - ZC5: Full          | BLK_ZONE_FULL
 *   - ZC6: Read Only     | BLK_ZONE_READONLY
 *   - ZC7: Offline       | BLK_ZONE_OFFLINE
 *
 * States 0x5 to 0xC are reserved by the current ZBC/ZAC spec.
 */
enum blk_zone_state {
	BLK_ZONE_NO_WP,
	BLK_ZONE_EMPTY,
	BLK_ZONE_OPEN,
	BLK_ZONE_OPEN_EXPLICIT,
	BLK_ZONE_CLOSED,
	BLK_ZONE_UNKNOWN = 0x5,
	BLK_ZONE_READONLY = 0xd,
	BLK_ZONE_FULL = 0xe,
	BLK_ZONE_OFFLINE = 0xf,
	BLK_ZONE_BUSY = 0x10,
};

/**
 * enum bdev_zone_same - Report Zones same code.
 *
 * @BLK_ZONE_SAME_ALL_DIFFERENT: All zones differ in type and size.
 * @BLK_ZONE_SAME_ALL: All zones are the same size and type.
 * @BLK_ZONE_SAME_LAST_DIFFERS: All zones are the same size and type
 *    except the last zone which differs by size.
 * @BLK_ZONE_SAME_LEN_TYPES_DIFFER: All zones are the same length
 *    but zone types differ.
 *
 * Returned from Report Zones. See bdev_zone_report* same_field.
 */
enum blk_zone_same {
	BLK_ZONE_SAME_ALL_DIFFERENT     = 0,
	BLK_ZONE_SAME_ALL               = 1,
	BLK_ZONE_SAME_LAST_DIFFERS      = 2,
	BLK_ZONE_SAME_LEN_TYPES_DIFFER  = 3,
};

/**
 * struct bdev_zone_get_report - ioctl: Report Zones request
 *
 * @zone_locator_lba: starting lba for first [reported] zone
 * @return_page_count: number of *bytes* allocated for result
 * @report_option: see: zone_report_option enum
 * @force_unit_access: Force report from media
 *
 * Used to issue report zones command to connected device
 */
struct bdev_zone_get_report {
	__u64 zone_locator_lba;
	__u32 return_page_count;
	__u8  report_option;
	__u8  force_unit_access;
} __attribute__((packed));

/**
 * struct bdev_zone_action - ioctl: Perform Zone Action
 *
 * @zone_locator_lba: starting lba for first [reported] zone
 * @return_page_count: number of *bytes* allocated for result
 * @action: One of the ZONE_ACTION_*'s Close,Finish,Open, or Reset
 * @all_zones: Flag to indicate if command should apply to all zones.
 * @force_unit_access: Force command to media (bypass zone cache).
 *
 * Used to issue report zones command to connected device
 */
struct bdev_zone_action {
	__u64 zone_locator_lba;
	__u32 action;
	__u8  all_zones;
	__u8  force_unit_access;
} __attribute__((packed));

/**
 * struct bdev_zone_descriptor - A Zone descriptor entry from report zones
 *
 * @type: see zone_type enum
 * @flags: Bits 0:reset, 1:non-seq, 2-3: resv, 4-7: see zone_condition enum
 * @reserved1: padding
 * @length: length of zone in sectors
 * @lba_start: lba where the zone starts.
 * @lba_wptr: lba of the current write pointer.
 * @reserved: padding
 *
 */
struct bdev_zone_descriptor {
	__u8 type;
	__u8 flags;
	__u8  reserved1[6];
	__be64 length;
	__be64 lba_start;
	__be64 lba_wptr;
	__u8 reserved[32];
} __attribute__((packed));

/**
 * struct bdev_zone_report - Report Zones result
 *
 * @descriptor_count: Number of descriptor entries that follow
 * @same_field: bits 0-3: enum zone_same (MASK: 0x0F)
 * @reserved1: padding
 * @maximum_lba: LBA of the last logical sector on the device, inclusive
 *               of all logical sectors in all zones.
 * @reserved2: padding
 * @descriptors: array of descriptors follows.
 */
struct bdev_zone_report {
	__be32 descriptor_count;
	__u8 same_field;
	__u8 reserved1[3];
	__be64 maximum_lba;
	__u8 reserved2[48];
	struct bdev_zone_descriptor descriptors[0];
} __attribute__((packed));

/**
 * struct bdev_zone_report_io - Report Zones ioctl argument.
 *
 * @in: Report Zones inputs
 * @out: Report Zones output
 */
struct bdev_zone_report_io {
	union {
		struct bdev_zone_get_report in;
		struct bdev_zone_report out;
	} data;
} __attribute__((packed));

#endif /* HAVE_BLKZONED_API_H */

#ifndef BLKREPORT
# define BLKREPORT	_IOWR(0x12, 130, struct bdev_zone_report_io)
#endif

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
static int do_endian_probe = 1;

static inline uint64_t endian64(uint64_t in)
{
	return is_big_endian ? be64toh(in) : in;
}

static inline uint32_t endian32(uint32_t in)
{
	return is_big_endian ? be32toh(in) : in;
}

static inline uint16_t endian16(uint16_t in)
{
	return is_big_endian ? be16toh(in) : in;
}

static void test_endian(struct bdev_zone_report * info)
{
	struct bdev_zone_descriptor * entry = &info->descriptors[0];
	uint64_t len = entry->length;

	if (!do_endian_probe)
		return;

	is_big_endian = 1;
	if ( len == 0x080000 ||
	     len == 0x100000 ||
	     len == 0x200000 ||
	     len == 0x300000 ||
	     len == 0x400000 ||
	     len == 0x800000 ) {
		fprintf(stdout, "Detected length: 0x%"PRIu64
			" appears little endian\n", len);
		is_big_endian = 0;
	}
}

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

static void print_zones(struct bdev_zone_report * info, uint32_t size)
{
	uint32_t count = endian32(info->descriptor_count);
	uint32_t max_count;
	uint32_t iter;
	int same_code = info->same_field & 0x0f;

	fprintf(stdout, "  count: %u, same %u (%s), max_lba %lu\n",
		count,
		same_code, same_text[same_code],
		endian64(info->maximum_lba & (~0ul >> 16)) );

	max_count = (size - sizeof(struct bdev_zone_report))
                        / sizeof(struct bdev_zone_descriptor);
	if (count > max_count) {
		fprintf(stdout, "Truncating report to %d of %d zones.\n",
			max_count, count );
		count = max_count;
	}

	for (iter = 0; iter < count; iter++ ) {
		struct bdev_zone_descriptor * entry = &info->descriptors[iter];
		unsigned int type  = entry->type & 0xF;
		unsigned int flags = entry->flags;
		uint64_t start = endian64(entry->lba_start);
		uint64_t wp = endian64(entry->lba_wptr);
		uint8_t cond = (flags & 0xF0) >> 4;
		uint64_t len = endian64(entry->length);

		if (!len) {
			break;
		}
		fprintf(stdout,
			"  start: %9lx, len %7lx, wptr %8lx"
			" reset:%u non-seq:%u, zcond:%2u(%s) [type: %u(%s)]\n",
		start, len, wp - start, flags & 0x01, (flags & 0x02) >> 1,
		cond, zone_condition_str(cond), type, type_text[type]);
	}
}

static inline int is_report_option_valid(uint64_t ropt)
{
	uint8_t _opt = ropt & ZBC_REPORT_OPTION_MASK;

	if (ropt & ZBC_ZONE_REPORTING_OPTION_RESERVED) {
		fprintf(stderr, "Illegal report option %x is reserved.\n",
			ZBC_ZONE_REPORTING_OPTION_RESERVED);
		return 0;
	}

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
	struct bdev_zone_report_io *zone_info;

	zone_info = malloc(len);
	if (zone_info) {
		memset(zone_info, 0, len);
		zone_info->data.in.report_option     = ropt;
		zone_info->data.in.return_page_count = len;
		zone_info->data.in.zone_locator_lba  = lba;
		zone_info->data.in.force_unit_access = fua;

		rc = ioctl(fd, BLKREPORT, zone_info);
		if (rc != -1) {
			test_endian(&zone_info->data.out);

			if (verbose)
				fprintf(stdout, "Found %d zones\n",
					endian32(zone_info->data.out.descriptor_count));

			print_zones(&zone_info->data.out, len);
		} else {
			fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
		}
		free(zone_info);
	}

	return rc;
}

static inline void _lba_to_cmd_ata(uint8_t *cmd, uint64_t _lba)
{
	cmd[1] =  _lba	      & 0xff;
	cmd[3] = (_lba >>  8) & 0xff;
	cmd[5] = (_lba >> 16) & 0xff;
	cmd[0] = (_lba >> 24) & 0xff;
	cmd[2] = (_lba >> 32) & 0xff;
	cmd[4] = (_lba >> 40) & 0xff;
}

/*
 * ata-16 passthrough byte 1:
 *   multiple [bits 7:5]
 *   protocol [bits 4:1]
 *   ext      [bit    0]
 */
static inline uint8_t ata16byte1(uint8_t multiple, uint8_t protocol, uint8_t ext)
{
	return ((multiple & 0x7) << 5) | ((protocol & 0xF) << 1) | (ext & 0x01);
}

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16

#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */
#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d

#define ATA_IDENTIFY_DEVICE 0xec
#define ATA_IDENTIFY_PACKET_DEVICE 0xa1
#define ID_RESPONSE_LEN 512


#define ATA_CMD_ZONE_MAN_IN	0x4A
#define ATA_SUBCMD_REP_ZONES	0x00


#define DEF_TIMEOUT		60

static int do_report_sat(int fd, uint64_t lba, uint64_t buf_len, int fua,
			 uint8_t ropt, int verbose)
{
	struct bdev_zone_report_io *zone_info;
	void *outbuf = NULL;
	uint8_t cmd[SAT_ATA_PASS_THROUGH16_LEN] = { 0 };
	uint8_t sense_buffer[64];
	unsigned char ata_return_desc[16];
	int resid = 0;
	int rc = -4;

	memset(cmd, 0, sizeof(cmd));
	memset(sense_buffer, 0, sizeof(sense_buffer));
	memset(ata_return_desc, 0, sizeof(ata_return_desc));

	cmd[0] = SAT_ATA_PASS_THROUGH16;
	cmd[1] = ata16byte1(0, 6, 1);
	cmd[2] = 0x0e;
	cmd[4] = ATA_SUBCMD_REP_ZONES;
	cmd[3] = ropt;
	cmd[5] = (buf_len / 512) >> 8;
	cmd[6] = (buf_len / 512) & 0xff;
	_lba_to_cmd_ata(&cmd[7], lba);
	cmd[13] = 1 << 6;
	cmd[14] = ATA_CMD_ZONE_MAN_IN;

	zone_info = malloc(buf_len);
	if (zone_info) {
		memset(zone_info, 0, buf_len);
		zone_info->data.in.report_option     = ropt;
		zone_info->data.in.return_page_count = buf_len;
		zone_info->data.in.zone_locator_lba  = lba;
		zone_info->data.in.force_unit_access = fua;

		rc = sg_ll_ata_pt(fd, cmd, sizeof(cmd), DEF_TIMEOUT,
				  zone_info, outbuf, buf_len,
				  sense_buffer, sizeof(sense_buffer),
				  ata_return_desc, sizeof(ata_return_desc),
				  &resid, verbose);
		if (rc >= 0) {
			test_endian(&zone_info->data.out);

			if (verbose)
				fprintf(stdout, "Found %d zones\n",
					endian32(zone_info->data.out.descriptor_count));

			print_zones(&zone_info->data.out, buf_len);
		} else {
			fprintf(stderr, "SAT - ERR: %d -> %s\n\n", errno, strerror(errno));
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

	setlocale(LC_ALL, "");

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
		case 'e':
			do_endian_probe = 0;
			is_big_endian = strtoull(optarg, NULL, 0);
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
		errx(EXIT_FAILURE, "%s: offset %" PRIu64 " is not aligned "
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

	if (sat) {
		if (length > MAX_REPORT_LEN_SAT) {
			if (length != MAX_REPORT_LEN)
				printf("Max length for sat is %d bytes\n", length);
			length = MAX_REPORT_LEN_SAT;
		}
		if (do_report_sat(fd, offset, length, fua, ropt & 0xFF, verbose))
			 err(EXIT_FAILURE, "%s: BLKREPORT (SAT) failed\n", path);
	} else {
		if (do_report(fd, offset, length, fua, ropt & 0xFF, verbose))
			 err(EXIT_FAILURE, "%s: BLKREPORT ioctl failed\n", path);
	}
	close(fd);

	return EXIT_SUCCESS;
}
