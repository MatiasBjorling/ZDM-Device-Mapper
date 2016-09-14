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

#endif /* HAVE_BLKZONED_API_H */

#ifndef BLKZONEACTION
#define BLKZONEACTION	_IOW(0x12, 131, struct bdev_zone_action)

#define ZONE_ACTION_CLOSE	0x01
#define ZONE_ACTION_FINISH	0x02
#define ZONE_ACTION_OPEN	0x03
#define ZONE_ACTION_RESET	0x04

#endif /* BLKZONEACTION */

static void print_stats(int act, char *path, uint64_t lba)
{
	switch (act) {
	case ZONE_ACTION_CLOSE:
		printf("%s: Close Zone %" PRIx64 "\n", path, lba);
		break;
	case ZONE_ACTION_FINISH:
		printf("%s: Open Zone %" PRIx64 "\n", path, lba);
		break;
	case ZONE_ACTION_OPEN:
		printf("%s: Open Zone %" PRIx64 "\n", path, lba);
		break;
	case ZONE_ACTION_RESET:
		printf("%s: Reset Zone %" PRIx64 "\n", path, lba);
		break;
	default:
		printf("%s: Unknown Action on %" PRIu64 "\n", path, lba);
		break;
	}
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

#define ATA_CMD_ZONE_MAN_OUT	0x9F

#define DEF_TIMEOUT		60

int do_sat_zonecmd(int fd, struct bdev_zone_action * za, int verbose)
{
	uint8_t cmd[SAT_ATA_PASS_THROUGH16_LEN] = { 0 };
	uint8_t sense_buffer[64];
	unsigned char ata_return_desc[16];
	int resid = 0;
	int rc = -4;

	memset(cmd, 0, sizeof(cmd));
	memset(sense_buffer, 0, sizeof(sense_buffer));
	memset(ata_return_desc, 0, sizeof(ata_return_desc));

	cmd[0] = SAT_ATA_PASS_THROUGH16;
	cmd[1] = ata16byte1(0, 3, 1);
	if (za->all_zones)
		cmd[3] = 0x01;
	cmd[4] = za->action;
	_lba_to_cmd_ata(&cmd[7], za->zone_locator_lba);
	cmd[13] = 1 << 6;
	cmd[14] = ATA_CMD_ZONE_MAN_OUT;

	rc = sg_ll_ata_pt(fd, cmd, sizeof(cmd), DEF_TIMEOUT,
			  NULL, /* dinp - returned from device */
			  NULL, /* doutp - sent to device */
			  0,
			  sense_buffer, sizeof(sense_buffer),
			  ata_return_desc, sizeof(ata_return_desc),
			  &resid, verbose);
	return rc;
}

#define warn(...)        fprintf(stdout, __VA_ARGS__)
#define warnx(...)       fprintf(stdout, __VA_ARGS__), exit(EXIT_FAILURE)
#define err(code, ...)   fprintf(stderr, __VA_ARGS__)
#define errx(code, ...)  fprintf(stderr, __VA_ARGS__), exit(code)

static void __attribute__((__noreturn__)) usage(FILE *out)
{
	fprintf(out,
	      " %s [options] <device>\n", program_invocation_short_name);
	fputs("Discard the content of sectors on a device.\n\n", out);
	fputs("Usage options\n", out);
	fputs(" -z, --zone <num>  lba of start of zone to act upon\n"
		" -o, --open        open zone\n"
		" -c, --close       close zone\n"
		" -f, --finish      finish zone\n"
		" -r, --reset       reset zone\n"
		" -a, --all         apply to all zones\n"
		" -S  --sat         use ATA16 (implies force)\n"
		" -F, --force       force command to be set to media\n"
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
	struct bdev_zone_action za;
	uint64_t zone_lba = 0ul;
	uint32_t act = ZONE_ACTION_OPEN;
	int fua = 0;
	int sat = 0;
	int rc = 0;
	int all = 0;

	static const struct option longopts[] = {
	    { "help",      0, 0, 'h' },
	    { "version",   0, 0, 'V' },
	    { "all",       0, 0, 'a' },
	    { "zone",      1, 0, 'z' },
	    { "close",     0, 0, 'c' },
	    { "finish",    0, 0, 'f' },
	    { "force",     0, 0, 'F' },
	    { "open",      0, 0, 'o' },
	    { "reset",     0, 0, 'r' },
	    { "sat",       0, 0, 'S' },
	    { "verbose",   0, 0, 'v' },
	    { NULL,        0, 0, 0 }
	};

	setlocale(LC_ALL, "");

	while ((c = getopt_long(argc, argv, "SahVvocFfrz:", longopts, NULL)) != -1) {
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
		case 'o':
			act = ZONE_ACTION_OPEN;
			break;
		case 'c':
			act = ZONE_ACTION_CLOSE;
			break;
		case 'f':
			act = ZONE_ACTION_FINISH;
			break;
		case 'r':
			act = ZONE_ACTION_RESET;
			break;
		case 'a':
			all = 1;
			break;
		case 'F':
			fua = 1;
			break;
		case 'S':
			sat = 1;
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

	fd = open(path, O_WRONLY);
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

	if (zone_lba != ~0ul) {
		/* check offset alignment to the sector size */
		if (zone_lba % secsize)
			errx(EXIT_FAILURE, "%s: offset %" PRIu64 " is not aligned "
				 "to sector size %i\n", path, zone_lba, secsize);

		/* is the range end behind the end of the device ?*/
		if (zone_lba > blksize)
			errx(EXIT_FAILURE, "%s: offset is greater than device size\n", path);
	}

	switch (act) {
	case ZONE_ACTION_CLOSE:
	case ZONE_ACTION_FINISH:
	case ZONE_ACTION_OPEN:
	case ZONE_ACTION_RESET:
		za.zone_locator_lba = zone_lba;
		za.all_zones = all;
		if (zone_lba == ~0ul) {
			za.zone_locator_lba = 0;
			za.all_zones = 1;
		}
		if (za.all_zones && za.zone_locator_lba)
			err(EXIT_FAILURE, "%s: All expects zone to be 0\n", path);
		za.action = act;
		za.force_unit_access = fua;
		if (sat)
			rc = do_sat_zonecmd(fd, &za, verbose);
		else
			rc = ioctl(fd, BLKZONEACTION, &za);
		if (rc < 0)
			err(EXIT_FAILURE, "%s: BLKZONEACTION ioctl failed\n", path);
		break;
	default:
		err(EXIT_FAILURE, "%s: Unknown zone action %d\n", path, act);
		break;
	}

	if (verbose && zone_lba)
		print_stats(act, path, zone_lba);

	close(fd);
	return EXIT_SUCCESS;
}
