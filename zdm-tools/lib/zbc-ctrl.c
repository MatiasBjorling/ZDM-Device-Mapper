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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include <scsi/sg.h>
#include <scsi/sg_cmds_basic.h>

#include "zbc-ctrl.h"

// typedef uint8_t u8;
// typedef uint16_t u16;
// typedef uint32_t u32;


#define Z_VPD_INFO_BYTE 8

static inline char * ha_or_dm_text(int is_ha)
{
	return is_ha  ? "Host AWARE"  : "Host or Drive Managed";
}

#define INQUIRY                         0x12
#define INQUIRY_CMDLEN		        6
#define ZAC_ATA_OPCODE_IDENTIFY         0xec

#define ZAC_PASS_THROUGH16_OPCODE       0x85
#define ZAC_PASS_THROUGH16_CDB_LEN      16

#define SCSI_SENSE_BUFFERSIZE 	        96


#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif /* offsetof */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof((x))/sizeof((*x)))
#endif

static const char * type_text[] = {
	"RESERVED",
	"CONVENTIONAL",
	"SEQ_WRITE_REQUIRED",
	"SEQ_WRITE_PREFERRED",
};


static const char * r_opt_text[] = {
        "NON_SEQ_AND_RESET",
        "ZC1_EMPTY",
	"ZC2_OPEN_IMPLICIT",
	"ZC3_OPEN_EXPLICIT",
	"ZC4_CLOSED",
	"ZC5_FULL",
	"ZC6_READ_ONLY",
	"ZC7_OFFLINE",
	"RESET",
	"NON_SEQ",
        "NON_WP_ZONES",
};

static const char * same_text[] = {
	"all zones are different",
	"all zones are same size",
	"last zone differs by size",
	"all zones same size - different types",
};


static unsigned char r_opts[] = {
	ZBC_ZONE_REPORTING_OPTION_ALL,
	ZBC_ZONE_REPORTING_OPTION_EMPTY,
	ZBC_ZONE_REPORTING_OPTION_IMPLICIT_OPEN,
	ZBC_ZONE_REPORTING_OPTION_EXPLICIT_OPEN,
	ZBC_ZONE_REPORTING_OPTION_CLOSED,
	ZBC_ZONE_REPORTING_OPTION_FULL,
	ZBC_ZONE_REPORTING_OPTION_READONLY,
	ZBC_ZONE_REPORTING_OPTION_OFFLINE,
	ZBC_ZONE_REPORTING_OPTION_NEED_RESET_WP,
	ZBC_ZONE_REPORTING_OPTION_NON_SEQWRITE,
	ZBC_ZONE_REPORTING_OPTION_NON_WP,
};


#define Z_VPD_INFO_BYTE 8
#define DATA_OFFSET (offsetof(struct zoned_inquiry, result))

int zdm_is_ha_device(uint32_t flags, int verbose)
{
	int is_smr = 0;
	int is_ha  = 0;

	switch (flags & 0xff) {
		case 1:
			is_ha = 1;
			is_smr = 1;
			break;
		case 2:
			is_smr = 1;
			break;
		default:
			break;
	}

	if (verbose) {
		printf("HostAware:%d, SMR:%d\n", is_ha, is_smr );
	}
	return is_ha;
}

/*
 * ata-16 passthrough byte 1:
 *   multiple [bits 7:5]
 *   protocol [bits 4:1]
 *   ext      [bit    0]
 */
static inline u8 ata16byte1(u8 multiple, u8 protocol, u8 ext)
{
	return ((multiple & 0x7) << 5) | ((protocol & 0xF) << 1) | (ext & 0x01);
}

static inline u16 zc_get_word(u8 *buf)
{
	u16 w = buf[1];

	w <<= 8;
	w |= buf[0];
	return w;
}


static int do_sg_io_inq(int fd, u8 *cdb, int cdb_sz, u8 *buf, int bufsz, u8 *sense, int s_sz)
{
	sg_io_hdr_t io_hdr;

	memset(&io_hdr, 0, sizeof(io_hdr));
	io_hdr.interface_id    = 'S';
	io_hdr.timeout         = 20000;
	io_hdr.flags           = 0; //SG_FLAG_DIRECT_IO;
	io_hdr.cmd_len         = cdb_sz;
	io_hdr.cmdp            = cdb;
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.dxfer_len       = bufsz;
	io_hdr.dxferp          = buf;
	io_hdr.mx_sb_len       = s_sz;
	io_hdr.sbp             = sense;

	return ioctl(fd, SG_IO, &io_hdr);
}


int blk_zoned_inquiry(int fd, uint32_t *zflags)
{
	int ret;
	uint8_t	buf[0xfc] = { 0 };

	ret = sg_ll_inquiry(fd, 0, 1, 0xb1, buf, sizeof(buf), 0, 0);
	if (!ret)
		return -1;

	*zflags = buf[Z_VPD_INFO_BYTE] >> 4 & 0x03;
	return ret;
}

#define ATA_PROT_NCQ 4

int blk_zoned_identify_ata(int fd, uint32_t *zflags)
{
	int ret;
	u8 cmd[ZAC_PASS_THROUGH16_CDB_LEN] = { 0 };
	u8 sense_buf[SCSI_SENSE_BUFFERSIZE] = { 0 };
	u8 buf[512] = { 0 };
	int flag = 0;

	cmd[0] = ZAC_PASS_THROUGH16_OPCODE;
	cmd[1] = ata16byte1(0, 4, 1);
	cmd[2] = 0xe;
	cmd[6] = 0x1;
	cmd[8] = 0x1;
	cmd[14] = ZAC_ATA_OPCODE_IDENTIFY;

	ret = do_sg_io_inq(fd, cmd, sizeof(cmd), buf, sizeof(buf),
			   sense_buf, sizeof(sense_buf));

	if (ret != 0)
		goto out;

	flag = zc_get_word(&buf[138]);
	if ((flag & 0x3) == 0x1)
		*zflags = 1;
	else
		ret = -1;

out:
	return ret;
}


uint32_t zdm_device_inquiry(int fd, int do_ata)
{
	uint32_t zflags = 0;
	if (do_ata) {
		if (blk_zoned_identify_ata(fd, &zflags) == 0)
			return zflags;
	} else {
		if (blk_zoned_inquiry(fd, &zflags) == 0)
			return zflags;
	}
	return ~0u;
}

int zdm_reset_wp(int fd, uint64_t lba)
{
	struct blk_zone_range za;
	uint64_t iolba = lba;
	int rc;

	za.sector = iolba;
	za.nr_sectors = 1 << 19;

	rc = ioctl(fd, BLKRESETZONE, &za);
	if (rc == -1) {
		fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
	}

	return rc;
}

int zdm_zone_close(int fd, uint64_t lba, int do_ata)
{
	return 0;
}

int zdm_zone_finish(int fd, uint64_t lba, int do_ata)
{
	return 0;
}

int zdm_zone_open(int fd, uint64_t lba, int do_ata)
{
	return 0;
}

int zdm_zone_reset_wp(int fd, uint64_t lba)
{
	return zdm_reset_wp(fd, lba);
}

void print_zones(struct blk_zone_report *zone_info)
{
	int iter;
	u32 count = zone_info->nr_zones;

	fprintf(stdout, "  count: %u\n", count);
	for (iter = 0; iter < count; iter++ ) {
		struct blk_zone * entry = &zone_info->zones[iter];
		u64 start = entry->start;
		u64 len   = entry->len;
		u64 wp    = entry->wp;


		

		fprintf(stdout,
			"  start: %"PRIx64", len %"PRIx64", wptr %"PRIx64"\n"
			"   type: %u(%s) reset:%u non-seq:%u, zcond:%u\n",
		start, len, wp - start, entry->type, type_text[entry->type],
		entry->reset, entry->non_seq, entry->cond);
	}
}

int zdm_report_zones(int fd, struct blk_zone_report *zone_info)
{
	int rc;

	rc = ioctl(fd, BLKREPORTZONE, zone_info);
	if (rc == -1) {
		fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
	}

	return rc;
}

int do_report_zones_ioctl(const char * pathname, uint64_t lba, int do_ata)
{
	int rc = -4;
	int fd = open(pathname, O_RDWR);

	if (fd != -1) {
		struct blk_zone_report *zone_info;
		u64 nr_zones = 4096;
                uint64_t size = sizeof(struct blk_zone) * nr_zones;

		zone_info = malloc(size + sizeof(struct blk_zone_report));
		if (zone_info) {
			memset(zone_info, 0, size);

			zone_info->sector = lba;
			zone_info->nr_zones = nr_zones;
//			zone_info->future = r_opts[opt];

			rc = zdm_report_zones(fd, zone_info);
			if (rc != -1) {
				fprintf(stdout, "found %d zones\n", zone_info->nr_zones);
				print_zones(zone_info);
			} else {
				fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
			}
			free(zone_info);
		}
		close(fd);
	} else {
		fprintf(stderr, "%s\n\n", strerror(errno));
	}

	return rc;
}

