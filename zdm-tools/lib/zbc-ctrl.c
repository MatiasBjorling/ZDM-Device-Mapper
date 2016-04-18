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
	ZOPT_NON_SEQ_AND_RESET,
	ZOPT_ZC1_EMPTY,
	ZOPT_ZC2_OPEN_IMPLICIT,
	ZOPT_ZC3_OPEN_EXPLICIT,
	ZOPT_ZC4_CLOSED,
	ZOPT_ZC5_FULL,
	ZOPT_ZC6_READ_ONLY,
	ZOPT_ZC7_OFFLINE,
	ZOPT_RESET,
	ZOPT_NON_SEQ,
	ZOPT_NON_WP_ZONES,
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

int zdm_zone_command(int fd, int command, uint64_t lba, int do_ata)
{
	uint64_t iolba = lba;
	int rc;

	if (do_ata) {
		iolba |= 1;
	} else {
		iolba &= ~1ul;
	}

	rc = ioctl(fd, command, iolba);
	if (rc == -1) {
		fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
	}

	return rc;
}

int zdm_zone_close(int fd, uint64_t lba, int do_ata)
{
	return zdm_zone_command(fd, BLKCLOSEZONE, lba, do_ata);
}

int zdm_zone_finish(int fd, uint64_t lba, int do_ata)
{
	fprintf(stderr, "zdm_zone_finish: Not Implemented!!\n"); 
	return zdm_zone_command(fd, BLKCLOSEZONE, lba, do_ata);
}

int zdm_zone_open(int fd, uint64_t lba, int do_ata)
{
	return zdm_zone_command(fd, BLKOPENZONE, lba, do_ata);
}

int zdm_zone_reset_wp(int fd, uint64_t lba, int do_ata)
{
	return zdm_zone_command(fd, BLKRESETZONE, lba, do_ata);
}


static int fix_endian = 0;

static u64 endian64(u64 in)
{
	return fix_endian ? be64toh(in) : in;
}

static u32 endian32(u32 in)
{
	return fix_endian ? be32toh(in) : in;
}

static void test_endian(struct bdev_zone_report *info)
{
	fix_endian = zdm_is_big_endian_report(info);
}

void print_zones(struct bdev_zone_report *info, uint32_t size)
{
	u32 count = endian32(info->descriptor_count);
	u32 max_count;
	int iter;
	int same_code = info->same_field & 0x0f;

	fprintf(stdout, "  count: %u, same %u (%s), max_lba %lu\n",
		count,
		same_code, same_text[same_code],
		endian64(info->maximum_lba & (~0ul >> 16)) );

	max_count = (size - sizeof(struct bdev_zone_report))
                        / sizeof(struct bdev_zone_descriptor);
	if (count > max_count) {
		fprintf(stderr, "Truncating report to %d of %d zones.\n",
			max_count, count );
		count = max_count;
	}

	for (iter = 0; iter < count; iter++ ) {
		struct bdev_zone_descriptor * entry =
			&info->descriptors[iter];
		unsigned int type  = entry->type & 0xF;
		unsigned int flags = entry->flags;
		u64 start = endian64(entry->lba_start);
		u64 wp = endian64(entry->lba_wptr);

		fprintf(stdout,
			"  start: %lx, len %lx, wptr %lx\n"
			"   type: %u(%s) reset:%u non-seq:%u, zcond:%u\n",
		start, endian64(entry->length), wp - start,
		type, type_text[type],
		flags & 0x01, (flags & 0x02) >> 1, (flags & 0xF0) >> 4);
	}
}

int zdm_is_big_endian_report(struct bdev_zone_report *info)
{
	int is_big = 0;
	struct bdev_zone_descriptor * entry = &info->descriptors[0];
	u64 be_len;
	be_len = be64toh(entry->length);
	if ( be_len == 0x080000 ||
             be_len == 0x100000 ||
             be_len == 0x200000 ||
             be_len == 0x300000 ||
             be_len == 0x400000 ||
             be_len == 0x800000 ) {
		is_big = 1;
	}
	return is_big;
}

int zdm_report_zones(int fd, struct bdev_zone_report_io *zone_info,
		     uint64_t size, uint8_t option, uint64_t lba, int do_ata)
{
	int rc;
	uint32_t cmd = BLKREPORT;

	zone_info->data.in.report_option     = option;
	zone_info->data.in.return_page_count = size;
	zone_info->data.in.zone_locator_lba  = lba;

	if (do_ata) {
		zone_info->data.in.report_option |= 0x80;
	}

	rc = ioctl(fd, cmd, zone_info);
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
		struct bdev_zone_report_io *zone_info;
                uint64_t size;

		/* NOTE: 128 seems to be about the RELIABLE limit ...     */
                /*       150 worked 180 was iffy (some or all ROs failed) */
                /*       256 all ROs failed..                             */
                size = 128 * 4096;
                zone_info = malloc(size);
                if (zone_info) {
			int opt = 0;
			for (opt = 0; opt < ARRAY_SIZE(r_opts); opt++) {
				memset(zone_info, 0, size);
				rc = zdm_report_zones(fd, zone_info, size, r_opts[opt], lba, do_ata);
				if (rc != -1) {
					test_endian(&zone_info->data.out);

					fprintf(stdout, "%s(%d): found %d zones\n",
						r_opt_text[opt],
						r_opts[opt],
						endian32(zone_info->data.out.descriptor_count) );
					print_zones(&zone_info->data.out, size);
				} else {
					fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
					break;
				}
			}
		}
                close(fd);
        } else {
                fprintf(stderr, "%s\n\n", strerror(errno));
        }

	return rc;
}

