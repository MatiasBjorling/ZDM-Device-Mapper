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

#ifndef _ZBC_CTRL_H_
#define _ZBC_CTRL_H_

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define DEBUG 1

#include <utypes.h>
#include <linux/blkzoned_api.h>

/**
 * struct bdev_zone_descriptor_le - See: bdev_zone_descriptor
 */
struct bdev_zone_descriptor_le {
	__u8 type;
	__u8 flags;
	__u8 reserved1[6];
	__le64 length;
	__le64 lba_start;
	__le64 lba_wptr;
	__u8 reserved[32];
} __attribute__((packed));

/**
 * struct bdev_zone_report_le - See: bdev_zone_report
 */
struct bdev_zone_report_le {
	__le32 descriptor_count;
	__u8 same_field;
	__u8 reserved1[3];
	__le64 maximum_lba;
	__u8 reserved2[48];
	struct bdev_zone_descriptor_le descriptors[0];
} __attribute__((packed));



int zdm_is_ha_device(uint32_t, int verbose);
int zdm_is_big_endian_report(struct bdev_zone_report *info);

uint32_t zdm_device_inquiry(int fd, int do_ata);
int zdm_zone_reset_wp(int fd, uint64_t lba, int do_ata);
int zdm_report_zones(int fd, struct bdev_zone_report_io *zone_info,
		     uint64_t size, uint8_t option, uint64_t lba, int do_ata);

int zdm_zone_open(int fd, uint64_t lba, int do_ata);
int zdm_zone_close(int fd, uint64_t lba, int do_ata);
int zdm_zone_finish(int fd, uint64_t lba, int do_ata);


#endif /* _ZBC_CTRL_H_ */
