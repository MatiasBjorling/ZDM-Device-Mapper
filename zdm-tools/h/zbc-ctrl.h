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
#include <linux/blk-zoned-ctrl.h>

/* Used for Zone based SMR devices */
#define SCSI_IOCTL_INQUIRY		0x10000
#define SCSI_IOCTL_CLOSE_ZONE		0x10001
#define SCSI_IOCTL_FINISH_ZONE		0x10002
#define SCSI_IOCTL_OPEN_ZONE		0x10003
#define SCSI_IOCTL_RESET_WP		0x10004
#define SCSI_IOCTL_REPORT_ZONES		0x10005

int zdm_is_ha_device(struct zoned_inquiry *inquire, int verbose);
int zdm_is_big_endian_report(struct bdev_zone_report *info);

struct zoned_inquiry* zdm_device_inquiry(int fd, int do_ata);
int zdm_zone_reset_wp(int fd, uint64_t lba, int do_ata);
int zdm_report_zones(int fd, struct bdev_zone_report_io *zone_info,
		     uint64_t size, uint8_t option, uint64_t lba, int do_ata);

int zdm_zone_open(int fd, uint64_t lba, int do_ata);
int zdm_zone_close(int fd, uint64_t lba, int do_ata);
int zdm_zone_finish(int fd, uint64_t lba, int do_ata);


#endif /* _ZBC_CTRL_H_ */
