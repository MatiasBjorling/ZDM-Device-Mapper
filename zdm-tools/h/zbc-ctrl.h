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
#include <linux/blkzoned.h>

int zdm_is_ha_device(uint32_t, int verbose);

uint32_t zdm_device_inquiry(int fd, int do_ata);

int zdm_zone_reset_wp(int fd, uint64_t lba);
int zdm_report_zones(int fd, struct blk_zone_report *zone_info);

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

#endif /* _ZBC_CTRL_H_ */
