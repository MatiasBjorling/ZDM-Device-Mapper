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

#ifndef _ZDMIOCTL_H_
#define _ZDMIOCTL_H_

// request an info dump from ZDM:
#define ZDM_IOC_MZCOUNT          0x5a4e0001
#define ZDM_IOC_WPS              0x5a4e0002
#define ZDM_IOC_FREE             0x5a4e0003
#define ZDM_IOC_STATUS           0x5a4e0004

#define PROC_WP			"wp.bin"
#define PROC_FREE		"free.bin"
#define PROC_DATA		"data.bin"
#define PROC_STATUS		"status"

#define Z_WP_GC_FULL		(1u << 31)
#define Z_WP_GC_ACTIVE		(1u << 30)
#define Z_WP_GC_TARGET		(1u << 29)
#define Z_WP_GC_READY		(1u << 28)
#define Z_WP_GC_BITS		(0xFu << 28)

#define Z_WP_RRECALC		(1u << 31)
// #define Z_WP_RA_ACTIVE		(1u << 30)
// #define Z_WP_RA_TARGET		(1u << 29)
// #define Z_WP_RA_READY		(1u << 28)
// #define Z_WP_RA_BITS		(0xFu << 28)


#define Z_WP_GC_PENDING		(Z_WP_GC_FULL|Z_WP_GC_ACTIVE)
#define Z_WP_NON_SEQ		(1u << 27)
#define Z_WP_RESV_01		(1u << 26)
#define Z_WP_RESV_02		(1u << 25)
#define Z_WP_RESV_03		(1u << 24)

#define Z_WP_VALUE_MASK		(~0u >> 8)
#define Z_WP_FLAGS_MASK		(~0u << 24)
#define Z_WP_STREAM_MASK        Z_WP_FLAGS_MASK

#define Z_AQ_GC			(1u << 31)
#define Z_AQ_META		(1u << 30)
#define Z_AQ_NORMAL		(1u << 29)
#define Z_AQ_STREAM_ID		(1u << 28)
#define Z_AQ_STREAM_MASK	(0xFF)
#define Z_AQ_META_STREAM	(Z_AQ_META | Z_AQ_STREAM_ID | 0xFE)

#ifdef __cplusplus
extern "C" {
#endif

/**
 */
struct zdm_ioc_status {
	uint64_t b_used;
	uint64_t b_available;
	uint64_t b_discard;
	uint64_t m_zones;
	uint64_t mc_entries;
	uint64_t mlut_blocks;
	uint64_t crc_blocks;
	uint64_t inpool;
	uint32_t bins[40];
} __attribute__((packed));

/**
 */
struct zdm_ioc_request {
    uint32_t result_size;
    uint32_t megazone_nr;
} __attribute__((packed));

/**
 */
union zdm_ioc_state {
	struct zdm_ioc_request request;
	struct zdm_ioc_status  status;
} __attribute__((packed));

/**
 */
struct megazone_info {
        uint32_t wps[1024];
        uint32_t free[1024];
        union zdm_ioc_state state;
} __attribute__((packed));


union zdm_ts {
	uint64_t ts64;
	time_t   tval;
} __attribute__((packed));

struct zdm_record {
	int64_t  size;
	int32_t  mz_count;
	uint32_t crc32;
	union zdm_ts at;
	struct megazone_info data[0];
} __attribute__((packed));


#ifdef __cplusplus
}
#endif

#endif // _ZDMIOCTL_H_
