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
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/major.h>

#include <errno.h>
#include <string.h> // strdup

#include "libzdm.h"
#include "libzdm-compat.h"
#include "zbc-ctrl.h"
#include "crc64.h"
#include "is_mounted.h"
#include "zdm_version.h"

#ifndef MAJOR
#define MAJOR(dev)	((dev)>>8)
#define MINOR(dev)	((dev) & 0xff)
#endif

#ifndef SCSI_BLK_MAJOR
#ifdef SCSI_DISK0_MAJOR
#ifdef SCSI_DISK8_MAJOR
#define SCSI_DISK_MAJOR(M) ((M) == SCSI_DISK0_MAJOR || \
	((M) >= SCSI_DISK1_MAJOR && (M) <= SCSI_DISK7_MAJOR) || \
	((M) >= SCSI_DISK8_MAJOR && (M) <= SCSI_DISK15_MAJOR))
#else
#define SCSI_DISK_MAJOR(M) ((M) == SCSI_DISK0_MAJOR || \
	((M) >= SCSI_DISK1_MAJOR && (M) <= SCSI_DISK7_MAJOR))
#endif /* defined(SCSI_DISK8_MAJOR) */
#define SCSI_BLK_MAJOR(M) (SCSI_DISK_MAJOR((M)) || (M) == SCSI_CDROM_MAJOR)
#else
#define SCSI_BLK_MAJOR(M)  ((M) == SCSI_DISK_MAJOR || (M) == SCSI_CDROM_MAJOR)
#endif /* defined(SCSI_DISK0_MAJOR) */
#endif /* defined(SCSI_BLK_MAJOR) */

#define MEDIA_ZBC 0x01
#define MEDIA_ZAC 0x02

#define MEDIA_HOST_AWARE    (0x01 << 16)
#define MEDIA_HOST_MANAGED  (0x01 << 17)

#define ZONE_SZ_IN_SECT      0x80000 /* 1 << 19 */

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * Use device major/minor to determine if whole device or partition is specified.
 */
static int is_part(const char *dname)
{
    int is_partition = 1;
    struct stat st_buf;
    if (stat(dname, &st_buf) == 0)
    {
        if ( ((MAJOR(st_buf.st_rdev) == HD_MAJOR &&
                (MINOR(st_buf.st_rdev) % 64) == 0))
                ||
                ((SCSI_BLK_MAJOR(MAJOR(st_buf.st_rdev)) &&
                  (MINOR(st_buf.st_rdev) % 16) == 0)))
        {
            is_partition = 0;
        }
    }
    return is_partition;
}


/**
 * Get the starting block of the partition.
 * Currently using HDIO_GETGEO and start is a long ...
 * Q: Is there better way to get this? Preferably an API
 *    returning the a full u64. Other option is to poke
 *    around in sysfs (/sys/block/sdX/sdXn/start)
 *
 * FUTURE: Do this better ...
 */
int blkdev_get_start(int fd, unsigned long *start)
{
    struct hd_geometry geometry;

    if (ioctl(fd, HDIO_GETGEO, &geometry) == 0)
    {
        *start = geometry.start;
        return 0;
    }
    return -1;
}


/**
 * Get the full size of a partition/block device.
 */
int blkdev_get_size(int fd, u64 *sz)
{
    if (ioctl(fd, BLKGETSIZE64, sz) >= 0)
    {
        return 0;
    }
    return -1;
}
/**
 * Detect the type field for what we are interested in.
 */
static inline int is_conv_or_relaxed(unsigned int type)
{
    return (type == 1 || type == 3) ? 1 : 0;
}

/**
 * Determine if device support ZAC [SATA on SAS] or ZBC [SATA on AHCI] access.
 *
 * Note: Host Managed detection not tested/supported.
 */
int zaczbc_probe_media(int fd, uint32_t *detected, int verbose)
{
    int do_ata = 0;
    int rcode = -1;
    uint32_t support_flags = 0u;

    struct zoned_inquiry *inq = zdm_device_inquiry(fd, do_ata);
    if (inq)
    {
        if (zdm_is_ha_device(inq, 0))
        {
            support_flags |= MEDIA_ZBC;
            support_flags |= MEDIA_HOST_AWARE;
            if (verbose > 0)
            {
                printf(" ... HA device supports ZBC access.\n");
            }
            rcode = 0;
        }
        free(inq);
    }

    do_ata = 1;
    inq = zdm_device_inquiry(fd, do_ata);
    if (inq)
    {
        if (zdm_is_ha_device(inq, 0))
        {
            support_flags |= MEDIA_ZAC;
            support_flags |= MEDIA_HOST_AWARE;
            if (verbose > 0)
            {
                printf(" ... HA device supports ZAC access.\n");
            }
            rcode = 0;
        }
        free(inq);
    }

    if (0 == support_flags)
    {
        if (verbose > 0)
        {
            printf(" ... No ZAC/ZAC support detected.\n");
        }
        rcode = 0;
    }

    *detected = support_flags;

    return rcode;
}



#if 0
int zdmadm_probe_zones(int fd, zdm_super_block_t * sblk)
{
    int rcode = 0;
    size_t size = 128 * 4096;
    struct bdev_zone_report_io * report = malloc(size);
    if (report)
    {
        int opt = ZOPT_NON_SEQ_AND_RESET;
        u64 lba = sblk->sect_start;
        int do_ata = (sblk->zac_zbc & MEDIA_ZAC) ? 1 : 0;

        memset(report, 0, size);
        rcode = zdm_report_zones(fd, report, size, opt, lba, do_ata);
        if (rcode < 0)
        {
            printf("report zones failure: %d\n", rcode);
        }
        else
        {
            int zone = 0;
            struct bdev_zone_report *info = &report->data.out;
            struct bdev_zone_descriptor *entry = &info->descriptors[zone];
            int is_be = zdm_is_big_endian_report(info);
            u64 fz_at = is_be ? be64toh(entry->lba_start) : entry->lba_start;
            u64 fz_sz = is_be ? be64toh(entry->length) : entry->length;
            unsigned int type = entry->type & 0xF;
            u64 cache, need, pref;
            u64 mdzcount = 0;
            u64 nmegaz = 0;


            unsigned long start; /* in 512 byte sectors */
            u64 sz;
            int exCode = 0;

            sblk->version = ZDM_SBLK_VER;
            sblk->discard = 1;
            memcpy(sblk->magic, zdm_magic, sizeof(sblk->magic));
            uuid_generate(sblk->uuid);
            sblk->mz_metadata_zones = resv;
            sblk->mz_over_provision = oprov;
            sblk->discard = trim;

            if (verbose > 0)
            {
                printf("Scanning device %s\n", dname );
            }

            if (blkdev_get_start(fd, &start) < 0)
            {
                printf("Failed to determine partition starting sector!!\n");
                exCode = 1;
                goto out;
            }
            sblk->sect_start = start; /* in 512 byte sectors */


            while (sblk->sect_start >= fz_at)
            {
                entry = &info->descriptors[++zone];
                fz_at = is_be ? be64toh(entry->lba_start) : entry->lba_start;
                fz_sz = is_be ? be64toh(entry->length) : entry->length;
            }


            for (; mdzcount < pref && zone < 200; zone++)
            {
                u64 length;

                entry = &info->descriptors[zone];
                length = is_be ? be64toh(entry->length) : entry->length;
                type = entry->type & 0xF;

                if ( !is_conv_or_relaxed(type) )
                {
                    printf("Unsupported device: ZDM first zone must be conventional"
                           " or sequential-write preferred\n");
                    rcode = -1;
                    goto out;
                }
                if ( length != fz_sz )
                {
                    printf("Unsupported device: all zones must be same size"
                           " excluding last zone on the drive!\n");
                    rcode = -1;
                    goto out;
                }
                mdzcount++;
            }
            sblk->data_start = zone;
            sblk->zone_size = fz_sz;
        }
    }
out:
    if (report)
    {
        free(report);
    }

    return rcode;
}

#endif


static uint8_t *buffer = NULL;

int zbc_fill_zone(int fd, u64 s_addr, u32 blksz, int verbose)
{
    int err = 0;
    u32 incr = blksz >> 9;
    u64 wp;

    if (!buffer)
    {
        u32 align = 4096;

        buffer = memalign(align << 1, blksz + align);
        if (!buffer)
        {
            return -ENOMEM;
        }
        buffer += align;
        memset(buffer, 0xff, blksz);
    }
    memcpy(buffer, &s_addr, sizeof(s_addr)); /* tag the write with the zone addr */

    if (verbose)
    {
        printf(	"zbc_fill_zone(.., %"PRIx64" %x -> %x\n", s_addr, blksz, incr);
    }


    for (wp = 0; wp < (1 << 19); wp += incr)
    {
        u64 lba = (s_addr + wp) << 9;
        int rc = pwrite64(fd, buffer, blksz, lba);

        if (verbose)
        {
            printf(	"pwrite64(.., .., %u, %"PRIx64" -> %u\n",
                    blksz, lba, rc);
        }

        if (rc != blksz)
        {
            fprintf(stderr, "write error: %d writing %"
                    PRIx64 "\n", rc, lba);
            err = -1;
            goto out;
        }
    }

    /* if blksz was not aligned to zone we may skip writing some blocks */

out:
    return err;
}

int zbc_example_io(int fd, u32 flgs, u32 blksz, u32 start_zone, u32 count, int verbose)
{
    int rcode = 0;
    u64 s_addr = ~0ul;
    int do_ata = flgs & MEDIA_ZAC ? 1 : 0;
    int wp_err;
    u64 zone;

    printf("ha/hm   - HostAware %s / HostManaged %s\n",
           flgs & MEDIA_HOST_AWARE   ? "Yes" : "No",
           flgs & MEDIA_HOST_MANAGED ? "Yes" : "No");

    printf("zac/zbc - ZAC: %s / ZBC: %s\n",
           flgs & MEDIA_ZAC ? "Yes" : "No",
           flgs & MEDIA_ZBC ? "Yes" : "No" );

    if (flgs)
    {
        wp_err = zdm_zone_command(fd, SCSI_IOCTL_RESET_WP, s_addr, do_ata);
        if (wp_err)
        {
            printf("Reset All WP: %" PRIx64 " -> %d failed.\n", s_addr, wp_err);
            rcode = wp_err;
            goto out;
        }
    }

    for (zone = start_zone; zone < (start_zone + count); zone++)
    {
        s_addr = zone << 19;

        if (flgs)
        {
            wp_err = zdm_zone_command(fd, SCSI_IOCTL_OPEN_ZONE, s_addr, do_ata);
            if (wp_err)
            {
                printf("Open Zone %" PRIu64 " @ %" PRIx64 " -> %d failed.\n",
                       zone, s_addr, wp_err);
                rcode = wp_err;
                goto out;
            }
        }

        wp_err = zbc_fill_zone(fd, s_addr, blksz, verbose);
        if (wp_err)
        {
            printf("Fill Zone %" PRIu64 " @ %" PRIx64 " -> %d failed.\n",
                   zone, s_addr, wp_err);
            rcode = wp_err;
            goto out;
        }

        if (flgs)
        {
            wp_err = zdm_zone_command(fd, SCSI_IOCTL_CLOSE_ZONE, s_addr, do_ata);
            if (wp_err)
            {
                printf("Close Zone %" PRIu64 " @ %" PRIx64 " -> %d failed.\n", zone, s_addr, wp_err);
                rcode = wp_err;
                goto out;
            }
        }
    }

out:
    return rcode;
}

void usage(void)
{
    printf("USAGE:\n"
           "    zdm-rawio [options] device\n"
           "Options:\n"
           "    -b <block_size> Size of writes default is 1MiB.\n"
           "    -z <zone> Zone to write to.\n"
           "    -c <nzones> Number of zones to fill.\n"
           "    -d open with O_DIRECT.\n"
           "    -s open with O_DSYNC.\n"
           "    -v verbosity. More v's more verbose.\n"
           "\n");
}

int main(int argc, char *argv[])
{
    int opt;
    int index;

    int exCode = 0;
    u32 blksz   = 1024 * 1024;
    u32 zone    = 512;
    u32 count   = 0;
    int o_flags = O_RDWR;
    int verbose = 0;
    int use_force = 0;

    printf("zdm-rawio %d.%d\n", zdm_VERSION_MAJOR, zdm_VERSION_MINOR );

    /* Parse command line */
    errno = EINVAL; // Assume invalid Argument if we die
    while ((opt = getopt(argc, argv, "b:z:c:sdvF")) != -1)
    {
        switch (opt)
        {
        case 'b':
            blksz = strtoul(optarg, NULL, 0);
            break;
        case 'z':
            zone = strtoul(optarg, NULL, 0);
            break;
        case 'c':
            count = strtoul(optarg, NULL, 0);
            break;
        case 'd':
            o_flags |= O_DIRECT;
            break;
        case 's':
            o_flags |= O_DSYNC;
            break;
        case 'v':
            verbose++;
            break;
        case 'F':
            use_force = 1;
            break;
        default:
            usage();
            break;
        } /* switch */
    } /* while */

    if (verbose > 0)
    {
        set_debug(verbose);
    }

    for (index = optind; index < argc; )
    {
        int fd;
        char *dname = argv[index];
        int is_busy;
        char buf[80];
        int flags;
        int need_rw = 0;
        int isa_partition;
        unsigned long start = 0ul;

        is_busy = is_anypart_mounted(dname, &flags, buf, sizeof(buf));
        if (is_busy || flags)
        {
            printf("%s is busy/mounted: %d:%x\n",
                   dname, is_busy, flags );
            printf("refusing to proceed\n");
            exCode = 1;
            goto out;
        }

        isa_partition = is_part(dname);
        if (isa_partition)
        {

            if (blkdev_get_start(fd, &start) < 0)
            {
                printf("Failed to determine partition starting sector!!\n");
                exCode = 1;
                goto out;
            }
        }


        fd = open(dname, o_flags);
        if (fd)
        {
            uint32_t flgs;

            exCode = zaczbc_probe_media(fd, &flgs, verbose);
            if (exCode)
            {
                printf("Media detect failed.\n");
                fsync(fd);
                close(fd);
                goto out;
            }
            if (!flgs)
            {
                printf("HA/HM and/or ZAC/ZBC support not detected.\n");
                if (use_force)
                {
                    printf("  ... continuing with errors.\n");
                }
                else
                {
                    exCode = 1;
                    fsync(fd);
                    close(fd);
                    goto out;
                }
            }

            if (count == 0)
            {
                u32 number_of_zones;
                u64 sz = 0ul;

                if (blkdev_get_size(fd, &sz) < 0)
                {
                    printf("Failed to determine device/partition size!!\n");
                    exCode = 1;
                    fsync(fd);
                    close(fd);
                    goto out;
                }

                number_of_zones = sz >> 28;
                if (zone < number_of_zones)
                {
                    count = number_of_zones - zone;
                }
            }
            if (flgs || use_force)
            {
                if (verbose)
                {
                    printf(" Z %d S: %u Count %u\n", zone, blksz, count);
                }
                zbc_example_io(fd, flgs, blksz, zone, count, verbose);
            }

            fsync(fd);
            close(fd);
        }
        index++;

    } /* end: for each device on cli */

    if (optind >= argc)
    {
        usage();
    }

out:
    return exCode;
}


