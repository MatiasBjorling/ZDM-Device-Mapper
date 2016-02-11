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
#include <time.h>


#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <linux/fs.h>
#include <errno.h>
#include <string.h> // strdup


#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "utypes.h"
#include <zdmioctl.h>
#include <libcrc.h>


typedef struct zdm_ioc_status zdm_ioc_status_t;
typedef struct zdm_ioc_request zdm_ioc_request_t;

typedef union zdm_ioc
{
    zdm_ioc_request_t request;
    zdm_ioc_status_t  status;
} zdm_ioc_t;

struct zone_value_entry
{
    u32 zone;
    u32 value;
};

static volatile int clean_exit = 0;

/* Ctrl-\ handler */
void sigint_handler(int sig)
{
    clean_exit = 1;
    signal(sig, sigint_handler); /* re-install handler */
}

int query_everything(int fd_stats, int fd_wps, int fd_use, FILE *wfp)
{
    int rcode = 0;
    int32_t mz_count = 0;
    u32 iter = 0;
    u32 mz;
    ssize_t in;
    ssize_t sz;
    struct zone_value_entry entry;
    struct zdm_ioc_status status;
    struct zdm_record * m_rec;
    off_t pos = 0ul;

    in = read(fd_stats, &status, sizeof(status));
    if (in == sizeof(status))
    {
        mz_count = (status.m_zones + 1023) / 1024;
    }
    else
    {
        fprintf(stderr, "Read -> %ld\n", in );
        return -1;
    }

    sz = sizeof(struct zdm_record) + (mz_count * sizeof(struct megazone_info));
    m_rec = malloc(sz);
    m_rec->size = sz;
    m_rec->mz_count = mz_count;
    m_rec->crc32 = 0u;
    time(&m_rec->at.tval);

    memset(m_rec->data, 0xff, mz_count * sizeof(struct megazone_info));
    for (iter = 0; iter < status.m_zones && in > 0; iter++)
    {
        mz = iter / 1024;
        in = read(fd_wps, &entry, sizeof(entry));
        if (in == sizeof(entry))
        {
            m_rec->data[mz].wps[iter % 1024] = entry.value;
        }
    }

    for (iter = 0; iter < status.m_zones && in > 0; iter++)
    {
        mz = iter / 1024;
        in = read(fd_use, &entry, sizeof(entry));
        if (in == sizeof(entry))
        {
            m_rec->data[mz].free[iter % 1024] = entry.value;
        }
    }

    lseek(fd_stats, pos, SEEK_SET);
    lseek(fd_wps,   pos, SEEK_SET);
    lseek(fd_use,   pos, SEEK_SET);

    for (iter = 0; iter < mz_count; iter++)
    {
        memcpy(&m_rec->data[iter].state, &status, sizeof(status));
    }

    m_rec->crc32 = crc32c(~(u32) 0u, m_rec, m_rec->size);

    in = fwrite(m_rec, 1, m_rec->size, wfp);
    fprintf(stderr, "Wrote: %ld\n", in );

    return rcode;
}


int do_query_wps(const char *ppath, int period, FILE *wfp)
{
    int rcode = -1;
    char stats[128];
    char wps[128];
    char use[128];
    int fd_stats = -1;
    int fd_wps = -1;
    int fd_use = -1;

    snprintf(stats, sizeof(stats), "%s/" PROC_DATA, ppath);
    snprintf(wps,   sizeof(wps  ), "%s/" PROC_WP, ppath);
    snprintf(use,   sizeof(use  ), "%s/" PROC_FREE, ppath);

    fd_stats = open(stats, O_RDONLY);
    if (fd_stats == -1)
    {
        goto out;
    }

    fd_wps = open(wps, O_RDONLY);
    if (fd_wps == -1)
    {
        goto out;
    }

    fd_use = open(use, O_RDONLY);
    if (fd_use == -1)
    {
        goto out;
    }

    while (!clean_exit)
    {
        rcode = query_everything(fd_stats, fd_wps, fd_use, wfp);
        if (rcode)
        {
            break;
        }
        sleep(period);
    }

out:

    if (fd_stats != -1)
    {
        close(fd_stats);
    }

    if (fd_wps != -1)
    {
        close(fd_wps);
    }

    if (fd_use != -1)
    {
        close(fd_use);
    }

    if (rcode < 0)
    {
        fprintf(stderr, "ERROR: %d\n", rcode);
    }
    return rcode;
}

void usage(void)
{
    printf("USAGE:\n"
           "    zdm-mlog [-l <level>] [-p <seconds>] -o <outfile> zdm_device\n"
           "Defaults are: -v 0\n"
           "              -p 1\n"
           "              -o ./zdm_device.log\n");
}

int main(int argc, char *argv[])
{
    int opt;
    int index;
    int period = 1;
    int exCode = 0;
    char *fname = NULL;

    /* Parse command line */
    errno = EINVAL; // Assume invalid Argument if we die
    while ((opt = getopt(argc, argv, "o:v:p:")) != -1)
    {
        switch (opt)
        {
        case 'o':
            fname = optarg;
            break;
        case 'p':
            period = atoi(optarg);
            break;
        default:
            usage();
            break;
        } /* switch */
    } /* while */

    if (!fname)
    {
        usage();
        printf(" ** -o <outfile> required to log data\n");
        exCode = 1;
        goto done;
    }

    for (index = optind; index < argc; index++)
    {
        struct stat st_buf;

        if (0 == stat(argv[index], &st_buf) &&
                S_ISDIR(st_buf.st_mode))
        {
            FILE *ofp = fopen(fname, "w");
            if (ofp)
            {
                /* Set up QUIT, INT, HUP and ABRT handlers */
                signal(SIGQUIT, sigint_handler);
                signal(SIGINT, sigint_handler);
                signal(SIGABRT, sigint_handler);
                signal(SIGHUP, sigint_handler);

                do_query_wps(argv[index], period, ofp);
                fclose(ofp);
            }
        }
        else
        {
            perror("Failed to open file");
            fprintf(stderr, "No a directory: %s", argv[index]);
        }
    }

    if (argc == 1 || optind == 0)
    {
        usage();
    }

done:
    return exCode;
}
