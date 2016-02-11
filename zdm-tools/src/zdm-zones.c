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

static volatile int clean_exit = 0;

/* Ctrl-\ handler */
void sigint_handler(int sig)
{
    clean_exit = 1;
    signal(sig, sigint_handler); /* re-install handler */
}

struct zone_value_entry
{
    u32 zone;
    u32 value;
};

int query_everything(int fd_wps, int fd_use, int skip)
{
    int ncolumns = 5;
    int cc;
    int rcode = 0;
    int zone_nr = 0;
    ssize_t in_wp, in_use;
    struct zone_value_entry wp;
    struct zone_value_entry use;
    off_t pos = 0ul;


    for (cc = 0; cc < ncolumns; cc++)
    {
        printf("entry fl.  wps .free -");
    }
    printf("\n");

    do
    {
        in_wp  = read(fd_wps, &wp, sizeof(wp));
        in_use = read(fd_use, &use, sizeof(use));

        if (in_wp == sizeof(wp) && in_use == sizeof(use))
        {
            zone_nr++;
            if (zone_nr < skip)
            {
                continue;
            }

            cc = zone_nr % ncolumns;
            printf("%4d: %2x %6x %5u ",
                   zone_nr,
                   wp.value >> 24,
                   wp.value & 0xFFFFFF,
                   use.value & 0xFFFFFF );

            if ((zone_nr % ncolumns) == 0)
            {
                printf("\n");
            }
        }
    }
    while (in_wp > 0 && in_use > 0);

    lseek(fd_wps,   pos, SEEK_SET);
    lseek(fd_use,   pos, SEEK_SET);
    printf("\n");

    return rcode;
}

int do_query_wps(const char *ppath, int skip, int period)
{
    int rcode = -1;
    char wps[128];
    char use[128];
    int fd_wps = -1;
    int fd_use = -1;

    snprintf(wps,   sizeof(wps  ), "%s/" PROC_WP, ppath);
    snprintf(use,   sizeof(use  ), "%s/" PROC_FREE, ppath);

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
        rcode = query_everything(fd_wps, fd_use, skip);
        if (rcode)
        {
            break;
        }
        if (period == 0)
        {
            break;
        }
        sleep(period);
        printf("\n");

    }

out:

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
           "    zdm-zones -p <repeat seconds> -m <skip_zones> proc_path ...\n"
           "Defaults are: -p 0 -m 0\n"
           "\n"
           "  Ex: zdm-zones /proc/zdm_sdf1\n" );
}


int main(int argc, char *argv[])
{
    int opt;
    int index;
    int megaz  = -1;
    int exCode = 0;
    int period = 0;

    /* Parse command line */
    errno = EINVAL; // Assume invalid Argument if we die
    while ((opt = getopt(argc, argv, "m:l:p:")) != -1)
    {
        switch (opt)
        {
        case 'm':
            megaz = atoi(optarg);
            break;
        case 'p':
            period = atoi(optarg);
            break;
        default:
            usage();
            break;
        } /* switch */
    } /* while */

    for (index = optind; index < argc; index++)
    {
        struct stat st_buf;

        if (0 == stat(argv[index], &st_buf) &&
                S_ISDIR(st_buf.st_mode))
        {

            /* Set up QUIT, INT, HUP and ABRT handlers */
            signal(SIGQUIT, sigint_handler);
            signal(SIGINT, sigint_handler);
            signal(SIGABRT, sigint_handler);
            signal(SIGHUP, sigint_handler);

            do_query_wps(argv[index], megaz, period);

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

    return exCode;
}


