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

#include <locale.h>


#include "utypes.h"
#include "libzdm.h"
#include "libzoned.h"

typedef struct zdm_ioc_status zdm_ioc_status_t;
typedef struct zdm_ioc_request zdm_ioc_request_t;

typedef union zdm_ioc
{
    zdm_ioc_request_t request;
    zdm_ioc_status_t  status;
} zdm_ioc_t;

void print_status(struct zdm_ioc_status * status, int sram)
{
    if (sram)
    {
        int ii;

        printf(" using %'" PRIu64
               " bytes of RAM\n", status->memstat );
        printf("   %'" PRIu64
               " 4k blocks\n", (status->memstat + 4095)/4096 );

        for (ii = 0; ii < 40; ii++)
        {
            if (status->bins[ii])
            {
                printf("  ..  %'d [in %d]\n",
                       status->bins[ii], ii );
            }
        }

    }


    printf("   b_used       %'" PRIu64 "\n", status->b_used );
    printf("   b_available  %'" PRIu64 "\n", status->b_available );
    printf("   b_discard    %'" PRIu64 "\n", status->b_discard );
    printf("   m_zones      %'" PRIu64 "\n", status->m_zones );
    printf("   mc_entries   %'" PRIu64 "\n", status->mc_entries );
    printf("   mlut_blocks  %'" PRIu64 "\n", status->mlut_blocks );
    printf("   crc_blocks   %'" PRIu64 "\n", status->crc_blocks );

}


int do_query_wps(int fd, int delay)
{
    int rcode = 0;

    ssize_t in;
    off_t pos = 0ul;
    struct zdm_ioc_status  status;

    do
    {
        in = read(fd, &status, sizeof(status));
        if (in  == sizeof(status))
        {
            print_status(&status, 1);
        }
        else
        {
            fprintf(stderr, "Read -> %ld\n", in );
        }
        if (delay == 0)
        {
            break;
        }
        sleep(delay);
        lseek(fd, pos, SEEK_SET);

    }
    while (1);

    return rcode;
}

void version(void)
{
}

void usage(void)
{
    printf("USAGE:\n"
           "    zdm-zones -d <repeat seconds> proc_path ...\n"
           "Defaults are: -d 0 [does not repeat]\n"
           "\n"
           "  Ex: zdm-status /proc/zdm_sdf1/stats.bin\n" );
}

int main(int argc, char *argv[])
{
    int opt;
    int index;
    int exCode = 0;
    int delay = 0;

    setlocale(LC_NUMERIC, "");

    /* Parse command line */
    errno = EINVAL;
    while ((opt = getopt(argc, argv, "Vd:")) != -1)
    {
        switch (opt)
        {
        case 'V':
            version();
            exit(exCode);
            break;
        case 'd':
            delay = strtol(optarg, NULL, 0);
            break;
        default:
            usage();
            exCode = 1;
            exit(exCode);
            break;
        } /* switch */
    } /* while */

    for (index = optind; index < argc; index++)
    {
        int fd;

        fd = open(argv[index], O_RDONLY);
        if (fd)
        {
            do_query_wps(fd, delay);
        }
        else
        {
            perror("Failed to open file");
            fprintf(stderr, "file: %s", argv[index]);
        }
    }

    if (argc == 1 || optind == 0)
    {
        usage();
    }

    return exCode;
}
