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
void sigint_handler(int sig) {
	clean_exit = 1;
	signal(sig, sigint_handler); /* re-install handler */
}

int query_everything(int m_fd, int m_count, FILE *wfp)
{
	int rcode = 0;
	int entry;
	size_t sz = sizeof(struct zdm_record) + (m_count * sizeof(struct megazone_info));
	struct zdm_record * m_data = calloc(1, sz);

	printf("how_big: header: %lu, data: %lu, total: %lu [m_count: %d]\n",
		sizeof(struct zdm_record),
		m_count * sizeof(struct megazone_info),
		sz,
		m_count );

	m_data->size = sz;
	m_data->mz_count = m_count;
	time(&m_data->at.tval);
        for (entry = 0; entry < m_count; entry++)
        {
            struct zdm_ioc_request * req_wps  = (struct zdm_ioc_request *)m_data->data[entry].wps;
            struct zdm_ioc_request * req_free = (struct zdm_ioc_request *)m_data->data[entry].free;
            union zdm_ioc_state * req_status  = (union zdm_ioc_state *)&m_data->data[entry].state;

            req_wps->result_size = sizeof(m_data->data[entry].wps);
            req_wps->megazone_nr = entry;
            req_free->result_size = sizeof(m_data->data[entry].free);
            req_free->megazone_nr = entry;
            req_status->request.result_size = sizeof(m_data->data[entry].state);
            req_status->request.megazone_nr = entry;

            rcode = ioctl(m_fd, ZDM_IOC_WPS, req_wps);
            if (rcode < 0)
            {
                fprintf(stderr, "ERROR: ZDM_IOC_WPS -> %d", rcode);
                break;
            }
            rcode = ioctl(m_fd, ZDM_IOC_FREE, req_free);
            if (rcode < 0)
            {
                fprintf(stderr, "ERROR: %d\n", rcode);
                break;
            }
            rcode = ioctl(m_fd, ZDM_IOC_STATUS, req_status);
            if (rcode < 0)
            {
                fprintf(stderr, "ERROR: ZDM_IOC_STATUS -> %d", rcode);
                break;
            }
        }
	m_data->crc32 = crc32c(~(u32) 0u, m_data, sz);

	fwrite(m_data, sz, 1, wfp);

	return rcode;
}


int do_query_wps(int fd, int period, FILE *wfp, int verbose)
{
	int rcode = ioctl(fd, ZDM_IOC_MZCOUNT, 0);
	if (rcode < 0) {
		fprintf(stderr, "ERROR: %d\n", rcode);
	} else {
		int mz_count = rcode;
                while (!clean_exit) {
			rcode = query_everything(fd, mz_count, wfp);
			if (rcode) {
				break;
			}
			sleep(period);
		}
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
	int loglevel;
	int exCode = 0;
	char *fname = NULL;

	/* Parse command line */
	errno = EINVAL; // Assume invalid Argument if we die
	while ((opt = getopt(argc, argv, "o:v:p:")) != -1) {
		switch (opt) {
		case 'o':
			fname = optarg;
			break;
                case 'p':
			period = atoi(optarg);
			break;
		case 'v':
			loglevel = atoi(optarg);
			break;
		default:
			usage();
			break;
		} /* switch */
	} /* while */

	if (!fname) {
		usage();
		printf(" ** -o <outfile> required to log data\n");
		exCode = 1;
		goto done;
	}

	for (index = optind; index < argc; index++) {
		int fd;

		fd = open(argv[index], O_RDWR);
		if (fd) {
			FILE *ofp = fopen(fname, "w");
			if (ofp) {

				/* Set up QUIT, INT, HUP and ABRT handlers */
				signal(SIGQUIT, sigint_handler);
				signal(SIGINT, sigint_handler);
				signal(SIGABRT, sigint_handler);
				signal(SIGHUP, sigint_handler);

				do_query_wps(fd, period, ofp, loglevel);
				fclose(ofp);
			}
			close(fd);
		} else {
			perror("Failed to open file");
			fprintf(stderr, "file: %s", argv[index]);
		}
	}

	(void) loglevel;

done:
	return exCode;
}


