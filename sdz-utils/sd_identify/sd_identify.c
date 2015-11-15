#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/blk-zoned-ctrl.h>

// #define DEBUG 1

/* Used for Zone based SMR devices */
#define SCSI_IOCTL_INQUIRY		0x10000
#define SCSI_IOCTL_CLOSE_ZONE		0x10001
#define SCSI_IOCTL_FINISH_ZONE		0x10002
#define SCSI_IOCTL_OPEN_ZONE		0x10003
#define SCSI_IOCTL_RESET_WP		0x10004
#define SCSI_IOCTL_REPORT_ZONES		0x10005

#define Z_VPD_INFO_BYTE 8

#define DATA_OFFSET (offsetof(struct zoned_inquiry, result))

int do_identify_ioctl(const char * sddev, int do_ata)
{
	int rc = -4;

#ifdef DEBUG
	fprintf(stderr, "offsetof: %lu\n",  DATA_OFFSET );
#endif
	int fd = open(sddev, O_RDWR);
	if (fd != -1) {
		struct zoned_inquiry * inquire;
		int sz = 64;
		int bytes = sz + DATA_OFFSET;
		inquire = malloc(bytes);
		if (inquire) {
			inquire->evpd        = 1;
			inquire->pg_op       = 0xb1;
			inquire->mx_resp_len = sz;

			if (do_ata) {
				printf("using ata passthrough\n");
				inquire->evpd |= 0x80; // force ATA passthrough
			}

			fprintf(stderr, "ioctl: %s\n", sddev );
			rc = ioctl(fd, SCSI_IOCTL_INQUIRY, inquire);
			if (rc != -1) {
				int is_smr = 0;
				int is_ha  = 0;

#ifdef DEBUG
				fprintf(stderr, "rc -> %d, len %d\n", rc, inquire->mx_resp_len );
#endif // DEBUG

				if (inquire->mx_resp_len > Z_VPD_INFO_BYTE) {
					uint8_t flags = inquire->result[Z_VPD_INFO_BYTE] >> 4 & 0x03;

#ifdef DEBUG
					int x;
					for (x = 0; x < 10; x++) {
						fprintf(stdout, " %d: %02x\n", x , inquire->result[x] );
					}
#endif // DEBUG
					switch (flags) {
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
				}


				fprintf(stderr, "Identify: %s %s\n",
					is_smr ? "SMR" : "PMR",
					is_smr ? (is_ha  ? "Host AWARE"  : "Host or Drive Managed") : "" );
			} else {
				fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
			}
		}

		close(fd);
	} else {
		fprintf(stderr, "%s\n\n", strerror(errno));
	}

	return rc;
}

/*
 *
 */
int main(int argc, char *argv[])
{
	const char * sddev = "/dev/sdm";
	char * fname = NULL;
	int ii;
	int do_ata = 0;

	for (ii = 1; ii < argc; ii++) {
		if (0 == strcmp(argv[ii], "ata") ) {
			do_ata = 1;
		} else {
			if (!fname) {
				fname = argv[ii];
			}
		}
	}

	if (argc == 1 || !fname) {
		printf("Usage:\n");
		printf("  sd_identify [ata] <device>\n");
		printf("\nwhere ata will cause ATA ZAC commands to be used.\n");
		printf("\ndefault is to use SCSI ZBC commands\n");
		printf("  sd_identify ata /dev/sdn\n");
		printf("     identify HA or PMR using using ata commands\n");
		printf("  sd_identify /dev/sdn\n");
		printf("     identify HA or PMR using scsi commands\n");
		return 1;
	}

	return do_identify_ioctl(fname ? fname : sddev, do_ata);
}
