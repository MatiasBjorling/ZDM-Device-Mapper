
## Introduction

Device Mapper for Zoned based devices: ZDM for short.
This project aims to present a traditional block device for Host Aware and Host
Managed zoned block device drives. ZDM presents to the drive a workload that
conforms to the Host Aware intended use or Host Managed constraints.

## Architecture

ZDM implements a translation layer between a the tradition block interface
and a zoned block device (ZBD) supporting the ZBC or ZAC command set. ZDM
utilizes the available conventional space on a ZBD drive for storing the
translation layer mapping data. The device configuration should include a
minimum of 0.1% of the drive capacity  as conventional space, however 0.2%
is currently preferred and most tested. The current design assumes the
conventional space is located at the low LBA range of the partition or the
drive. The preferred layout is a typical GPT partitioned drive with a large
single partition [ex: parted -s /dev/sdX mkpart 1MiB -- -1].

It is recommended that ZDM be configured to allocate 1%, the default, of the
drive capacity as over provisioning used to manage the garbage collection of
stale blocks.

ZDM supports the BLKDISCARD IOCTL issued by blkdiscard(). It is recommended
that filesystems are mounted with the -o discard option.

The initial implementation focuses on drives with same sized zones of 256 MiB.
In future the support for other zones sizes will be added.
Internally all addressing is on 4-KiB (4k) boundaries. Currently a 4k PAGE_SIZE
is assumed. Architectures with 8k (or other) PAGE_SIZE values have not been
tested and are likely broken at the moment.

Drives of the more restrictive Host Managed device type are expected to work
provided the required amount of conventional space is available.

## Software Requirements

  - Current Linux Kernel v4.1 to v.4.4 with ZDM patches
  - Recommended: sg3utils (1.41 or later) or sd-tools.

## Caveat Emptor - Warning

  - ZDM software is a work in progress, subject to change without
    notice and is provided without warranty for any particular
    intended purpose beyond testing and reference. The ZDM may
    become unstable, resulting in system crash or hang, including
    the possibility of data loss.
    No responsibility for lost data or system damage is assumed by
    the creators or distributors of ZDM software.
    Users explicitly assume all risk associated with running
    the ZDM software.

## Current restrictions/assumptions

  - All zones are 256 MiB.
  - 4k page or block size.
  - Host Aware zoned block device, possibly with conventional zones.
  - Host Managed zoned block device with conventional zones.
  - Currently 256 MiB of RAM per drive is recommended.

## Userspace utilities
  - zdm-tools: zdmadm, zdm-status, zdm-zones, zdmon and others ...
  - zbc/zac tools (sd_* tools)

## Typical Setup

  - Reset all WPs on drive:
```
      sg_reset_wp --all /dev/sdX
```
or
```
      sd_reset_wp -1 /dev/sdX
```
or
```
      sd_reset_wp ata -1 /dev/sdX
```

  - Partition the drive to start the partition at a WP boundary.
```
      parted -s /dev/sdX mklabel gpt
      parted -s mkpart primary 1MiB -- -1
```

  - Place ZDM drive mapper on /dev/sdX
```
      zdmadm -F -c /dev/sdX1
```

  - Format:
```
      mkfs -t ext4 -E discard /dev/mapper/zdm_sdX1
```
or
```
      mkfs -t ext4 -b 4096 -g 32768 -G 32 \
        -E offset=0,num_backup_sb=0,packed_meta_blocks=1,discard \
        -O flex_bg,extent,sparse_super2 /dev/mapper/zdm_sdX1
```

  - Mounting the filesystem.
```
      mount -o discard /dev/mapper/zdm_sdX1 /mnt/zdm_sdX1
```

Building:
  - Normal kernel build with CONFIG_DM_ZONED and CONFIG_BLK_ZONED_CTRL enabled.

## Standards Versions Supported

ZAC/ZBC standards are still being developed. Changes to the command set and
command interface can be expected before the final public release.

## License

ZDM is distributed under the terms of GPL v2 or any later version.

ZDM and all and all utilities here in are distributed "as is," without technical
support, and WITHOUT ANY WARRANTY, without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Along with ZDM, you should
have received a copy of the GNU General Public License.
If not, please see http://www.gnu.org/licenses/.

## Contact and Bug Reports

  - Adrian Palmer [adrian.palmer@seagate.com](mailto:adrian.palmer@seagate.com)

## ZDM Patches for other projects

  - CEPH: Enable ceph to created and used an OSD that used ZDM. NOTE: depends on blkid support from util-linux or util-linux-ng.
    * 0.94.5 [ceph patch](/patches/ceph)
  - util-linux
    * 2.20.1 [2.20.1 in use by Ubuntu 14.04](/patches/util-linux/2.20.1)
    * 2.27 [2.27 development](/patches/util-linux/2.27)
  - util-linux-ng
    * 2.17.2 [2.17.2 in use by CentOS 6.7](/patches/util-linux-ng)

## ZDM Linux Kernel

  - Patches
    * v4.1 [ZDM r101 patches for linux v4.1](/patches/linux/v4.1+ZDM-r101)
    * v4.2 [ZDM r101 patches for linux v4.2](/patches/linux/v4.2+ZDM-r101)
    * v4.3 [ZDM r101 patches for linux v4.3](/patches/linux/v4.3+ZDM-r101)
    * v4.4 [ZDM r103 patches for linux v4.4](/patches/linux/v4.4+ZDM-r103)
  - Linux kernel with ZDM patches applied.
    * v4.1 https://seagit.okla.seagate.com/ZDM-Release/zdm-kernel/tree/v4.1+ZDM-r101
    * v4.2 https://seagit.okla.seagate.com/ZDM-Release/zdm-kernel/tree/v4.2+ZDM-r101
    * v4.3 https://seagit.okla.seagate.com/ZDM-Release/zdm-kernel/tree/v4.3+ZDM-r101
    * v4.4 https://seagit.okla.seagate.com/ZDM-Release/zdm-kernel/tree/v4.4+ZDM-r103

## Observations and Known Issues in this release (#103)

  - Discard cache support is incomplete and unbounded, theoretically it could use up a lot of memory.
     * In practice this is not happening.
     * Fix is planned for #105.
  - Bug: Discard on-disk format is not handled during for restore.
     * Fix is planned for #104.
  - Bug: Write back of metadata could cause inconsitency in case of sudden power loss between SYNC's
     * Fix is planned for #105.
  - Bug: A race condition exists causing corrupt metadata and -ENOSPC will be reported and halting writes.
     * Fixed for next release.
  - Bug: A race condition exists allowing ingress to overwhelm GC rate -ENOSPC will be reported and ingress halted.
     * Fixed in next release.

## Changes from Initial Release

  - ZDM #91
    * Kernel from v4.2 tag is pre-patched.
    * Added version number to track alpha/beta releases.
    * Numerous bug fixes and better stability.
    * Much improved GC / zone compaction handling.
    * Patch set is cleaner and better defined.
    * Patches provided to apply cleanly against 4.1 (stable), 4.2, and 4.3.

  - ZDM #96
    * Support for ZDM metadata on conventional space.
    * Modified queue limits to not confuse sgdisk.
    * Initial ceph support for ZDM OSD (ceph-disk prepare --zdm).
    * Block layer fixes for ZAC commands.
    * Move ZDM metadata initialization to zdmadm userspace.
    * Kernel from v4.2 tag is pre-patched.
    * More code cleanups: Endian (__le/__be), style and formatting, started adding inline documentation.
    * Numerous bug fixes and better stability.
    * More GC / zone compaction improvements.
    * Patches provided to apply cleanly against 4.1 (stable), 4.2, and 4.3.

  - ZDM #97
    * Fix block ata zoned_command (Reset WP). Using wrong psudo constant.
    * Fix a deadlock when gc_immediate is called from multple threads.

  - ZDM #101
    * Added Stream Id to manage co-location of data with similar expected lifetimes.
    * Remove the fixed address segmentation (Megazone) scheme.
    * Added support for large conventional space in low LBAs and utilize the space for translation tables.

  - ZDM #103
    * Added read-ahead for LT entries.
    * Removed big io_mutex
    * Added discard extent cache
    * Enabled discard support for md-raid to be enabled by ZDM block devices.
    * Added an experimental prototype hack to use PID as stream id.
    * Changed userspace ioctl to use procfs as ioctl are disabled in v4.4 and later kernels.
