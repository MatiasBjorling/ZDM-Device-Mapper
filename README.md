
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

  - Current Linux Kernel v4.1 to v.4.6-rc6 with ZDM patches
  - Recommended: Util Linux with ZDM patches
  - Recommended: sg3utils (1.41 or later)

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
      blkzonecmd --reset --zone -1 /dev/sdX
```
or
```
      blkzonecmd --reset --zone -1 --ata /dev/sdX
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
  - Normal kernel build with CONFIG_DM_ZDM
  - Additionally CONFIG_SCSI_ZBC and CONFIG_BLK_DEV_ZONED can be used for testing file systmes such as NILFS2 and F2FS.

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

  - Shaun Tancheff [shaun.tancheff@seagate.com](mailto:shaun.tancheff@seagate.com)

## ZDM Patches for other projects

  - CEPH: Enable ceph to created and used an OSD that used ZDM. NOTE: depends on blkid support from util-linux or util-linux-ng.
    * 0.94.5 [ceph patch](/patches/ceph)
  - util-linux -- Added: blkreport, blkzonecmd
    * 2.20.1 [For Ubuntu 14.04](/patches/util-linux/2.20.1)
    * 2.28-rc2 [For Debian sid development](/patches/util-linux/2.28-rc2)
  - util-linux-ng -- Missing: blkreport, blkzonecmd
    * 2.17.2 [For CentOS 6.7](/patches/util-linux-ng)

## ZDM Linux Kernel

  - Patches
    * v4.2.8 [ZDM r114 patches for linux v4.2.8](/patches/linux/v4.2.8+ZDM-r114)
    * v4.4 [ZDM r114 patches for linux v4.4](/patches/linux/v4.4+ZDM-r114)
    * v4.6 [ZDM r114 patches for linux v4.6-rc6](/patches/linux/v4.6+ZDM-r114)

## Observations and Known Issues in this release (#114)

  - Bug: mkfs segfaulting with 4.6 kernel on (some) embedded platforms.

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
    * Fix block ata zoned_command (Reset WP). Using wrong psuedo constant.
    * Fix a deadlock when gc_immediate is called from multiple threads.

  - ZDM #101
    * Added Stream Id to manage co-location of data with similar expected lifetimes.
    * Remove the fixed address segmentation (Megazone) scheme.
    * Added support for large conventional space in low LBAs and utilize the space for translation tables.

  - ZDM #103
    * Added read-ahead for LT entries.
    * Removed big io_mutex
    * Added discard extent cache
    * Enable discard support for md-raid to be enabled by ZDM block devices.
    * Added an experimental prototype hack to use PID as stream id.
    * Changed userspace ioctl to use procfs as ioctl are disabled in v4.4 and later kernels.

  - ZDM #104
    * Transition to using streamid patches from Jens Axobe.
    * Add ZAC->ZBC report zones little to big endian translation.
    * Add flags to struct bio to support ZBC commands: Report zones, reset, open and close zone(s).
    * Reworked flush handling to ensure metadata is durable before releasing.

  - ZDM #105
    * Bug Fixes
       * Memory leak during undrop.
       * Bio set not allocated.
       * GC queuing bugs .. wrap under on free zone count.
       * Reworked immediate/wait logic.
     * Update to v4.5 kernel.

  - ZDM #106
    * Bug Fix: Change lazy-drop timeout back to 15s

  - ZDM #107
    * Bug Fix: sync() NULL dereference bug fix

  - ZDM #108
    * Bug Fix: Rework BIO flags, fix zone off-by-1 error when partition is not zone aligned.

  - ZDM #109
    * Updated to v4.6-rc2
    * Re based on  separate operations from flags in the bio/request structs https://lkml.kernel.org/r/1456343292-14535-1-git-send-email-mchristi@redhat.com
    * Re based on libata: SATL update: https://lkml.kernel.org/r/1459763047-125551-1-git-send-email-hare@suse.de
    * Re based on libata: ZAC support: https://lkml.kernel.org/r/1459763271-125856-1-git-send-email-hare@suse.de
    * Re based on Update version of write stream ID patchset https://lkml.kernel.org/r/1457107853-8689-1-git-send-email-axboe@fb.com
    * Forced GC now starts 2 zones earlier and will always attempt a GC even when only 1 block is known to be stale (due to the deferred discard the stale counting can be far out of date.
    * Reduced memory used by arrays of map page pointers to a sparse array using a hash map. 8TB should now use ~12 MiB during first fill and ~25MiB during GC.
    * Initial implementation of metadata journal to CoW metadata changes between sync / cache flush events.
    * Changed ZDM superblock crc64 to crc32 as crc64 was removed from util-linux.
    * util-linux updated and required (blkreport and blkzonecmd).
    * zdm-tools updated to used blkreport and blkzonecmd IOCTLs as well as crc32 instead of crc64.

  - ZDM #110
    * Metadata journal write back is is expanded to include 2 journal passes before overwriting origin lba (every 3rd flush). This also includes a bug fix to force migration out of journal to free up journal space.
    * Added Hannes caching device mapper (dm-zoned) to being quantitative comparison with ZDM (dm-zdm).
    * Rename circus to accommodate both device mappers (dm-zoned -> dm-zdm then added dm-zoned).
    * Re-Sync zdmadm tools to match name changes and refreshed libzdm code base.

  - ZDM #112
    * Fix memory corruption due to over writting allocated space for WB Journal tracking
    * Updated to rc6 and removed pending bio split patch series.
    * Updated SCSI_ZBC/BLK_DEV_ZONED features to support current HA drives.
    * Added support for Write Same via SCT for SATA drives.

  - ZDM #114
    * Disabled WB journal path by default.
    * Expanded de-dupe to include any 4k aligned bio.
    * Updated to 4.6 kerenl.
