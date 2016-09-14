
Device Mapper for Zoned based devices: ZDM for short.

This project aims to present a traditional block device for Host Aware and
Host Managed drives.

Current restrictions/assumptions:
  - Zone size (256MiB).
  - 4k page / block size.
  - Host Aware, Conventional
  - Host Managed w/partition starting on a Conventional, or Preferred zone type.
  - Currently 1 GiB of RAM per drive is recommened.

Userspace utilities:
  - zdm-tools: zdmadm, zdm-status, zdm-zones ...
  - smrffs-tools (sd_* tools)

Typical Setup:
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

  - Partition the drive to start the partion at a WP boundary.
```
      parted /dev/sdX
      mklabel gpt
      mkpart primary 256MiB 7452GiB
```

  - Place ZDM drive mapper on /dev/sdX
```
      zdmadm -c /dev/sdX1
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
  - Normal kernel build with CONFIG_DM_ZDM enabled.

Architecture:

   ZDM treats a zoned device as a collection of 1024 zones [256GiB],
   referred to internally as 'megazones' as with zoned devices the last
   megazone may be less than 1024 zones in size. Each megazone reserves a
   minimum 8 zones for metadata and over-provisioning [less than 1% of a disk].

   Device trim [aka discard] support is enabled by default. It is recommeded
   to increase the over-provision ratio if discard is disabled.
   
   The initial implementation focuses on drives with same sized zones of
   256MB which is 65536 4k blocks. In future the zone size of 256MB will
   be relaxed to allow any size of zone as long as they are all the same.
   
   Internally all addressing is on 4k boundaries. Currently a 4k PAGE_SIZE is
   assumed. Architectures with 8k (or other) PAGE_SIZE values have not been
   tested and are likly broken at the moment.
   
   Host Managed drives should work if the zone type at the start of the partition
   is Conventional, or Preferred.
