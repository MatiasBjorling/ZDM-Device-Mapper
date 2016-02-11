ZDM Tools
=========

Tools for working with ZDM instances.


zdmadm is used to create, load, unload, and repair ZDM instances.

zdm-status is used to report detailed status of an active ZDM instance.
zdm-zones is used to report current zone wp's, and block usage
zdm-mlog is used to report zone information to a file for playback by zdmon
zdm-rawio is an example of performing raw I/O to a zoned device.

zdmon is a Qt QUI for viewing ZDM instances in real-time or saved with zdm-mlog.

```
zdmon usage:
      zdmon <proc path> | <log path>
   Ex:
      zdmon /proc/zdm_sdb1
```
