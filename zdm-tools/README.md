
Device Mapper for Zoned based devices: ZDM for short.

User spaces for ZDM

zdmadm - Is the primary tool for creating and restoring ZDM instances.

Utilities:
 - zdm-report: Analogue to blkreport that also offers a --sat option.
 - zdm-zonecmd: Analogue to blkzonecmd that also offers a --sat option.
 
 * These utilities are useful for older kernel's and for working around SAS
   HBAs that do not have ZBC SAT support.

Debugging and analysis tools:
 zdmon - A Qt GUI tool to monitor ZDM activity (debugging)
 zdm-mlog - A debug tool used to monitor and log zdm state. Use zdmon to view.
 zdm-zones - Parsing zone state to terminal
 zdm-status - Parsing zone state to terminal (deprecated: see /proc/zdm_*/status)
 
Examples:
 - zdm-rawio: An example command for issuing direct raw I/O and sending zone
   open/close/reset.
