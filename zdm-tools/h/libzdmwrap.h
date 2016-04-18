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

#ifndef _ZONED_H_
#define _ZONED_H_

#define __packed                        __attribute__((packed))
#include <stdint.h>
#include <inttypes.h>

#include <time.h>
#include <uuid/uuid.h>

#include "utypes.h"
#include "list.h"
#include "hash.h"
#include "libcrc.h"
#include "libsort.h"
#include "malloc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef __u32 __le32;
typedef __u64 __le64;
typedef unsigned __bitwise__ gfp_t;


#define be32_to_cpu(x) be32toh(x)
#define cpu_to_be32(x) htobe32(x)
#define be64_to_cpu(x) be64toh(x)
#define cpu_to_be64(x) htobe64(x)

// #define GFP_ATOMIC	(__GFP_HIGH|__GFP_ATOMIC|__GFP_KSWAPD_RECLAIM)
// #define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
// #define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
// #define GFP_NOWAIT	(__GFP_KSWAPD_RECLAIM)
// #define GFP_NOIO	(__GFP_RECLAIM)
// #define GFP_NOFS	(__GFP_RECLAIM | __GFP_IO)

#define WARN_ON(x) if (x) printf("Warning at %d of %s\n", __LINE__, __FILE__);

#define GFP_ATOMIC	(0)
#define GFP_KERNEL	(0)
#define GFP_NOWAIT	(0)
#define GFP_NOIO	(0)
#define GFP_NOFS	(0)

/*
 * Request flags.  For use in the cmd_flags field of struct request, and in
 * bi_rw of struct bio.  Note that some flags are only valid in either one.
 */
enum rq_flag_bits {
	/* common flags */
	__REQ_FAILFAST_DEV,	/* no driver retries of device errors */
	__REQ_FAILFAST_TRANSPORT, /* no driver retries of transport errors */
	__REQ_FAILFAST_DRIVER,	/* no driver retries of driver errors */

	__REQ_SYNC,		/* request is sync (sync write or read) */
	__REQ_META,		/* metadata io request */
	__REQ_PRIO,		/* boost priority in cfq */
	__REQ_SECURE,		/* secure discard (used with REQ_OP_DISCARD) */

	__REQ_NOIDLE,		/* don't anticipate more IO after this one */
	__REQ_INTEGRITY,	/* I/O includes block integrity payload */
	__REQ_FUA,		/* forced unit access */
	__REQ_PREFLUSH,		/* request for cache flush */

	__REQ_REPORT_ZONES,	/* Zoned device: Report Zones */
	__REQ_OPEN_ZONE,	/* Zoned device: Open Zone */
	__REQ_CLOSE_ZONE,	/* Zoned device: Close Zone */

	/* bio only flags */
	__REQ_RAHEAD,		/* read ahead, can fail anytime */
	__REQ_THROTTLED,	/* This bio has already been subjected to
				 * throttling rules. Don't do it again. */

	/* request only flags */
	__REQ_SORTED,		/* elevator knows about this request */
	__REQ_SOFTBARRIER,	/* may not be passed by ioscheduler */
	__REQ_NOMERGE,		/* don't touch this for merging */
	__REQ_STARTED,		/* drive already may have started this one */
	__REQ_DONTPREP,		/* don't call prep for this one */
	__REQ_QUEUED,		/* uses queueing */
	__REQ_ELVPRIV,		/* elevator private data attached */
	__REQ_FAILED,		/* set if the request failed */
	__REQ_QUIET,		/* don't worry about errors */
	__REQ_PREEMPT,		/* set for "ide_preempt" requests and also
				   for requests for which the SCSI "quiesce"
				   state must be ignored. */
	__REQ_ALLOCED,		/* request came from our alloc pool */
	__REQ_COPY_USER,	/* contains copies of user pages */
	__REQ_FLUSH_SEQ,	/* request for flush sequence */
	__REQ_IO_STAT,		/* account I/O stat */
	__REQ_MIXED_MERGE,	/* merge of different types, fail separately */
	__REQ_PM,		/* runtime pm request */
	__REQ_HASHED,		/* on IO scheduler merge hash */
	__REQ_MQ_INFLIGHT,	/* track inflight for MQ */
	__REQ_NR_BITS,		/* stops here */
};

#define REQ_FAILFAST_DEV	(1ULL << __REQ_FAILFAST_DEV)
#define REQ_FAILFAST_TRANSPORT	(1ULL << __REQ_FAILFAST_TRANSPORT)
#define REQ_FAILFAST_DRIVER	(1ULL << __REQ_FAILFAST_DRIVER)
#define REQ_SYNC		(1ULL << __REQ_SYNC)
#define REQ_META		(1ULL << __REQ_META)
#define REQ_PRIO		(1ULL << __REQ_PRIO)
#define REQ_NOIDLE		(1ULL << __REQ_NOIDLE)
#define REQ_INTEGRITY		(1ULL << __REQ_INTEGRITY)

#define REQ_REPORT_ZONES	(1ULL << __REQ_REPORT_ZONES)
#define REQ_OPEN_ZONE		(1ULL << __REQ_OPEN_ZONE)
#define REQ_CLOSE_ZONE		(1ULL << __REQ_CLOSE_ZONE)
#define REQ_RESET_ZONE		(REQ_REPORT_ZONES)
#define REQ_ZONED_CMDS \
	(REQ_OPEN_ZONE | REQ_CLOSE_ZONE | REQ_RESET_ZONE | REQ_REPORT_ZONES)

#define REQ_FAILFAST_MASK \
	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)
#define REQ_COMMON_MASK \
	(REQ_FAILFAST_MASK | REQ_SYNC | REQ_META | REQ_PRIO | REQ_NOIDLE | \
	 REQ_PREFLUSH | REQ_FUA | REQ_SECURE | REQ_INTEGRITY | REQ_ZONED_CMDS)
#define REQ_CLONE_MASK		REQ_COMMON_MASK

/* This mask is used for both bio and request merge checking */
#define REQ_NOMERGE_FLAGS \
	(REQ_NOMERGE | REQ_STARTED | REQ_SOFTBARRIER | REQ_PREFLUSH | \
	 REQ_FUA | REQ_FLUSH_SEQ | REQ_ZONED_CMDS)

#define REQ_RAHEAD		(1ULL << __REQ_RAHEAD)
#define REQ_THROTTLED		(1ULL << __REQ_THROTTLED)

#define REQ_SORTED		(1ULL << __REQ_SORTED)
#define REQ_SOFTBARRIER		(1ULL << __REQ_SOFTBARRIER)
#define REQ_FUA			(1ULL << __REQ_FUA)
#define REQ_NOMERGE		(1ULL << __REQ_NOMERGE)
#define REQ_STARTED		(1ULL << __REQ_STARTED)
#define REQ_DONTPREP		(1ULL << __REQ_DONTPREP)
#define REQ_QUEUED		(1ULL << __REQ_QUEUED)
#define REQ_ELVPRIV		(1ULL << __REQ_ELVPRIV)
#define REQ_FAILED		(1ULL << __REQ_FAILED)
#define REQ_QUIET		(1ULL << __REQ_QUIET)
#define REQ_PREEMPT		(1ULL << __REQ_PREEMPT)
#define REQ_ALLOCED		(1ULL << __REQ_ALLOCED)
#define REQ_COPY_USER		(1ULL << __REQ_COPY_USER)
#define REQ_PREFLUSH		(1ULL << __REQ_PREFLUSH)
#define REQ_FLUSH_SEQ		(1ULL << __REQ_FLUSH_SEQ)
#define REQ_IO_STAT		(1ULL << __REQ_IO_STAT)
#define REQ_MIXED_MERGE		(1ULL << __REQ_MIXED_MERGE)
#define REQ_SECURE		(1ULL << __REQ_SECURE)
#define REQ_PM			(1ULL << __REQ_PM)
#define REQ_HASHED		(1ULL << __REQ_HASHED)
#define REQ_MQ_INFLIGHT		(1ULL << __REQ_MQ_INFLIGHT)

enum req_op {
	REQ_OP_READ,
	REQ_OP_WRITE,
	REQ_OP_DISCARD,		/* request to discard sectors */
	REQ_OP_WRITE_SAME,	/* write same block many times */
	REQ_OP_FLUSH,		/* request for cache flush */
};

int ilog2(u64 n);

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define BDEVNAME_SIZE 40


enum dm_io_mem_type {
	DM_IO_PAGE_LIST,/* Page list */
	DM_IO_BIO,      /* Bio vector */
	DM_IO_VMA,      /* Virtual memory area */
	DM_IO_KMEM,     /* Kernel memory */
};

struct dm_target {
	int             fd;
	const char * fname; /* usually a device: /dev/sdb[1-n] */
	void *     private;
	char *       error;
};

struct atomic_type {
	int counter;
};

struct work_struct {
	int  tag;
};

struct delayed_work {
	struct work_struct work;
};

struct mutex {
	int  inuse;
};

struct dm_target_callbacks {
	void * pfn;
};

struct inode {
	void * node;
};

struct timer_list {
	u64 ticks;
	u64 data;
};

typedef int spinlock_t;
typedef struct atomic_type atomic_t;
typedef u64 sector_t;
struct dm_kcopyd_client {
	int dummy;
};

struct dm_kcopyd_throttle {
	unsigned throttle;
	unsigned num_io_jobs;
	unsigned io_period;
	unsigned total_period;
	unsigned last_jiffies;
};

struct workqueue_struct {
	int      q_id;
	char * q_name;
};

static inline void del_timer_sync(struct timer_list * t)
{
	t->data = 0;
}

static inline void might_sleep(void) {}
static inline void msleep_interruptible(unsigned t) { (void) t; }
static void activity_timeout(unsigned long data);
static void bg_work_task(struct work_struct *work);

typedef void pfnTimeout(unsigned long data);
static void activity_timeout(unsigned long data);

static inline void setup_timer(struct timer_list * t, pfnTimeout * to_fn, unsigned long arg)
{
	(void)to_fn;
	(void)arg;
	t->data = 1;
}


#include "libzdm.h"

static inline char * _zdisk(struct zdm *znd)
{
	return znd->bdev_name;
}

int _debug(void);
void set_debug(int state);

#define Z_ERR(znd, fmt, arg...) \
	do { if (_debug() > 0) { \
		pr_err("dm-zdm(%s): " fmt "\n", _zdisk(znd), ## arg); \
	} } while (0)

#define Z_INFO(znd, fmt, arg...) \
	do { if (_debug() > 1) { \
		pr_err("dm-zdm(%s): " fmt "\n", _zdisk(znd), ## arg); \
	} } while (0)

#define Z_DBG(znd, fmt, arg...) \
	do { if (_debug() > 2) { \
		fprintf(stdout, "dm-zdm(%s): " fmt "\n", _zdisk(znd), ## arg); \
	} } while (0)


#define jiffies              ((u64)clock())
#define jiffies_64           ((u64)clock())
#define msecs_to_jiffies(v)  ( (v) * 1000)
#define time_before64(a, b)  ( (a) < (b) ? 1 : 0 )
#define time_after64(a, b)   ( (a) < (b) ? 0 : 1 )

#define Dspin_lock( p )
#define Dspin_unlock( p )
#define spin_lock(p)                 (void)p
#define spin_unlock(p)               (void)p
#define spin_lock_irqsave(p, f)      (void)p, (void)f
#define	spin_unlock_irqrestore(p, f) (void)p, (void)f

#define mzio_lock( p )   (void)p
#define mzio_unlock( p ) (void)p

static inline spin_trylock_irqsave(spinlock_t *lck, unsigned long flags)
{
	return 1;
}

static inline spin_trylock(spinlock_t *lck)
{
	return 1;
}

static inline void * vzalloc(size_t sz) { return calloc(sz, 1); }
static inline void * kzalloc(size_t sz, int f) {
	(void)f;
	return vzalloc(sz);
}
static inline void * kcalloc(size_t sz, size_t ct, int f)
{
        (void)f;
	return calloc(sz, ct);
}
static inline void * kmalloc(size_t sz, int f)
{
	return kzalloc(sz, f);
}

static inline void * vmalloc(size_t sz) { return calloc(sz, 1); }


static inline void vfree(void *p) { free(p); }
static inline void kfree(void *p) { free(p); }

static inline void free_pages(unsigned long p, int order)
{
	free( (void *)p );
	(void) order;
}

static inline void free_page(unsigned long p)
{
	free_pages(p, 0);
}

static inline void * __get_free_pages(int kind, int order)
{
	int count = 1 << order;
        void * pmem = calloc(Z_C4K, count);
        (void) kind;

        return pmem;
}

static inline void * get_zeroed_page(int kind)
{
	return __get_free_pages(kind, 0);
}


static inline le16 cpu_to_le16(u16 val) { return htole16(val); }
static inline u16 le16_to_cpu(le16 val) { return le16toh(val); }

static inline le32 cpu_to_le32(u32 val) { return htole32(val); }
static inline u32 le32_to_cpu(le32 val) { return le32toh(val); }

static inline le64 cpu_to_le64(u64 val) { return htole64(val); }
static inline u64 le64_to_cpu(le64 val) { return le64toh(val); }


#define pr_err(fmt, ...)    fprintf(stdout, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)  fprintf(stdout, fmt, ##__VA_ARGS__)
#define DMERR(fmt, ...)     fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define DMINFO(fmt, ...)    fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define DMWARN(fmt, ...)    fprintf(stdout, fmt "\n", ##__VA_ARGS__)

#define IS_ERR( v )         ((v) != 0 )
#define PTR_ERR( v )         ((v) != 0 )

#define BUG_ON( x )         do { if ( (x) ) { fprintf(stderr, "FAIL: %" PRIx64 " at %s.%d\n", (u64)(x), __FILE__, __LINE__ ); } } while (0)

#define CONFIG_BLK_ZONED 1
#define SINGLE_DEPTH_NESTING 1

#define dm_round_up(n, sz) (dm_div_up((n), (sz)) * (sz))

static inline void dm_io_client_destroy(void * p) { (void)p; }
static inline void dm_kcopyd_client_destroy(void * p) { (void)p; }
static inline void destroy_workqueue(void * p) { (void)p; }
static inline void dm_put_device(void * p, void * d) { (void)p; (void) d; }
static inline u64 i_size_read(void * p) { (void)p;  return 0; }


#define dm_div_up(n, sz) (((n) + (sz) - 1) / (sz))

static inline void spin_lock_init(spinlock_t * plck)  { *plck = 0; }

static inline int mutex_is_locked(struct mutex * plck)  { return plck->inuse; }
static inline void mutex_init(struct mutex * plck)  { plck->inuse = 0; }
static inline void mutex_lock(struct mutex * plck)    { plck->inuse++; }
static inline void mutex_lock_nested(struct mutex * plck, int class_id)
{
	(void) class_id;
	mutex_lock(plck);
}

static inline int mutex_trylock(struct mutex * plck) { return plck->inuse++; }


static inline void mutex_unlock(struct mutex * plck)  { plck->inuse--; }

static inline void atomic_inc(atomic_t * value) { value->counter++; }
static inline void atomic_dec(atomic_t * value) { value->counter--; }
static inline int atomic_read(atomic_t * value) { return value->counter; }


#define INIT_WORK(work, pfn_task)  (void)work, (void) pfn_task
#define INIT_DELAYED_WORK(work, pfn_task)  (void)work, (void) pfn_task

static inline struct delayed_work *to_delayed_work(struct work_struct *work)
{
        return container_of(work, struct delayed_work, work);
}

#define blkdev_issue_flush(a, b, c) *(c) = 0


static inline void * dm_io_client_create(void) { return calloc(1, 1); }
static inline void * dm_kcopyd_client_create(struct dm_kcopyd_throttle * throttle)
{
	return calloc(1, sizeof(struct dm_kcopyd_client));
}

static inline struct workqueue_struct * create_singlethread_workqueue(const char * name )
{
	struct workqueue_struct * wq = calloc(1, sizeof(*wq));
	wq->q_id++;
	wq->q_name = (char *)name;
	return wq;
};

static inline void generate_random_uuid(uuid_t out)
{
	uuid_generate(out);
}

static inline void set_bit(int bit_no, unsigned long * bits)
{
	*bits |= (1 << bit_no);
}

static inline void clear_bit(int bit_no, unsigned long * bits)
{
	*bits &= ~(1 << bit_no);
}

static inline int test_bit(int bit_no, unsigned long * bits)
{
	return (*bits & (1 << bit_no) ) ? -1 : 0;
}

static inline int test_and_set_bit(int bit_no, unsigned long * bits)
{
	int value = test_bit(bit_no, bits);
	set_bit(bit_no, bits);
	return value;
}

static inline int test_and_clear_bit(int bit_no, unsigned long * bits)
{
	int value = test_bit(bit_no, bits);
	clear_bit(bit_no, bits);
	return value;
}

static inline void queue_work(struct workqueue_struct * wq, struct work_struct * work)
{
	printf("do something: %d\n", __LINE__);
}

static inline int queue_delayed_work(struct workqueue_struct * wq,
				      struct delayed_work * work,
				      unsigned long delay)
{
	printf("do nothing: %d\n", __LINE__);
	return 0;
}

static inline int delayed_work_pending(struct delayed_work * work)
{
	return 0;
}
static inline void mod_delayed_work(struct workqueue_struct * wq,
				      struct delayed_work * work,
				      unsigned long delay)
{
}

static inline bool flush_delayed_work(struct delayed_work * work)
{
	return 1;
}

static inline void flush_workqueue(struct workqueue_struct * wq)
{
	printf("do nothing: %d\n", __LINE__);
}

static inline int work_pending(struct work_struct * work)
{
	return 0;
}


static inline void ssleep(int s)
{
	sleep(s);
}

static inline void msleep(int ms)
{
	usleep(1000 * ms);
}

#define ENOTSUPP	524

void * alloc_pages(gfp_t mask, int order);
void __free_pages(void *pgs, int order);
static inline void * page_address(void *pgs) { return pgs; }



u64 zdm_mcache_find_gen(struct zdm *mz, u64 base, int opt, u64 * out);
u64 zdm_mcache_greatest_gen(struct zdm * mz, int at, u64 *_a, u64 *_b);
int dmz_report_zones(struct zdm *znd, u64 z_id, void *pgs, size_t bufsz);
int zdm_reset_wp(struct zdm * znd, u64 z_id);
int zdm_close(struct zdm * znd, u64 z_id);
int zdm_open(struct zdm * znd, u64 z_id);
int zdm_zoned_inq(struct zdm *znd);
int zdm_zone_command(int fd, int command, uint64_t lba, int do_ata);

struct zdm * zdm_acquire(int fd, char * name);
struct zdm * zoned_alloc(int fd, char * name);

// void zdm_release(struct zdm *znd);
int zdm_read(struct zdm *znd, void * data, u64 lba, int count);
int zdm_write(struct zdm *znd, void * data, u64 lba, int count);

typedef void (*io_notify_fn)(unsigned long error, void *context);
int znd_async_io(struct zdm *znd, enum dm_io_mem_type dtype,
		 void *data, sector_t block, unsigned int nDMsect,
		 u8 bi_op, unsigned int bi_flags, int queue,
		 io_notify_fn callback, void *context);


int zdm_superblock(struct zdm * znd);
int zdm_superblock_check(struct zdm_superblock * sblock);
int zdm_meta_test(struct zdm * znd);
int zdm_do_something(struct zdm * znd);
int zdm_sb_test_flag(struct zdm_superblock * sb, int bit_no);
void zdm_sb_set_flag(struct zdm_superblock * sb, int bit_no);

int zdm_sync_crc_pages(struct zdm * znd);
int zdm_unused_phy(struct zdm * znd, u64 block_nr, u64 orig, gfp_t);
int zdm_unused_addr(struct zdm * znd, u64 dm_s);
u64 zdm_lookup(struct zdm * znd, struct map_addr * maddr);
int zdm_mapped_addmany(struct zdm *znd, u64 dm_s, u64 lba, u64,
			    gfp_t gfp);
int zdm_mapped_discard(struct zdm * znd, u64 dm_s, u64 lba, gfp_t gfp);
int zdm_mapped_to_list(struct zdm * megaz, u64 dm_s, u64 lba, gfp_t gfp);
int zdm_mapped_sync(struct zdm * znd);
int zdm_mapped_init(struct zdm * znd);
int zdm_write_if_dirty(struct zdm * znd, struct map_pg * oldest, int use_wq, int sync);
void zdm_release_table_pages(struct zdm * znd);

int zdm_sync(struct zdm * znd);
u32 zdm_sb_crc32(struct zdm_superblock *sblock);
u64 zdm_reserve_blocks(struct zdm * znd, u32 flags, u32 count, u32 *avail);
int zdm_move_to_map_tables(struct zdm * znd, struct map_cache * jrnl);
struct map_pg *zdm_get_map_entry(struct zdm *znd, u64 lba, gfp_t gfp);

// int zdm_free_unused(struct zdm * znd, int allowed_pages);
int zdm_mz_integrity_check(struct zdm * znd);
u16 zdm_crc16_le16(void const *data, size_t len);

u64 zdm_map_value(struct zdm * znd, u32 delta);
u64 zdm_map_encode(struct zdm * znd, u64 to_addr, u32 * value);

int zdm_zoned_wp_sync(struct zdm *znd, int reset_non_empty);

u64 zdm_lookup_cache(struct zdm *znd, u64 addr, int type);
u64 zdm_locate_sector(struct zdm *znd, u64 addr, gfp_t gfp);
int zdm_read_pg(struct zdm *znd, struct map_pg *pg, u64 lba48, gfp_t gfp, struct mpinfo *mpi);

#ifdef __cplusplus
}
#endif

#endif // _ZONED_H_

