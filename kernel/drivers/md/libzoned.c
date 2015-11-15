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

#define BUILD_NO		97

#define EXTRA_DEBUG		0

#define MZ_MEMPOOL_SZ		128
#define JOURNAL_MEMCACHE_BLOCKS	4
#define MEM_PURGE_MSECS		2500

/* acceptable 'free' count for MZ free levels */
#define GC_PRIO_DEFAULT		0xFF00
#define GC_PRIO_LOW		0x7FFF
#define GC_PRIO_HIGH		0x0400
#define GC_PRIO_CRIT		0x0040

/* When less than 20 zones are free use aggressive gc in the megazone */
#define GC_COMPACT_AGGRESSIVE	32

/*
 *  For performance tuning:
 *   Q? smaller strips give smoother performance
 *      a single drive I/O is 8 (or 32?) blocks?
 *   A? Does not seem to ...
 */
#define GC_MAX_STRIPE		256
#define REPORT_BUFFER		65 /* 65 -> min # pages for 4096 descriptors */
#define SYNC_IO_ORDER		2
#define SYNC_IO_SZ		((1 << SYNC_IO_ORDER) * PAGE_SIZE)

#define MZTEV_UNUSED		(cpu_to_le32(0xFFFFFFFFu))
#define MZTEV_NF		(cpu_to_le32(0xFFFFFFFEu))

#define Z_TABLE_MAGIC		0x123456787654321Eul
#define Z_KEY_SIG		0xFEDCBA987654321Ful

#define Z_CRC_4K		4096
#define Z_BLKBITS		16
#define Z_BLKSZ			(1 << Z_BLKBITS)
#define MAX_ZONES_PER_MZ	1024
#define Z_SMR_SZ_BYTES		(Z_C4K << Z_BLKBITS)

#define GC_READ			(1ul << 15)
#define BAD_ADDR		(~0ul)
#define MC_INVALID		(cpu_to_le64(BAD_ADDR))

/**
 * Convert an upper layer sector number to the locally managed
 * data sector number
 */
static int map_addr_to_zdm(struct zoned *, u64 sector_nr, struct map_addr *out);

/**
 * Locate meta data for locally managed sector.
 */
static int map_addr_calc(struct zoned *, u64 dm_s, struct map_addr *out);

/**
 * Megazone:
 */
static int megazone_init(struct zoned *znd);
static void megazone_destroy(struct zoned *znd);
static void megazone_flush_all(struct zoned *znd);
static void megazone_free_all(struct zoned *znd);
static int megazone_wp_sync(struct zoned *znd, int reset_non_empty);
static int write_if_dirty(struct megazone *, struct map_pg *, int use_wq);
static void gc_work_task(struct work_struct *work);
static void meta_work_task(struct work_struct *work);
static u64 mcache_greatest_gen(struct megazone *, int, u64 *, u64 *);
static u64 mcache_find_gen(struct megazone *, u64 base, int, u64 *out);
static int find_superblock(struct megazone *megaz, int use_wq, int do_init);
static int do_sync_metadata(struct megazone *megaz);
static int sync_mapped_pages(struct megazone *megaz);
static int sync_crc_pages(struct megazone *megaz);
static int unused_phy(struct megazone *megaz, u64 lba, u64 orig_s);
static struct io_4k_block *get_io_vcache(struct megazone *megaz);
static int put_io_vcache(struct megazone *megaz, struct io_4k_block *cache);
static int move_to_map_tables(struct megazone *megaz, struct map_cache *jrnl);
static int load_page(struct megazone *, struct map_pg *, u64 lba, int);
static struct map_pg *get_map_entry(struct megazone *, struct map_addr *, int);
static struct map_pg *sector_map_entry(struct megazone *, struct map_addr *);
static struct map_pg *reverse_map_entry(struct megazone *, struct map_addr *);
static u64 locate_sector(struct megazone *megaz, struct map_addr *maddr);
static int load_crc_meta_pg(struct megazone *, struct crc_pg *,
			    u64, __le16, int);
static struct map_pg *get_map_table_entry(struct megazone *megaz, u64 lba, int);
static int map_entry_page(struct megazone *, struct map_pg *, u64, int);
static int zoned_init(struct dm_target *ti, struct zoned *znd);
static int keep_active_pages(struct megazone *megaz, int allowed_pages);
static int zoned_create_disk(struct dm_target *ti, struct zoned *znd);
static sector_t jentry_value(struct map_sect_to_lba *e, bool is_block);
static u64 z_lookup_cache(struct megazone *megaz, struct map_addr *sm);
static u64 z_lookup(struct megazone *megaz, struct map_addr *sm);
static int z_mapped_add_one(struct megazone *megaz, u64 dm_s, u64 lba);
static int z_mapped_discard(struct megazone *megaz, u64 dm_s, u64 lba);
static int z_mapped_addmany(struct megazone *megaz, u64 dm_s, u64 lba, u64);
static int z_mapped_to_list(struct megazone *megaz, u64 dm_s, u64 lba);
static int z_mapped_sync(struct megazone *megaz);
static int z_mapped_init(struct megazone *megaz);
static u64 z_acquire(struct megazone *megaz, u32 flags, u32 nblks, u32 *nfound);
static __le32 sb_crc32(struct zdm_superblock *sblock);
static struct crc_pg *get_meta_pg_crc(struct megazone *, struct map_addr *,
				      int, int);
static int update_map_entry(struct megazone *, struct map_pg *,
			    struct map_addr *, u64, int);
static int read_block(struct dm_target *, enum dm_io_mem_type,
		      void *, u64, unsigned int, int);
static int write_block(struct dm_target *, enum dm_io_mem_type,
		       void *, u64, unsigned int, int);
static int zoned_init_disk(struct dm_target *ti, struct zoned *znd,
			   int create, int check, int force);

/**
 * 16 bit crc
 */
static inline u16 crc16_md(void const *data, size_t len)
{
	const u16 init = 0xFFFF;
	const u8 *p = data;

	return crc16(init, p, len);
}

/**
 * 16 bit CRC converted to little endian
 */
static inline __le16 crc_md_le16(void const *data, size_t len)
{
	u16 crc = crc16_md(data, len);

	return cpu_to_le16(crc);
}

/**
 * 32 bit CRC [NOTE: 32c is HW assisted on Intel]
 */
static inline u32 crcpg(void *data)
{
	return crc32c(~0u, data, Z_CRC_4K) ^ SUPERBLOCK_CSUM_XOR;
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline u64 le64_to_lba48(__le64 enc, u16 *flg)
{
	const u64 lba64 = le64_to_cpu(enc);

	if (flg)
		*flg = (lba64 >> 48) & 0xFFFF;

	return lba64 & Z_LOWER48;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline __le64 lba48_to_le64(u16 flags, u64 lba48)
{
	u64 high_bits = flags;

	return cpu_to_le64((high_bits << 48) | (lba48 & Z_LOWER48));
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int sb_test_flag(struct zdm_superblock *sb, int bit_no)
{
	u32 flags = le32_to_cpu(sb->flags);

	return (flags & (1 << bit_no)) ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline void sb_set_flag(struct zdm_superblock *sb, int bit_no)
{
	u32 flags = le32_to_cpu(sb->flags);

	flags |= (1 << bit_no);
	sb->flags = cpu_to_le32(flags);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int is_expired_msecs(u64 age, u32 msecs)
{
	u64 expire_at = age + msecs_to_jiffies(msecs);
	int expired = time_after64(jiffies_64, expire_at);

	return expired;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int is_expired(u64 age)
{
	return is_expired_msecs(age, MEM_PURGE_MSECS);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline u16 _calc_zone(struct zoned *znd, u64 addr)
{
	u16 znum = 0xffff;

	if (addr >= znd->data_lba)
		znum = ((addr - znd->data_lba) >> 16) & 0x3FF;

	return znum;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline struct map_pg *_pool_last(struct megazone *megaz)
{
	struct map_pg *expg = NULL;

	if (!list_empty(&megaz->smtpool)) {
		expg = list_last_entry(&megaz->smtpool, typeof(*expg), inpool);
		if (&expg->inpool == &megaz->smtpool)
			expg = NULL;
	}
	if (expg)
		atomic_inc(&expg->refcount);

	return expg;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_pg *_pool_prev(struct megazone *megaz, struct map_pg *expg)
{
	struct map_pg *aux = NULL;

	if (expg)
		aux = list_prev_entry(expg, inpool);
	if (aux)
		if (&aux->inpool == &megaz->smtpool)
			aux = NULL;
	if (aux)
		atomic_inc(&aux->refcount);

	return aux;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline void pool_add(struct megazone *megaz, struct map_pg *expg)
{
	if (expg) {
		spin_lock(&megaz->map_pool_lock);
		list_add(&expg->inpool, &megaz->smtpool);
		spin_unlock(&megaz->map_pool_lock);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * incore_hint() - Make expg first entry in pool list
 * @param megaz: Megazone
 * @param expg: active map_pg
 */
static inline void incore_hint(struct megazone *megaz, struct map_pg *expg)
{
	spin_lock(&megaz->map_pool_lock);
	if (megaz->smtpool.next != &expg->inpool)
		list_move(&expg->inpool, &megaz->smtpool);
	spin_unlock(&megaz->map_pool_lock);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int is_revmap(struct megazone *megaz, struct map_addr *maddr)
{
	int is_rtm = 0;
	u64 rbase = megaz->logical_map.r_base;
	u64 addr = maddr->dm_s;

	if ((rbase <= addr) && (addr < (rbase + Z_BLKSZ)))
		is_rtm = 1;

	return is_rtm;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int to_table_entry(struct zoned *znd, u64 lba, int is_to)
{
	int entry = -1;

	if (is_to && test_bit(ZF_POOL_FWD, &znd->flags))
		entry = (lba - znd->pool_lba) & 0xFFFF;
	else if (!is_to && test_bit(ZF_POOL_REV, &znd->flags))
		entry = (lba - znd->pool_lba) & 0xFFFF;
	else
		entry = lba & 0xFFFF;

	return entry;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void megazone_fill_lam(struct megazone *megaz, struct mzlam *lam)
{
	struct zoned *znd = megaz->znd;
	u64 ncrcs = (MZKY_NCRC * 2);
	u64 s_off = megaz->mega_nr << Z_BLKBITS;
	u64 r_off = (megaz->mega_nr + znd->mz_count) << Z_BLKBITS;
	u64 c_off = (megaz->mega_nr * ncrcs) + (znd->mz_count << (Z_BLKBITS+1));

	lam->mz_base = znd->data_lba + ((megaz->mega_nr * 1024) << Z_BLKBITS);
	lam->r_base  = lam->mz_base + (ZDM_RMAP_ZONE << Z_BLKBITS);
	lam->s_base  = lam->mz_base + (ZDM_SECTOR_MAP_ZNR  << Z_BLKBITS);
	lam->crc_low = lam->mz_base + (ZDM_CRC_STASH_ZNR   << Z_BLKBITS);

	if (test_bit(ZF_POOL_FWD, &znd->flags))
		lam->s_base = znd->pool_lba + s_off;
	if (test_bit(ZF_POOL_REV, &znd->flags))
		lam->r_base = znd->pool_lba + r_off;
	if (test_bit(ZF_POOL_CRCS, &znd->flags))
		lam->crc_low = znd->pool_lba + c_off;

	lam->crc_hi  =  lam->crc_low + ncrcs;
	lam->sk_low  =  lam->s_base  + (ZDM_SECTOR_MAP_ZNR * MZKY_NBLKS);
	lam->sk_high =  lam->sk_low  +  MZKY_NBLKS;

	if (test_bit(ZF_POOL_FWD, &znd->flags))
		lam->sk_low = lam->sk_high = 0ul;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int is_ready_for_gc(struct megazone *megaz, u16 z_id)
{
	if ((megaz->z_ptrs[z_id] & Z_WP_GC_BITS) == Z_WP_GC_READY)
		if (Z_BLKSZ == (megaz->z_ptrs[z_id] & Z_WP_VALUE_MASK))
			return 1;
	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 *  generic-ish n-way alloc/free
 *  Use kmalloc for small (< 4k) allocations.
 *  Use vmalloc for multi-page alloctions
 *  Except:
 *  Use multipage allocations for dm_io'd pages that a frequently hit.
 *
 *  NOTE: ALL allocations are zero'd before returning.
 *        alloc/free count is tracked for dynamic analysis.
 */

#define GET_PG_SYNC   0x010000

#define GET_ZPG       0x040000
#define GET_KM        0x080000
#define GET_VM        0x100000

#define MP_SIO   (GET_PG_SYNC | 23)

#define PG_01    (GET_ZPG |  1)
#define PG_02    (GET_ZPG |  2)
#define PG_05    (GET_ZPG |  5)
#define PG_06    (GET_ZPG |  6)
#define PG_08    (GET_ZPG |  8)
#define PG_09    (GET_ZPG |  9)
#define PG_10    (GET_ZPG | 10)
#define PG_11    (GET_ZPG | 11)
#define PG_13    (GET_ZPG | 13)
#define PG_17    (GET_ZPG | 17)
#define PG_27    (GET_ZPG | 27)

#define KM_00    (GET_KM  |  0)
#define KM_07    (GET_KM  |  7)
#define KM_14    (GET_KM  | 14)
#define KM_15    (GET_KM  | 15)
#define KM_16    (GET_KM  | 16)
#define KM_18    (GET_KM  | 18)
#define KM_19    (GET_KM  | 19)
#define KM_20    (GET_KM  | 20)
#define KM_25    (GET_KM  | 25)
#define KM_26    (GET_KM  | 26)
#define KM_28    (GET_KM  | 28)
#define KM_29    (GET_KM  | 29)
#define KM_30    (GET_KM  | 30)

#define VM_03    (GET_VM  |  3)
#define VM_04    (GET_VM  |  4)
#define VM_12    (GET_VM  | 12)
#define VM_21    (GET_VM  | 21)
#define VM_22    (GET_VM  | 22)

#define ZDM_FREE(z, _p, sz, id) \
	do { zdm_free((z), (_p), (sz), (id)); (_p) = NULL; } while (0)

#define ZDM_ALLOC(z, sz, id)       zdm_alloc((z), (sz), (id))
#define ZDM_CALLOC(z, n, sz, id)   zdm_calloc((z), (n), (sz), (id))

/**
 * Unified free by 'code':
 *
 * This (ugly) unified scheme helps to find leaks and monitor usage
 *   via ioctl tools.
 */
static void zdm_free(struct zoned *znd, void *p, size_t sz, u32 code)
{
	int id    = code & 0x00FFFF;
	int flag  = code & 0xFF0000;

	if (p) {
		if (znd) {
			spin_lock(&znd->stats_lock);
			if (sz > znd->memstat)
				Z_ERR(znd,
				      "Free'd more mem than allocated? %d", id);

			if (sz > znd->bins[id]) {
				Z_ERR(znd,
				      "Free'd more mem than allocated? %d", id);
				dump_stack();
			}
			znd->memstat -= sz;
			znd->bins[id] -= sz;
			spin_unlock(&znd->stats_lock);
		}

		switch (flag) {
		case GET_PG_SYNC:
			free_pages((unsigned long)p, SYNC_IO_ORDER);
			break;
		case GET_ZPG:
			free_page((unsigned long)p);
			break;
		case GET_KM:
			kfree(p);
			break;
		case GET_VM:
			vfree(p);
			break;
		default:
			Z_ERR(znd,
			      "zdm_free %p scheme %x not mapped.", p, code);
			break;
		}

	} else {
		Z_ERR(znd, "double zdm_free %p [%d]", p, id);
		dump_stack();
	}
}

/**
 * Unified alloc by 'code':
 *
 * There a few things (like dm_io) that seem to need pages and not just
 *   kmalloc'd memory.
 *
 * This (ugly) unified scheme helps to find leaks and monitor usage
 *   via ioctl tools.
 */
static void *zdm_alloc(struct zoned *znd, size_t sz, int code)
{
	void *pmem = NULL;
	int id    = code & 0x00FFFF;
	int flag  = code & 0xFF0000;

	might_sleep();

	switch (flag) {
	case GET_PG_SYNC:
		pmem = (void *)__get_free_pages(GFP_KERNEL, SYNC_IO_ORDER);
		if (pmem)
			memset(pmem, 0, sz);
		break;
	case GET_ZPG:
		pmem = (void *)get_zeroed_page(GFP_KERNEL);
		break;
	case GET_KM:
		pmem = kzalloc(sz, GFP_KERNEL);
		break;
	case GET_VM:
		pmem = vzalloc(sz);
		break;
	default:
		Z_ERR(znd, "zdm alloc scheme for %u unknown.", code);
		break;
	}
	if (!pmem) {
		Z_ERR(znd, "Out of memory. %d", id);
		dump_stack();
	}
	if (znd && pmem) {
		spin_lock(&znd->stats_lock);
		znd->memstat += sz;
		znd->bins[id] += sz;
		spin_unlock(&znd->stats_lock);
	}
	return pmem;
}

/**
 * calloc is just an zeroed memory array alloc.
 * all zdm_alloc schemes are for zeroed memory so no extra memset needed.
 */
static inline void *zdm_calloc(struct zoned *znd, size_t n, size_t sz, int code)
{
	return zdm_alloc(znd, sz * n, code);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct io_4k_block *get_io_vcache(struct megazone *megaz)
{
	struct zoned *znd = megaz->znd;
	struct io_4k_block *cache = NULL;
	int avail;

	might_sleep();

	for (avail = 0; avail < ARRAY_SIZE(znd->io_vcache); avail++) {
		if (!test_and_set_bit(avail, &znd->io_vcache_flags)) {
			cache = znd->io_vcache[avail];
			if (!cache)
				znd->io_vcache[avail] = cache =
					ZDM_CALLOC(znd, IO_VCACHE_PAGES,
						sizeof(*cache), VM_12);
			if (cache)
				break;
		}
	}
	return cache;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int put_io_vcache(struct megazone *megaz, struct io_4k_block *cache)
{
	struct zoned *znd = megaz->znd;
	int err = -ENOENT;
	int avail;

	if (cache) {
		for (avail = 0; avail < ARRAY_SIZE(znd->io_vcache); avail++) {
			if (cache == znd->io_vcache[avail]) {
				WARN_ON(!test_and_clear_bit(avail,
					&znd->io_vcache_flags));
				err = 0;
				break;
			}
		}
	}
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 *  translate a lookup table entry to a Sector #, or LBA
 */
static inline u64 map_value(struct megazone *megaz, __le32 delta)
{
	u64 mval = 0ul;

	if ((delta != MZTEV_UNUSED) && (delta != MZTEV_NF))
		mval = le32_to_cpu(delta);

	return mval;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 *  map_encode()
 *  Encode a Sector # or LBA to a lookup table entry value.
 */
static int map_encode(struct megazone *megaz, u64 to_addr, __le32 *value)
{
	int err = 0;

	*value = MZTEV_UNUSED;
	if (to_addr != BAD_ADDR)
		*value = cpu_to_le32((u32)to_addr);

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 *  Warn if a give LBA is not valid (Esp if beyond a WP)
 */
static inline int warn_bad_lba(struct megazone *megaz, u64 lba48)
{
#define FMT_ERR "LBA %" PRIx64 " is not valid: MZ# %u, off:%x wp:%x"
	int rcode = 0;
	u64 zone  = lba48 / Z_BLKSZ;
	u64 mz_nr = zone / 1024;

	if (lba48 < megaz->znd->data_lba)
		return rcode;

	if (mz_nr == megaz->mega_nr) {
		u32 wp_at;
		u32 off = lba48 & 0xFFFF;

		zone %= 1024;
		if (zone < megaz->z_count) {
			wp_at = megaz->z_ptrs[zone] & Z_WP_VALUE_MASK;
			if (off >= wp_at) {
				rcode = 1;
				Z_ERR(megaz->znd, FMT_ERR,
					lba48, megaz->mega_nr, off, wp_at);
				dump_stack();
			}
		} else {
			rcode = 1;
			Z_ERR(megaz->znd, "LBA is not valid - Z: %" PRIu64
				" count %u", zone, megaz->z_count);
		}
	} else {
		rcode = 1;
		Z_ERR(megaz->znd, "Lut %" PRIx64 " is not in MZ %u (got %"
			PRIu64 ")!!!", lba48, megaz->mega_nr, mz_nr);
	}

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 *  Teardown a zoned device mapper instance.
 */
static void zoned_destroy(struct zoned *znd)
{
	int purge;
	size_t sz = IO_VCACHE_PAGES * sizeof(struct io_4k_block *);

	if (znd->io_client)
		dm_io_client_destroy(znd->io_client);

	del_timer_sync(&znd->timer);

	if (znd->io_wq) {
		destroy_workqueue(znd->io_wq);
		znd->io_wq = NULL;
	}
	if (znd->meta_wq) {
		destroy_workqueue(znd->meta_wq);
		znd->meta_wq = NULL;
	}
	if (znd->gc_wq) {
		destroy_workqueue(znd->gc_wq);
		znd->gc_wq = NULL;
	}
	if (znd->bg_wq) {
		destroy_workqueue(znd->bg_wq);
		znd->bg_wq = NULL;
	}
	if (znd->dev) {
		dm_put_device(znd->ti, znd->dev);
		znd->dev = NULL;
	}
	for (purge = 0; purge < ARRAY_SIZE(znd->io_vcache); purge++) {
		if (znd->io_vcache[purge]) {
			if (test_and_clear_bit(purge, &znd->io_vcache_flags))
				Z_ERR(znd, "sync cache entry %d still in use!",
				      purge);
			ZDM_FREE(znd, znd->io_vcache[purge], sz, VM_12);
		}
	}
	if (znd->z_superblock)
		ZDM_FREE(znd, znd->z_superblock, Z_C4K, PG_05);
	if (znd->gc_io_buf)
		ZDM_FREE(znd, znd->gc_io_buf, GC_MAX_STRIPE * Z_C4K, VM_04);

	if (znd->gc_postmap.jdata) {
		size_t sz = Z_BLKSZ * sizeof(*znd->gc_postmap.jdata);

		ZDM_FREE(znd, znd->gc_postmap.jdata, sz, VM_03);
	}
	ZDM_FREE(NULL, znd, sizeof(*znd), KM_00);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * Initialize a zoned device mapper instance
 *
 * Setup the zone pointer table and do a one time calculation of some
 * basic limits
 */
static int zoned_init(struct dm_target *ti, struct zoned *znd)
{
	u64 size = i_size_read(get_bdev_bd_inode(znd));
	u64 bdev_nr_sect4k = size / Z_C4K;
	u64 data_zones = (bdev_nr_sect4k >> Z_BLKBITS) - znd->zdstart;
	u64 mzcount = dm_div_up(data_zones, MAX_ZONES_PER_MZ);
	u64 remainder = data_zones % MAX_ZONES_PER_MZ;
	u64 cache = MAX_CACHE_INCR * CACHE_COPIES * MAX_MZ_SUPP;
	u64 lba0zone = dm_div_up(znd->start_sect, Z_BLKSZ) << Z_BLKBITS;
	u32 mz_min = 0; /* cache */

	if (remainder > 0 && remainder < 8) {
		Z_ERR(znd, "Final MZ contains too few zones!");
		mzcount--;
	}

	znd->data_zones = data_zones;
	znd->mz_count = mzcount;
	/* lba0zone - lba of first full zone in disk addr space      */
	/* pool_lba - lba of first full zone in partition addr space */
	znd->pool_lba = lba0zone - znd->start_sect;
	if (znd->pool_lba < cache) {
		znd->pool_lba += Z_BLKSZ;
		mz_min++;
	}
	mz_min += mzcount;
	if (mz_min < znd->zdstart)
		set_bit(ZF_POOL_FWD, &znd->flags);
	mz_min += mzcount;
	if (mz_min < znd->zdstart)
		set_bit(ZF_POOL_REV, &znd->flags);
	mz_min++;
	if (mz_min < znd->zdstart) {
		Z_ERR(znd, "Conv space for CRCs: Seting ZF_POOL_CRCS");
		set_bit(ZF_POOL_CRCS, &znd->flags);
	}
	znd->data_lba = (znd->zdstart << Z_BLKBITS) - znd->start_sect;

	Z_INFO(znd, "ZDM #%u", BUILD_NO);

	Z_INFO(znd, "Start Sect: %" PRIx64
		    " Pool LBA %" PRIx64
		    " Data LBA %" PRIx64 " [Z:%" PRIx64 "]", znd->start_sect,
		    znd->pool_lba, znd->data_lba, znd->zdstart);

	Z_DBG(znd, "%s: size:%" PRIu64 " zones: %" PRIu64 ", megas %" PRIu64
		 ", resvd %" PRIu64 " %d", __func__, size,
		 znd->data_zones, znd->mz_count,
		 znd->mz_count * znd->mz_provision, __LINE__);

	spin_lock_init(&znd->gc_lock);
	spin_lock_init(&znd->stats_lock);

	mutex_init(&znd->gc_vcio_lock);

	znd->gc_postmap.jdata =
		ZDM_CALLOC(znd, Z_BLKSZ, sizeof(*znd->gc_postmap.jdata), VM_03);
	if (!znd->gc_postmap.jdata) {
		ti->error = "Could not create gc_postmap array";
		return -ENOMEM;
	}
	znd->gc_postmap.jsize = Z_BLKSZ;
	mutex_init(&znd->gc_postmap.cached_lock);

	znd->io_client = dm_io_client_create();
	if (!znd->io_client)
		return -ENOMEM;

	znd->meta_wq = create_singlethread_workqueue("znd_meta_wq");
	if (!znd->meta_wq) {
		ti->error = "couldn't start header metadata update thread";
		return -ENOMEM;
	}

	znd->gc_wq = create_singlethread_workqueue("znd_gc_wq");
	if (!znd->gc_wq) {
		ti->error = "couldn't start GC workqueue.";
		return -ENOMEM;
	}
	INIT_DELAYED_WORK(&znd->gc_work, gc_work_task);

	znd->bg_wq = create_singlethread_workqueue("znd_bg_wq");
	if (!znd->bg_wq) {
		ti->error = "couldn't start background workqueue.";
		return -ENOMEM;
	}
	INIT_WORK(&znd->bg_work, bg_work_task);

	setup_timer(&znd->timer, activity_timeout, (unsigned long)znd);

	znd->gc_io_buf = ZDM_CALLOC(znd, GC_MAX_STRIPE, Z_C4K, VM_04);
	if (!znd->gc_io_buf) {
		ti->error = "couldn't gc io buffer";
		return -ENOMEM;
	}

	znd->io_wq = create_singlethread_workqueue("kzoned_dm_io_wq");
	if (!znd->io_wq) {
		ti->error = "couldn't start header metadata update thread";
		return -ENOMEM;
	}
	znd->z_superblock = ZDM_ALLOC(znd, Z_C4K, PG_05);
	if (!znd->z_superblock) {
		ti->error = "couldn't allocate in-memory superblock";
		return -ENOMEM;
	}
	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * Metadata of zoned device mapper (for future backward compatibility)
 */
static int check_metadata_version(struct zdm_superblock *sblock)
{
	u32 metadata_version = le32_to_cpu(sblock->version);

	if (metadata_version < MIN_ZONED_VERSION
	    || metadata_version > MAX_ZONED_VERSION) {
		DMERR("Unsupported metadata version %u found.",
		      metadata_version);
		DMERR("Only versions between %u and %u supported.",
		      MIN_ZONED_VERSION, MAX_ZONED_VERSION);
		return -EINVAL;
	}

	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * CRC check for superblock.
 */
static __le32 sb_crc32(struct zdm_superblock *sblock)
{
	const __le32 was = sblock->csum;
	u32 crc;

	sblock->csum = 0;
	crc = crc32c(~(u32) 0u, sblock, sizeof(*sblock)) ^ SUPERBLOCK_CSUM_XOR;

	sblock->csum = was;
	return cpu_to_le32(crc);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * Check the superblock to see if it is valid and not corrupt.
 */
static int sb_check(struct zdm_superblock *sblock)
{
	__le32 csum_le;

	if (le64_to_cpu(sblock->magic) != SUPERBLOCK_MAGIC) {
		DMERR("sb_check failed: magic %" PRIx64 ": wanted %lx",
		      le64_to_cpu(sblock->magic), SUPERBLOCK_MAGIC);
		return -EILSEQ;
	}

	csum_le = sb_crc32(sblock);
	if (csum_le != sblock->csum) {
		DMERR("sb_check failed: csum %u: wanted %u",
		      csum_le, sblock->csum);
		return -EILSEQ;
	}

	return check_metadata_version(sblock);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void megazone_init_one_c(struct megazone *megaz, __le16 crc)
{
	int off;

	for (off = 0; off < ARRAY_SIZE(megaz->bmkeys->rtm_crc_pg); off++) {
		megaz->bmkeys->rtm_crc_pg[off] = crc;
		megaz->bmkeys->stm_crc_pg[off] = crc;
	}
	set_bit(DO_SYNC, &megaz->flags);
}

/*
 * Initialize the on-disk format of a zoned device mapper.
 */
static int zoned_create_disk(struct dm_target *ti, struct zoned *znd)
{
	const int reset_non_empty = 1;
	struct zdm_superblock *sblock = znd->super_block;
	void *data = NULL;
	int iter;
	int err;

	memset(sblock, 0, sizeof(*sblock));
	generate_random_uuid(sblock->uuid);
	sblock->magic = cpu_to_le64(SUPERBLOCK_MAGIC);
	sblock->version = cpu_to_le32(Z_VERSION);
	sblock->zdstart = cpu_to_le64(znd->zdstart);

	err = megazone_wp_sync(znd, reset_non_empty);
	if (err)
		goto out;

	data = ZDM_ALLOC(znd, Z_C4K, PG_06);
	if (!data) {
		err = -ENOMEM;
		goto out;
	}

	if (test_bit(ZF_POOL_CRCS, &znd->flags)) {
		__le16 *crcs = data;
		__le16 crc;

		memset(data, 0xFF, Z_CRC_4K);
		crc = crc_md_le16(data, Z_CRC_4K);

		/* make page of CRCs */
		for (iter = 0; iter < 2048; iter++)
			crcs[iter] = crc;

		/* CRC of a page of CRCs to init each MZone */
		crc = crc_md_le16(data, Z_CRC_4K);
		for (iter = 0; iter < znd->mz_count; iter++)
			megazone_init_one_c(&znd->z_mega[iter], crc);
	}

out:
	if (data)
		ZDM_FREE(znd, data, Z_C4K, PG_06);

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * Repair an otherwise good device mapper instance that was not cleanly removed.
 */
static int zoned_repair(struct zoned *znd)
{
	Z_INFO(znd, "Is Dirty .. zoned_repair consistency fixer TODO!!!.");
	return -ENOMEM;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * Locate the existing SB on disk and re-load or create the device-mapper
 * instance based on the existing disk state.
 */
static int zoned_init_disk(struct dm_target *ti, struct zoned *znd,
			   int create, int check, int force)
{
	struct mz_superkey *key_blk = znd->z_superblock;
	struct megazone *megaz = &znd->z_mega[0];
	int jinit = 1;
	int n4kblks = 1;
	int use_wq = 1;
	int rc = 0;
	u64 zdstart = znd->zdstart;

	memset(key_blk, 0, sizeof(*key_blk));

	if (create && force) {
		Z_ERR(znd, "Force Creating a clean instance.");
	} else if (find_superblock(megaz, use_wq, 1)) {
		u64 sb_lba = 0;
		u64 generation;

		Z_INFO(znd, "Found existing superblock");
		if (force) {
			if (zdstart != znd->zdstart) {
				Z_ERR(znd, "  (force) override first zone: %"
				      PRIu64  " with %" PRIu64 "",
				      znd->zdstart, zdstart);
				jinit = 0;
				znd->zdstart = zdstart;
			}
		}
		generation = mcache_greatest_gen(megaz, use_wq, &sb_lba, NULL);
		Z_DBG(znd, "Generation: %" PRIu64 " @ %" PRIx64,
			generation, sb_lba);

		rc = read_block(ti, DM_IO_KMEM, key_blk, sb_lba,
				n4kblks, use_wq);
		if (rc) {
			ti->error = "Superblock read error.";
			return rc;
		}
	}
	znd->super_block = &key_blk->sblock;
	rc = sb_check(znd->super_block);
	if (rc) {
		jinit = 0;
		if (create) {
			DMWARN("Check failed .. creating superblock.");
			zoned_create_disk(ti, znd);
			znd->super_block->nr_zones =
				cpu_to_le64(znd->data_zones);
			DMWARN("in-memory superblock created.");
			znd->is_empty = 1;
		} else {
			ti->error = "Superblock check failed.";
			return rc;
		}
	}

	if (sb_test_flag(znd->super_block, SB_DIRTY)) {
		int repair_check = zoned_repair(znd);

		if (!force) {
			/* if repair failed -- don't load from disk */
			if (repair_check)
				jinit = 0;
		} else if (repair_check && jinit) {
			Z_ERR(znd, "repair failed, force enabled loading ...");
		}
	}

	if (jinit) {
		u32 iter;

		Z_ERR(znd, "INIT: Reloading DM Zoned metadata from DISK");

		znd->zdstart = le64_to_cpu(znd->super_block->zdstart);
		for (iter = 0; iter < znd->mz_count; iter++) {
			struct megazone *megaz = &znd->z_mega[iter];

			set_bit(DO_JOURNAL_LOAD, &megaz->flags);
			queue_work(znd->meta_wq, &megaz->meta_work);
		}
		Z_ERR(znd, "Waiting for load to complete.");
		flush_workqueue(znd->meta_wq);
	}

	Z_ERR(znd, "ZONED: Build No %d marking superblock dirty.", BUILD_NO);

	/* write the 'dirty' flag back to disk. */
	sb_set_flag(znd->super_block, SB_DIRTY);
	znd->super_block->csum = sb_crc32(znd->super_block);

	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline sector_t jentry_value(struct map_sect_to_lba *e, bool is_block)
{
	sector_t value = 0;

	if (is_block)
		value = le64_to_lba48(e->physical, NULL);
	else
		value = le64_to_lba48(e->logical, NULL);

	return value;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int compare_logical_sectors(const void *x1, const void *x2)
{
	const struct map_sect_to_lba *r1 = x1;
	const struct map_sect_to_lba *r2 = x2;
	const u64 v1 = le64_to_lba48(r1->logical, NULL);
	const u64 v2 = le64_to_lba48(r2->logical, NULL);

	return (v1 < v2) ? -1 : ((v1 > v2) ? 1 : 0);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int __find_sector_entry_chunk(struct map_sect_to_lba *data,
				     s32 count, sector_t find, bool is_block)
{
	int at = -1;
	s32 first = 0;
	s32 last = count - 1;
	s32 middle = (first + last) / 2;

	while ((-1 == at) && (first <= last)) {
		sector_t logical = BAD_ADDR;

		if (count > middle && middle >= 0)
			logical = jentry_value(&data[middle], is_block);

		if (logical < find)
			first = middle + 1;
		else if (logical > find)
			last = middle - 1;
		else
			at = middle;

		middle = (first + last) / 2;
	}
	return at;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u64 z_lookup_key_range(struct megazone *megaz, struct map_addr *maddr)
{
	u64 found = 0ul;
	struct mzlam *lam = &megaz->logical_map;

	if ((lam->sk_low <= maddr->dm_s) && (maddr->dm_s < lam->sk_high)) {
		int off = maddr->dm_s - lam->sk_low;

		mutex_lock(&megaz->mapkey_lock);
		found = le64_to_cpu(megaz->bmkeys->stm_keys[off]);
		mutex_unlock(&megaz->mapkey_lock);
	}
	return found;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_mapped_add_one(struct megazone *megaz, u64 dm_s, u64 lba)
{
	int err = 0;
	struct mzlam *lam = &megaz->logical_map;

	if (dm_s < megaz->znd->data_lba)
		return err;

	/*
	 * location of the SLT key sectors need to be
	 * stashed into the sector lookup table block map
	 * Does dm_s point in the sector lookup table block map
	 */
	if ((lam->sk_low <= dm_s) && (dm_s < lam->sk_high)) {
		int off = dm_s - lam->sk_low;

		mutex_lock(&megaz->mapkey_lock);
		megaz->bmkeys->stm_keys[off] = cpu_to_le64(lba);
		mutex_unlock(&megaz->mapkey_lock);
	}
	do {
		err = z_mapped_to_list(megaz, dm_s, lba);
	} while (-EBUSY == err);

	if (lba) {
		u16 zone = _calc_zone(megaz->znd, lba);

		if (zone < megaz->z_count) {
			megaz->z_commit[zone]++;
			if (megaz->z_commit[zone] == Z_BLKSZ) {
				mutex_lock(&megaz->zp_lock);
				megaz->z_ptrs[zone] |= Z_WP_GC_READY;
				mutex_unlock(&megaz->zp_lock);
			}
		}
	}

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_mapped_discard(struct megazone *megaz, u64 dm_s, u64 lba)
{
	int err;

	do {
		err = z_mapped_to_list(megaz, dm_s, 0ul);
	} while (-EBUSY == err);

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_cache *jalloc(struct zoned *znd)
{
	struct map_cache *jrnl_first;

	jrnl_first = ZDM_ALLOC(znd, sizeof(*jrnl_first), KM_07);
	if (jrnl_first) {
		mutex_init(&jrnl_first->cached_lock);
		jrnl_first->jcount = 0;
		jrnl_first->jsorted = 0;
		jrnl_first->jdata = ZDM_CALLOC(znd, Z_UNSORTED,
			sizeof(*jrnl_first->jdata), PG_08);

		if (jrnl_first->jdata) {
			u64 logical = Z_LOWER48;
			u64 physical = Z_LOWER48;

			jrnl_first->jdata[0].logical = cpu_to_le64(logical);
			jrnl_first->jdata[0].physical = cpu_to_le64(physical);
			jrnl_first->jsize = Z_UNSORTED - 1;

		} else {
			Z_ERR(znd, "%s: in memory journal is out of space.",
			      __func__);
			ZDM_FREE(znd, jrnl_first, sizeof(*jrnl_first), KM_07);
			jrnl_first = NULL;
		}
	}
	return jrnl_first;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_cache *jfirst_entry(struct megazone *megaz)
{
	unsigned long flags;
	struct list_head *_jhead;
	struct map_cache *jrnl;

	spin_lock_irqsave(&megaz->jlock, flags);
	_jhead = &(megaz->jlist);
	jrnl = list_first_entry_or_null(_jhead, typeof(*jrnl), jlist);
	if (jrnl && (&jrnl->jlist != _jhead))
		atomic_inc(&jrnl->refcount);
	else
		jrnl = NULL;

	spin_unlock_irqrestore(&megaz->jlock, flags);

	return jrnl;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline void jlist_add(struct megazone *megaz, struct map_cache *jrnl)
{
	unsigned long flags;
	struct list_head *_jhead;

	spin_lock_irqsave(&megaz->jlock, flags);
	_jhead = &(megaz->jlist);
	list_add(&(jrnl->jlist), _jhead);
	spin_unlock_irqrestore(&megaz->jlock, flags);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline void jderef(struct megazone *megaz, struct map_cache *jrnl)
{
	unsigned long flags;

	spin_lock_irqsave(&megaz->jlock, flags);
	atomic_dec(&jrnl->refcount);
	spin_unlock_irqrestore(&megaz->jlock, flags);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline struct map_cache *jnext_entry(struct megazone *megaz,
					    struct map_cache *jrnl)
{
	unsigned long flags;
	struct list_head *_jhead;
	struct map_cache *next;

	spin_lock_irqsave(&megaz->jlock, flags);
	_jhead = &(megaz->jlist);
	next = list_next_entry(jrnl, jlist);
	if (next && (&next->jlist != _jhead))
		atomic_inc(&next->refcount);
	else
		next = NULL;
	atomic_dec(&jrnl->refcount);
	spin_unlock_irqrestore(&megaz->jlock, flags);

	return next;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void jcache_sort_no_lock(struct map_cache *jrnl)
{
	if (jrnl->jsorted < jrnl->jcount) {
		sort(&jrnl->jdata[1], jrnl->jcount,
		     sizeof(*jrnl->jdata),
		     compare_logical_sectors, NULL);
		jrnl->jsorted = jrnl->jcount;
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void jcache_sort_locked(struct map_cache *jrnl)
{
	if (jrnl->jsorted < jrnl->jcount) {
		mutex_lock_nested(&jrnl->cached_lock, SINGLE_DEPTH_NESTING);
		jcache_sort_no_lock(jrnl);
		mutex_unlock(&jrnl->cached_lock);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int jlinear_find(struct map_cache *jrnl, u64 dm_s)
{
	int at = -1;
	int jentry;

	for (jentry = jrnl->jcount; jentry > 0; jentry--) {
		u64 logi = le64_to_lba48(jrnl->jdata[jentry].logical, NULL);

		if (logi == dm_s) {
			at = jentry - 1;
			goto out;
		}
	}

out:
	return at;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u64 z_lookup_cache(struct megazone *megaz, struct map_addr *maddr)
{
	struct map_cache *jrnl;
	u64 found = 0ul;

	jrnl = jfirst_entry(megaz);
	while (jrnl) {
		int at;

		if (jrnl->no_sort_flag) {
			at = jlinear_find(jrnl, maddr->dm_s);
		} else {
			/* Possible dead-lock if unsorted: */
			jcache_sort_locked(jrnl);
			at = __find_sector_entry_chunk(
				&jrnl->jdata[1], jrnl->jcount, maddr->dm_s, 0);
		}
		if (at != -1) {
			struct map_sect_to_lba *data = &jrnl->jdata[at + 1];

			found = le64_to_lba48(data->physical, NULL);
		}
		if (found) {
			jderef(megaz, jrnl);
			goto out;
		}

		jrnl = jnext_entry(megaz, jrnl);
	}
out:
	return found;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int lba_in_zone(struct megazone *megaz, struct map_cache *jrnl, u16 zone)
{
	int jentry;

	if (zone >= MAX_ZONES_PER_MZ)
		goto out;

	for (jentry = jrnl->jcount; jentry > 0; jentry--) {
		u64 lba = le64_to_lba48(jrnl->jdata[jentry].physical, NULL);

		if (lba && _calc_zone(megaz->znd, lba) == zone)
			return 1;
	}
out:
	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int gc_verify_cache(struct megazone *megaz, u16 zone)
{
	struct map_cache *jrnl = NULL;
	int err = 0;

	jrnl = jfirst_entry(megaz);
	while (jrnl) {
		mutex_lock(&jrnl->cached_lock);
		if (lba_in_zone(megaz, jrnl, zone)) {
			Z_ERR(megaz->znd,
			      "GC: **ERR** %x LBA in cache <= Corrupt",
			      zone);
			err = 1;
			megaz->meta_result = -ENOSPC;
		}
		mutex_unlock(&jrnl->cached_lock);
		jrnl = jnext_entry(megaz, jrnl);
	}
	return err;
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int _cached_to_tables(struct megazone *megaz, u16 zone)
{
	struct map_cache *jrnl = NULL;
	int err = 0;

	jrnl = jfirst_entry(megaz);
	while (jrnl) {
		int try_free = 0;
		struct map_cache *jskip;

		mutex_lock(&jrnl->cached_lock);
		if (jrnl->jcount == jrnl->jsize) {
			jcache_sort_no_lock(jrnl);
			err = move_to_map_tables(megaz, jrnl);
			if (!err && (jrnl->jcount == 0))
				try_free = 1;
		} else {
			if (lba_in_zone(megaz, jrnl, zone)) {
				Z_ERR(megaz->znd,
					"Moving %d Runts because z: %u",
					jrnl->jcount, zone);

				jcache_sort_no_lock(jrnl);
				err = move_to_map_tables(megaz, jrnl);
			}
		}
		mutex_unlock(&jrnl->cached_lock);

		if (err) {
			jderef(megaz, jrnl);
			Z_ERR(megaz->znd, "%s: Sector map failed.", __func__);
			goto out;
		}

		jskip = jnext_entry(megaz, jrnl);
		if (try_free) {
			if (!jrnl->refcount.counter) {
				unsigned long flags;
				size_t sz = Z_UNSORTED * sizeof(*jrnl->jdata);

				spin_lock_irqsave(&megaz->jlock, flags);
				list_del(&jrnl->jlist);
				spin_unlock_irqrestore(&megaz->jlock, flags);

				ZDM_FREE(megaz->znd, jrnl->jdata, sz, PG_08);
				ZDM_FREE(megaz->znd, jrnl,
					 sizeof(*jrnl), KM_07);
				jrnl = NULL;

				megaz->mc_entries--;
			} else {
				Z_ERR(megaz->znd,
					"Journal still in use. Not freed");
			}
		}
		jrnl = jskip;
	}
out:
	return err;
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_flush_bdev(struct zoned *znd)
{
	int err;
	sector_t bi_done;

	err = blkdev_issue_flush(znd->dev->bdev, GFP_KERNEL, &bi_done);
	if (err)
		Z_ERR(znd, "%s: flush failing sector %lu!", __func__, bi_done);

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int _megaz_sync_to_disk(struct megazone *megaz)
{
	int err = 0;

	err = do_sync_metadata(megaz);
	if (err) {
		Z_ERR(megaz->znd, "Uh oh: do_sync_metadata -> %d", err);
		goto out;
	}

	err = z_mapped_sync(megaz);
	if (err) {
		Z_ERR(megaz->znd, "Uh oh. z_mapped_sync -> %d", err);
		goto out;
	}

out:
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int do_init_from_journal(struct megazone *megaz)
{
	int err = 0;

	if (test_and_clear_bit(DO_JOURNAL_LOAD, &megaz->flags)) {
		mutex_lock(&megaz->mz_io_mutex);
		err = z_mapped_init(megaz);
		mutex_unlock(&megaz->mz_io_mutex);
	}
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int mdtest(struct megazone *megaz, struct map_addr *maddr, __le32 *data,
		  int z_id, int is_to, int use_wq, u32 pg_no, __le16 crc_pgv)
{
	int rcode = 0;
	int crc_okay = 0;
	u32 unused = 0;
	int off;
	u64 lba = z_lookup(megaz, maddr);

	if (lba) {
		const int count = 1;
		int err;
		__le16 crc;

		err = read_block(megaz->znd->ti, DM_IO_KMEM, data, lba,
				 count, use_wq);
		if (err) {
			Z_ERR(megaz->znd, "Integrity ERR: %" PRIx64
			      " on disk %" PRIx64 " read err %d",
			      maddr->dm_s, lba, err);
			rcode = err;
			goto out;
		}
		crc = crc_md_le16(data, Z_CRC_4K);

		if (crc == crc_pgv) {
			crc_okay = 1;
		} else {
			Z_ERR(megaz->znd,
			      "Integrity ERR: %04x != %04x at lba %"
			      PRIx64 " lmap %" PRIx64,
			      crc, crc_pgv, lba, maddr->dm_s);
			rcode = -EIO;
			goto out;
		}
	} else {
		Z_ERR(megaz->znd,
		      "MZ# %u LBA Not found for: 0x%" PRIx64 " is_to %d",
		      megaz->mega_nr, maddr->dm_s, is_to);
	}

	if (is_to || (!crc_okay))
		goto out;

	for (off = 0; off < 1024; off++) {
		__le32 enc = data[off];
		u64 ORlba = (megaz->mega_nr * Z_BLKSZ * 1024)
			  + (z_id * Z_BLKSZ) + pg_no + off;

		if (enc == MZTEV_UNUSED) {
			unused++;
		} else {
			u64 dm_s = map_value(megaz, enc);

			if (dm_s < megaz->znd->nr_blocks) {
				struct map_pg *Smap;
				struct map_addr Saddr;

				map_addr_calc(megaz->znd, dm_s, &Saddr);
				Smap = sector_map_entry(megaz, &Saddr);
				if (Smap && Smap->mdata)
					Z_DBG(megaz->znd,
					      "lba: %" PRIx64 " okay",
					      ORlba);
				else
					Z_ERR(megaz->znd,
					      "lba: %" PRIx64" ERROR",
					      ORlba);

			} else {
				Z_ERR(megaz->znd,
				      "Invalid rmap entry: %x.",
				      le32_to_cpu(enc));
			}
		}
	}
	rcode = unused;

out:
	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int meta_integrity_test_table(struct megazone *megaz, u64 base,
				     __le32 *data)
{
	int rc = 0;
	u64 entry;
	u32 z_used = Z_BLKSZ;

	for (entry = base; entry < base + Z_BLKSZ; entry++) {
		const int use_wq = 0;
		int z_id = entry / 64;
		int is_to;
		int crce;
		__le16 crc_pgv;
		struct map_addr maddr;
		struct crc_pg *pblock;

		map_addr_calc(megaz->znd, entry, &maddr);
		crce = maddr.crc % 2048;
		is_to = !is_revmap(megaz, &maddr);
		pblock = get_meta_pg_crc(megaz, &maddr, is_to, use_wq);
		if (!pblock) {
			Z_ERR(megaz->znd, "%s: Out of space for metadata?",
				__func__);
			return -ENOSPC;
		}

		if (!is_to && (entry % 64) == 0)
			z_used = Z_BLKSZ;

		atomic_inc(&pblock->refcount);

		mutex_lock(&pblock->lock_pg);
		crc_pgv = pblock->cdata[crce];
		mutex_unlock(&pblock->lock_pg);

		if (crc_pgv) {
			u32 pg_no = is_to ? 0 : ((entry % 64) * 1024);
			int rcode;

			rcode = mdtest(megaz, &maddr, data, z_id, is_to, use_wq,
				       pg_no, crc_pgv);

			if (rcode < 0)
				rc = rcode;
			else
				z_used -= rcode;
		}

		atomic_dec(&pblock->refcount);

		if (!is_to && (entry % 64) == 63) {
			if ((megaz->z_ptrs[z_id] & Z_WP_FLAGS_MASK) == 0)
				megaz->zfree_count[z_id] = Z_BLKSZ - z_used;
		}
	}
	return rc;
}

static int meta_integrity_test(struct megazone *megaz)
{
	int rc = 0;
	__le32 *data = ZDM_ALLOC(megaz->znd, Z_C4K, PG_09);

	if (!data)
		return -ENOMEM;

	rc = meta_integrity_test_table(megaz, megaz->logical_map.r_base, data);
	if (rc)
		goto out;

	rc = meta_integrity_test_table(megaz, megaz->logical_map.s_base, data);

out:
	ZDM_FREE(megaz->znd, data, Z_C4K, PG_09);
	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int do_meta_check(struct megazone *megaz)
{
	int err = 0;

	if (test_and_clear_bit(DO_META_CHECK, &megaz->flags)) {
		mutex_lock(&megaz->mz_io_mutex);
		err = meta_integrity_test(megaz);
		mutex_unlock(&megaz->mz_io_mutex);
	}
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int do_journal_to_table(struct megazone *megaz)
{
	int err = 0;

	if (test_and_clear_bit(DO_JOURNAL_MOVE, &megaz->flags)) {
		mutex_lock(&megaz->mz_io_mutex);
		err = _cached_to_tables(megaz, MAX_ZONES_PER_MZ);
		mutex_unlock(&megaz->mz_io_mutex);
	}

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int do_free_pages(struct megazone *megaz)
{
	int err = 0;

	if (test_and_clear_bit(DO_MEMPOOL, &megaz->flags)) {
		int pool_size = MZ_MEMPOOL_SZ * 4;

		if (is_expired_msecs(megaz->age, MEM_PURGE_MSECS))
			pool_size = MZ_MEMPOOL_SZ;

		if (is_expired_msecs(megaz->age, 5000))
			pool_size = 3;

		mutex_lock(&megaz->mz_io_mutex);
		err = keep_active_pages(megaz, pool_size);
		mutex_unlock(&megaz->mz_io_mutex);
	}
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int do_sync_to_disk(struct megazone *megaz)
{
	int err = 0;

	if (test_and_clear_bit(DO_SYNC, &megaz->flags)) {
		mutex_lock(&megaz->mz_io_mutex);
		err = _megaz_sync_to_disk(megaz);
		mutex_unlock(&megaz->mz_io_mutex);
	}
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void meta_work_task(struct work_struct *work)
{
	int err = 0;
	struct megazone *megaz;

	if (!work)
		return;

	megaz = container_of(work, struct megazone, meta_work);
	if (!megaz)
		return;

	err = do_init_from_journal(megaz);

	/*
	 * Reduce memory pressure on journal list of arrays
	 * by pushing them into the sector map lookup tables
	 */
	if (!err)
		err = do_journal_to_table(megaz);

	/*
	 *  Reduce memory pressure on sector map lookup tables
	 * by pushing them onto disc
	 */
	if (!err)
		err = do_free_pages(megaz);

	/* force a consistent set of meta data out to disk */
	if (!err)
		err = do_sync_to_disk(megaz);

	if (!err)
		err = do_meta_check(megaz);

	megaz->age = jiffies_64;
	if (err)
		megaz->meta_result = err;

	clear_bit(DO_METAWORK_QD, &megaz->flags);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_mapped_to_list(struct megazone *megaz, u64 dm_s, u64 lba)
{
	struct map_cache *jrnl = NULL;
	struct map_cache *jrnl_first = NULL;
	int handled = 0;
	int list_count = 0;
	int err = 0;

	jrnl = jfirst_entry(megaz);
	while (jrnl) {
		int at;

		mutex_lock(&jrnl->cached_lock);
		jcache_sort_no_lock(jrnl);
		at = __find_sector_entry_chunk(&jrnl->jdata[1], jrnl->jcount,
					       dm_s, 0);
		if (at != -1) {
			struct map_sect_to_lba *data = &jrnl->jdata[at + 1];
			u64 lba_was = le64_to_lba48(data->physical, NULL);
			u64 physical = lba & Z_LOWER48;

			if (lba != lba_was) {
				Z_DBG(megaz->znd,
					 "Remap %" PRIx64 " -> %" PRIx64
					 " (was %" PRIx64 "->%" PRIx64 ")",
					 dm_s, lba,
					 le64_to_lba48(data->logical, NULL),
					 le64_to_lba48(data->physical, NULL));
				err = unused_phy(megaz, lba_was, 0);
				if (err == 1)
					err = 0;
			}
			data->physical = cpu_to_le64(physical);
			handled = 1;
		} else if (!jrnl_first) {
			if (jrnl->jcount < jrnl->jsize)
				jrnl_first = jrnl;
		}
		mutex_unlock(&jrnl->cached_lock);
		if (handled) {
			jderef(megaz, jrnl);
			goto out;
		}
		jrnl = jnext_entry(megaz, jrnl);
		list_count++;
	}

	/* ------------------------------------------------------------------ */
	/* ------------------------------------------------------------------ */
	if (jrnl_first) {
		atomic_inc(&jrnl_first->refcount);
	} else {
		jrnl_first = jalloc(megaz->znd);
		if (jrnl_first) {
			atomic_inc(&jrnl_first->refcount);
			jlist_add(megaz, jrnl_first);
		} else {
			Z_ERR(megaz->znd,
			      "%s: in memory journal is out of space.",
			      __func__);
			err = -ENOMEM;
			goto out;
		}

		if (list_count > JOURNAL_MEMCACHE_BLOCKS)
			set_bit(DO_JOURNAL_MOVE, &megaz->flags);
		megaz->mc_entries = list_count + 1;
	}

	/* ------------------------------------------------------------------ */
	/* ------------------------------------------------------------------ */

	if (jrnl_first) {
		mutex_lock(&jrnl_first->cached_lock);

		if (jrnl_first->jcount < jrnl_first->jsize) {
			u16 idx = ++jrnl_first->jcount;

			WARN_ON(jrnl_first->jcount > jrnl_first->jsize);

			jrnl_first->jdata[idx].logical = lba48_to_le64(0, dm_s);
			jrnl_first->jdata[idx].physical = lba48_to_le64(0, lba);
		} else {
			Z_ERR(megaz->znd, "%s: cached bin out of space!",
			      __func__);
			err = -EBUSY;
		}
		mutex_unlock(&jrnl_first->cached_lock);
		jderef(megaz, jrnl_first);
	}
out:

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline void sb_merge(struct megazone *megaz)
{
	struct zdm_superblock *sblk = &megaz->bmkeys->sblock;

	memcpy(sblk, megaz->znd->super_block, sizeof(*sblk));
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline u64 next_generation(struct megazone *megaz)
{
	u64 generation = le64_to_cpu(megaz->bmkeys->generation);

	if (generation == 0)
		generation = 2;

	generation++;
	if (generation == 0)
		generation++;

	return generation;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_mapped_sync(struct megazone *megaz)
{
	struct dm_target *ti = megaz->znd->ti;
	struct map_cache *jrnl;
	int nblks = 1;
	int use_wq = 0;
	int rc = 1;
	int jwrote = 0;
	int cached = 0;
	int idx = 0;
	int do_reset_wp = 0;
	int z_id = 0;
	int need_sync_io = 1;
	int sync_io_blocks = sizeof(*megaz->sync_io) / Z_C4K;
	u64 lba = LBA_SB_START;
	u64 generation = next_generation(megaz);
	u64 modulo = CACHE_COPIES;
	u64 incr = MAX_CACHE_INCR;
	struct io_4k_block *io_vcache;

	mutex_lock(&megaz->vcio_lock);
	io_vcache = get_io_vcache(megaz);
	if (!io_vcache) {
		Z_ERR(megaz->znd, "%s: FAILED to get SYNC CACHE.", __func__);
		rc = -ENOMEM;
		goto out;
	}

	if (megaz->mega_nr >= MAX_MZ_SUPP)
		Z_ERR(megaz->znd, "TODO: Use lba of mz #MAX_MZ_SUPP.");
	else
		lba += (modulo * incr) * megaz->mega_nr;

	lba += (generation % modulo) * incr;
	if (lba == 0)
		lba++;

	megaz->bmkeys->generation = cpu_to_le64(generation);
	megaz->bmkeys->gc_resv = megaz->z_gc_resv;
	megaz->bmkeys->meta_resv = megaz->z_meta_resv;

	sb_merge(megaz);

	jrnl = jfirst_entry(megaz);
	while (jrnl) {
		u64 phy = le64_to_lba48(jrnl->jdata[0].physical, NULL);
		u16 jcount = jrnl->jcount & 0xFFFF;

		jrnl->jdata[0].physical = lba48_to_le64(jcount, phy);
		megaz->bmkeys->crcs[idx] = crc_md_le16(jrnl->jdata, Z_CRC_4K);
		idx++;

		memcpy(io_vcache[cached].data, jrnl->jdata, Z_C4K);
		cached++;

		if (cached == IO_VCACHE_PAGES) {
			rc = write_block(ti, DM_IO_VMA,
					 io_vcache, lba, cached, use_wq);
			if (rc) {
				Z_ERR(megaz->znd, "%s: cache-> %" PRIu64
				      " [%d blks] %p -> %d",
				      __func__, lba, nblks, jrnl->jdata, rc);
				jderef(megaz, jrnl);
				goto out;
			}
			lba    += cached;
			jwrote += cached;
			cached  = 0;
		}
		jrnl = jnext_entry(megaz, jrnl);
	}

	jwrote += cached;
	if (jwrote > 20)
		Z_ERR(megaz->znd, "MZ#%u **WARNING** large map cache %d",
		       megaz->mega_nr, jwrote);

	mutex_lock(&megaz->zp_lock);
	megaz->bmkeys->n_crcs = cpu_to_le16(jwrote);
	megaz->bmkeys->zp_crc = crc_md_le16(megaz->z_ptrs, Z_CRC_4K);
	megaz->bmkeys->free_crc = crc_md_le16(megaz->zfree_count, Z_CRC_4K);
	megaz->bmkeys->key_crc = 0;
	megaz->bmkeys->key_crc = crc_md_le16(megaz->bmkeys, Z_CRC_4K);

	if (cached < (IO_VCACHE_PAGES - 3)) {
		memcpy(io_vcache[cached].data, megaz->bmkeys, Z_C4K);
		cached++;
		memcpy(io_vcache[cached].data, megaz->z_ptrs, Z_C4K);
		cached++;
		memcpy(io_vcache[cached].data, megaz->zfree_count, Z_C4K);
		cached++;
		need_sync_io = 0;
	}

	if (cached > 0) {
		rc = write_block(ti, DM_IO_VMA, io_vcache, lba, cached,
				 use_wq);
		if (rc) {
			Z_ERR(megaz->znd, "%s: Jrnl-> %" PRIu64
			      " [%d blks] %p -> %d",
			      __func__, lba, cached, io_vcache, rc);
			mutex_unlock(&megaz->zp_lock);
			goto out;
		}
		lba += cached;
	}

	if (need_sync_io) {
		void *data = megaz->sync_io;

		nblks = sync_io_blocks;
		rc = write_block(ti, DM_IO_KMEM, data, lba, nblks, use_wq);
		if (rc) {
			Z_ERR(megaz->znd,
			      "%s: WPs -> %" PRIu64 " [%d blks] %p -> %d",
			       __func__, lba, nblks, data, rc);
			mutex_unlock(&megaz->zp_lock);
			goto out;
		}
	}
	mutex_unlock(&megaz->zp_lock);

	if (do_reset_wp)
		dmz_reset_wp(megaz, z_id);

out:
	put_io_vcache(megaz, io_vcache);
	mutex_unlock(&megaz->vcio_lock);
	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int is_key_page(void *_data)
{
	int is_key = 0;
	struct mz_superkey *data = _data;

	/* Starts with Z_KEY_SIG and ends with magic */

	if (le64_to_cpu(data->sig1) == Z_KEY_SIG) {
		if (le64_to_cpu(data->magic) == Z_TABLE_MAGIC) {
			__le16 crc_value = data->key_crc;
			__le16 crc_check;

			data->key_crc = 0;
			crc_check = crc_md_le16(data, Z_CRC_4K);
			data->key_crc = crc_value;
			if (crc_check == crc_value)
				is_key = 1;
		}
	}
	return is_key;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline void zoned_personality(struct zoned *znd,
				     struct zdm_superblock *sblock)
{
	znd->zdstart = le64_to_cpu(sblock->zdstart);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int find_superblock_at(struct megazone *megaz, u64 lba, int use_wq,
			      int do_init)
{
	struct dm_target *ti = megaz->znd->ti;
	int found = 0;
	int nblks = 1;
	int rc = -ENOMEM;
	u32 count = 0;
	u64 *data = ZDM_ALLOC(megaz->znd, Z_C4K, PG_10);

	if (!data) {
		Z_ERR(megaz->znd, "No memory for finding generation ..");
		return 0;
	}
	if (lba == 0)
		lba++;
	do {
		rc = read_block(ti, DM_IO_KMEM, data, lba, nblks, use_wq);
		if (rc) {
			Z_ERR(megaz->znd,
				"%s: read @%" PRIu64 " [%d blks] %p -> %d",
			       __func__, lba, nblks, data, rc);
			goto out;
		}
		if (is_key_page(data)) {
			struct mz_superkey *kblk = (struct mz_superkey *) data;
			struct zdm_superblock *sblock = &kblk->sblock;
			int err = sb_check(sblock);

			if (!err) {
				found = 1;
				if (do_init)
					zoned_personality(megaz->znd, sblock);
			}
			goto out;
		}
		if (data[0] == 0 && data[1] == 0) {
			/* No SB here. */
			Z_ERR(megaz->znd, "FGen: Invalid block %" PRIx64 "?",
				lba);
			goto out;
		}
		lba++;
		count++;
		if (count > MAX_CACHE_SYNC) {
			Z_ERR(megaz->znd, "FSB: Too deep to be useful.");
			goto out;
		}
	} while (!found);

out:
	ZDM_FREE(megaz->znd, data, Z_C4K, PG_10);
	return found;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int find_superblock(struct megazone *megaz, int use_wq, int do_init)
{
	int found = 0;
	u64 lba;

	for (lba = 0; lba < 0x30000; lba += Z_BLKSZ) {
		found = find_superblock_at(megaz, lba, use_wq, do_init);
		if (found)
			break;
	}
	return found;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u64 mcache_find_gen(struct megazone *megaz, u64 lba, int use_wq,
				    u64 *sb_lba)
{
	struct dm_target *ti = megaz->znd->ti;
	u64 generation = 0;
	int nblks = 1;
	int rc = 1;
	int done = 0;
	u32 count = 0;
	u64 *data = ZDM_ALLOC(megaz->znd, Z_C4K, PG_11);

	if (!data) {
		Z_ERR(megaz->znd, "No memory for finding generation ..");
		return 0;
	}
	do {
		rc = read_block(ti, DM_IO_KMEM, data, lba, nblks, use_wq);

		if (rc) {
			Z_ERR(megaz->znd,
				"%s: Jrnl-> %" PRIu64 " [%d blks] %p -> %d",
			       __func__, lba, nblks, data, rc);
			goto out;
		}
		if (is_key_page(data)) {
			struct mz_superkey *kblk = (struct mz_superkey *) data;

			generation = le64_to_cpu(kblk->generation);
			done = 1;
			if (sb_lba)
				*sb_lba = lba;
			goto out;
		}
		if (data[0] == 0 && data[1] == 0) {
			/* No SB here... */
			Z_DBG(megaz->znd,
				"FGen: Invalid block %" PRIx64 "?", lba);
			goto out;
		}
		lba++;
		count++;
		if (count > MAX_CACHE_SYNC) {
			Z_ERR(megaz->znd, "FGen: Too deep to be useful.");
			goto out;
		}
	} while (!done);

out:
	ZDM_FREE(megaz->znd, data, Z_C4K, PG_11);
	return generation;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int cmp_gen(u64 left, u64 right)
{
	int result = 0;

	if (left != right) {
		u64 delta = (left > right) ? left - right : right - left;

		result = -1;
		if (delta > 1) {
			if (left == BAD_ADDR)
				result = 1;
		} else {
			if (right > left)
				result = 1;
		}
	}

	return result;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u64 mcache_greatest_gen(struct megazone *megaz, int use_wq, u64 *sb,
				u64 *at_lba)
{
	u64 lba = LBA_SB_START;
	u64 gen_no[CACHE_COPIES] = { 0ul, 0ul, 0ul };
	u64 gen_lba[CACHE_COPIES] = { 0ul, 0ul, 0ul };
	u64 gen_sb[CACHE_COPIES] = { 0ul, 0ul, 0ul };
	u64 incr = Z_BLKSZ;
	int locations = ARRAY_SIZE(gen_lba);
	int pick = 0;
	int idx;

	incr = MAX_CACHE_INCR;
	if (megaz->mega_nr >= MAX_MZ_SUPP)
		Z_ERR(megaz->znd, "TODO: Use lba of mz #32.");
	else
		lba += (locations * incr) * megaz->mega_nr;

	for (idx = 0; idx < locations; idx++) {
		u64 *pAt = &gen_sb[idx];

		gen_lba[idx] = lba;
		gen_no[idx] = mcache_find_gen(megaz, lba, use_wq, pAt);
		if (gen_no[idx])
			pick = idx;
		lba += incr;
	}

	for (idx = 0; idx < locations; idx++) {
		if (cmp_gen(gen_no[pick], gen_no[idx]) > 0)
			pick = idx;
	}

	if (gen_no[pick]) {
		if (at_lba)
			*at_lba = gen_lba[pick];
		if (sb)
			*sb = gen_sb[pick];
	}

	return gen_no[pick];
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_mapped_init(struct megazone *megaz)
{
	struct dm_target *ti = megaz->znd->ti;
	int nblks = 1;
	int use_wq = 0;
	int rc = 1;
	int done = 0;
	int jfound = 0;
	int idx = 0;
	struct list_head hjload;
	u64 lba = 0;
	u64 generation;
	__le16 crc_chk;
	struct io_4k_block *io_vcache;

	mutex_lock(&megaz->vcio_lock);
	io_vcache = get_io_vcache(megaz);

	if (!io_vcache) {
		Z_ERR(megaz->znd, "%s: FAILED to get SYNC CACHE.", __func__);
		rc = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&hjload);

	generation = mcache_greatest_gen(megaz, use_wq, NULL, &lba);
	if (generation == 0) {
		rc = -ENODATA;
		goto out;
	}

	if (lba == 0)
		lba++;

	do {
		struct map_cache *jrnl = jalloc(megaz->znd);

		if (!jrnl) {
			rc = -ENOMEM;
			goto out;
		}

		rc = read_block(ti, DM_IO_KMEM,
				jrnl->jdata, lba, nblks, use_wq);
		if (rc) {
			Z_ERR(megaz->znd,
				"%s: Jrnl-> %" PRIu64 " [%d blks] %p -> %d",
			       __func__, lba, nblks, jrnl->jdata, rc);

			goto out;
		}
		lba++;

		if (is_key_page(jrnl->jdata)) {
			size_t sz = Z_UNSORTED * sizeof(*jrnl->jdata);

			memcpy(megaz->bmkeys, jrnl->jdata, Z_C4K);
			jrnl->jcount = 0;
			done = 1;
			ZDM_FREE(megaz->znd, jrnl->jdata, sz, PG_08);
			ZDM_FREE(megaz->znd, jrnl, sizeof(*jrnl), KM_07);
			jrnl = NULL;
		} else {
			u16 jcount;

			(void)le64_to_lba48(jrnl->jdata[0].physical, &jcount);
			jrnl->jcount = jcount;
			list_add(&(jrnl->jlist), &hjload);
			jfound++;
		}

		if (jfound > MAX_CACHE_SYNC) {
			rc = -EIO;
			goto out;
		}
	} while (!done);

	crc_chk = megaz->bmkeys->key_crc;
	megaz->bmkeys->key_crc = 0;
	megaz->bmkeys->key_crc = crc_md_le16(megaz->bmkeys, Z_CRC_4K);

	if (crc_chk != megaz->bmkeys->key_crc) {
		Z_ERR(megaz->znd, "Bad Block Map KEYS!");
		Z_ERR(megaz->znd,
		      "MZ#%u Key CRC: Ex: %04x vs %04x <- calculated",
		      megaz->mega_nr, le16_to_cpu(crc_chk),
		      le16_to_cpu(megaz->bmkeys->key_crc));
		rc = -EIO;
	}

	if (jfound != le16_to_cpu(megaz->bmkeys->n_crcs)) {
		Z_ERR(megaz->znd,
			"MZ#%u mcache entries: found = %u, expected = %u",
			megaz->mega_nr, jfound,
			le16_to_cpu(megaz->bmkeys->n_crcs));
		rc = -EIO;
	}

	if ((crc_chk == megaz->bmkeys->key_crc) && !list_empty(&hjload)) {
		struct map_cache *jrnl;
		struct map_cache *jsafe;

		list_for_each_entry_safe(jrnl, jsafe, &hjload, jlist) {
			__le16 crc = crc_md_le16(jrnl->jdata, Z_CRC_4K);

			Z_DBG(megaz->znd,
				"MZ#%u JRNL CRC: %u: %04x [vs %04x] (c:%d)",
			      megaz->mega_nr, idx, le16_to_cpu(crc),
			      le16_to_cpu(megaz->bmkeys->crcs[idx]),
			      jrnl->jcount);

			if (crc == megaz->bmkeys->crcs[idx]) {
				jlist_add(megaz, jrnl);
			} else {
				Z_ERR(megaz->znd,
				      "MZ#%u %04x [vs %04x] (c:%d)",
				      megaz->mega_nr, le16_to_cpu(crc),
				      le16_to_cpu(megaz->bmkeys->crcs[idx]),
				      jrnl->jcount);
				rc = -EIO;
			}
			idx++;
		}
	}

	mutex_lock(&megaz->zp_lock);

	/*
	 * Read last know write printers
	 */
	rc = read_block(ti, DM_IO_VMA, io_vcache, lba, nblks, use_wq);
	if (rc)
		Z_DBG(megaz->znd,
		      "%s: WPs -> %" PRIu64 " [%d blks] %p -> %d",
		      __func__, lba, nblks, megaz->z_ptrs, rc);

	memcpy(megaz->z_ptrs, io_vcache[0].data, Z_C4K);
	crc_chk = crc_md_le16(megaz->z_ptrs, Z_CRC_4K);
	if (crc_chk != megaz->bmkeys->zp_crc) {
		Z_ERR(megaz->znd,
		      "MZ#%u WPs CRC: Ex %04x vs %04x  <- calculated",
		      megaz->mega_nr, le16_to_cpu(megaz->bmkeys->zp_crc),
		      le16_to_cpu(crc_chk));
		Z_ERR(megaz->znd, "Bad zone pointers!!");
		set_bit(DO_META_CHECK, &megaz->flags);
	}
	memcpy(megaz->z_commit, megaz->z_ptrs, Z_C4K);
	lba++;

	/*
	 * Read last calculated free counters
	 */
	rc = read_block(ti, DM_IO_VMA, io_vcache, lba, nblks, use_wq);
	if (rc)
		Z_DBG(megaz->znd,
		      "%s: WPs -> %" PRIu64 " [%d blks] %p -> %d",
		      __func__, lba, nblks, megaz->zfree_count, rc);

	memcpy(megaz->zfree_count, io_vcache[0].data, Z_C4K);

	crc_chk = crc_md_le16(megaz->zfree_count, Z_CRC_4K);
	if (crc_chk != megaz->bmkeys->free_crc) {
		Z_ERR(megaz->znd, "Bad zone free counters!!");
		Z_ERR(megaz->znd,
		      "MZ#%u FreeCount CRC: Ex %04x vs %04x  <- calculated",
		      megaz->mega_nr, le16_to_cpu(megaz->bmkeys->free_crc),
		      le16_to_cpu(crc_chk));
		set_bit(DO_META_CHECK, &megaz->flags);
	} else {
		int entry = 0;

		megaz->discard_count = 0;
		for (; entry < megaz->z_count; entry++) {
			u32 used = megaz->z_ptrs[entry] & Z_WP_VALUE_MASK;

			if (used == Z_BLKSZ) {
				u32 nfree = megaz->zfree_count[entry];

				megaz->discard_count += nfree;
			}
		}
	}
	megaz->z_gc_resv = megaz->bmkeys->gc_resv;
	megaz->z_meta_resv = megaz->bmkeys->meta_resv;
	mutex_unlock(&megaz->zp_lock);

out:
	put_io_vcache(megaz, io_vcache);
	mutex_unlock(&megaz->vcio_lock);
	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_mapped_addmany(struct megazone *megaz, u64 dm_s, u64 lba,
			    u64 count)
{
	int rc = 0;
	sector_t blk;

	for (blk = 0; blk < count; blk++) {
		rc = z_mapped_add_one(megaz, dm_s + blk, lba + blk);
		if (rc)
			goto out;
	}
out:
	return rc;
}

/* -------------------------------------------------------------------------- */
/**
 * Lookup a logical sector address to find the disk LBA
 *
 *   z_lookup		 (u64)
 *     locate_sector	  *, u64
 *       sector_map_entry     (int)
 *	 get_map_entry      *, u64, *, int
 *	   get_map_table_entry *, *, u64, u64
 *	   load_page	u64, int, int, int, int, *, u16, int
 *	     z_lookup
 *
 *
 *
 *
 */
static u64 z_lookup(struct megazone *megaz, struct map_addr *maddr)
{
	u64 found = 0ul;

	if (maddr->dm_s < megaz->znd->data_lba)
		found = maddr->dm_s;
	if (!found)
		found = z_lookup_key_range(megaz, maddr);
	if (!found)
		found = z_lookup_cache(megaz, maddr);
	if (!found)
		found = locate_sector(megaz, maddr);

	return found;
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * load_map_entry() - Find page of forward or reverse map. Page will be loaded
 * from disk it if is not already in core memory.
 *
 * @param megaz: Owning megazone
 * @param lba: From megaz->logical_map
 * @param is_to: true if logical map is forward map table.
 *
 *
 */
static struct map_pg *load_map_entry(struct megazone *megaz, u64 lba, int is_to)
{
	struct map_pg *mapped = get_map_table_entry(megaz, lba, is_to);

	if (mapped) {
		if (!mapped->mdata) {
			int rc = map_entry_page(megaz, mapped, lba, is_to);

			if (rc < 0)
				megaz->meta_result = rc;
		}
	} else {
		Z_ERR(megaz->znd, "%s: No table for page# %" PRIx64 ".",
		      __func__, lba);
	}
	return mapped;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int metadata_dirty_fling(struct megazone *megaz, u64 dm_s)
{
	struct zoned *znd = megaz->znd;
	struct mzlam *lam = &megaz->logical_map;
	struct map_pg *Smap = NULL;
	int is_flung = 0;

	Smap = NULL;
	if ((lam->r_base <= dm_s) && dm_s < (lam->r_base + Z_BLKSZ)) {
		Smap = load_map_entry(megaz, dm_s, 0);
		if (!Smap)
			Z_ERR(znd, "Failed to fling: %" PRIx64, dm_s);
	} else if ((lam->s_base <= dm_s) && dm_s < (lam->s_base + Z_BLKSZ)) {
		Smap = load_map_entry(megaz, dm_s, 1);
		if (!Smap)
			Z_ERR(znd, "Failed to fling: %" PRIx64, dm_s);
	}
	if (Smap) {
		atomic_inc(&Smap->refcount);
		mutex_lock(&Smap->md_lock);
		Smap->age = jiffies_64;
		set_bit(IS_DIRTY, &Smap->flags);
		is_flung = 1;
		mutex_unlock(&Smap->md_lock);
		atomic_dec(&Smap->refcount);

		if (Smap->lba != dm_s)
			Z_ERR(znd, "Excess churn? lba %"PRIx64
				   " [last: %"PRIx64"]", dm_s, Smap->lba);
	}

	if ((lam->crc_low <= dm_s) && (dm_s < lam->crc_hi)) {
		int off = dm_s - lam->crc_low;
		struct crc_pg *pblock = NULL;
		u64 lba;
		__le16 crc;

		if (off < MZKY_NCRC) {
			pblock = &megaz->rtm_crc[off];
			mutex_lock(&megaz->mapkey_lock);
			lba = le64_to_cpu(megaz->bmkeys->rtm_crc_lba[off]);
			crc = megaz->bmkeys->rtm_crc_pg[off];
			mutex_unlock(&megaz->mapkey_lock);
		} else {
			off -= MZKY_NCRC;
			pblock = &megaz->stm_crc[off];
			mutex_lock(&megaz->mapkey_lock);
			lba = le64_to_cpu(megaz->bmkeys->stm_crc_lba[off]);
			crc = megaz->bmkeys->stm_crc_pg[off];
			mutex_unlock(&megaz->mapkey_lock);
		}
		if (pblock && lba) {
			const int wqueue = 0;

			atomic_inc(&pblock->refcount);
			load_crc_meta_pg(megaz, pblock, lba, crc, wqueue);
			mutex_lock(&pblock->lock_pg);
			set_bit(IS_DIRTY, &pblock->flags);
			pblock->age = jiffies_64;
			is_flung = 1;
			mutex_unlock(&pblock->lock_pg);
			if (pblock->lba != dm_s)
				Z_ERR(znd, "Excess churn? lba %"PRIx64
				      " [last: %"PRIx64"]", dm_s, pblock->lba);
			atomic_dec(&pblock->refcount);
		}
	}
	return is_flung;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline void z_do_copy_more(struct gc_state *gc_entry)
{
	unsigned long flags;
	struct zoned *znd = gc_entry->megaz->znd;

	spin_lock_irqsave(&znd->gc_lock, flags);
	set_bit(DO_GC_PREPARE, &gc_entry->gc_flags);
	spin_unlock_irqrestore(&znd->gc_lock, flags);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int gc_post(struct megazone *megaz, u64 dm_s, u64 lba)
{
	struct zoned *znd = megaz->znd;
	struct map_cache *post = &znd->gc_postmap;
	int handled = 0;

	if (post->jcount < post->jsize) {
		u16 idx = ++post->jcount;

		WARN_ON(post->jcount > post->jsize);

		post->jdata[idx].logical = lba48_to_le64(0, dm_s);
		post->jdata[idx].physical = lba48_to_le64(0, lba);
		handled = 1;
	} else {
		Z_ERR(znd, "*CRIT* post overflow L:%" PRIx64 "-> S:%" PRIx64,
		      lba, dm_s);
	}
	return handled;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_zone_gc_metadata_to_ram(struct gc_state *gc_entry)
{
	struct megazone *megaz = gc_entry->megaz;
	struct zoned *znd = megaz->znd;
	struct map_pg *ORmap;
	struct map_pg *Smap;
	struct mzlam *lam = &megaz->logical_map;
	u64 from_lba;
	struct map_addr ORaddr;
	struct map_addr Saddr;
	int rcode = 0;
	int count;

	from_lba = lam->mz_base + (gc_entry->z_gc * Z_BLKSZ);
	mutex_lock(&megaz->mz_io_mutex);
	for (count = 0; count < MZKY_NCRC; count++) {
		struct crc_pg *pblock;
		__le16 crc;
		u64 lba;
		int wqueue = 0;

		mutex_lock(&megaz->mapkey_lock);
		lba = le64_to_cpu(megaz->bmkeys->rtm_crc_lba[count]);
		mutex_unlock(&megaz->mapkey_lock);
		if (lba && (_calc_zone(megaz->znd, lba) == gc_entry->z_gc)) {
			pblock = &megaz->rtm_crc[count];
			crc = megaz->bmkeys->rtm_crc_pg[count];
			atomic_inc(&pblock->refcount);
			load_crc_meta_pg(megaz, pblock, lba, crc, wqueue);
			mutex_lock(&pblock->lock_pg);
			set_bit(IS_DIRTY, &pblock->flags);
			pblock->age = jiffies_64;
			mutex_unlock(&pblock->lock_pg);
			atomic_dec(&pblock->refcount);
		}
		mutex_lock(&megaz->mapkey_lock);
		lba = le64_to_cpu(megaz->bmkeys->stm_crc_lba[count]);
		mutex_unlock(&megaz->mapkey_lock);
		if (lba && (_calc_zone(megaz->znd, lba) == gc_entry->z_gc)) {
			pblock = &megaz->stm_crc[count];
			crc = megaz->bmkeys->stm_crc_pg[count];
			atomic_inc(&pblock->refcount);
			load_crc_meta_pg(megaz, pblock, lba, crc, wqueue);
			mutex_lock(&pblock->lock_pg);
			set_bit(IS_DIRTY, &pblock->flags);
			pblock->age = jiffies_64;
			mutex_unlock(&pblock->lock_pg);
			atomic_dec(&pblock->refcount);
		}
	}

	/* pull all of the affect struct map_pg and crc pages into memory: */
	for (count = 0; count < Z_BLKSZ; count++) {
		__le32 ORencoded;
		u64 ORlba = from_lba + count;

		map_addr_calc(megaz->znd, ORlba, &ORaddr);
		ORmap = reverse_map_entry(megaz, &ORaddr);
		if (ORmap && ORmap->mdata) {
			atomic_inc(&ORmap->refcount);
			mutex_lock(&ORmap->md_lock);
			ORencoded = ORmap->mdata[ORaddr.offentry];
			mutex_unlock(&ORmap->md_lock);
			if (ORencoded != MZTEV_UNUSED) {
				u64 dm_s = map_value(megaz, ORencoded);

				if (dm_s < znd->nr_blocks) {
					map_addr_calc(megaz->znd, dm_s, &Saddr);
					Smap = sector_map_entry(megaz, &Saddr);
					if (!Smap)
						rcode = -ENOMEM;
				} else {
					Z_ERR(znd, "Invalid rmap entry: %x.",
					      ORencoded);
				}
				if (!metadata_dirty_fling(megaz, dm_s))
					gc_post(megaz, dm_s, ORlba);
			}
			atomic_dec(&ORmap->refcount);
		}
	}
	mutex_unlock(&megaz->mz_io_mutex);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int append_blks(struct megazone *megaz, u64 lba,
		       struct io_4k_block *io_buf, int count)
{
	int rcode = 0;
	int rc;
	u32 chunk;
	struct zoned *znd = megaz->znd;
	struct io_4k_block *io_vcache;

	mutex_lock(&znd->gc_vcio_lock);
	io_vcache = get_io_vcache(megaz);

	if (!io_vcache) {
		Z_ERR(megaz->znd, "%s: FAILED to get SYNC CACHE.", __func__);
		rc = -ENOMEM;
		goto out;
	}

	for (chunk = 0; chunk < count; chunk += IO_VCACHE_PAGES) {
		u32 nblks = count - chunk;

		if (nblks > IO_VCACHE_PAGES)
			nblks = IO_VCACHE_PAGES;

		rc = read_block(znd->ti, DM_IO_VMA, io_vcache, lba, nblks, 0);
		if (rc) {
			Z_ERR(znd, "Reading error ... disable zone: %u",
				(u32)(lba >> 16));
			rcode = -EIO;
			goto out;
		}
		memcpy(&io_buf[chunk], io_vcache, nblks * Z_C4K);
		lba += nblks;
	}
out:
	put_io_vcache(megaz, io_vcache);
	mutex_unlock(&znd->gc_vcio_lock);
	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_zone_gc_read(struct gc_state *gc_entry)
{
	struct megazone *megaz = gc_entry->megaz;
	struct zoned *znd = megaz->znd;
	struct io_4k_block *io_buf = megaz->znd->gc_io_buf;
	struct map_cache *post = &znd->gc_postmap;
	unsigned long flags;
	u64 start_lba;
	int nblks;
	int rcode = 0;
	int fill = 0;
	int jstart;
	int jentry;

	spin_lock_irqsave(&megaz->znd->gc_lock, flags);
	jstart = gc_entry->r_ptr;
	spin_unlock_irqrestore(&megaz->znd->gc_lock, flags);

	if (!jstart)
		jstart++;

	mutex_lock(&post->cached_lock);

	/* A discard may have puched holes in the postmap. re-sync lba */
	jentry = jstart;
	while (jentry <= post->jcount && (Z_LOWER48 ==
			le64_to_lba48(post->jdata[jentry].physical, NULL))) {
		jentry++;
	}
	/* nothing left to move */
	if (jentry > post->jcount)
		goto out_finished;

	/* skip over any discarded blocks */
	if (jstart != jentry)
		jstart = jentry;

	start_lba = le64_to_lba48(post->jdata[jentry].physical, NULL);
	post->jdata[jentry].physical = lba48_to_le64(GC_READ, start_lba);
	nblks = 1;
	jentry++;

	while (jentry <= post->jcount && (nblks+fill) < GC_MAX_STRIPE) {
		u64 dm_s = le64_to_lba48(post->jdata[jentry].logical, NULL);
		u64 lba = le64_to_lba48(post->jdata[jentry].physical, NULL);

		if (Z_LOWER48 == dm_s || Z_LOWER48 == lba) {
			jentry++;
			continue;
		}

		post->jdata[jentry].physical = lba48_to_le64(GC_READ, lba);

		/* if the block is contiguous add it to the read */
		if (lba == (start_lba + nblks)) {
			nblks++;
		} else {
			if (nblks) {
				int err;

				err = append_blks(megaz, start_lba,
						  &io_buf[fill], nblks);
				if (err) {
					rcode = err;
					goto out;
				}
				fill += nblks;
			}
			start_lba = lba;
			nblks = 1;
		}
		jentry++;
	}

	/* Issue a copy of 'nblks' blocks */
	if (nblks > 0) {
		int err;

		err = append_blks(megaz, start_lba, &io_buf[fill], nblks);
		if (err) {
			rcode = err;
			goto out;
		}
		fill += nblks;
	}

out_finished:
	Z_DBG(znd, "Read %d blocks from %d", fill, gc_entry->r_ptr);

	spin_lock_irqsave(&megaz->znd->gc_lock, flags);
	gc_entry->nblks = fill;
	gc_entry->r_ptr = jentry;
	if (fill > 0)
		set_bit(DO_GC_WRITE, &gc_entry->gc_flags);
	else
		set_bit(DO_GC_COMPLETE, &gc_entry->gc_flags);

	spin_unlock_irqrestore(&megaz->znd->gc_lock, flags);

out:
	mutex_unlock(&post->cached_lock);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline u64 current_mapping(struct megazone *megaz, u64 dm_s)
{
	struct map_addr maddr;

	map_addr_calc(megaz->znd, dm_s, &maddr);
	return z_lookup(megaz, &maddr);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_zone_gc_write(struct gc_state *gc_entry)
{
	struct megazone *megaz = gc_entry->megaz;
	struct zoned *znd = megaz->znd;
	struct dm_target *ti = znd->ti;
	struct io_4k_block *io_buf = megaz->znd->gc_io_buf;
	struct map_cache *post = &znd->gc_postmap;
	unsigned long flags;
	u64 lba;
	u32 nblks;
	u32 out = 0;
	int err = 0;
	int jentry;

	spin_lock_irqsave(&megaz->znd->gc_lock, flags);
	jentry = gc_entry->w_ptr;
	nblks = gc_entry->nblks;
	spin_unlock_irqrestore(&megaz->znd->gc_lock, flags);

	if (!jentry)
		jentry++;

	mutex_lock(&post->cached_lock);

	while (nblks > 0) {
		u32 nfound = 0;
		u32 added = 0;

		/*
		 * When lba is zero blocks were not allocated.
		 * Retry with the smaller request
		 */
		lba = z_acquire(megaz, Z_AQ_GC, nblks, &nfound);
		if (!lba) {
			if (nfound) {
				u32 avail = nfound;

				nfound = 0;
				lba = z_acquire(megaz, Z_AQ_GC, avail, &nfound);
			}
		}

		if (!lba) {
			err = -ENOSPC;
			goto out;
		}

		err = write_block(ti, DM_IO_VMA, &io_buf[out], lba, nfound, 0);
		if (err) {
			Z_ERR(znd, "Write %d blocks to %"PRIx64". ERROR: %d",
			      nfound, lba, err);
			goto out;
		}
		out += nfound;

		while ((jentry <= post->jcount) && (added < nfound)) {
			u16 rflg;
			u64 orig = le64_to_lba48(
					post->jdata[jentry].physical, &rflg);
			u64 dm_s = le64_to_lba48(
					post->jdata[jentry].logical, NULL);

			if ((Z_LOWER48 == dm_s || Z_LOWER48 == orig)) {
				jentry++;

				if (rflg & GC_READ) {
					Z_ERR(znd, "ERROR: %" PRIx64
					      " read and not written %" PRIx64,
					      orig, dm_s);
					lba++;
					added++;
				}
				continue;
			}
			rflg &= ~GC_READ;
			post->jdata[jentry].physical = lba48_to_le64(rflg, lba);
			lba++;
			added++;
			jentry++;
		}
		nblks -= nfound;
	}
	Z_DBG(znd, "Write %d blocks from %d", gc_entry->nblks, gc_entry->w_ptr);
	set_bit(DO_GC_META, &gc_entry->gc_flags);

out:
	spin_lock_irqsave(&megaz->znd->gc_lock, flags);
	gc_entry->nblks = 0;
	gc_entry->w_ptr = jentry;
	spin_unlock_irqrestore(&megaz->znd->gc_lock, flags);
	mutex_unlock(&post->cached_lock);

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int gc_finalize(struct gc_state *gc_entry)
{
	int err = 0;
	struct megazone *megaz = gc_entry->megaz;
	struct map_cache *post = &megaz->znd->gc_postmap;
	int jentry;

	mutex_lock(&post->cached_lock);
	for (jentry = post->jcount; jentry > 0; jentry--) {
		u64 dm_s = le64_to_lba48(post->jdata[jentry].logical, NULL);
		u64 lba = le64_to_lba48(post->jdata[jentry].physical, NULL);

		if (dm_s != Z_LOWER48 || lba != Z_LOWER48) {
			Z_ERR(megaz->znd,
			      "GC: Failed to move MZ# %u %" PRIx64
			      " from %"PRIx64" [%d]",
			      megaz->mega_nr, dm_s, lba, jentry);
			err = -EIO;
		}
	}
	mutex_unlock(&post->cached_lock);
	post->jcount = jentry;

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void clear_gc_target(struct megazone *megaz)
{
	int z_id;

	for (z_id = megaz->z_data; z_id < megaz->z_count; z_id++) {
		if (megaz->z_ptrs[z_id] & Z_WP_GC_TARGET) {
			mutex_lock(&megaz->zp_lock);
			megaz->z_ptrs[z_id] &= ~Z_WP_GC_TARGET;
			mutex_unlock(&megaz->zp_lock);
		}
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_zone_gc_metadata_update(struct gc_state *gc_entry)
{
	struct megazone *megaz = gc_entry->megaz;
	struct zoned *znd = megaz->znd;
	struct map_cache *post = &znd->gc_postmap;
	u32 used = post->jcount;
	int err = 0;
	int jentry;
	struct mzlam *lam = &megaz->logical_map;

	mutex_lock(&megaz->mz_io_mutex);
	for (jentry = post->jcount; jentry > 0; jentry--) {
		int discard = 0;
		int mapping = 0;
		struct map_pg *mapped = NULL;
		u64 dm_s = le64_to_lba48(post->jdata[jentry].logical, NULL);
		u64 lba = le64_to_lba48(post->jdata[jentry].physical, NULL);

		if ((lam->r_base <= dm_s) && dm_s < (lam->r_base + Z_BLKSZ)) {
			u64 off = dm_s - lam->r_base;

			mapped = megaz->reversetm[off];
			mapping = 1;
		} else if ((lam->s_base <= dm_s) &&
			   (dm_s < (lam->s_base + Z_BLKSZ))) {
			u64 off = dm_s - lam->s_base;

			mapped = megaz->sectortm[off];
			mapping = 1;
		}

		if (mapping && !mapped)
			Z_ERR(megaz->znd,
				 "MD: dm_s: %" PRIx64 " -> lba: %" PRIx64
				 " no mapping in ram.", dm_s, lba);

		if (mapped) {
			u16 in_z;

			atomic_inc(&mapped->refcount);
			mutex_lock(&mapped->md_lock);
			in_z = _calc_zone(megaz->znd, mapped->last_write);
			if (in_z != gc_entry->z_gc) {
				Z_ERR(znd, "MD: %" PRIx64
				      " Discarded - %" PRIx64
				      " already flown to: %x",
				      dm_s, mapped->last_write, in_z);
				discard = 1;
			} else if (mapped->mdata &&
				   test_bit(IS_DIRTY, &mapped->flags)) {
				Z_ERR(znd,
				      "MD: %" PRIx64 " Discarded - %"PRIx64
				      " is in-flight",
				      dm_s, mapped->last_write);
				discard = 2;
			}
			if (!discard)
				mapped->last_write = lba;
			mutex_unlock(&mapped->md_lock);
			atomic_dec(&mapped->refcount);
		}

		/*
		 * location of the SLT key sectors need to be
		 * stashed into the sector lookup table block map
		 * Does dm_s point in the sector lookup table block map ?
		 */
		if ((lam->sk_low <= dm_s) && (dm_s < lam->sk_high)) {
			if (!discard) {
				int off = dm_s - lam->sk_low;

				mutex_lock(&megaz->mapkey_lock);
				megaz->bmkeys->stm_keys[off] = cpu_to_le64(lba);
				mutex_unlock(&megaz->mapkey_lock);
			}
		} else if (lam->crc_low <= dm_s && dm_s < lam->crc_hi) {
			const u16 z_gc = gc_entry->z_gc;
			int off = dm_s - lam->crc_low;
			struct crc_pg *pblock = NULL;
			u16 in_z;

			mutex_lock(&megaz->mapkey_lock);
			if (off < 32)
				pblock = &megaz->rtm_crc[off];
			else
				pblock = &megaz->stm_crc[off - 32];

			in_z = _calc_zone(megaz->znd, pblock->last_write);
			if (in_z != z_gc) {
				Z_ERR(znd,
				      "MD: %" PRIx64 " Discarded - %"PRIx64
				      " already flown to: %x [CRC]",
				      dm_s, pblock->last_write, in_z);
				discard = 1;
			} else if (pblock->cdata &&
				   test_bit(IS_DIRTY, &pblock->flags)) {

				Z_ERR(znd, "MD: %" PRIx64 " Discarded - %"PRIx64
				      " is in-flight [CRC]",
				      dm_s, pblock->last_write);
				discard = 2;
			}
			/* update current lba for 'moved' and 'in-flight' */
			if (discard != 1) {
				mutex_lock(&pblock->lock_pg);

				Z_ERR(znd, "MD: %" PRIx64 " mv from  %"PRIx64
					   " to: %" PRIu64 " [CRC]",
				      dm_s, pblock->last_write, lba);

				pblock->last_write = lba;
				if (off < 32)
					megaz->bmkeys->rtm_crc_lba[off] =
					    cpu_to_le64(lba);
				else
					megaz->bmkeys->stm_crc_lba[off - 32] =
					    cpu_to_le64(lba);

				mutex_unlock(&pblock->lock_pg);
			}
			mutex_unlock(&megaz->mapkey_lock);
		}

		mutex_lock(&post->cached_lock);
		if (discard == 1) {
			Z_ERR(znd, "Dropped: %" PRIx64 " ->  %"PRIx64,
			      le64_to_cpu(post->jdata[jentry].logical),
			      le64_to_cpu(post->jdata[jentry].physical));

			post->jdata[jentry].logical = MC_INVALID;
			post->jdata[jentry].physical = MC_INVALID;
		}
		if (post->jdata[jentry].logical  == MC_INVALID &&
		    post->jdata[jentry].physical == MC_INVALID) {
			used--;
		} else if (lba) {
			u16 zone = _calc_zone(megaz->znd, lba);

			megaz->z_commit[zone]++;
			if (megaz->z_commit[zone] == Z_BLKSZ) {
				mutex_lock(&megaz->zp_lock);
				megaz->z_ptrs[zone] |= Z_WP_GC_READY;
				mutex_unlock(&megaz->zp_lock);
			}
		}
		mutex_unlock(&post->cached_lock);
	}
	err = move_to_map_tables(megaz, post);
	if (err)
		Z_ERR(znd, "Move to tables post GC failure");

	clear_gc_target(megaz);
	mutex_unlock(&megaz->mz_io_mutex);

	return err;
}

/**
 * _blkalloc() - Attempt to reserve blocks within megazone
 * @megaz:	 Megazone to write
 * @z_at:	 Zone to write data to
 * @flags:	 Acquisition type.
 * @nblks:	 Number of blocks desired.
 * @nfound:	 Number of blocks allocated or available.
 *
 * Attempt allocation of @param nblks within fron the current WP of z_at
 * When nblks are not available 0 is returned and @param nfound is the
 * contains the number of blocks *available* but not *allocated*.
 * When nblks are available the starting LBA in 4k space is returned and
 * nblks are allocated *allocated* and *nfound is the number of blocks
 * remaining in zone z_at from the LBA returned.
 *
 * Return: LBA if request is met, otherwise 0. nfound will contain the
 *         available blocks remaining.
 */
static sector_t _blkalloc(struct megazone *megaz, u32 z_at, u32 flags,
			  u32 nblks, u32 *nfound)
{
	u32 wptr = megaz->z_ptrs[z_at];
	u32 gc_tflg = wptr & (Z_WP_GC_TARGET|Z_WP_NON_SEQ);
	sector_t found = 0;
	u32 avail = 0;
	int do_open_zone = 0;

	wptr &= ~(Z_WP_GC_TARGET|Z_WP_NON_SEQ);
	if (wptr < Z_BLKSZ)
		avail = Z_BLKSZ - wptr;

#if 0 /* DEBUG START: Testing zm_write_pages() */
	if (avail > 7)
		avail = 7;
#endif /* DEBUG END: Testing zm_write_pages() */

	*nfound = avail;
	if (nblks <= avail) {
		u64 disk_zone = ((megaz->mega_nr * 1024) + z_at) * Z_BLKSZ;

		mutex_lock(&megaz->zp_lock);
		found = disk_zone + wptr + megaz->znd->data_lba;
		*nfound = nblks;
		if (megaz->z_ptrs[z_at] == 0)
			do_open_zone = 1;

		wptr += nblks;
		megaz->zfree_count[z_at] -= nblks;
		if (wptr == Z_BLKSZ)
			megaz->discard_count += megaz->zfree_count[z_at];

		wptr |= gc_tflg;
		if (flags & Z_AQ_GC)
			wptr |= Z_WP_GC_TARGET;

		megaz->z_ptrs[z_at] = wptr;
		mutex_unlock(&megaz->zp_lock);
		if (do_open_zone)
			dmz_open_zone(megaz, z_at);
	}

	return found;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u16 _gc_tag = 1;

/**
 * Add a zone onto the GC queue -- and kick start the compact operation if
 *  not already in progress.
 */
static int z_zone_compact_queue(struct megazone *megaz, u64 z_gc, int delay)
{
	unsigned long flags;
	struct zoned *znd = megaz->znd;
	int do_queue = 0;
	int err = 0;
	struct gc_state *gc_entry = ZDM_ALLOC(znd, sizeof(*gc_entry), KM_16);

	if (!gc_entry) {
		Z_ERR(znd, "No Memory for compact!!");
		return -ENOMEM;
	}
	gc_entry->megaz = megaz;
	gc_entry->z_gc = z_gc;
	gc_entry->tag = _gc_tag++;
	set_bit(DO_GC_NEW, &gc_entry->gc_flags);
	znd->gc_backlog++;

	spin_lock_irqsave(&znd->gc_lock, flags);
	if (!znd->gc_active) {
		znd->gc_active = gc_entry;
		do_queue = 1;
	}
	spin_unlock_irqrestore(&znd->gc_lock, flags);

	if (do_queue) {
		unsigned long tval = msecs_to_jiffies(delay);

		queue_delayed_work(znd->gc_wq, &znd->gc_work, tval);

		Z_DBG(znd, "%s: Queue GC: MZ# %d Z# %" PRIx64
		      ", wp: %x, free %x - tag %u",
		      __func__, megaz->mega_nr, z_gc, megaz->z_ptrs[z_gc],
		      megaz->zfree_count[z_gc], gc_entry->tag);
	} else {
		Z_ERR(znd, "Queue GC: MZ# %d Z# %" PRIx64 " ** fail: active",
			megaz->mega_nr, z_gc);
		ZDM_FREE(znd, gc_entry, sizeof(*gc_entry), KM_16);
		znd->gc_backlog--;
	}

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * Called periodically to see if GC needs to be done. ...
 *
 * FIXME: this is really too aggressive ...
 *
 */
static int gc_compact_check(struct megazone *megaz, int delay)
{
	unsigned long flags;
	int queued = 0;
	int n_filled = 0;
	int n_empty = 0;
	int z_gc = megaz->z_data;
	u16 gc_tag = 0;
	u16 top_roi = 0xFFFF;
	u32 stale = 0;

	Z_DBG(megaz->znd, "MZ# %u Checking zone range [%u,%u)",
		megaz->mega_nr, z_gc, megaz->z_count);

	if (megaz->meta_result)
		goto out;

	if (test_bit(ZF_FREEZE, &megaz->znd->flags)) {
		Z_ERR(megaz->znd, "MZ# %u is frozen -- GC paused.",
		      megaz->mega_nr);
		goto out;
	}

	spin_lock_irqsave(&megaz->znd->gc_lock, flags);
	if (megaz->znd->gc_active) {
		queued = 1;
		gc_tag = megaz->znd->gc_active->tag;
	}
	spin_unlock_irqrestore(&megaz->znd->gc_lock, flags);

	if (queued) {
		Z_ERR(megaz->znd, "GC is active: %u", gc_tag);
		goto out;
	}

	/* scan for most stale zone in MZ [top_roi] */
	for (; z_gc < megaz->z_count; z_gc++) {
		u32 wp = megaz->z_ptrs[z_gc] & Z_WP_VALUE_MASK;

		if (wp == Z_BLKSZ)
			stale += megaz->zfree_count[z_gc];

		if ((megaz->z_ptrs[z_gc] & Z_WP_GC_PENDING) != 0) {
			n_filled++;
			continue;
		}
		if (is_ready_for_gc(megaz, z_gc)) {
			u32 nfree = megaz->zfree_count[z_gc];

			n_filled++;
			if (top_roi == 0xFFFF)
				top_roi = z_gc;
			else if (nfree > megaz->zfree_count[top_roi])
				top_roi = z_gc;

		} else if ((Z_BLKSZ - wp) < 0xff) {
			n_filled++;
		}
		if (megaz->z_ptrs[z_gc] == 0)
			n_empty++;
	}
	megaz->z_gc_free = n_empty;

	if (megaz->discard_count != stale) {
		Z_ERR(megaz->znd, "MZ# %u. Repair discard count %d <- %d",
		      megaz->mega_nr, megaz->discard_count, stale);
		megaz->discard_count = stale;
	}

	/* determine the cut-off for GC based on MZ overall staleness */
	if (top_roi != 0xFFFF) {
		u32 state_metric = GC_PRIO_DEFAULT;
		int pctfree = n_empty * 100 / megaz->z_count;

		/*
		 * -> at less than 5 zones free switch to critical
		 * -> at less than 5% zones free switch to HIGH
		 * -> at less than 25% free switch to LOW
		 * -> high level is 'cherry picking' near empty zones
		 */
		if (megaz->z_gc_free < 5)
			state_metric = GC_PRIO_CRIT;
		else if (pctfree < 5)
			state_metric = GC_PRIO_HIGH;
		else if (pctfree < 25)
			state_metric = GC_PRIO_LOW;

		if (megaz->zfree_count[top_roi] > state_metric)
			if (z_zone_compact_queue(megaz, top_roi, delay))
				queued = 1;
	}
out:
	return queued;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int z_zone_gc_compact(struct gc_state *gc_entry)
{
	unsigned long flags;
	int err = 0;
	int do_meta_flush = 0;
	struct megazone *megaz = gc_entry->megaz;

	megaz->age = jiffies_64;
	if (test_and_clear_bit(DO_GC_NEW, &gc_entry->gc_flags)) {
		err = z_flush_bdev(megaz->znd);
		if (err) {
			gc_entry->result = err;
			goto out;
		}

		mutex_lock(&megaz->zp_lock);
		megaz->z_ptrs[gc_entry->z_gc] |= Z_WP_GC_FULL;
		mutex_unlock(&megaz->zp_lock);

		mutex_lock(&megaz->mz_io_mutex);
		err = _cached_to_tables(megaz, gc_entry->z_gc);
		set_bit(DO_GC_NO_PURGE, &megaz->flags);
		mutex_unlock(&megaz->mz_io_mutex);
		if (err) {
			Z_ERR(megaz->znd, "Failed to purge journal: %d", err);
			gc_entry->result = err;
			goto out;
		}

		if (megaz->znd->gc_postmap.jcount > 0) {
			Z_ERR(megaz->znd, "*** Unexpected data in postmap!!");
			megaz->znd->gc_postmap.jcount = 0;
		}

		err = z_zone_gc_metadata_to_ram(gc_entry);
		if (err) {
			Z_ERR(megaz->znd,
			      "Pre-load metadata to memory failed!! %d", err);
			gc_entry->result = err;
			goto out;
		}
		set_bit(DO_GC_PREPARE, &gc_entry->gc_flags);

		if (megaz->znd->gc_throttle.counter == 0)
			return -EAGAIN;
	}

next_in_queue:
	megaz->age = jiffies_64;
	if (test_and_clear_bit(DO_GC_PREPARE, &gc_entry->gc_flags)) {
		mutex_lock(&megaz->mz_io_mutex);
		err = z_zone_gc_read(gc_entry);
		mutex_unlock(&megaz->mz_io_mutex);
		if (err < 0) {
			Z_ERR(megaz->znd,
			      "z_zone_gc_chunk issue failure: %d", err);
			gc_entry->result = err;
			goto out;
		}
		if (megaz->znd->gc_throttle.counter == 0)
			return -EAGAIN;
	}

	if (test_and_clear_bit(DO_GC_WRITE, &gc_entry->gc_flags)) {
		mutex_lock(&megaz->mz_io_mutex);
		err = z_zone_gc_write(gc_entry);
		mutex_unlock(&megaz->mz_io_mutex);
		if (err) {
			Z_ERR(megaz->znd,
			      "z_zone_gc_chunk issue failure: %d", err);
			gc_entry->result = err;
			goto out;
		}
		if (megaz->znd->gc_throttle.counter == 0)
			return -EAGAIN;
	}

	if (test_and_clear_bit(DO_GC_META, &gc_entry->gc_flags)) {
		z_do_copy_more(gc_entry);
		goto next_in_queue;
	}

	megaz->age = jiffies_64;
	if (test_and_clear_bit(DO_GC_COMPLETE, &gc_entry->gc_flags)) {
		u32 non_seq = megaz->z_ptrs[gc_entry->z_gc] & Z_WP_NON_SEQ;

		err = z_zone_gc_metadata_update(gc_entry);
		gc_entry->result = err;
		if (err) {
			Z_ERR(megaz->znd, "Metadata error ... disable zone: %u",
			      gc_entry->z_gc);
		}
		err = gc_finalize(gc_entry);
		if (err) {
			Z_ERR(megaz->znd, "GC: Failed to finalize: %d", err);
			gc_entry->result = err;
			goto out;
		}

		gc_verify_cache(megaz, gc_entry->z_gc);

		mutex_lock(&megaz->mz_io_mutex);
		err = _cached_to_tables(megaz, gc_entry->z_gc);
		mutex_unlock(&megaz->mz_io_mutex);
		if (err) {
			Z_ERR(megaz->znd, "Failed to purge journal: %d", err);
			gc_entry->result = err;
			goto out;
		}

		err = z_flush_bdev(megaz->znd);
		if (err) {
			gc_entry->result = err;
			goto out;
		}

		/* Release the zones for writing */
		dmz_reset_wp(megaz, gc_entry->z_gc);

		mutex_lock(&megaz->zp_lock);
		megaz->z_ptrs[gc_entry->z_gc] = 0 | non_seq;
		megaz->z_commit[gc_entry->z_gc] = 0;
		megaz->discard_count -= megaz->zfree_count[gc_entry->z_gc];
		megaz->zfree_count[gc_entry->z_gc] = Z_BLKSZ;

		megaz->z_gc_free++;
		if (megaz->z_gc_resv & Z_WP_GC_ACTIVE)
			megaz->z_gc_resv = gc_entry->z_gc;
		else if (megaz->z_meta_resv & Z_WP_GC_ACTIVE)
			megaz->z_meta_resv = gc_entry->z_gc;

		mutex_unlock(&megaz->zp_lock);

		Z_ERR(megaz->znd,
		      "GC %d: MZ# %d, z#0x%x, wp:%08x, free:%x finished.",
		      gc_entry->tag, megaz->mega_nr, gc_entry->z_gc,
		      megaz->z_ptrs[gc_entry->z_gc],
		      megaz->zfree_count[gc_entry->z_gc]);

		spin_lock_irqsave(&megaz->znd->gc_lock, flags);
		megaz->znd->gc_backlog--;
		megaz->znd->gc_active = NULL;
		spin_unlock_irqrestore(&megaz->znd->gc_lock, flags);

		ZDM_FREE(megaz->znd, gc_entry, sizeof(*gc_entry), KM_16);

		set_bit(DO_JOURNAL_MOVE, &megaz->flags);
		set_bit(DO_MEMPOOL, &megaz->flags);
		set_bit(DO_SYNC, &megaz->flags);
		do_meta_flush = 1;
	}
out:
	clear_bit(DO_GC_NO_PURGE, &megaz->flags);
	if (do_meta_flush) {
		struct zoned *znd = megaz->znd;

		if (!work_pending(&megaz->meta_work))
			queue_work(znd->meta_wq, &megaz->meta_work);
	}
	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void gc_work_task(struct work_struct *work)
{
	struct gc_state *gc_entry = NULL;
	unsigned long flags;
	struct zoned *znd;
	int err;

	if (!work)
		return;

	znd = container_of(to_delayed_work(work), struct zoned, gc_work);
	if (!znd)
		return;

	spin_lock_irqsave(&znd->gc_lock, flags);
	if (znd->gc_active)
		gc_entry = znd->gc_active;
	spin_unlock_irqrestore(&znd->gc_lock, flags);

	if (!gc_entry) {
		Z_ERR(znd, "ERROR: gc_active not set!");
		return;
	}

	err = z_zone_gc_compact(gc_entry);
	if (-EAGAIN == err) {
		unsigned long tval = msecs_to_jiffies(3);

		queue_delayed_work(znd->gc_wq, &znd->gc_work, tval);
	} else {
		on_timeout_activity(znd, 0);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static inline int is_reserved(struct megazone *megaz, const u32 z_pref)
{
	const u32 gc   = megaz->z_gc_resv & Z_WP_VALUE_MASK;
	const u32 meta = megaz->z_meta_resv & Z_WP_VALUE_MASK;

	return (gc == z_pref || meta == z_pref) ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int gc_immediate(struct megazone *megaz)
{
	int can_retry = 0;
	struct zoned *znd = megaz->znd;
	int queued;

	atomic_inc(&znd->gc_throttle);

	if (znd->gc_throttle.counter > 1) {
		Z_ERR(znd, " ... GC immediate .. in progress.");
		goto out;
	}

	mutex_unlock(&megaz->mz_io_mutex);
	flush_delayed_work(&znd->gc_work);
	mutex_lock(&megaz->mz_io_mutex);

	queued = gc_compact_check(megaz, 0);
	if (!queued) {
		Z_ERR(znd, " ... GC immediate .. failed to queue GC!!.");
		dump_stack();
		goto out;
	}

	mutex_unlock(&megaz->mz_io_mutex);
	can_retry = flush_delayed_work(&znd->gc_work);
	mutex_lock(&megaz->mz_io_mutex);
	if (can_retry)
		Z_ERR(znd, " ... GC flushed.");

out:
	atomic_dec(&znd->gc_throttle);

	return can_retry;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u64 z_acquire(struct megazone *megaz, u32 flags, u32 nblks, u32 *nfound)
{
	sector_t found = 0;
	u32 z_pref = megaz->z_current;

	found = _blkalloc(megaz, z_pref, flags, nblks, nfound);
	if (found || *nfound)
		goto out;

	/* no space left in zone .. explicitly close it */
	dmz_close_zone(megaz, z_pref);

	if (megaz->z_gc_free < 5) {
		Z_ERR(megaz->znd, "... alloc - gc low on free space.");
		gc_immediate(megaz);
	}

retry:
	for (z_pref = megaz->z_data; z_pref < megaz->z_count; z_pref++) {
		if (is_reserved(megaz, z_pref))
			continue;

		found = _blkalloc(megaz, z_pref, flags, nblks, nfound);
		if (found || *nfound) {
			megaz->z_current = z_pref;
			megaz->z_gc_free--;
			goto out;
		}
	}

	if (flags & Z_AQ_GC) {
		u32 gresv = megaz->z_gc_resv & Z_WP_VALUE_MASK;

		Z_ERR(megaz->znd, "MZ# %u: Using GC Reserve (%u)",
			megaz->mega_nr, gresv);
		found = _blkalloc(megaz, gresv, flags, nblks, nfound);
		megaz->z_gc_resv |= Z_WP_GC_ACTIVE;
	}

	if (flags & Z_AQ_META) {
		int can_retry;
		u32 mresv;

		mresv = megaz->z_meta_resv & Z_WP_VALUE_MASK;

		Z_ERR(megaz->znd, "MZ# %u: Using META Reserve (%u)",
			megaz->mega_nr, megaz->z_meta_resv);

		can_retry = gc_immediate(megaz);
		if (can_retry)
			goto retry;

		found = _blkalloc(megaz, mresv, flags, nblks, nfound);
	}

out:
	if (!found && (*nfound == 0)) {
		Z_ERR(megaz->znd, "%s: -> MZ# %u: Out of space.",
		       __func__, megaz->mega_nr);

		if (gc_immediate(megaz))
			goto retry;
	}
	return found;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void do_free_mapped(struct megazone *megaz, struct map_pg *mapped)
{
	struct zoned *znd = megaz->znd;
	u64 rbase = megaz->logical_map.r_base;
	u64 addr = mapped->lba;
	struct map_pg **table;
	int is_to = 1;
	int entry;

	if ((rbase <= addr) && (addr < (rbase + Z_BLKSZ)))
		is_to = 0;
	table = is_to ? megaz->sectortm : megaz->reversetm;
	entry = to_table_entry(znd, addr, is_to);

	if (table[entry]) {
		mutex_lock(&mapped->md_lock);
		if (mapped->mdata) {
			ZDM_FREE(znd, mapped->mdata, Z_C4K, PG_27);
			megaz->incore_count--;
		}
		mutex_unlock(&mapped->md_lock);

		if (table[entry])
			ZDM_FREE(znd, table[entry], sizeof(**table), KM_20);
		table[entry] = NULL;
	} else {
		Z_ERR(znd, " *** purge: %"PRIx64 " @ %d ????", addr, entry);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */


static int compare_lba(const void *x1, const void *x2)
{
	const struct map_pg *v1 = x1;
	const struct map_pg *v2 = x2;

	return (v1->lba < v2->lba) ? -1 : ((v1->lba > v2->lba) ? 1 : 0);
}

static int expire_old_pool(struct megazone *megaz, int count)
{
	const int use_wq = 0;
	int iter = count;
	int err = 0;
	int stale_count = 0;
	struct map_pg **stale = NULL;
	struct map_pg *expg;

	if (count > 1024)
		count = 1024;

	if (!count)
		goto out;

	stale = ZDM_CALLOC(megaz->znd, sizeof(*stale), count, KM_19);

	/* fill stale with dirty table pages */
	spin_lock(&megaz->map_pool_lock);
	stale_count = 0;
	expg = _pool_last(megaz);
	while (expg && stale_count < count) {
		struct map_pg *aux = _pool_prev(megaz, expg);

		if (is_expired(expg->age))
			if (!test_bit(IS_DIRTY, &expg->flags))
				stale[stale_count++] = expg;

		atomic_dec(&expg->refcount);
		expg = aux;
	}
	if (expg)
		atomic_dec(&expg->refcount);
	spin_unlock(&megaz->map_pool_lock);

	/* write dirty table pages */
	if (stale_count > 0) {
		sort(stale, stale_count, sizeof(*stale), compare_lba, NULL);

		for (iter = 0; iter < stale_count; iter++) {
			err = write_if_dirty(megaz, stale[iter], use_wq);
			if (err) {
				Z_ERR(megaz->znd, "Write failed: %d", err);
				goto out;
			}
		}
		sync_crc_pages(megaz);
	}

	/* Stage 2: Drop clean table pages from ram */
	if (test_bit(DO_GC_NO_PURGE, &megaz->flags))
		goto out;

	/* fill stale with clean expired table pages */
	spin_lock(&megaz->map_pool_lock);
	stale_count = 0;
	expg = _pool_last(megaz);
	while (expg && stale_count < count) {
		struct map_pg *aux = _pool_prev(megaz, expg);

		if (!test_bit(IS_DIRTY, &expg->flags) &&
		    (expg->refcount.counter == 1) &&
		    is_expired(expg->age)) {
			stale[stale_count++] = expg;
			list_del(&expg->inpool);
		}
		atomic_dec(&expg->refcount);
		expg = aux;
	}
	if (expg)
		atomic_dec(&expg->refcount);
	spin_unlock(&megaz->map_pool_lock);

	for (iter = 0; iter < stale_count; iter++) {
		expg = stale[iter];
		if (expg)
			do_free_mapped(megaz, expg);
	}

out:
	if (stale)
		ZDM_FREE(megaz->znd, stale, sizeof(*stale) * count, KM_19);

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int load_crc_meta_pg(struct megazone *megaz, struct crc_pg *pblock,
			    u64 pg_lba, __le16 crc16, int use_wq)
{
	int err = 0;

	if (pblock && !pblock->cdata) {
		__le16 *data = ZDM_ALLOC(megaz->znd, Z_C4K, PG_17);

		if (!data) {
			Z_ERR(megaz->znd, "Out of memory");
			err = -ENOMEM;
			goto out;
		}
		if (pg_lba) {
			__le16 check;
			int count = 1;

			if (warn_bad_lba(megaz, pg_lba))
				Z_ERR(megaz->znd,
				      "Bad CRC pg %" PRIx64, pg_lba);

			err = read_block(megaz->znd->ti, DM_IO_KMEM, data,
					 pg_lba, count, use_wq);
			if (err) {
				ZDM_FREE(megaz->znd, data, Z_C4K, PG_17);
				Z_ERR(megaz->znd, "Read of CRC page @%" PRIx64
				      " failed: %d", pg_lba, err);
				goto out;
			}

			check = crc_md_le16(data, Z_CRC_4K);
			if (check == crc16)
				pblock->last_write = pg_lba;
			else
				Z_ERR(megaz->znd,
				      "CRC PG: %" PRIx64 " from %" PRIx64
				      " calc: %04x, ex: %04x last: %" PRIx64,
				      pblock->lba, pg_lba, le16_to_cpu(check),
				      le16_to_cpu(crc16), pblock->last_write);
		}
		pblock->cdata = data;
	}
	if (pblock)
		pblock->age = jiffies_64;

out:
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * get_meta_pg_crc() - Given an LBA of lookup table data load the page of CRC's
 * @param megaz:
 * @param maddr:
 * @param is_to
 * @param use_wq
 *
 * Return: a crc_pg structure
 */
static struct crc_pg *get_meta_pg_crc(struct megazone *megaz,
		struct map_addr *maddr, int is_to, int use_wq)
{
	struct crc_pg *pblock = NULL;
	int pg_no = maddr->crc / 2048;
	__le16 crc16 = 0;
	u64 pg_lba = 0ul;
	int is_rtz = is_revmap(megaz, maddr);
	int err;

	if (is_rtz == is_to) {
		u64 rbase = megaz->logical_map.r_base;

		Z_ERR(megaz->znd, "CRC: is_rtz == is_to [%d != %d] lba: %"
		      PRIx64, is_rtz, is_to, maddr->dm_s);

		Z_ERR(megaz->znd, "MZOFF: %"PRIx64
				 " DM_S: %"PRIx64
				 " rbase: %"PRIx64
				 " pg_no: %d",
		      maddr->crc, maddr->dm_s, rbase, pg_no);
	}

	if (!is_to) {
		pblock = &megaz->rtm_crc[pg_no];
		mutex_lock(&megaz->mapkey_lock);
		crc16 = megaz->bmkeys->rtm_crc_pg[pg_no];
		pg_lba = le64_to_cpu(megaz->bmkeys->rtm_crc_lba[pg_no]);
		mutex_unlock(&megaz->mapkey_lock);
	} else {
		pblock = &megaz->stm_crc[pg_no];
		mutex_lock(&megaz->mapkey_lock);
		crc16 = megaz->bmkeys->stm_crc_pg[pg_no];
		pg_lba = le64_to_cpu(megaz->bmkeys->stm_crc_lba[pg_no]);
		mutex_unlock(&megaz->mapkey_lock);
	}

	if (pblock->last_write && pg_lba != pblock->last_write)
		Z_ERR(megaz->znd, "load1 %"PRIx64", last %"PRIx64,
		      pg_lba, pblock->last_write);

	err = load_crc_meta_pg(megaz, pblock, pg_lba, crc16, use_wq);
	if (err)
		pblock = NULL;

	return pblock;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u64 z_metadata_lba(struct megazone *megaz, struct map_pg *map, u32 *num)
{
	struct zoned *znd = megaz->znd;
	u32 nblks = 1;
	u64 lba = map->lba;

	if (lba < znd->data_lba) {
		*num = 1;
		return map->lba;
	}
	return z_acquire(megaz, Z_AQ_META, nblks, num);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static u64 z_metacrc_lba(struct megazone *megaz, struct crc_pg *map, u32 *num)
{
	struct zoned *znd = megaz->znd;
	u32 nblks = 1;
	u64 lba = map->lba;

	if (lba < znd->data_lba) {
		*num = 1;
		return map->lba;
	}
	return z_acquire(megaz, Z_AQ_META, nblks, num);
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int write_if_dirty(struct megazone *megaz, struct map_pg *oldest, int wq)
{
	int rcode = 0;
	struct map_addr maddr;

	if (!oldest)
		return rcode;

	atomic_inc(&oldest->refcount);
	if (test_bit(IS_DIRTY, &oldest->flags) && oldest->mdata) {
		u64 dm_s = oldest->lba;
		u64 lba;
		u32 nfound;

		/*
		 * We need the maddr to acquire a free block in
		 * the correct megazone
		 */
		map_addr_calc(megaz->znd, dm_s, &maddr);
		lba = z_metadata_lba(megaz, oldest, &nfound);
		if (lba && nfound) {
			int rcwrt;
			int count = 1;
			int crce = maddr.crc % 2048;
			struct crc_pg *pblock;
			int is_to = !is_revmap(megaz, &maddr);
			__le16 md_crc;

			Z_DBG(megaz->znd, "Write if dirty: %" PRIx64
			      " -> is map to %d", dm_s, is_to);

			pblock = get_meta_pg_crc(megaz, &maddr, is_to, wq);
			if (!pblock) {
				Z_ERR(megaz->znd,
				      "%s: Out of space for metadata?",
				      __func__);
				rcode = -ENOSPC;
				goto out;
			}

			md_crc = crc_md_le16(oldest->mdata, Z_CRC_4K);
			rcwrt = write_block(megaz->znd->ti, DM_IO_KMEM,
					    oldest->mdata, lba, count, wq);
			oldest->age = jiffies_64;
			oldest->last_write = lba;

			atomic_inc(&pblock->refcount);
			pblock->cdata[crce] = md_crc;
			set_bit(IS_DIRTY, &pblock->flags);
			pblock->age = jiffies_64;
			atomic_dec(&pblock->refcount);

			if (rcwrt) {
				Z_ERR(megaz->znd,
				      "write_page: %" PRIx64 " -> %" PRIx64
				      " ERR: %d", oldest->lba, lba, rcwrt);
				rcode = rcwrt;
				goto out;
			}

			if (crc_md_le16(oldest->mdata, Z_CRC_4K) == md_crc)
				clear_bit(IS_DIRTY, &oldest->flags);
			else
				Z_ERR(megaz->znd,
				     "Page Mod during write: %" PRIx64, dm_s);

			if (lba < megaz->znd->data_lba)
				goto out;

			Z_DBG(megaz->znd, "meta: %" PRIx64 " -> %" PRIx64
			      " (table entry)", dm_s, lba);

			rcwrt = z_mapped_addmany(megaz, dm_s, lba, nfound);
			if (rcwrt) {
				Z_ERR(megaz->znd, "%s: Journal MANY failed.",
				      __func__);
				rcode = rcwrt;
				goto out;
			}

		} else {
			Z_ERR(megaz->znd, "%s: Out of space for metadata?",
			      __func__);
			rcode = -ENOSPC;
			goto out;
		}
	}
out:
	atomic_dec(&oldest->refcount);

	if (rcode)
		megaz->meta_result = rcode;

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int keep_active_pages(struct megazone *megaz, int allowed_pages)
{
	int rc = 0;

	if (megaz->incore_count > allowed_pages) {
		int count = megaz->incore_count - allowed_pages;

		rc = expire_old_pool(megaz, count);
		if (rc)
			Z_ERR(megaz->znd, "%s: Failed to remove oldest pages!",
				__func__);
	}

	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int write_if_pg_blk_dirty(struct megazone *megaz,
				 struct crc_pg *pblock,
				 __le64 *paddrs, __le16 *crc16, int pg_no)
{
	int rcode = 0;

	atomic_inc(&pblock->refcount);

	if (!pblock->cdata)
		goto out;	/* nothing to write. */

	if (test_bit(IS_DIRTY, &pblock->flags)) {
		u64 dm_s = pblock->lba;
		u64 lba;
		u32 nfound;

		lba = z_metacrc_lba(megaz, pblock, &nfound);
		if (lba && nfound) {
			int count = 1;
			int use_wq = 0;
			void *data = pblock->cdata;
			u32 crcb4 = crcpg(data);

			rcode = write_block(megaz->znd->ti, DM_IO_KMEM,
					    data, lba, count, use_wq);
			if (rcode) {
				Z_ERR(megaz->znd,
				      "%s: %d: %" PRIx64 " -> %" PRIx64
				      " ERR: %d", __func__, pg_no,
				      pblock->lba, lba, rcode);
				goto out;
			}

			mutex_lock(&megaz->mapkey_lock);
			paddrs[pg_no] = cpu_to_le64(lba);
			crc16[pg_no] = crc_md_le16(data, Z_CRC_4K);
			mutex_unlock(&megaz->mapkey_lock);
			pblock->last_write = lba;
			pblock->age = jiffies_64;
			if (crcpg(data) == crcb4)
				clear_bit(IS_DIRTY, &pblock->flags);

			Z_DBG(megaz->znd, "meta: %" PRIx64 " -> %" PRIx64
			      " (crc entry)", dm_s, lba);

			if (lba < megaz->znd->data_lba)
				goto out;

			rcode = z_mapped_addmany(megaz, dm_s, lba, nfound);
			if (rcode) {
				Z_ERR(megaz->znd, "%s: Journal MANY failed.",
				      __func__);
				goto out;
			}

		} else {
			Z_ERR(megaz->znd, "%s: Out of space for metadata?",
			      __func__);
			rcode = -ENOSPC;
			goto out;
		}
	}
out:
	atomic_dec(&pblock->refcount);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */


static int write_purge_crc_pages(struct megazone *megaz, struct crc_pg *pgs,
				 __le64 *lbas, __le16 *crcs)
{
	int err = 0;
	int pg_no = 0;

	for (pg_no = 0; pg_no < 32; pg_no++) {
		int sync_err;
		struct crc_pg *pblock = &pgs[pg_no];

		atomic_inc(&pblock->refcount);
		sync_err = write_if_pg_blk_dirty(megaz, pblock, lbas,
						 crcs, pg_no);
		atomic_dec(&pblock->refcount);
		if (sync_err)
			err = sync_err;

		if ((pblock->cdata)
		    && is_expired(pblock->age)
		    && (pblock->refcount.counter == 0)
		    && !test_bit(DO_GC_NO_PURGE, &megaz->flags))
			ZDM_FREE(megaz->znd, pblock->cdata, Z_C4K, PG_17);
	}
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int sync_crc_pages(struct megazone *megaz)
{
	int err = 0;
	int rcode;

	/*
	 * do this in lba order:
	 *    - Reverse ->  0 - 31 blocks
	 *    - Forward -> 32 - 63 blocks
	 */
	rcode = write_purge_crc_pages(megaz, megaz->rtm_crc,
				      megaz->bmkeys->rtm_crc_lba,
				      megaz->bmkeys->rtm_crc_pg);
	if (rcode)
		err = rcode;

	rcode = write_purge_crc_pages(megaz, megaz->stm_crc,
				      megaz->bmkeys->stm_crc_lba,
				      megaz->bmkeys->stm_crc_pg);
	if (rcode)
		err = rcode;

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_pg *get_map_table_entry(struct megazone *megaz, u64 lba,
				       int is_to)
{
	struct map_pg *found = NULL;
	struct map_pg **table = is_to ? megaz->sectortm : megaz->reversetm;
	int entry = to_table_entry(megaz->znd, lba, is_to);

	found = table[entry];
	if (!found) {
		/* if we didn't find one .. create it */
		found = ZDM_ALLOC(megaz->znd, sizeof(*found), KM_20);
		if (found) {
			found->lba = lba;
			found->mdata = NULL;
			mutex_init(&found->md_lock);
			table[entry] = found;
		} else {
			Z_ERR(megaz->znd, "NO MEM for mapped_t !!!");
		}
	}
	return found;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void megazone_free_one(struct megazone *megaz)
{
	if (megaz) {
		struct zoned *znd = megaz->znd;
		size_t mapsz = Z_BLKSZ * sizeof(struct map_pg *);

		if (megaz->sectortm)
			ZDM_FREE(megaz->znd, megaz->sectortm, mapsz, VM_21);
		if (megaz->reversetm)
			ZDM_FREE(megaz->znd, megaz->reversetm, mapsz, VM_22);

		if (megaz->sync_io) {
			size_t ssz = sizeof(*megaz->sync_io);

			ZDM_FREE(megaz->znd, megaz->sync_io, ssz, MP_SIO);
			megaz->z_ptrs = NULL;
			megaz->zfree_count = NULL;
			megaz->bmkeys = NULL;
		}
		if (megaz->cow_block)
			ZDM_FREE(znd, megaz->cow_block, Z_C4K, PG_02);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int megazone_init_one_b(struct megazone *megaz)
{
	int rcode = 0;
	struct zoned *znd = megaz->znd;

	megaz->sync_io = ZDM_ALLOC(znd, sizeof(*megaz->sync_io), MP_SIO);
	megaz->sectortm = ZDM_CALLOC(znd, Z_BLKSZ, sizeof(struct map_pg *),
				     VM_21);
	megaz->reversetm = ZDM_CALLOC(znd, Z_BLKSZ, sizeof(struct map_pg *),
				      VM_22);
	if (!megaz->sync_io || !megaz->sectortm || !megaz->reversetm) {
		rcode = -ENOMEM;
		goto out;
	}

	megaz->bmkeys = &megaz->sync_io->bmkeys;
	megaz->z_ptrs = megaz->sync_io->z_ptrs;
	megaz->zfree_count = megaz->sync_io->zfree;
	megaz->incore_count = 0;
	megaz->last_w = BAD_ADDR;
	megaz->bmkeys->sig0 = Z_KEY_SIG;
	megaz->bmkeys->sig1 = cpu_to_le64(Z_KEY_SIG);
	megaz->bmkeys->magic = cpu_to_le64(Z_TABLE_MAGIC);
	megazone_fill_lam(megaz, &megaz->logical_map);
	if (megaz->z_count > znd->mz_provision) {
		u64 lba = megaz->logical_map.crc_low;
		int znr;

		for (znr = 0; znr < megaz->z_count; znr++)
			megaz->zfree_count[znr] = Z_BLKSZ;

		for (; znr < 1024; znr++) {
			megaz->z_ptrs[znr] = 0xffffffff;
			megaz->zfree_count[znr] = 0;
		}

		megaz->z_gc_free = megaz->z_count - 2;
		megaz->z_meta_resv = megaz->z_count - 2;
		megaz->z_gc_resv = megaz->z_count - 1;
		megaz->z_gc_free -= 2;
		megaz->z_data = 0;
		megaz->z_current = megaz->z_data;

		for (znr = 0; znr < 32; znr++) {
			megaz->rtm_crc[znr].lba = lba + znr;
			megaz->stm_crc[znr].lba = lba + znr + MZKY_NCRC;
			if (test_bit(ZF_POOL_CRCS, &megaz->znd->flags)) {
				megaz->bmkeys->rtm_crc_lba[znr] =
					megaz->rtm_crc[znr].lba;
				megaz->bmkeys->stm_crc_lba[znr] =
					megaz->stm_crc[znr].lba;
			}
			mutex_init(&megaz->rtm_crc[znr].lock_pg);
			mutex_init(&megaz->stm_crc[znr].lock_pg);
		}
	}

out:
	if (rcode)
		megazone_free_one(megaz);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int megazone_init_one_a(struct megazone *megaz)
{
	int rcode = 0;

	megaz->flags = 0;

	INIT_LIST_HEAD(&megaz->jlist);
	INIT_LIST_HEAD(&megaz->smtpool);

	spin_lock_init(&megaz->map_pool_lock);
	spin_lock_init(&megaz->jlock);

	mutex_init(&megaz->vcio_lock);
	mutex_init(&megaz->zp_lock);
	mutex_init(&megaz->discard_lock);
	mutex_init(&megaz->mz_io_mutex);
	mutex_init(&megaz->mapkey_lock);
	INIT_WORK(&megaz->meta_work, meta_work_task);

	megaz->incore_count = 0;
	megaz->last_w = BAD_ADDR;

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int megazone_init(struct zoned *znd)
{
	int rcode = 0;
	struct megazone *megazones;
	u32 iter;

	megazones = ZDM_CALLOC(znd, znd->mz_count,
				sizeof(*megazones), KM_25);
	if (!megazones) {
		Z_ERR(znd, "No memory for megazone array.");
		rcode = -ENOMEM;
		goto out;
	}
	znd->z_mega = megazones;

	for (iter = 0; iter < znd->mz_count; iter++) {
		u64 remaining = znd->data_zones - (1024 * iter);
		struct megazone *megaz = &megazones[iter];

		megaz->mega_nr = iter;
		megaz->znd = znd;
		megaz->z_count = remaining < 1024 ? remaining : 1024;

		rcode = megazone_init_one_a(megaz);
		if (rcode) {
			Z_ERR(megaz->znd,
			      "Catastrophic ERR megazone init A failed!!");
			goto out;
		}
	}

	for (iter = 0; iter < znd->mz_count; iter++) {
		struct megazone *megaz = &megazones[iter];

		rcode = megazone_init_one_b(megaz);
		if (rcode) {
			Z_ERR(megaz->znd,
			      "Catastrophic ERR megazone init B failed!!");
			goto out;
		}
	}

out:
	if (rcode)
		megazone_free_all(znd);

	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int sync_mapped_pages(struct megazone *megaz)
{
	const int use_wq = 0;
	int err = 0;
	int entry;

	/* NOTE: This is Prefering CPU for memory (a linked list) */
	for (entry = 0; entry < Z_BLKSZ; entry++) {
		struct map_pg *expg = megaz->sectortm[entry];

		if (expg && expg->mdata) {
			if (test_bit(IS_DIRTY, &expg->flags)) {
				err = write_if_dirty(megaz, expg, use_wq);
				if (err)
					goto out;
			}
		}
	}

	for (entry = 0; entry < Z_BLKSZ; entry++) {
		struct map_pg *expg = megaz->reversetm[entry];

		if (expg && expg->mdata) {
			if (test_bit(IS_DIRTY, &expg->flags)) {
				err = write_if_dirty(megaz, expg, use_wq);
				if (err)
					goto out;
			}
		}
	}
out:
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int do_sync_metadata(struct megazone *megaz)
{
	int err = _cached_to_tables(megaz, MAX_ZONES_PER_MZ);

	if (err)
		goto out;

	sync_mapped_pages(megaz);
	sync_crc_pages(megaz);

out:
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * Release resources as ZDM is being removed
 */
static void mapped_free(struct megazone *megaz, struct map_pg *mapped)
{
	if (mapped) {
		mutex_lock(&mapped->md_lock);
		WARN_ON(test_bit(IS_DIRTY, &mapped->flags));
		if (mapped->mdata) {
			ZDM_FREE(megaz->znd, mapped->mdata, Z_C4K, PG_27);
			megaz->incore_count--;
		}
		mutex_unlock(&mapped->md_lock);
		ZDM_FREE(megaz->znd, mapped, sizeof(*mapped), KM_20);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int flush_sector_map(struct megazone *megaz)
{
	int ii;
	int err = 0;

	if (!megaz->sectortm)
		return err;

	for (ii = 0; ii < Z_BLKSZ; ii++) {
		if (megaz->sectortm[ii] && megaz->sectortm[ii]->mdata)
			err |= write_if_dirty(megaz, megaz->sectortm[ii], 1);
	}

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int flush_reverse_map(struct megazone *megaz)
{
	int ii;
	int err = 0;

	if (!megaz->reversetm)
		return err;

	for (ii = 0; ii < Z_BLKSZ; ii++) {
		if (megaz->reversetm[ii] && megaz->reversetm[ii]->mdata)
			err |= write_if_dirty(megaz, megaz->reversetm[ii], 1);
	}

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int release_table_pages(struct megazone *megaz)
{
	int entry;
	int err;

	INIT_LIST_HEAD(&megaz->smtpool);

	err = flush_sector_map(megaz);
	if (err)
		goto out;

	err = flush_reverse_map(megaz);
	if (err)
		goto out;

	if (megaz->sectortm) {
		for (entry = 0; entry < Z_BLKSZ; entry++) {
			mapped_free(megaz, megaz->sectortm[entry]);
			megaz->sectortm[entry] = NULL;
		}
	}

	if (megaz->reversetm) {
		for (entry = 0; entry < Z_BLKSZ; entry++) {
			mapped_free(megaz, megaz->reversetm[entry]);
			megaz->reversetm[entry] = NULL;
		}
	}

out:
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int release_journal_pages(struct megazone *megaz)
{
	struct list_head *_jhead = &(megaz->jlist);
	struct map_cache *jrnl;
	struct map_cache *jtmp;

	if (list_empty(_jhead))
		return 0;

	list_for_each_entry_safe(jrnl, jtmp, _jhead, jlist) {
		/** move all the journal entries into the SLT */
		spin_lock(&megaz->jlock);
		list_del(&jrnl->jlist);
		ZDM_FREE(megaz->znd, jrnl->jdata, Z_C4K, PG_08);
		ZDM_FREE(megaz->znd, jrnl, sizeof(*jrnl), KM_07);
		spin_unlock(&megaz->jlock);
	}
	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void megazone_free_all(struct zoned *znd)
{
	if (znd->z_mega) {
		u32 iter;

		for (iter = 0; iter < znd->mz_count; iter++) {
			struct megazone *megaz = &znd->z_mega[iter];

			if (megaz) {
				release_table_pages(megaz);
				release_journal_pages(megaz);
				megazone_free_one(megaz);
			}
		}
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void megazone_flush_all(struct zoned *znd)
{
	set_bit(ZF_FREEZE, &znd->flags);
	if (znd->z_mega) {
		u32 iter;

		atomic_inc(&znd->gc_throttle);

		mod_delayed_work(znd->gc_wq, &znd->gc_work, 0);
		flush_delayed_work(&znd->gc_work);

		for (iter = 0; iter < znd->mz_count; iter++) {
			struct megazone *megaz = &znd->z_mega[iter];

			if (megaz) {
				clear_bit(DO_GC_NO_PURGE, &megaz->flags);
				set_bit(DO_JOURNAL_MOVE, &megaz->flags);
				set_bit(DO_MEMPOOL, &megaz->flags);
				set_bit(DO_SYNC, &megaz->flags);
				queue_work(znd->meta_wq, &megaz->meta_work);
			}
		}
		flush_workqueue(znd->meta_wq);
		mod_delayed_work(znd->gc_wq, &znd->gc_work, 0);
		flush_delayed_work(&znd->gc_work);
		atomic_dec(&znd->gc_throttle);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void megazone_destroy(struct zoned *znd)
{
	set_bit(ZF_FREEZE, &znd->flags);
	if (znd->z_mega) {
		size_t zmsz = znd->mz_count * sizeof(*znd->z_mega);

		megazone_flush_all(znd);
		megazone_free_all(znd);
		ZDM_FREE(znd, znd->z_mega, zmsz, KM_25);
	}
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * dm_s is a logical sector that maps 1:1 to the whole disk in 4k blocks
 * Here the logical LBA and field are calculated for the lookup table
 * where the physical LBA can be read from disk.
 */
static int map_addr_data(struct zoned *znd, u64 dm_s, struct map_addr *out)
{
	u64 zone_nr = dm_s / Z_BLKSZ;
	u64 mz_nr = zone_nr / 1024;

	/* offset: blocks from base of mega zone */
	u64 offset = dm_s - (mz_nr * Z_BLKSZ * 1024);
	u64 dm_tbl_s = offset / 1024;

	/*
	 *  In that block, which index (as an array of 1024 entries?
	 *  -> entry in the set [0-1024)
	 */
	u64 entry = offset - (dm_tbl_s * 1024);

	/* Logically what LBA is the table block? -> lut_s */
	u64 b_addr = dm_tbl_s + (mz_nr * Z_BLKSZ * 1024);
	u64 pool = dm_tbl_s + znd->pool_lba;

	/*
	 * NOTE: CRC pages start at b_addr+0
	 *    REVERSE map table starts at b_addr + (1 * zone size)
	 *    FORWARD map table starts at b_addr + (2 * zone size)
	 */
	b_addr += Z_BLKSZ;

	out->zone_id = zone_nr;
	out->mz_id = mz_nr;

	/* CRC lookup table mapping: */
	out->crc = dm_s & 0xFFFF;

	out->offentry = entry;          /* (0->1024] */
	out->lut_r = b_addr + Z_BLKSZ;
	out->lut_s = b_addr + (2 * Z_BLKSZ);

	if (test_bit(ZF_POOL_FWD, &znd->flags))
		out->lut_s = pool + (mz_nr << Z_BLKBITS);
	if (test_bit(ZF_POOL_REV, &znd->flags))
		out->lut_r = out->lut_s + (znd->mz_count << Z_BLKBITS);

	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int map_addr_meta(struct zoned *znd, u64 dm_s, struct map_addr *out)
{
	u64 mz_nr    = dm_s >> 16;
	u64 block    = dm_s & 0xFFFF;
	u64 zone_nr  = ZDM_SECTOR_MAP_ZNR;
	u64 offset;
	u64 dm_tbl_s;
	u64 entry;
	u64 pool;

	if (mz_nr > znd->mz_count) {
		mz_nr -= znd->mz_count;
		zone_nr = ZDM_RMAP_ZONE;
	}
	if (mz_nr > znd->mz_count) {
		mz_nr = block / 64;
		zone_nr = ZDM_CRC_STASH_ZNR;
		offset = (zone_nr << Z_BLKBITS) + (block % 64);
	} else {
		offset = (zone_nr << Z_BLKBITS) + block;
	}
	dm_tbl_s = offset / 1024;
	entry = offset - (dm_tbl_s * 1024);

	out->zone_id = zone_nr; /* no containing data zone */
	out->mz_id = mz_nr;     /* simulated mz_id */

	/* CRC table mapping: */
	out->crc = dm_s & 0xFFFF;
	out->offentry = entry;

	/* not sure this pool, lut_s, lut_r makes any sense for metadata,
	 * there are no backing blocks for metadata as the data is pinned
	 */
	pool = znd->pool_lba + (block / 1024);
	out->lut_s = pool + (mz_nr << Z_BLKBITS);

	if (!test_bit(ZF_POOL_FWD, &znd->flags))
		Z_ERR(znd, "Invalid config: FWD map must be in metadata pool.");

	if (test_bit(ZF_POOL_REV, &znd->flags))
		out->lut_r = out->lut_s + (znd->mz_count << Z_BLKBITS);
	else
		out->lut_r = (block / 1024)
			   + (((mz_nr * 1024) + ZDM_RMAP_ZONE) << Z_BLKBITS);

	return 0;
}

/**
 * dm_s is a logical sector that maps 1:1 to the whole disk in 4k blocks
 * Here the logical LBA and field are calculated for the lookup table
 * where the physical LBA can be read from disk.
 */
static int map_addr_calc(struct zoned *znd, u64 origin, struct map_addr *out)
{
	int err;

	out->dm_s = origin;
	if (origin < znd->data_lba)
		err = map_addr_meta(znd, origin - znd->pool_lba, out);
	else
		err = map_addr_data(znd, origin - znd->data_lba, out);

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/* data sector (fs layer) -> mapper sector */
/**
 * s_nr is a logical sector that maps 1:1 to
 * to the subset of the disk presented as a block device to
 * an upper layer (typically a file-system or raid).
 *
 * read/write to this level are mapped onto dm_s
 */
static int map_addr_to_zdm(struct zoned *znd, u64 s_nr, struct map_addr *out)
{
#define LOW_CHUNK  ((0x400ul -  znd->mz_provision)      << Z_BLKBITS)
#define EXPAND      (0x400ul                            << Z_BLKBITS)

	u64 dm_s = 0;
	u64 s = s_nr;

	if (s < LOW_CHUNK) {
		dm_s = s;
	} else {
		u64 jno;
		u64 joff;

		s -= LOW_CHUNK;
		jno = s / LOW_CHUNK;
		joff = s - (jno * LOW_CHUNK);
		jno++;
		dm_s = (jno * EXPAND) + joff;
	}

	dm_s += znd->data_lba;
	out->dm_s = dm_s;
	map_addr_calc(znd, dm_s, out);

	return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * ---------------------------------------------------------------------
 *
 *   Load a page of the sector lookup table that maps to sm->lut_s.
 *
 *   This sector is normally stored within the zone data sectors
 *    co-located with the upper level data.
 *
 *   When no sector has been written fill a new block of the memory
 *   pool with 0xff
 */
static int load_page(struct megazone *megaz, struct map_pg *mapped, u64 lba,
		     int is_to)
{
	struct map_addr maddr;
	u64 lba48;
	int rcode = 0;

	/**
	 * This table entry may be on-disk, if so it needs to
	 * be loaded.
	 * If not it needs to be initialized to 0xFF
	 */



	/* may be recursive to load_page */
	map_addr_calc(megaz->znd, lba, &maddr);
	lba48 = z_lookup(megaz, &maddr);
	if (lba48) {
		const int count = 1;
		const int use_wq = 1;
		const int crce = maddr.crc % 2048;
		int rd;
		struct crc_pg *pblock;
		__le16 check;

		if (mapped->last_write == lba48)
			Z_DBG(megaz->znd,
			      "Page RE-LOAD %" PRIx64 " from %" PRIx64,
			      mapped->lba, lba48);

		atomic_inc(&mapped->refcount);
		mutex_lock(&mapped->md_lock);
		if (warn_bad_lba(megaz, lba48))
			Z_ERR(megaz->znd, "Bad PAGE %" PRIx64, lba48);

		rd = read_block(megaz->znd->ti, DM_IO_KMEM, mapped->mdata,
				lba48, count, use_wq);

		check = crc_md_le16(mapped->mdata, Z_CRC_4K);
		mutex_unlock(&mapped->md_lock);
		atomic_dec(&mapped->refcount);
		if (rd) {
			Z_ERR(megaz->znd, "%s: read_block: ERROR: %d",
				__func__, rd);
			rcode = -EIO;
			goto out;
		}
		pblock = get_meta_pg_crc(megaz, &maddr, is_to, use_wq);
		if (!pblock) {
			Z_ERR(megaz->znd, "%s: Out of space for metadata?",
				__func__);
			rcode = -ENOSPC;
			goto out;
		}
		atomic_inc(&pblock->refcount);
		mutex_lock(&pblock->lock_pg);
		if (pblock->cdata[crce] == check)
			mapped->last_write = lba48;
		mutex_unlock(&pblock->lock_pg);
		atomic_dec(&pblock->refcount);
		if (pblock->cdata[crce] != check) {
			/* FIXME:!! */
			int count;
			u64 lba_recheck;

			map_addr_calc(megaz->znd, lba, &maddr);
			lba_recheck = z_lookup(megaz, &maddr);

			Z_ERR(megaz->znd,
			      "Sanity: %" PRIx64 " mapped to %" PRIx64 " vs %"
			      PRIx64 "", lba, lba_recheck, lba48);

			Z_ERR(megaz->znd,
			      "Corrupt metadata: %" PRIx64 " from %" PRIx64
			      " [%04x != %04x] crc lba: %" PRIx64 " flags:%lx",
			      lba, lba48, le16_to_cpu(check),
			      le16_to_cpu(pblock->cdata[crce]),
			      pblock->lba, mapped->flags);

			Z_ERR(megaz->znd,
			      "load_page: %" PRIx64 " from lba:%" PRIx64
			      " last written to: %" PRIx64 " - map_to? %d",
			      mapped->lba, lba48, mapped->last_write,
			      is_to);

			mutex_lock(&mapped->md_lock);
			for (count = 0; count < 1024; count++) {
				Z_ERR(megaz->znd, "mapped->mdata[%d] -> %08x",
				      count, mapped->mdata[count]);
			}
			mutex_unlock(&mapped->md_lock);

			megaz->meta_result = -ENOSPC;
			rcode = -EIO;
			goto out;
		}
		rcode = 1;
	}

out:
	return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int map_entry_page(struct megazone *megaz, struct map_pg *mapped,
			  u64 lba, int is_to)
{
	int rc = -ENOMEM;

	atomic_inc(&mapped->refcount);
	mutex_lock(&mapped->md_lock);
	mapped->mdata = ZDM_ALLOC(megaz->znd, Z_C4K, PG_27);
	if (mapped->mdata)
		memset(mapped->mdata, 0xFF, Z_C4K);
	mutex_unlock(&mapped->md_lock);
	if (!mapped->mdata) {
		Z_ERR(megaz->znd, "%s: Out of memory.", __func__);
		atomic_dec(&mapped->refcount);
		mapped = NULL;
		goto out;
	}
	rc = load_page(megaz, mapped, lba, is_to);
	if (rc < 0) {
		Z_ERR(megaz->znd, "%s: load_page from %" PRIx64
		      " [to? %d] error: %d", __func__, lba,
		      is_to, rc);
		atomic_dec(&mapped->refcount);
		ZDM_FREE(megaz->znd, mapped->mdata, Z_C4K, PG_27);
		mapped = NULL;
		goto out;
	}
	megaz->incore_count++;
	mapped->age = jiffies_64;
	pool_add(megaz, mapped);
	atomic_dec(&mapped->refcount);

	Z_DBG(megaz->znd, "Page loaded: lba: %" PRIx64, lba);
out:
	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_pg *get_map_entry(struct megazone *megaz,
				    struct map_addr *maddr, int is_to)
{
	u64 lba = is_to ? maddr->lut_s : maddr->lut_r;
	struct map_pg *mapped = get_map_table_entry(megaz, lba, is_to);

	if (mapped) {
		if (!mapped->mdata) {
			int rc = map_entry_page(megaz, mapped, lba, is_to);

			if (rc < 0) {
				megaz->meta_result = rc;
				mapped = NULL;
			}
		}
	} else {
		Z_ERR(megaz->znd,
		      "%s: No table for %" PRIx64 " page# %" PRIx64 ".",
		      __func__, maddr->dm_s, lba);
	}
	return mapped;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/* load a page of the (sector -> lba) sector map table into core memory */
static struct map_pg *sector_map_entry(struct megazone *megaz,
				       struct map_addr *maddr)
{
	const int is_to = 1;

	return get_map_entry(megaz, maddr, is_to);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/* load a page of the (lba -> sector) reverse map table into core memory */
static struct map_pg *reverse_map_entry(struct megazone *megaz,
					struct map_addr *maddr)
{
	const int is_to = 0;

	return get_map_entry(megaz, maddr, is_to);
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/* resolve a sector mapping to the on-block-device lba via the lookup table */
static u64 locate_sector(struct megazone *megaz, struct map_addr *maddr)
{
	struct map_pg *mapped;
	u64 old_phy = 0;

	mapped = sector_map_entry(megaz, maddr);
	if (mapped) {
		atomic_inc(&mapped->refcount);
		if (mapped->mdata) {
			__le32 delta;

			mutex_lock(&mapped->md_lock);
			delta = mapped->mdata[maddr->offentry];
			mutex_unlock(&mapped->md_lock);
			old_phy = map_value(megaz, delta);
			mapped->age = jiffies_64;
			incore_hint(megaz, mapped);
		}
		atomic_dec(&mapped->refcount);
	}
	return old_phy;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/*
 * when is_fwd is 0:
 *  - maddr->dm_s is a sector -> lba.
 *         in this case the old lba is discarded and scheduled for cleanup
 *         by updating the reverse map lba tables noting that this location
 *         is now unused.
 * when is_fwd is 0:
 *  - maddr->dm_s is an lba, lba -> dm_s
 */

static int update_map_entry(struct megazone *megaz, struct map_pg *mapped,
			    struct map_addr *maddr, u64 to_addr, int is_fwd)
{
	int err = -ENOMEM;

	if (mapped && mapped->mdata) {
		u64 index = maddr->offentry;
		__le32 delta;
		__le32 value;
		int was_updated = 0;

		atomic_inc(&mapped->refcount);
		mutex_lock(&mapped->md_lock);
		delta = mapped->mdata[index];
		mutex_unlock(&mapped->md_lock);
		err = map_encode(megaz, to_addr, &value);
		if (!err) {
			mutex_lock(&mapped->md_lock);
			/*
			 * if the value is modified update the table and
			 * place it on top of the active [inpool] list
			 * this will keep the chunk of lookup table in
			 * memory.
			 */
			if (mapped->mdata[index] != value) {
				mapped->mdata[index] = value;
				mapped->age = jiffies_64;
				set_bit(IS_DIRTY, &mapped->flags);
				was_updated = 1;
				incore_hint(megaz, mapped);
			} else {
				Z_ERR(megaz->znd,
					"*ERR* %" PRIx64
					" -> mdata[index] (%x) == (%x)",
					maddr->dm_s,
					mapped->mdata[index], value);
				dump_stack();
			}
			mutex_unlock(&mapped->md_lock);
		} else {
			Z_ERR(megaz->znd,
				"*ERR* Mapping: %" PRIx64 " to %" PRIx64,
				to_addr, maddr->dm_s);
		}

		if (was_updated && is_fwd && (delta != MZTEV_UNUSED)) {
			u64 old_phy = map_value(megaz, delta);

			/*
			 * add to discard list of the controlling mzone
			 * for the 'delta' physical block
			 * unlikly, but they may be different megazones
			 */
			Z_DBG(megaz->znd, "%s: unused_phy: %" PRIu64
			      " (new lba: %" PRIu64 ")",
			      __func__, old_phy, to_addr);

			WARN_ON(old_phy >= megaz->znd->nr_blocks);

			err = unused_phy(megaz, old_phy, 0);
			if (err)
				err = -ENOSPC;
		}
		atomic_dec(&mapped->refcount);
	}
	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 *  Copy a journal block into the sector map [SLT] for this megazone.
 */
static int move_to_map_tables(struct megazone *megaz, struct map_cache *jrnl)
{
	struct map_pg *smtbl = NULL;
	struct map_pg *rmtbl = NULL;
	struct map_addr maddr = { .dm_s = 0ul };
	struct map_addr reverse = { .dm_s = 0ul };
	u64 lut_s = BAD_ADDR;
	u64 lut_r = BAD_ADDR;
	int jentry;
	int err = 0;
	int is_fwd = 1;

	/* the journal being move must remain stable so sorting
	 * is disabled. If a sort is desired due to an unsorted
	 * page the search devolves to a linear lookup.
	 */
	jrnl->no_sort_flag = 1;

	for (jentry = jrnl->jcount; jentry > 0;) {
		u64 dm_s = le64_to_lba48(jrnl->jdata[jentry].logical, NULL);
		u64 lba = le64_to_lba48(jrnl->jdata[jentry].physical, NULL);

		if (dm_s == Z_LOWER48 || lba == Z_LOWER48) {
			jrnl->jcount = --jentry;
			continue;
		}

		map_addr_calc(megaz->znd, dm_s, &maddr);
		if (lut_s != maddr.lut_s) {
			if (smtbl)
				atomic_dec(&smtbl->refcount);
			smtbl = sector_map_entry(megaz, &maddr);
			if (!smtbl) {
				err = -ENOMEM;
				goto out;
			}
			atomic_inc(&smtbl->refcount);
			lut_s = smtbl->lba;
		}

		is_fwd = 1;
		if (lba == 0ul)
			lba = BAD_ADDR;
		err = update_map_entry(megaz, smtbl, &maddr, lba, is_fwd);
		if (err < 0)
			goto out;

		/*
		 * In this case the reverse was handled as part of
		 * discarding the forward map entry -- if it was in use.
		 */
		if (lba != BAD_ADDR) {
			map_addr_calc(megaz->znd, lba, &reverse);
			if (lut_r != reverse.lut_r) {
				if (rmtbl)
					atomic_dec(&rmtbl->refcount);
				rmtbl = reverse_map_entry(megaz, &reverse);
				if (!rmtbl) {
					err = -ENOMEM;
					goto out;
				}
				atomic_inc(&rmtbl->refcount);
				lut_r = rmtbl->lba;
			}
			is_fwd = 0;
			err = update_map_entry(megaz, rmtbl, &reverse,
						dm_s, is_fwd);
			if (err == 1)
				err = 0;
		}

		if (err < 0)
			goto out;

		jrnl->jdata[jentry].logical = MC_INVALID;
		jrnl->jdata[jentry].physical = MC_INVALID;
		jrnl->jcount = --jentry;
	}
out:
	if (smtbl)
		atomic_dec(&smtbl->refcount);
	if (rmtbl)
		atomic_dec(&rmtbl->refcount);

	set_bit(DO_MEMPOOL, &megaz->flags);

	jrnl->no_sort_flag = 0;

	return err;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

/**
 * Add an unused block to the list of blocks to be
 *  discarded during garbage collection.
 */
static int unused_phy(struct megazone *megaz, u64 lba, u64 orig_s)
{
	int err = 0;
	struct map_pg *mapped;
	struct map_addr reverse;
	int z_off;

	if (lba < megaz->znd->data_lba)
		return 0;

	mutex_lock(&megaz->discard_lock);

	map_addr_calc(megaz->znd, lba, &reverse);
	z_off = reverse.zone_id % 1024;
	mapped = reverse_map_entry(megaz, &reverse);
	if (!mapped) {
		err = -EIO;
		Z_ERR(megaz->znd, "unused_phy: Reverse Map Entry not found.");
		goto out;
	}

	if (!mapped->mdata) {
		Z_ERR(megaz->znd, "Catastrophic missing LUT page.");
		dump_stack();
		err = -EIO;
		goto out;
	}

	atomic_inc(&mapped->refcount);
	mutex_lock(&mapped->md_lock);

	/*
	 * if the value is modified update the table and
	 * place it on top of the active [inpool] list
	 */
	if (mapped->mdata[reverse.offentry] != MZTEV_UNUSED) {
		u32 wp = megaz->z_ptrs[z_off] & Z_WP_VALUE_MASK;

		if (orig_s) {
			__le32 enc = mapped->mdata[reverse.offentry];
			u64 dm_s = map_value(megaz, enc);
			int drop_discard = 0;

			if (dm_s < megaz->znd->data_lba) {
				drop_discard = 1;
				Z_ERR(megaz->znd, "Discard invalid target %"
				      PRIx64" - Is ZDM Meta %"PRIx64" vs %"
				      PRIx64, lba, orig_s, dm_s);
			}
			if (orig_s != dm_s) {
				drop_discard = 1;
				Z_ERR(megaz->znd,
				      "Discard %" PRIx64
				      " mismatched src: %"PRIx64 " vs %" PRIx64,
				      lba, orig_s, dm_s);
			}
			if (drop_discard)
				goto out_unlock;
		}
		mapped->mdata[reverse.offentry] = MZTEV_UNUSED;
		mapped->age = jiffies_64;
		set_bit(IS_DIRTY, &mapped->flags);
		incore_hint(megaz, mapped);

		if (wp && megaz->zfree_count[z_off] < Z_BLKSZ)
			megaz->zfree_count[z_off]++;
		if (wp == Z_BLKSZ)
			megaz->discard_count++;
	} else {
		Z_DBG(megaz->znd,
		      "lba: %" PRIx64 " alread reported as free?", lba);
	}

out_unlock:
	mutex_unlock(&mapped->md_lock);
	atomic_dec(&mapped->refcount);

out:
	mutex_unlock(&megaz->discard_lock);

	return err;
}
