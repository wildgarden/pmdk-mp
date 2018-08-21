/*
 * Copyright 2015-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * heap.c -- heap implementation
 */

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <float.h>
#include <pthread.h>

#include "queue.h"
#include "heap.h"
#include "out.h"
#include "util.h"
#include "sys_util.h"
#include "valgrind_internal.h"
#include "recycler.h"
#include "container_ctree.h"
#include "container_seglists.h"
#include "alloc_class.h"
#include "os_thread.h"
#include "lane.h"
#include "inttypes.h"
#include "sync.h"

/* calculates the size of the entire run, including any additional chunks */
#define SIZEOF_RUN(runp, size_idx) (sizeof(*run) + ((size_idx - 1) * CHUNKSIZE))

/*
 * XXX mp-mode -- increased to avoid contention (until proper lock distribution
 * is implemented).
 */
#define MAX_RUN_LOCKS (MAX_CHUNK)

/*
 * Arenas store the collection of buckets for allocation classes. Each thread
 * is assigned an arena on its first allocator operation.
 */
struct arena {
	/* one bucket per allocation class */
	struct bucket *buckets[MAX_ALLOCATION_CLASSES];

	size_t nthreads;
};

/*
 * This structure represents the shared heap runtime state
 */
struct heap_rt_shm {
	os_mutex_t zone_trans_lock; /* needed when transiting to next zone */
	os_mutex_t run_locks[MAX_RUN_LOCKS];

	volatile unsigned zones_exhausted;
};

struct heap_rt {
	struct alloc_class_collection *alloc_classes;

	/* DON'T use these two variable directly! */
	struct bucket *default_bucket; /* per process */
	struct arena *arenas;

	/*
	 * used to prevent region transitions while another thread is allocating
	 *
	 * states:
	 * - 'shared' 		during allocation
	 * - 'exclusive' 	region transition in progress
	 *
	 * we use a rwlock, instead of a condition variable, due to better
	 * support from helgrind
	 */
	os_rwlock_t rwlock;

	/* protects assignment of arenas */
	os_mutex_t arenas_lock; /* per process */

	/* stores a pointer to one of the arenas */
	os_tls_key_t thread_arena;

	struct recycler *recyclers[MAX_ALLOCATION_CLASSES]; /* per process */

	unsigned max_zone;
	unsigned narenas;

	/* pointer to the shared runtime state that lives in shared memory */
	struct heap_rt_shm *shrd;

	/*
	 * currently all access happens either during boot or after the default
	 * bucket is acquired  and thus there is no reason to lock
	 */
	unsigned active_zone_id;

	/* region that is currently used for allocations */
	struct zone_region *active_region;

	/* registry shared */
	struct registry *registry;

	/* function used for locking mutexes (depending on mp-mode) */
	lock_fn mtx_lock;
	populate_bucket_fn populate_bucket;
	reclaim_garbage_fn reclaim_garbage;

	region_transiton_hold_shrd_fn region_trans_lock_shrd;
	region_transiton_hold_excl_fn region_trans_lock_excl;
	region_transiton_release_fn region_trans_release;

	zone_transition_hold_fn zone_trans_hold;
	zone_transition_release_fn zone_trans_release;
};

/*
 * heap_memblock_from_act_region -- returns 1 in non-mp mode or if the
 * given
 * memory block belongs to the active region, 0 otherwise
 */
int
heap_memblock_from_act_region(const struct memory_block *m)
{
	ASSERTne(m->heap->rt->active_region, NULL);
	int ret = ((m->heap->mp_mode == 0) ||
	    (m->heap->rt->active_zone_id == m->zone_id &&
	    HEAP_CHUNK_FROM_REGION(m->heap->rt->active_region, m->chunk_id)));

	return ret;
}

/*
 * heap_arena_init -- (internal) initializes arena instance
 */
static void
heap_arena_init(struct arena *arena)
{
	arena->nthreads = 0;

	for (int i = 0; i < MAX_ALLOCATION_CLASSES; ++i)
		arena->buckets[i] = NULL;
}

/*
 * heap_arena_destroy -- (internal) destroys arena instance
 */
static void
heap_arena_destroy(struct arena *arena)
{
	for (int i = 0; i < MAX_ALLOCATION_CLASSES; ++i)
		if (arena->buckets[i] != NULL)
			bucket_delete(arena->buckets[i]);
}

/*
 * heap_get_best_class -- returns the alloc class that best fits the
 *	requested size
 */
struct alloc_class *
heap_get_best_class(struct palloc_heap *heap, size_t size)
{
	return alloc_class_by_alloc_size(heap->rt->alloc_classes, size);
}

/*
 * heap_get_active_region -- (internal) returns the active region
 */
struct zone_region *
heap_get_active_region(struct palloc_heap *heap)
{
	ASSERTne(heap->rt->active_region, NULL);

	return heap->rt->active_region;
}

/*
 * heap_thread_arena_destructor -- (internal) removes arena thread assignment
 */
static void
heap_thread_arena_destructor(void *arg)
{
	struct arena *a = arg;
	util_fetch_and_sub(&a->nthreads, 1);
}

/*
 * heap_thread_arena_assign -- (internal) assigns the least used arena
 *	to current thread
 *
 * To avoid complexities with regards to races in the search for the least
 * used arena, a lock is used, but the nthreads counter of the arena is still
 * bumped using atomic instruction because it can happen in parallel to a
 * destructor of a thread, which also touches that variable.
 */
static struct arena *
heap_thread_arena_assign(struct heap_rt *heap)
{
	os_mutex_lock(&heap->arenas_lock);

	struct arena *least_used = NULL;

	struct arena *a;
	for (unsigned i = 0; i < heap->narenas; ++i) {
		a = &heap->arenas[i];
		if (least_used == NULL || a->nthreads < least_used->nthreads)
			least_used = a;
	}

	LOG(4, "assigning %p arena to current thread", least_used);

	util_fetch_and_add(&least_used->nthreads, 1);

	os_mutex_unlock(&heap->arenas_lock);

	os_tls_set(heap->thread_arena, least_used);

	return least_used;
}

/*
 * heap_thread_arena -- (internal) returns the arena assigned to the current
 *	thread
 */
static struct arena *
heap_thread_arena(struct heap_rt *heap)
{
	struct arena *a;
	if ((a = os_tls_get(heap->thread_arena)) == NULL)
		a = heap_thread_arena_assign(heap);

	return a;
}

/*
 * heap_ensure_huge_bucket_filled --
 *	(internal) refills the default bucket if needed
 */
static int
heap_ensure_huge_bucket_filled(struct palloc_heap *heap, struct bucket *bucket,
	uint32_t units)
{
	LOG(3, "bucket %p", bucket);
	int ret;
	if ((ret = heap->rt->reclaim_garbage(heap, bucket, units)) == 0)
		return 0;

	if (ret != ENOMEM)
		return ret;

	if ((ret = heap->rt->populate_bucket(heap, bucket, units)) == 0)
		return 0;

	return ret;
}

static int
heap_region_lock(struct palloc_heap *heap, struct zone_region *r)
{
	LOG(4, "lock %p id %"PRIu32 " offset %"PRIu32,
		&r->lock, r->idx, r->offset);
	ASSERTne(&r->lock, NULL);

	if ((errno = heap_mutex_lock(heap, &r->lock))) {
		ERR("!could not aquire region lock %p id %"PRIu32 " offset "
		    "%"PRIu32, &r->lock, r->idx, r->offset);
		return -1;
	}

	return 0;
}

static void
heap_region_release(struct palloc_heap *heap, struct zone_region *r)
{
	LOG(4, "release region lock %p", &r->lock);
	util_mutex_unlock(&r->lock);
}

/*
 * heap_bucket_acquire_by_id -- fetches by id a bucket exclusive for the thread
 *	until heap_bucket_release is called
 *
 *	returns NULL when a locking error occured and sets errno appropriately
 */
struct bucket *
heap_bucket_acquire_by_id(struct palloc_heap *heap, uint8_t class_id)
{
	struct heap_rt *rt = heap->rt;
	struct bucket *b;

	if (class_id == DEFAULT_ALLOC_CLASS_ID) {
		b = rt->default_bucket;
	} else {
		struct arena *arena = heap_thread_arena(heap->rt);
		b = arena->buckets[class_id];
	}

	util_mutex_lock(&b->lock);

	/*
	 * lock our active region shared lock in case the default bucket was
	 * acquired. This prevents races with other processes, which free
	 * blocks from our regions.
	 */
	if (heap->mp_mode && class_id == DEFAULT_ALLOC_CLASS_ID) {
		if (heap_region_lock(heap, heap->rt->active_region)) {
			goto err;
		}
	}

	return b;

err:
	util_mutex_unlock(&b->lock);
	LOG(4, "heap_bucket_acquire_by_id %s", strerror(errno));

	return NULL;
}

/*
 * heap_region_trans_lock_shrd -- while this lock is held by any thread,
 * it is not allowed to change the active region
 */
void
heap_region_trans_lock_shrd(struct palloc_heap *heap)
{
	heap->rt->region_trans_lock_shrd(heap);
}

/*
 * heap_region_trans_release -- release the lock
 */
void
heap_region_trans_release(struct palloc_heap *heap)
{
	heap->rt->region_trans_release(heap);
}

/*
 * heap_region_trans_lock_excl -- (nothing to lock)
 */
static void
heap_region_trans_lock_excl(struct palloc_heap *heap)
{
	/* NOP */
}

/*
 * heap_reg_trans_lock_excl_mp -- while this lock is held the region is
 * allowed to change
 */
static void
heap_reg_trans_lock_excl_mp(struct palloc_heap *heap)
{
	util_rwlock_wrlock(&heap->rt->rwlock);
}


/*
 * heap_reg_trans_lock_shrd -- (nothing to lock)
 */
static void
heap_reg_trans_lock_shrd(struct palloc_heap *heap)
{
	/* NOP */
}

/*
 * heap_reg_trans_lock_shrd_mp -- while this lock is held by any thread,
 * it is not allowed to change the active region
 */
static void
heap_reg_trans_lock_shrd_mp(struct palloc_heap *heap)
{
	util_rwlock_rdlock(&heap->rt->rwlock);
}

/*
 * heap_reg_trans_release -- (nothing to lock)
 */
static void
heap_reg_trans_release(struct palloc_heap *heap)
{
	/* NOP */
}

/*
 * heap_reg_trans_release_mp -- unlocks the region transition lock
 */
static void
heap_reg_trans_release_mp(struct palloc_heap *heap)
{
	util_rwlock_unlock(&heap->rt->rwlock);
}

/*
 * heap_zone_trans_lock -- (notghing to lock)
 */
static int
heap_zone_trans_lock(struct palloc_heap *heap)
{
	return 0; /* NOP */
}

/*
 * heap_zone_trans_lock -- (internal) locks the entire heap
 */
static int
heap_zone_trans_lock_mp(struct palloc_heap *heap)
{
	LOG(5, "heap %p", heap);

	int ret = heap->rt->mtx_lock(&heap->rt->shrd->zone_trans_lock);
	switch (ret) {
		case 0:
			break;
		case EOWNERDEAD:
			/*
			 * the other process might have crashed in the middle
			 * of zone initialisation. But then the magic value
			 * will not be set and initialsation will run again.
			 */
			util_mutex_consistent(&heap->rt->shrd->zone_trans_lock);
			LOG(4, "!EOWNERDEAD shared heap lock");
			break;
		case EAGAIN:
			FATAL("!EAGAIN shared heap lock");
			break;
		case EBUSY:
			FATAL("!EBUSY already locked");
			break;
		case ETIMEDOUT:
			ERR("!ETIMEDOUT");
			break;
		default:
			ASSERT(0);
	}
	return ret;
}

/*
 * heap_zone_trans_release -- (nothing to release)
 */
static void
heap_zone_trans_release(struct palloc_heap *heap)
{
	/* NOP */
}

/*
 * heap_zone_trans_release -- unlocks the zone transition lock
 */
static void
heap_zone_trans_release_mp(struct palloc_heap *heap)
{
	LOG(5, "heap %p", heap);

	util_mutex_unlock(&heap->rt->shrd->zone_trans_lock);
}


/*
 * heap_mutex_lock -- (internal) helper function to lock
 * the given lock and handle EOWNERDEAD and friends.
 */
int
heap_mutex_lock(struct palloc_heap *h, os_mutex_t *lock)
{
	ASSERTne(lock, NULL);

	int err = h->rt->mtx_lock(lock);
	switch (err) {
		case 0:
			return 0;
		case EOWNERDEAD:
			/*
			 * Another process died while holding a shared lock.
			 * Before we continue we have to consider following
			 * cases:
			 *	1. We need to recover the persistent state.
			 *	2. We need to recover the runtime state, as long
			 *	   as the chunk belongs to our region.
			 *
			 * Regarding 1:
			 * We either need to run recovery and mark
			 * the state of the lock as consistent before we
			 * unlock. Or we simply unlock and leave this decision
			 * to the caller by returning ENOTRECOVERABLE.
			 * We cant't simply mark as consistent and unlock,
			 * because the moment another thread might lock
			 * the run and continue on unrecovered data.
			 * In future we might introduce a dirty bit (flag) on
			 * the run to signal others that recovery is
			 * still pending.
			 *
			 * See 'man 3p posix_mutex_consistent'
			 * "[..] The  pthread_mutex_consistent() function is
			 * only responsible for notifying the implementation
			 * that the state protected by the mutex has
			 * been recovered and that normal operations with the
			 * mutex can be resumed. It is the responsibility of
			 * the  application  to  recover  the state  so it can
			 * be reused. If the application is not able to perform
			 * the recovery, it can notify the implementation that
			 * the situation is unrecoverable by a call to
			 * pthread_mutex_unlock() without a prior call  to
			 * pthread_mutex_consistent(),  in  which  case
			 * subsequent threads that attempt to lock the mutex
			 * will fail to acquire the lock and be
			 * returned [ENOTRECOVERABLE]."
			 *
			 * Regarding 2:
			 * If the chunk belongs to our region, its free blocks
			 * are contained in our buckets.
			 * The other process crashed during 'free' operation.
			 * After recovery the free block will be set in the
			 * persistent state and we will lazily update our
			 * runtime state on the next run
			 * of heap_ensure_run_bucket_filled().
			 *
			 * If the chunk belonged to some other process region
			 * it won't be contained in our buckets.
			 *
			 * Moreover, the redo log might contain entries of two
			 * different chunks e,g. another chunk's lock might
			 * still be held by the crashed process.
			 * This lock needs to released and made consistent, too.
			 * Another process might have encountered that
			 * crashed lock and is trying to run recovery.
			 *
			 * Thus, during recovery we won't be able to acquire the
			 * lock since this results in a deadlock situation.
			 *
			 * We have the choice to recover without requiring the
			 * lock, since we know that recovery is protected by the
			 * registry lock.
			 * Another option is to leave the relevant entries in
			 * the recovery lock, such that the other process can
			 * run recovery again.
			 */

			if (obj_crash_check_and_recover(h->pop) != 0) {
				/*
				 * Although recovery might be dissabled and
				 * obj_crash_check_and_recover (returned
				 * 1) we set errorcode ENOTRECOVERABLE because
				 * the callee can not access the internal lock.
				 */
				LOG(7, "recovery failed");
				util_mutex_unlock(lock);

				return ENOTRECOVERABLE;
			}
			util_mutex_consistent(lock);
			util_mutex_unlock(lock);
			LOG(4, "util_mutex_consistent");
			break;
		case ETIMEDOUT:
			break;
		default:
			FATAL("os_mutex_lock returned an unexpected error.");
	}

	return err;
}

/*
 * heap_bucket_acquire_by_id -- fetches by class a bucket exclusive for the
 *	thread until heap_bucket_release is called
 *
 *	returns NULL in case the default bucket was tried to acquire and a
 *	locking error occured.
 */
struct bucket *
heap_bucket_acquire(struct palloc_heap *heap, struct alloc_class *c)
{
	return heap_bucket_acquire_by_id(heap, c->id);
}

/*
 * heap_bucket_release -- puts the bucket back into the heap
 */
void
heap_bucket_release(struct palloc_heap *heap, struct bucket *b)
{
	ASSERTne(heap->rt->active_region, NULL);

	if (heap->mp_mode && b->aclass->id == DEFAULT_ALLOC_CLASS_ID) {
		heap_region_release(heap, heap->rt->active_region);
	}

	util_mutex_unlock(&b->lock);
}

/*
 * heap_get_run_lock -- returns the lock associated with memory block
 */
os_mutex_t *
heap_get_run_lock(struct palloc_heap *heap, uint32_t chunk_id)
{
	/*
	 * XXX mp-mode -- needs proper lock distribution
	 * Several zones might be active at the same time.
	 */
	return &heap->rt->shrd->run_locks[chunk_id % MAX_RUN_LOCKS];
}

/*
 * heap_max_zone -- (internal) calculates how many zones can the heap fit
 */
static unsigned
heap_max_zone(size_t size)
{
	unsigned max_zone = 0;
	size -= sizeof(struct heap_header);

	while (size >= ZONE_MIN_SIZE) {
		max_zone++;
		size -= size <= ZONE_MAX_SIZE ? size : ZONE_MAX_SIZE;
	}

	return max_zone;
}

/*
 * get_zone_size_idx -- (internal) calculates zone size index
 */
static uint16_t
get_zone_size_idx(uint32_t zone_id, unsigned max_zone, size_t heap_size)
{
	ASSERT(max_zone > 0);
	if (zone_id < max_zone - 1)
		return MAX_CHUNK;

	ASSERT(heap_size >= zone_id * ZONE_MAX_SIZE);
	size_t zone_raw_size = heap_size - zone_id * ZONE_MAX_SIZE;

	ASSERT(zone_raw_size >= (sizeof(struct zone_header) +
			sizeof(struct zone_region) * MAX_REGIONS +
			sizeof(struct chunk_header) * MAX_CHUNK));
	zone_raw_size -= sizeof(struct zone_header) +
		sizeof(struct zone_region) * MAX_REGIONS +
		sizeof(struct chunk_header) * MAX_CHUNK;

	size_t zone_size_idx = zone_raw_size / CHUNKSIZE;
	ASSERT(zone_size_idx <= UINT16_MAX);

	/* upper limit ==  MAX_CHUNK */
	return (uint16_t)zone_size_idx;
}

/*
 * heap_chunk_write_footer -- writes a chunk footer
 */
static void
heap_chunk_write_footer(struct chunk_header *hdr, uint32_t size_idx)
{
	if (size_idx == 1) /* that would overwrite the header */
		return;

	VALGRIND_DO_MAKE_MEM_UNDEFINED(hdr + size_idx - 1, sizeof(*hdr));

	struct chunk_header f = *hdr;
	f.type = CHUNK_TYPE_FOOTER;
	f.size_idx = size_idx;
	*(hdr + size_idx - 1) = f;
	/* no need to persist, footers are recreated in heap_populate_bucket */
	VALGRIND_SET_CLEAN(hdr + size_idx - 1, sizeof(f));
}

/*
 * heap_chunk_init -- (internal) writes chunk header
 */
static void
heap_chunk_init(struct palloc_heap *heap, struct chunk_header *hdr,
	uint16_t type, uint32_t size_idx)
{
	struct chunk_header nhdr = {
		.type = type,
		.flags = 0,
		.size_idx = size_idx
	};
	VALGRIND_DO_MAKE_MEM_UNDEFINED(hdr, sizeof(*hdr));

	*hdr = nhdr; /* write the entire header (8 bytes) at once */
	pmemops_persist(&heap->p_ops, hdr, sizeof(*hdr));

	heap_chunk_write_footer(hdr, size_idx);
}

/*
 * heap_write_region -- (internal) writes a zone_region
 */
static void
heap_write_region(const struct palloc_heap *heap, struct zone_region *r,
    uint16_t size, uint16_t offset,  unsigned idx) {

	struct zone_region nrgn = {
		.idx = idx,
		.offset = offset,
		.size = size,
		.claimant = REGION_UNCLAIMED,
	};
	/*
	 * Although struct region_zone exceeds the 8 byte limit,
	 * it is safe to persist without a redo log, because the
	 * region will be reinitialized as long the zone magic value
	 * is not set.
	 */

	*r = nrgn;
	pmemops_persist(&heap->p_ops, r, sizeof(*r));
}

/*
 * heap_zone_init -- (internal) writes zone's header and the first chunk of
 * each region
 */
static void
heap_zone_init(struct palloc_heap *heap, uint32_t zone_id, uint16_t num_regions)
{
	LOG(3, "heap %p zone_id %d num_regions %d", heap, zone_id, num_regions);

	ASSERT(num_regions <= MAX_REGIONS);

	uint16_t r_size;
	uint16_t r_size_last;
	uint16_t r_size_current;
	struct zone_region *r;

	struct zone *z = ZID_TO_ZONE(heap->layout, zone_id);
	uint16_t z_size_idx = get_zone_size_idx(zone_id, heap->rt->max_zone,
	    heap->size);
	ASSERT(z_size_idx > 0);

	/*
	 * If we do not have at least one chunk per region, we init that zone
	 * with a single region.
	 * Othewise we devide the zone in equally sized segments, with the
	 * exception that the last region additionaly contains the
	 * remainder.
	 */
	if (z_size_idx <= num_regions) {
		/* for last zone only */
		num_regions = 1;
		r_size = z_size_idx;
		r_size_last = r_size;
	} else {
		r_size = (uint16_t)((z_size_idx / num_regions));
		r_size_last = (uint16_t)(r_size + (z_size_idx % (r_size *
		    num_regions)));
	}

	for (unsigned i = 0; i < num_regions; ++i) {
		/* init first chunk of each region */
		int is_last = (i == (uint16_t)(num_regions - 1));
		r_size_current = is_last ? r_size_last : r_size;

		r = &z->regions[i];
		heap_write_region(heap, r, r_size_current,
		    (uint16_t)(r_size * i), i);

		/* regions are only locked and cleaned up in mp-mode */
		if (heap->mp_mode)
			util_mutex_init_mp(&r->lock);

		heap_chunk_init(heap, &z->chunk_headers[r->offset],
		    CHUNK_TYPE_FREE, r_size_current);
	}
	struct zone_header nhdr = {
		.size_idx = z_size_idx,
		.magic = ZONE_HEADER_MAGIC,
		.regions_in_use = num_regions,
	};
	z->header = nhdr;  /* write the entire header (8 bytes) at once */
	pmemops_persist(&heap->p_ops, &z->header, sizeof(z->header));
}

/*
 * heap_run_init -- (internal) creates a run based on a chunk
 */
static void
heap_run_init(struct palloc_heap *heap, struct bucket *b,
	const struct memory_block *m)
{
	struct alloc_class *c = b->aclass;
	ASSERTeq(c->type, CLASS_RUN);
	ASSERT(heap_memblock_from_act_region(m));
	struct zone *z = ZID_TO_ZONE(heap->layout, m->zone_id);

	struct chunk_run *run = (struct chunk_run *)&z->chunks[m->chunk_id];
	ASSERTne(m->size_idx, 0);
	size_t runsize = SIZEOF_RUN(run, m->size_idx);

	VALGRIND_DO_MAKE_MEM_UNDEFINED(run, runsize);

	/* add/remove chunk_run and chunk_header to valgrind transaction */
	VALGRIND_ADD_TO_TX(run, runsize);
	run->block_size = c->unit_size;
	pmemops_persist(&heap->p_ops, &run->block_size,
			sizeof(run->block_size));

	/* set all the bits */
	memset(run->bitmap, 0xFF, sizeof(run->bitmap));

	unsigned nval = c->run.bitmap_nval;
	ASSERT(nval > 0);
	/* clear only the bits available for allocations from this bucket */
	memset(run->bitmap, 0, sizeof(uint64_t) * (nval - 1));
	run->bitmap[nval - 1] = c->run.bitmap_lastval;

	run->incarnation_claim = heap->run_id;
	VALGRIND_SET_CLEAN(&run->incarnation_claim,
		sizeof(run->incarnation_claim));

	VALGRIND_REMOVE_FROM_TX(run, runsize);

	pmemops_persist(&heap->p_ops, run->bitmap, sizeof(run->bitmap));

	struct chunk_header run_data_hdr;
	run_data_hdr.type = CHUNK_TYPE_RUN_DATA;
	run_data_hdr.flags = 0;

	struct chunk_header *data_hdr;
	for (unsigned i = 1; i < m->size_idx; ++i) {
		data_hdr = &z->chunk_headers[m->chunk_id + i];
		VALGRIND_DO_MAKE_MEM_UNDEFINED(data_hdr, sizeof(*data_hdr));
		VALGRIND_ADD_TO_TX(data_hdr, sizeof(*data_hdr));
		run_data_hdr.size_idx = i;
		*data_hdr = run_data_hdr;
		VALGRIND_REMOVE_FROM_TX(data_hdr, sizeof(*data_hdr));
	}
	pmemops_persist(&heap->p_ops,
		&z->chunk_headers[m->chunk_id + 1],
		sizeof(struct chunk_header) * (m->size_idx - 1));

	struct chunk_header *hdr = &z->chunk_headers[m->chunk_id];
	ASSERT(hdr->type == CHUNK_TYPE_FREE);

	VALGRIND_ADD_TO_TX(hdr, sizeof(*hdr));
	struct chunk_header run_hdr;
	run_hdr.size_idx = hdr->size_idx;
	run_hdr.type = CHUNK_TYPE_RUN;
	run_hdr.flags = header_type_to_flag[c->header_type];
	*hdr = run_hdr;
	VALGRIND_REMOVE_FROM_TX(hdr, sizeof(*hdr));

	pmemops_persist(&heap->p_ops, hdr, sizeof(*hdr));
}

/*
 * heap_run_insert -- (internal) inserts and splits a block of memory into a run
 */
static void
heap_run_insert(struct palloc_heap *heap, struct bucket *b,
	const struct memory_block *m, uint32_t size_idx, uint16_t block_off)
{
	struct alloc_class *c = b->aclass;
	ASSERTeq(c->type, CLASS_RUN);

	ASSERT(size_idx <= BITS_PER_VALUE);
	ASSERT(block_off + size_idx <= c->run.bitmap_nallocs);

	uint32_t unit_max = RUN_UNIT_MAX;
	struct memory_block nm = *m;
	nm.size_idx = unit_max - (block_off % unit_max);
	nm.block_off = block_off;
	if (nm.size_idx > size_idx)
		nm.size_idx = size_idx;

	do {
		ASSERT(heap_memblock_from_act_region(&nm));
		bucket_insert_block(b, &nm);
		ASSERT(nm.size_idx <= UINT16_MAX);
		ASSERT(nm.block_off + nm.size_idx <= UINT16_MAX);
		nm.block_off = (uint16_t)(nm.block_off + (uint16_t)nm.size_idx);
		size_idx -= nm.size_idx;
		nm.size_idx = size_idx > unit_max ? unit_max : size_idx;
	} while (size_idx != 0);
}

/*
 * heap_process_run_metadata -- (internal) parses the run bitmap
 */
static uint32_t
heap_process_run_metadata(struct palloc_heap *heap, struct bucket *b,
	const struct memory_block *m)
{
	struct alloc_class *c = b->aclass;
	ASSERTeq(c->type, CLASS_RUN);
	ASSERTeq(m->size_idx, c->run.size_idx);

	uint16_t block_off = 0;
	uint16_t block_size_idx = 0;
	uint32_t inserted_blocks = 0;

	struct zone *z = ZID_TO_ZONE(heap->layout, m->zone_id);
	struct chunk_run *run = (struct chunk_run *)&z->chunks[m->chunk_id];

	ASSERTeq(run->block_size, c->unit_size);

	for (unsigned i = 0; i < c->run.bitmap_nval; ++i) {
		ASSERT(i < MAX_BITMAP_VALUES);
		uint64_t v = run->bitmap[i];
		ASSERT(BITS_PER_VALUE * i <= UINT16_MAX);
		block_off = (uint16_t)(BITS_PER_VALUE * i);
		if (v == 0) {
			heap_run_insert(heap, b, m, BITS_PER_VALUE, block_off);
			inserted_blocks += BITS_PER_VALUE;
			continue;
		} else if (v == UINT64_MAX) {
			continue;
		}

		for (unsigned j = 0; j < BITS_PER_VALUE; ++j) {
			if (BIT_IS_CLR(v, j)) {
				block_size_idx++;
			} else if (block_size_idx != 0) {
				ASSERT(block_off >= block_size_idx);

				heap_run_insert(heap, b, m,
					block_size_idx,
					(uint16_t)(block_off - block_size_idx));
				inserted_blocks += block_size_idx;
				block_size_idx = 0;
			}

			if ((block_off++) == c->run.bitmap_nallocs) {
				i = MAX_BITMAP_VALUES;
				break;
			}
		}

		if (block_size_idx != 0) {
			ASSERT(block_off >= block_size_idx);

			heap_run_insert(heap, b, m,
					block_size_idx,
					(uint16_t)(block_off - block_size_idx));
			inserted_blocks += block_size_idx;
			block_size_idx = 0;
		}
	}

	return inserted_blocks;
}

/*
 * heap_create_run -- (internal) initializes a new run on an existing free chunk
 */
static void
heap_create_run(struct palloc_heap *heap, struct bucket *b,
	struct memory_block *m)
{
	heap_run_init(heap, b, m);
	memblock_rebuild_state(heap, m);
	heap_process_run_metadata(heap, b, m);
}

/*
 * heap_reuse_run -- (internal) reuses existing run
 */
static uint32_t
heap_reuse_run(struct palloc_heap *heap, struct bucket *b,
	const struct memory_block *m)
{
	ASSERTeq(m->type, MEMORY_BLOCK_RUN);

	return heap_process_run_metadata(heap, b, m);
}

/*
 * heap_reclaim_run -- checks the run for available memory if unclaimed.
 *
 * Returns  number of reclaimed chunks.
 */
static int
heap_reclaim_run(struct palloc_heap *heap, struct bucket *defb,
	struct chunk_run *run, struct memory_block *m,
	struct zone_region *reg)
{
	LOG(4, "heap %p bucket %p, memory block %p reg %" PRIu32,
		heap, defb, m, reg->idx);
	ASSERT(heap->mp_mode == 0 || HEAP_CHUNK_FROM_REGION(reg, m->chunk_id));

	if (m->m_ops->claim(m) != 0)
		return 0; /* this run already has an owner */

	int chunks = 0;
	struct alloc_class_run_proto run_proto;
	alloc_class_generate_run_proto(&run_proto,
		run->block_size, m->size_idx);

	os_mutex_t *lock = m->m_ops->get_lock(m);
	if ((errno = heap_mutex_lock(heap, lock)) != 0)
		return -1;

	unsigned i;
	unsigned nval = run_proto.bitmap_nval;
	for (i = 0; nval > 0 && i < nval - 1; ++i)
		if (run->bitmap[i] != 0)
			break;

	int empty = (i == (nval - 1)) &&
		(run->bitmap[i] == run_proto.bitmap_lastval);
	if (empty) {
		struct zone *z = ZID_TO_ZONE(heap->layout, m->zone_id);
		struct chunk_header *hdr = &z->chunk_headers[m->chunk_id];

		/*
		 * The redo log ptr can be NULL if we are sure that there's only
		 * one persistent value modification in the entire operation
		 * context.
		 */
		struct operation_context ctx;
		operation_init(&ctx, heap->base, NULL, NULL);
		ctx.p_ops = &heap->p_ops;

		struct memory_block nb = MEMORY_BLOCK_NONE;
		nb.chunk_id = m->chunk_id;
		nb.zone_id = m->zone_id;
		nb.block_off = 0;
		nb.size_idx = m->size_idx;

		heap_chunk_init(heap, hdr, CHUNK_TYPE_FREE, nb.size_idx);
		memblock_rebuild_state(heap, &nb);

		nb = heap_coalesce_huge(heap, defb, &nb, reg);
		nb.m_ops->prep_hdr(&nb, MEMBLOCK_FREE, &ctx);

		operation_process(&ctx);

		ASSERT(heap->mp_mode == 0 ||
		    HEAP_CHUNK_FROM_REGION(reg, nb.chunk_id));
		bucket_insert_block(defb, &nb);

		*m = nb;
		chunks = (int)nb.size_idx;
	} else {
		struct alloc_class *c = alloc_class_by_unit_size(
			heap->rt->alloc_classes,
			run->block_size);

		if (c == NULL ||
		    c->type != CLASS_RUN ||
		    c->run.size_idx != m->size_idx ||
		    c->header_type != m->header_type ||
			recycler_put(heap->rt->recyclers[c->id], m) < 0)
			m->m_ops->claim_revoke(m);
	}

	util_mutex_unlock(lock);

	return chunks;
}

/*
 * heap_init_free_chunk -- initializes free chunk transient state
 */
static void
heap_init_free_chunk(struct palloc_heap *heap,
	struct bucket *bucket,
	struct chunk_header *hdr,
	struct memory_block *m,
	struct zone_region *r)
{
	struct operation_context ctx;
	operation_init(&ctx, heap->base, NULL, NULL);
	ctx.p_ops = &heap->p_ops;
	heap_chunk_write_footer(hdr, hdr->size_idx);
	ASSERT(heap->mp_mode == 0 || HEAP_CHUNK_FROM_REGION(r, m->chunk_id));

	/*
	 * Perform coalescing just in case there
	 * are any neighbouring free chunks.
	 */
	struct memory_block nm = heap_coalesce_huge(heap, bucket, m, r);
	if (nm.chunk_id != m->chunk_id) {
		m->m_ops->prep_hdr(&nm, MEMBLOCK_FREE, &ctx);
		operation_process(&ctx);
	}
	*m = nm;
	ASSERT(heap->mp_mode == 0 || HEAP_CHUNK_FROM_REGION(r, m->chunk_id));
	bucket_insert_block(bucket, m);
}

/*
 * heap_empty_bucket -- (internal) empty / clear a  buckets content
 */
static void
heap_empty_bucket(struct bucket *b)
{
	LOG(4, "bucket %p", b);

	b->c_ops->rm_all(b->container);

	/* get rid of the active block in the bucket */
	if (b->is_active) {
		b->is_active = 0;
		b->active_memory_block.m_ops
			->claim_revoke(&b->active_memory_block);
	}
}

/*
 * heap_mutex_timedlock -- (internal) wraps os_mutex_timedlock to pass in
 * the default timeout
 */
static int
heap_mutex_timedlock(os_mutex_t *mutex)
{
	LOG(5, "mutex %p", mutex);
	struct timespec ts;

	return os_mutex_timedlock(mutex, mp_set_mtx_timeout(&ts));
}

/*
 * heap_reclaim_region_garbage -- (internal) creates volatile state of
 * unused runs
 */
static int
heap_reclaim_region_garbage(struct palloc_heap *heap, struct bucket *b,
	uint32_t zone_id, int init, struct zone_region *r, uint32_t units)
{
	LOG(4, "heap %p bucket %p zone_id %" PRIu32 " region %" PRIu32
		" units %" PRIu32 " init %d ",
		heap, b, zone_id, r->idx, units, init);

	struct zone *z = ZID_TO_ZONE(heap->layout, zone_id);

	struct chunk_run *run = NULL;
	int ret = 0;
	int rchunks = 0;
	int max_chunks = 0;

	uint32_t region_end = HEAP_END_OF_REGION(r);
	ASSERT(region_end <= z->header.size_idx);

	/*
	 * If this is the first time this zone is processed, recreate all
	 * footers BEFORE any other operation takes place. For example, the
	 * heap_init_free_chunk call expects the footers to be created.
	 */
	if (init) {
		for (uint32_t i = r->offset; i <= region_end; ) {
			struct chunk_header *hdr = &z->chunk_headers[i];
			switch (hdr->type) {
				case CHUNK_TYPE_FREE:
				case CHUNK_TYPE_USED:
					heap_chunk_write_footer(hdr,
						hdr->size_idx);
					break;
			}

			i += hdr->size_idx;
		}
	}

	for (uint32_t i = r->offset; i <= region_end; ) {
		struct chunk_header *hdr = &z->chunk_headers[i];
		ASSERT(hdr->size_idx != 0);

		struct memory_block m = MEMORY_BLOCK_NONE;
		m.zone_id = zone_id;
		m.chunk_id = i;
		m.size_idx = hdr->size_idx;

		memblock_rebuild_state(heap, &m);

		switch (hdr->type) {
			case CHUNK_TYPE_RUN:
				run = (struct chunk_run *)&z->chunks[i];
				if ((ret = heap_reclaim_run(heap, b, run, &m,
					r)) == -1)
					return ret;

				rchunks += ret;
				max_chunks = MAX(max_chunks, ret);
				break;
			case CHUNK_TYPE_FREE:
				if (init) {
					heap_init_free_chunk(heap, b,
						hdr, &m, r);
					ret = (int)m.size_idx;
					rchunks += ret;
					max_chunks = MAX(max_chunks, ret);
				}
				break;
			case CHUNK_TYPE_USED:
				break;
			default:
				ASSERT(0);
		}

		i = m.chunk_id + m.size_idx; /* hdr might have changed */
	}

	if (units > 0) {
		/* the caller requested at least 'units' of chunks. */
		return max_chunks < (int)units  ? ENOMEM : 0;
	} else {
		return rchunks == 0 ? ENOMEM : 0;
	}
}

/*
 * heap_clear_volatile_state() -- (internal) clears the volatile state of the
 * heap by removing all blocks from all buckets
 */
static void
heap_clear_volatile_state(struct palloc_heap *heap)
{
	LOG(4, NULL);

	struct bucket *b;
	struct alloc_class *c;
	struct memory_block m = MEMORY_BLOCK_NONE;
	for (uint8_t i = 0; i < MAX_ALLOCATION_CLASSES; ++i) {
		/* remove memory blocks from recycler */
		while (recycler_get(heap->rt->recyclers[i], &m) == 0) {
			m.m_ops->claim_revoke(&m);
			m.size_idx = 0;
		}

		/*
		 * huge memory blocks are always allocated from a
		 * single bucket
		 */
		if ((c = alloc_class_by_id(heap->rt->alloc_classes, i)) ==
		    NULL || c->id == DEFAULT_ALLOC_CLASS_ID)
			continue;

		for (unsigned j = 0; j < heap->rt->narenas; j++) {
			b = heap->rt->arenas[j].buckets[c->id];
			LOG(4, "clearing arena %u, class_id %"PRIu8,
				j, b->aclass->id);
			/*
			 * We don't respect existing bucket locks, because
			 * this operation is synchronized by the default
			 * bucket.
			 */
			if (b->is_active) {
				b->c_ops->rm_all(b->container);
				b->is_active = 0;
			}
		}
	}

	/*
	 * Since all arenas use the same default bucket, we need to empty it
	 * only once
	 */
	heap_empty_bucket(heap->rt->default_bucket);
}

/*
 * heap_region_reset_claimant -- resets the field claimant to initial value
 */
static void
heap_region_reset_claimant(struct zone_region *r)
{
	__sync_fetch_and_or(&r->claimant, REGION_UNCLAIMED);

	/* no need to persist, (re-)initialized in heap_boot */
	VALGRIND_SET_CLEAN(&r->claimant, sizeof(r->claimant));
}

/*
 * heap_region_claim -- (internal) claim the given region, if available
 */
static int
heap_region_claim(struct palloc_heap *h, uint32_t r_id, uint32_t zone_id)
{
	struct zone *z = ZID_TO_ZONE(h->layout, zone_id);
	struct zone_region *r_new = &z->regions[r_id];
	struct zone_region *r_old = h->rt->active_region;

	if (r_new->claimant != REGION_UNCLAIMED ||
	    !util_bool_compare_and_swap32(&r_new->claimant, REGION_UNCLAIMED,
		    h->proc_idx)) {
			return -1;
	}

	/* we found an unclaimed region */
	h->rt->active_region = r_new;

	/* no need to persist, (re-)initialized in heap_boot */
	VALGRIND_SET_CLEAN(&r_new->claimant, sizeof(r_new->claimant));

	LOG(4, "transition: zone_id %"	PRIu32 " -> %"PRIu32 ", region %"PRIu32
		" -> %"PRIu32, h->rt->active_zone_id, zone_id,
		r_old ? r_old->idx : 0, r_new->idx);

	/* unclaim old region */
	if (r_old != NULL) {
		heap_region_reset_claimant(r_old);
	}
	/* no need to persist, (re-)initialized in heap_boot */

	return 0;
}

/*
 * heap_region_acquire -- updates volatile state
 */
static int
heap_region_acquire(struct palloc_heap *h, struct bucket *b, uint32_t r_id,
	uint32_t zone_id, int init, uint32_t units)
{
	LOG(4, "heap %p bucket %p r_id %" PRIu32
		" zone_id %" PRIu32 " init %d units %" PRIu32,
		h, b, r_id, zone_id, init, units);

	struct zone_region *r_old = h->rt->active_region;

	if (heap_region_claim(h, r_id, zone_id) != 0)
		goto out;

	/*
	 * swap locked regions.
	 */
	if (h->mp_mode) {
		heap_region_release(h, r_old);

		int err;
		if ((err = heap_region_lock(h, h->rt->active_region))) {
			LOG(4, "heap_region_lock error %d", err);
			return err;
		}
	}

	/* process region */
	if (heap_reclaim_region_garbage(h, b, zone_id, init,
		h->rt->active_region, units) == 0) {
		return 0;
	}
out:
	return ENOMEM;
}

static int
heap_zone_reclaim_regions(struct palloc_heap *heap, struct bucket *b,
    unsigned start_idx, uint32_t zone_id, int init, uint32_t units)
{
	LOG(3, "heap %p bucket %p start_idx %d zone_id %d init %d units %d",
	    heap, b, start_idx, zone_id, init, units);

	ASSERTne(heap->rt->active_region, NULL);

	unsigned processed_regions = 0;
	uint32_t regions_in_use = ZID_TO_ZONE(heap->layout,
		zone_id)->header.regions_in_use;

	/*
	 * iterate the entire zone
	 * starts from beginning (wraps around) when zone end is reached
	 */
	for (unsigned i = start_idx;
	    ++(processed_regions) < regions_in_use;
	    i = (i + 1) % regions_in_use) {

		/* skip current */
		if (unlikely(zone_id == heap->rt->active_zone_id &&
			    heap->rt->active_region->idx == i))
			continue;

		heap_clear_volatile_state(heap);

		if (heap_region_acquire(heap, b, i, zone_id, init, units) == 0)
			return 0;
	}

	return -1;
}

static int
heap_zone_assign(struct palloc_heap *heap, uint32_t *assigned_zone_id,
    int new_zone)
{
	LOG(3, "heap %p new_zone %d", heap, new_zone);

	struct heap_rt *h = heap->rt;

	int ret = 0;
	uint32_t zone_id;
	volatile unsigned *zones_exhausted_ptr = &h->shrd->zones_exhausted;

	if ((errno = heap->rt->zone_trans_hold(heap)) != 0) {
		if (errno == EOWNERDEAD)
			h->zone_trans_release(heap);

		FATAL("heap_zone_trans_lock");
	}

	if (new_zone) {
		if (*zones_exhausted_ptr == h->max_zone) {
			LOG(4, "!all zones exhausted");
			ret = ENOMEM;

			goto out;
		}
		zone_id = (*zones_exhausted_ptr)++;
	} else {
		/* get last used zone */
		zone_id = *zones_exhausted_ptr;
	}

	struct zone *z = ZID_TO_ZONE(heap->layout, zone_id);

	/* ignore zone and chunk headers */
	VALGRIND_ADD_TO_GLOBAL_TX_IGNORE(z, sizeof(z->header) +
					    sizeof(z->regions) +
					    sizeof(z->chunk_headers));

	if (z->header.magic != ZONE_HEADER_MAGIC)
		heap_zone_init(heap, zone_id, MAX_REGIONS);

	*assigned_zone_id = zone_id;

out:
	h->zone_trans_release(heap);

	return ret;
}

/*
 * heap_populate_bucket -- (internal) creates volatile state of memory blocks
 */
static int
heap_populate_bucket_mp(struct palloc_heap *heap, struct bucket *bucket,
    uint32_t units)
{
	LOG(3, "heap %p bucket %p units %d", heap, bucket, units);

	uint32_t zone_start_id;
	int ret = 0;
	struct heap_rt *h = heap->rt;
	struct heap_rt_shm *shrd = h->shrd;

	uint32_t zone_id;

	ASSERTne(h->active_region, NULL);

	/* upgrade lock */
	h->region_trans_release(heap);
	h->region_trans_lock_excl(heap);

	uint32_t region_start_id = h->active_region->idx + 1;

	/* process current zone */
	if (heap_zone_reclaim_regions(heap, bucket, region_start_id,
		h->active_zone_id, 1 /* init */, units) == 0)
		goto out;

	/*
	 * Travere all other zones (that are already in use).
	 *
	 * This is expensive, but we want to keep fragmentation low.
	 *
	 * Maybe we should leave this decision to the user via a env-var or
	 * ctrl.
	 */
	zone_start_id = h->active_zone_id;

	zone_id = 0; /* start from scratch */
	do {
		if (zone_id == zone_start_id)
			continue;

		if (heap_zone_reclaim_regions(heap, bucket, 0, zone_id,
			1 /* init */, units) == 0)
			goto out_zone;

	} while (++zone_id < shrd->zones_exhausted);

	/*
	 * We have no other choice than to assign a new zone.
	 * We could run recovery to cleanup any leftovers, that we could use.
	 * But we delegate that decission to the caller.
	 */
	while (heap_zone_assign(heap, &zone_id, 1 /* new zone */) == 0) {
		if (heap_zone_reclaim_regions(heap, bucket, 0, zone_id,
			1 /* init */, 0) == 0)
			goto out_zone;
	}

	/* downgrade lock */
	h->region_trans_release(heap);
	h->region_trans_lock_shrd(heap);

	return ENOMEM;

out_zone:
	h->active_zone_id = zone_id;
out:
	/*
	 * downgrade such that others can proceed
	 * and update their volatile state
	 */
	/* downgrade lock */
	h->region_trans_release(heap);
	h->region_trans_lock_shrd(heap);

	return ret;
}

/*
 * heap_populate_bucket -- (internal) creates volatile state of memory blocks
 */
static int
heap_populate_bucket(struct palloc_heap *heap, struct bucket *bucket,
	uint32_t units)
{
	LOG(4, "heap %p bucket %p", heap, bucket);

	/* only used in multi-process mode */
	(void) units;

	ASSERTne(heap->rt->active_region, NULL);
	uint32_t zone_id = heap->rt->active_zone_id;

	unsigned next_region_idx = heap->rt->active_region->idx + 1;

	do {
		uint32_t regions_in_use = ZID_TO_ZONE(heap->layout,
			zone_id)->header.regions_in_use;

		for (unsigned r_id = next_region_idx;
			r_id < regions_in_use;
			++r_id) {

			if (heap_region_acquire(heap, bucket, r_id,
				zone_id, 1 /* init */, 0) == 0) {
				heap->rt->active_zone_id = zone_id;
				return 0;
			}
		}

		next_region_idx = 0;
	} while (heap_zone_assign(heap, &zone_id, 1 /* new zone */) == 0);

	return ENOMEM;
}

/*
 * heap_reclaim_garbage -- (internal) creates volatile state of unused runs
 */
static int
heap_reclaim_garbage(struct palloc_heap *heap, struct bucket *bucket,
	uint32_t units)
{
	LOG(4, "heap %p bucket %p", heap, bucket);
	ASSERTne(heap->rt->active_region, NULL);

	(void) units; /* only used in mp-mode */

	struct memory_block m;
	for (size_t i = 0; i < MAX_ALLOCATION_CLASSES; ++i) {
		while (recycler_get(heap->rt->recyclers[i], &m) == 0) {
			m.m_ops->claim_revoke(&m);
		}
	}

	int ret = ENOMEM;
	for (unsigned i = 0;
		i == 0|| i < heap->rt->shrd->zones_exhausted; ++i) {
		struct zone *z = ZID_TO_ZONE(heap->layout, i);
		uint16_t r_max = z->header.regions_in_use;
		for (unsigned r_id = 0; r_id < r_max; ++r_id) {
			struct zone_region *r = &z->regions[r_id];
			if (heap_reclaim_region_garbage(heap, bucket,
			    i, 0 /* not init */, r, 0) == 0) {
				ret = 0;
			}
		}
	}

	return ret;
}

/*
 * heap_reclaim_garbage_mp -- (internal) creates volatile state of unused runs
 * multi-process variant of heap_reclaim_garbage()
 */
static int
heap_reclaim_garbage_mp(struct palloc_heap *heap, struct bucket *bucket,
	uint32_t units)
{
	LOG(3, "heap %p bucket %p", heap, bucket);

	ASSERTne(heap->rt->active_region, NULL);

	struct memory_block m = MEMORY_BLOCK_NONE;
	for (size_t i = 0; i < MAX_ALLOCATION_CLASSES; ++i) {
		while (recycler_get(heap->rt->recyclers[i], &m) == 0) {
			m.m_ops->claim_revoke(&m);
		}
	}

	/*
	 * To avoid duplicate entries we clear the bucket.
	 * We do this since another process might have tainted our region and
	 * our transient state needs to be rebuild.
	 *
	 * Huge buckets are normaly returned to the transient state in
	 * palloc_operation. But in case another process frees a chunk from
	 * our region it wouldn't be put back to the bucket without
	 * reinitialisation in heap_init_free_chunk().
	 */
	heap_empty_bucket(bucket);

	return heap_reclaim_region_garbage(heap, bucket,
	    heap->rt->active_zone_id, 1 /* init */, heap->rt->active_region,
	    units);
}

/*
 * heap_resize_chunk -- (internal) splits the chunk into two smaller ones
 */
static void
heap_resize_chunk(struct palloc_heap *heap, struct bucket *bucket,
	uint32_t chunk_id, uint32_t zone_id, uint32_t new_size_idx)
{
	ASSERT(heap->mp_mode == 0 ||
	    HEAP_CHUNK_FROM_REGION(heap->rt->active_region, chunk_id));

	uint32_t new_chunk_id = chunk_id + new_size_idx;

	struct zone *z = ZID_TO_ZONE(heap->layout, zone_id);
	struct chunk_header *old_hdr = &z->chunk_headers[chunk_id];
	struct chunk_header *new_hdr = &z->chunk_headers[new_chunk_id];

	uint32_t rem_size_idx = old_hdr->size_idx - new_size_idx;
	heap_chunk_init(heap, new_hdr, CHUNK_TYPE_FREE, rem_size_idx);
	heap_chunk_init(heap, old_hdr, CHUNK_TYPE_FREE, new_size_idx);

	struct memory_block m = {new_chunk_id, zone_id, rem_size_idx, 0,
	    0, 0, NULL, NULL};
	memblock_rebuild_state(heap, &m);
	ASSERT(heap->mp_mode == 0 ||
	    HEAP_CHUNK_FROM_REGION(heap->rt->active_region, new_chunk_id));

	bucket_insert_block(bucket, &m);
}


/*
 * heap_recycle_block -- (internal) recycles unused part of the memory block
 */
static void
heap_recycle_block(struct palloc_heap *heap, struct bucket *b,
	struct memory_block *m, uint32_t units)
{
	if (b->aclass->type == CLASS_RUN) {
		ASSERT(units <= UINT16_MAX);
		ASSERT(m->block_off + units <= UINT16_MAX);
		struct memory_block r = { m->chunk_id, m->zone_id,
		    m->size_idx - units, (uint16_t)(m->block_off + units), 0,
		    0, NULL, NULL};
		memblock_rebuild_state(heap, &r);
		if ((heap->mp_mode == 0 ||
		    HEAP_CHUNK_FROM_REGION(heap->rt->active_region,
		    r.chunk_id)) == 0)
			return;

		bucket_insert_block(b, &r);
	} else {
		heap_resize_chunk(heap, b, m->chunk_id, m->zone_id, units);
	}

	m->size_idx = units;
}

/*
 * heap_free_chunk_reuse -- reuses existing free chunk
 */
void
heap_free_chunk_reuse(struct palloc_heap *heap,
	struct bucket *bucket,
	struct memory_block *m)
{
	struct operation_context ctx;
	operation_init(&ctx, heap->base, NULL, NULL);
	ctx.p_ops = &heap->p_ops;

	/*
	 * Perform coalescing just in case there
	 * are any neighbouring free chunks.
	 */
	struct memory_block nm = heap_coalesce_huge(heap, bucket, m,
	    heap_get_active_region(heap));
	if (nm.size_idx != m->size_idx) {
		m->m_ops->prep_hdr(&nm, MEMBLOCK_FREE, &ctx);
		operation_process(&ctx);
	}

	*m = nm;

	bucket_insert_block(bucket, m);
}


/*
 * heap_ensure_run_bucket_filled -- (internal) refills the bucket if needed
 */
static int
heap_ensure_run_bucket_filled(struct palloc_heap *heap, struct bucket *b,
	uint32_t units)
{
	LOG(4, "heap %p bucket %p units %i", heap, b, units);

	ASSERTeq(b->aclass->type, CLASS_RUN);

	int ret = 0;

	/* get rid of the active block in the bucket */
	if (b->is_active) {
		b->c_ops->rm_all(b->container);
		b->active_memory_block.m_ops
			->claim_revoke(&b->active_memory_block);

		b->is_active = 0;
	}

	struct heap_rt *h = heap->rt;
	struct memory_block m = MEMORY_BLOCK_NONE;

	if (recycler_get(h->recyclers[b->aclass->id], &m) == 0) {
		heap_reuse_run(heap, b, &m);

		b->active_memory_block = m;
		b->is_active = 1;

		return 0;
	}

	m.size_idx = b->aclass->run.size_idx;

	/*
	 * unlock the rwlock, such that one thread can obtain the write lock.
	 * default bucket lock protects/syncs next steps.
	 *
	 * If we don't drop the transistion lock here, we will run into a
	 * deadlock, since the default bucket can only be hold from a single
	 * thread at a time. When the waiting process obtains the lock, a
	 * region tranistion might have happened in the meantime.
	 */
	heap->rt->region_trans_release(heap);

	/* cannot reuse an existing run, create a new one */
	struct bucket *defb = heap_bucket_acquire_by_id(heap,
			DEFAULT_ALLOC_CLASS_ID);

	/*
	 * In case we obtained the default bucket, it is safe to share the
	 * region, again.
	 */
	h->region_trans_lock_shrd(heap);

	if (defb == NULL)
		return errno;

	if ((ret = heap_get_bestfit_block(heap, defb, &m)) == 0) {
		ASSERTeq(m.block_off, 0);

		ASSERT(heap_memblock_from_act_region(&m));

		heap_create_run(heap, b, &m);

		b->active_memory_block = m;
		b->is_active = 1;

		goto out;
	}

	if (ret != ENOMEM)
		goto err;

	heap_bucket_release(heap, defb);

	ASSERTne(heap->rt->active_region, NULL);

	/*
	 * Try the recycler again, the previous call to the bestfit_block for
	 * huge chunks might have reclaimed some unused runs.
	 */
	if (recycler_get(h->recyclers[b->aclass->id], &m) == 0) {
		os_mutex_t *lock = m.m_ops->get_lock(&m);
		if ((ret = heap_mutex_lock(heap, lock)) != 0)
			return ret;

		heap_reuse_run(heap, b, &m);
		util_mutex_unlock(lock);

		/*
		 * To verify that the recycler run is not able to satisfy our
		 * request we attempt to retrieve a block. This is not ideal,
		 * and should be replaced by a different heuristic once proper
		 * memory block scoring is implemented.
		 */
		struct memory_block tmp = MEMORY_BLOCK_NONE;
		tmp.size_idx = units;
		if (b->c_ops->get_rm_bestfit(b->container, &tmp) != 0) {
			b->c_ops->rm_all(b->container);
			m.m_ops->claim_revoke(&m);
			return ENOMEM;
		} else {
			bucket_insert_block(b, &tmp);
		}

		b->active_memory_block = m;
		b->is_active = 1;

		return 0;
	}

	return ENOMEM;

err:
out:
	heap_bucket_release(heap, defb);

	return ret;
}

/*
 * heap_get_bestfit_block --
 *	extracts a memory block of equal size index
 */
int
heap_get_bestfit_block(struct palloc_heap *heap, struct bucket *b,
	struct memory_block *m)
{
	ASSERTne(heap->rt->active_region, NULL);

	int ret;
	uint32_t units = m->size_idx;

	while (b->c_ops->get_rm_bestfit(b->container, m) != 0) {
		if (b->aclass->type == CLASS_HUGE) {
			if ((ret = heap_ensure_huge_bucket_filled(heap, b,
				units)) != 0) {
				LOG(4, "!heap_ensure_huge_bucket_filled");
				return ret;
			}
		} else {
			if ((ret = heap_ensure_run_bucket_filled(heap, b,
			    units)) != 0) {
				LOG(4, "!heap_ensure_run_bucket_filled");
				return ret;
			}
		}
	}

	ASSERT(m->size_idx >= units);
	ASSERT(heap_memblock_from_act_region(m));
	if (units != m->size_idx)
		heap_recycle_block(heap, b, m, units);

	return 0;
}

/*
 * heap_get_adjacent_free_block -- locates adjacent free memory block in heap
 */
static int
heap_get_adjacent_free_block(struct palloc_heap *heap,
	const struct memory_block *in,
	struct memory_block *out,
	struct zone_region *region,
	int prev)
{
	struct zone *z = ZID_TO_ZONE(heap->layout, in->zone_id);
	struct chunk_header *hdr = &z->chunk_headers[in->chunk_id];
	out->zone_id = in->zone_id;

	if (prev) {
		if (in->chunk_id == 0 ||
		    in->chunk_id <= region->offset)
			return ENOENT;

		struct chunk_header *prev_hdr =
			&z->chunk_headers[in->chunk_id - 1];
		out->chunk_id = in->chunk_id - prev_hdr->size_idx;

		if (z->chunk_headers[out->chunk_id].type != CHUNK_TYPE_FREE)
			return ENOENT;

		out->size_idx = z->chunk_headers[out->chunk_id].size_idx;
	} else { /* next */
		/* crossing region boundary */
		if (in->chunk_id + hdr->size_idx == z->header.size_idx ||
		    in->chunk_id + hdr->size_idx >=
		    HEAP_END_OF_REGION(region)) {
			return ENOENT;
		}

		out->chunk_id = in->chunk_id + hdr->size_idx;

		if (z->chunk_headers[out->chunk_id].type != CHUNK_TYPE_FREE)
			return ENOENT;

		out->size_idx = z->chunk_headers[out->chunk_id].size_idx;
	}
	memblock_rebuild_state(heap, out);

	return 0;
}

/*
 * heap_coalesce -- (internal) merges adjacent memory blocks
 */
static struct memory_block
heap_coalesce(struct palloc_heap *heap,
	const struct memory_block *blocks[], int n)
{
	struct memory_block ret;
	const struct memory_block *b = NULL;
	ret.size_idx = 0;
	for (int i = 0; i < n; ++i) {
		if (blocks[i] == NULL)
			continue;
		b = b ? b : blocks[i];
		ret.size_idx += blocks[i] ? blocks[i]->size_idx : 0;
	}

	ASSERTne(b, NULL);

	ret.chunk_id = b->chunk_id;
	ret.zone_id = b->zone_id;
	ret.block_off = b->block_off;
	memblock_rebuild_state(heap, &ret);

	return ret;
}

/*
 * heap_coalesce_huge -- finds neighbours of a huge block, removes them from the
 *	volatile state and returns the resulting block
 */
struct memory_block
heap_coalesce_huge(struct palloc_heap *heap, struct bucket *b,
	const struct memory_block *m, struct zone_region *r)
{
	const struct memory_block *blocks[3] = {NULL, m, NULL};

	struct memory_block prev = MEMORY_BLOCK_NONE;
	if (heap_get_adjacent_free_block(heap, m, &prev, r, 1) == 0 &&
		b->c_ops->get_rm_exact(b->container, &prev) == 0) {
		blocks[0] = &prev;
	}

	struct memory_block next = MEMORY_BLOCK_NONE;
	if (heap_get_adjacent_free_block(heap, m, &next, r, 0) == 0 &&
		b->c_ops->get_rm_exact(b->container, &next) == 0) {
		blocks[2] = &next;
	}

	return heap_coalesce(heap, blocks, 3);
}

/*
 * heap_end -- returns first address after heap
 */
void *
heap_end(struct palloc_heap *h)
{
	ASSERT(h->rt->max_zone > 0);

	struct zone *last_zone = ZID_TO_ZONE(h->layout, h->rt->max_zone - 1);

	return &last_zone->chunks[last_zone->header.size_idx];
}

/*
 * heap_get_narenas -- (internal) returns the number of arenas to create
 */
static unsigned
heap_get_narenas(struct palloc_heap *heap)
{
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpus < 1)
		cpus = 1;

	unsigned arenas = (unsigned)cpus;

	LOG(4, "creating %u arenas", arenas);

	return arenas;
}

/*
 * heap_create_alloc_class_buckets -- (internal) allocates all cache bucket
 * instances of the specified type
 */
static int
heap_create_alloc_class_buckets(struct palloc_heap *heap, struct alloc_class *c)
{
	struct heap_rt *h = heap->rt;
	int i;
	for (i = 0; i < (int)h->narenas; ++i) {
		h->arenas[i].buckets[c->id] = bucket_new(
			container_new_seglists(heap), c);
		if (h->arenas[i].buckets[c->id] == NULL)
			goto error_cache_bucket_new;
	}

	return 0;

error_cache_bucket_new:
	for (i -= 1; i >= 0; --i) {
		bucket_delete(h->arenas[i].buckets[c->id]);
	}

	return -1;
}

/*
 * heap_buckets_init -- (internal) initializes bucket instances
 */
int
heap_buckets_init(struct palloc_heap *heap)
{
	struct heap_rt *h = heap->rt;

	for (uint8_t i = 0; i < MAX_ALLOCATION_CLASSES; ++i) {
		struct alloc_class *c = alloc_class_by_id(h->alloc_classes, i);
		if (c != NULL) {
			if (heap_create_alloc_class_buckets(heap, c) != 0)
				goto error_bucket_create;
		}
	}

	h->default_bucket = bucket_new(container_new_ctree(heap),
		alloc_class_by_id(h->alloc_classes, DEFAULT_ALLOC_CLASS_ID));

	if (h->default_bucket == NULL)
		goto error_bucket_create;

	return 0;

error_bucket_create:
	for (unsigned i = 0; i < h->narenas; ++i)
		heap_arena_destroy(&h->arenas[i]);

	return -1;
}

int
heap_boot_env(struct palloc_heap *heap, void *shm_start, size_t shm_size,
	struct registry *registry, int init)
{
	LOG(3, "heap %p, shm_start %p shm_size %zu init %d", heap, shm_start,
		shm_size, init);

	COMPILE_ERROR_ON(OBJ_SHM_HEAP_SIZE < sizeof(struct heap_rt_shm));

	struct heap_rt *h = heap->rt;

	if (heap->mp_mode) {
		if (shm_size < sizeof(struct heap_rt_shm))
			FATAL("!shm_size given size %lu, needed %lu",
				shm_size, sizeof(struct heap_rt_shm));

		if ((h->shrd = (struct heap_rt_shm *)shm_start) == NULL)
			FATAL("!shm_start is NULL");

		h->registry = registry;
	} else {
		h->shrd = Malloc(sizeof(struct heap_rt_shm));
		if (h->shrd == NULL)
			FATAL("Malloc");
	}

	if (init) {
		/*
		 * we are the first process (primary) that opens the heap.
		 * This section is protected by obj_boot(). Secondary
		 * processes wait until state READY is reached.
		 */
		util_mutex_init_mp(&h->shrd->zone_trans_lock);

		/*
		 * if this lock fails there is not much we can do, since it
		 * implies some global problem in the system.
		 */
		for (int i = 0; i < MAX_RUN_LOCKS; ++i)
			util_mutex_init_mp(&h->shrd->run_locks[i]);

		h->shrd->zones_exhausted = 0;
	}

	/*
	 * assign zone and region, but don't populate the buckets, yet.
	 * This has to be done here, because other functions rely on an
	 * initialized region.
	 */
	if (heap_zone_assign(heap, &h->active_zone_id, 0 /* assign */) != 0)
		return -1;

	do {
		uint32_t regions_in_use = ZID_TO_ZONE(heap->layout,
			h->active_zone_id)->header.regions_in_use;

		for (unsigned r_id = 0; r_id < regions_in_use; ++r_id) {
			if (heap_region_claim(heap, r_id,
				h->active_zone_id) == 0)
				return 0;
		}

	} while (heap_zone_assign(heap, &h->active_zone_id, 1 /* new */) == 0);

	return -1;
}

/*
 * heap_region_reset -- (internal) cleanups an acquired region, such that
 * locks are released and default values are set
 *
 * - searches in all regions of all zones for the given idx
 *    - on match it is reset to zero
 * - locks, whose owner died are marked as consistent
 *
 * XXX mp-mode -- should take an array of idxs
 * to avoid traversing the regions multiple times in case several processes
 * crashed.
 */
void
heap_region_reset(const struct palloc_heap *heap, unsigned idx)
{
	LOG(4, "heap %p idx %i", heap, idx);

	int realesed = 0;
	for (unsigned z_id = 0; z_id < heap->rt->max_zone; ++z_id) {
		struct zone *z = ZID_TO_ZONE(heap->layout, z_id);

		if (z->header.magic == 0)
			return;

		uint16_t r_max = z->header.regions_in_use;
		for (unsigned r_id = 0; r_id < r_max; ++r_id) {
			struct zone_region *r = &z->regions[r_id];

			if (r->claimant != idx)
				continue;

			/* check for unlocked regions */
			int err = os_mutex_trylock(&r->lock);
			switch (err) {
				case EOWNERDEAD:
					util_mutex_consistent(&r->lock);
					/* don't break */
				case 0:
					util_mutex_unlock(&r->lock);
					break;
				default:
					ERR("Unexpected lock error"
					    "for region %d claimant %d",
					    r->idx, r->claimant);
			}
			heap_region_reset_claimant(r);
		}
	}
	ASSERT(realesed < 1);
}

struct zone_region *
heap_get_region_by_chunk_id(struct palloc_heap *heap,
	const struct memory_block *m)
{
	struct zone *z = ZID_TO_ZONE(heap->layout, m->zone_id);
	for (unsigned r_id = 0; r_id < z->header.regions_in_use; ++r_id) {
		struct zone_region *r = &z->regions[r_id];
		if (HEAP_CHUNK_FROM_REGION(r, m->chunk_id)) {
			return r;
		}
	}

	return NULL;
}

/*
 * heap_region_init_and_boot -- (internal) inits region runtime values
 */
static void
heap_region_init_and_boot(const struct palloc_heap *heap)
{
	LOG(4, "heap %p", heap);

	for (unsigned z_id = 0; z_id < heap->rt->max_zone; ++z_id) {
		struct zone *z = ZID_TO_ZONE(heap->layout, z_id);

		if (z->header.magic == 0)
			return;

		uint32_t r_max = z->header.regions_in_use;
		for (unsigned r_id = 0; r_id < r_max; ++r_id) {
			struct zone_region *r = &z->regions[r_id];
			heap_region_reset_claimant(r);

			/*
			 * XXX mp-mode -- Placeholder for dynameic region sizes
			 *
			 * Once dyamic region sizes are implemented we have to
			 * adopt the offset and size values here.
			 */

			/*
			 * We overwrite the previous lock.
			 * Such that we don't need to care about whether it was
			 * previously locked and undefined behaviour, due to
			 * reinitialization of an already initialized lock.
			 */
			if (heap->mp_mode)
				util_mutex_init_mp(&r->lock);
		}
	}
}

/*
 * heap_boot -- opens the heap region of the pmemobj pool
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
heap_boot(struct palloc_heap *heap, void *heap_start, uint64_t heap_size,
    uint64_t run_id, void *base, struct pmem_ops *p_ops,
    struct pmemobjpool *pop, int is_primary, unsigned proc_idx)
{
	struct heap_rt *h = Malloc(sizeof(*h));
	int err;
	if (h == NULL) {
		err = ENOMEM;
		goto error_heap_malloc;
	}

	h->active_region = NULL;
	h->active_zone_id = 0;
	h->alloc_classes = alloc_class_collection_new();
	if (h->alloc_classes == NULL) {
		err = ENOMEM;
		goto error_alloc_classes_new;
	}

	h->narenas = heap_get_narenas(heap);
	h->arenas = Malloc(sizeof(struct arena) * h->narenas);
	if (h->arenas == NULL) {
		err = ENOMEM;
		goto error_arenas_malloc;
	}

	h->max_zone = heap_max_zone(heap_size);

	if (heap->mp_mode) {
		h->mtx_lock = heap_mutex_timedlock;
		h->reclaim_garbage = heap_reclaim_garbage_mp;
		h->populate_bucket = heap_populate_bucket_mp;

		h->region_trans_lock_excl = heap_reg_trans_lock_excl_mp;
		h->region_trans_lock_shrd = heap_reg_trans_lock_shrd_mp;
		h->region_trans_release = heap_reg_trans_release_mp;

		h->zone_trans_hold = heap_zone_trans_lock_mp;
		h->zone_trans_release = heap_zone_trans_release_mp;

		/*
		 * XXX mp-mode -- temporary prototypical implementation
		 * should be changed to cond_var or os_* variants for
		 * portability reasons
		 */
		pthread_rwlockattr_t attr;
		/* NP == non-portable */
		pthread_rwlockattr_setkind_np(&attr,
			PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
		pthread_rwlockattr_init(&attr);

		if ((errno = pthread_rwlock_init(
			(pthread_rwlock_t *)&h->rwlock, &attr)))
			FATAL("!os_rwlock_init");
	} else {
		h->mtx_lock = os_mutex_lock;
		h->reclaim_garbage = heap_reclaim_garbage;
		h->populate_bucket = heap_populate_bucket;

		h->region_trans_lock_excl = heap_region_trans_lock_excl;
		h->region_trans_lock_shrd = heap_reg_trans_lock_shrd;
		h->region_trans_release = heap_reg_trans_release;

		h->zone_trans_hold = heap_zone_trans_lock;
		h->zone_trans_release = heap_zone_trans_release;
	}

	util_mutex_init(&h->arenas_lock);

	os_tls_key_create(&h->thread_arena, heap_thread_arena_destructor);

	heap->run_id = run_id;
	heap->proc_idx = proc_idx;
	heap->p_ops = *p_ops;
	heap->layout = heap_start;
	heap->rt = h;
	heap->size = heap_size;
	heap->base = base;
	heap->pop = pop;
	VALGRIND_DO_CREATE_MEMPOOL(heap->layout, 0, 0);

	for (unsigned i = 0; i < h->narenas; ++i)
		heap_arena_init(&h->arenas[i]);

	size_t rec_i;
	for (rec_i = 0; rec_i < MAX_ALLOCATION_CLASSES; ++rec_i) {
		if ((h->recyclers[rec_i] = recycler_new(heap)) == NULL) {
			err = ENOMEM;
			goto error_recycler_new;
		}
	}

	if (is_primary)
		heap_region_init_and_boot(heap);

	return 0;

error_recycler_new:
	Free(h->arenas);
	for (size_t i = 0; i < rec_i; ++i)
		recycler_delete(h->recyclers[i]);
error_arenas_malloc:
	alloc_class_collection_delete(h->alloc_classes);
error_alloc_classes_new:
	Free(h);
	heap->rt = NULL;
error_heap_malloc:
	return err;
}

/*
 * heap_write_header -- (internal) creates a clean header
 */
static void
heap_write_header(struct heap_header *hdr, size_t size)
{
	struct heap_header newhdr = {
		.signature = HEAP_SIGNATURE,
		.major = HEAP_MAJOR,
		.minor = HEAP_MINOR,
		.size = size,
		.chunksize = CHUNKSIZE,
		.chunks_per_zone = MAX_CHUNK,
		.reserved = {0},
		.checksum = 0
	};

	util_checksum(&newhdr, sizeof(newhdr), &newhdr.checksum, 1);
	*hdr = newhdr;
}

/*
 * heap_init -- initializes the heap
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
heap_init(void *heap_start, uint64_t heap_size, struct pmem_ops *p_ops)
{
	if (heap_size < HEAP_MIN_SIZE)
		return EINVAL;

	VALGRIND_DO_MAKE_MEM_UNDEFINED(heap_start, heap_size);

	struct heap_layout *layout = heap_start;
	heap_write_header(&layout->header, heap_size);
	pmemops_persist(p_ops, &layout->header, sizeof(struct heap_header));

	unsigned zones = heap_max_zone(heap_size);
	for (unsigned i = 0; i < zones; ++i) {
		pmemops_memset_persist(p_ops,
				&ZID_TO_ZONE(layout, i)->header,
				0, sizeof(struct zone_header));
		pmemops_memset_persist(p_ops,
				&ZID_TO_ZONE(layout, i)->chunk_headers,
				0, sizeof(struct chunk_header));

		/*
		 * zone_regions are lazily initialized at runtime
		 * in heap_region_init_and_boot() or heap_zone_init()
		 */

		/* only explicitly allocated chunks should be accessible */
		VALGRIND_DO_MAKE_MEM_NOACCESS(
			&ZID_TO_ZONE(layout, i)->chunk_headers,
			sizeof(struct chunk_header));
	}

	return 0;
}

/*
 * heap_runlock_cleanup -- (internal) destroy all shared run locks. Handles
 * crashed locks.
 */
static void
heap_runlock_cleanup(const struct heap_rt *h)
{
	LOG(4, NULL);

	for (int i = 0; i < MAX_RUN_LOCKS; ++i)
		util_mutex_destroy_shrd(&h->shrd->run_locks[i]);
}

/*
 * heap_region_lock_cleanup -- (internal) destroys all region locks. Handles
 * crashed locks.
 */
static void
heap_region_lock_cleanup(struct palloc_heap *h)
{
	int err;
	for (unsigned z_id = 0; z_id < h->rt->max_zone; ++z_id) {
		struct zone *z = ZID_TO_ZONE(h->layout, z_id);

		if (z->header.magic == 0)
			return;

		uint16_t r_max = z->header.regions_in_use;
		for (unsigned r_id = 0; r_id < r_max; ++r_id) {
			struct zone_region *r = &z->regions[r_id];

			err = os_mutex_trylock(&r->lock);
			switch (err) {
				case EOWNERDEAD:
					if (os_mutex_consistent(&r->lock)) {
						ERR("!os_mutex_consistent");
					}
					LOG(3, "Detected a crashed process. "
					    "Shuting down anyway");
				case 0:
					util_mutex_unlock(&r->lock);
					break;
				case EBUSY:
					ERR("Unlocked lock detected.");
				default:
					ERR("Unexpected lock error, during "
					    "shutdown. Destroying lock anyway. "
					    "Undefined behaviour might happen. "
					    "region %d claimant %d",
					    r->idx, r->claimant);

			}
			util_mutex_destroy(&r->lock);
		}
	}
}

/*
 * heap_cleanup_shm -- (internal) cleanups the shared volatile state
 */
void
heap_cleanup_shm(struct palloc_heap *h)
{
	struct heap_rt_shm *shrd_rt = h->rt->shrd;

	heap_runlock_cleanup(h->rt);

	heap_region_lock_cleanup(h);

	util_mutex_destroy(&shrd_rt->zone_trans_lock);
	/* no free here -- deallocation happens in obj_shm_cleanup */
	h->rt->shrd = NULL;
}

/*
 * heap_cleanup -- cleanups the volatile heap state
 */
void
heap_cleanup(struct palloc_heap *heap, int clean_shrd)
{
	struct heap_rt *rt = heap->rt;

	alloc_class_collection_delete(rt->alloc_classes);

	bucket_delete(rt->default_bucket);

	for (unsigned i = 0; i < rt->narenas; ++i)
		heap_arena_destroy(&rt->arenas[i]);

	heap_region_reset_claimant(heap->rt->active_region);

	if (heap->mp_mode) {
		util_rwlock_destroy(&rt->rwlock);

		if (clean_shrd)
			heap_cleanup_shm(heap);

	} else {
		Free(rt->shrd);
	}

	util_mutex_destroy(&rt->arenas_lock);

	os_tls_key_delete(rt->thread_arena);

	Free(rt->arenas);

	for (int i = 0; i < MAX_ALLOCATION_CLASSES; ++i) {
		recycler_delete(rt->recyclers[i]);
	}

	VALGRIND_DO_DESTROY_MEMPOOL(heap->layout);

	Free(rt);
	heap->rt = NULL;
}

/*
 * heap_verify_header -- (internal) verifies if the heap header is consistent
 */
static int
heap_verify_header(struct heap_header *hdr)
{
	if (util_checksum(hdr, sizeof(*hdr), &hdr->checksum, 0) != 1) {
		ERR("heap: invalid header's checksum");
		return -1;
	}

	if (memcmp(hdr->signature, HEAP_SIGNATURE, HEAP_SIGNATURE_LEN) != 0) {
		ERR("heap: invalid signature");
		return -1;
	}

	return 0;
}

/*
 * heap_verify_zone_header --
 *	(internal) verifies if the zone header is consistent
 */
static int
heap_verify_zone_header(struct zone_header *hdr)
{
	if (hdr->size_idx == 0) {
		ERR("heap: invalid zone size");
		return -1;
	}

	return 0;
}

/*
 * heap_verify_chunk_header --
 *	(internal) verifies if the chunk header is consistent
 */
static int
heap_verify_chunk_header(struct chunk_header *hdr)
{
	if (hdr->type == CHUNK_TYPE_UNKNOWN) {
		ERR("heap: invalid chunk type");
		return -1;
	}

	if (hdr->type >= MAX_CHUNK_TYPE) {
		ERR("heap: unknown chunk type");
		return -1;
	}

	if (hdr->flags & ~CHUNK_FLAGS_ALL_VALID) {
		ERR("heap: invalid chunk flags");
		return -1;
	}

	return 0;
}

/*
 * heap_verify_zone -- (internal) verifies if the zone is consistent
 */
static int
heap_verify_zone(struct zone *zone)
{
	if (zone->header.magic == 0)
		return 0; /* not initialized, and that is OK */

	if (zone->header.magic != ZONE_HEADER_MAGIC) {
		ERR("heap: invalid zone magic");
		return -1;
	}

	if (heap_verify_zone_header(&zone->header))
		return -1;

	uint32_t i;
	for (i = 0; i < zone->header.size_idx; ) {
		if (heap_verify_chunk_header(&zone->chunk_headers[i]))
			return -1;

		i += zone->chunk_headers[i].size_idx;
	}

	if (i != zone->header.size_idx) {
		ERR("heap: chunk sizes mismatch");
		return -1;
	}

	/* verify regions */
	uint32_t rchunks = 0;
	for (int j = 0; j < MAX_PROCS; j++) {
		rchunks += zone->regions[j].size;
	}

	if (rchunks != zone->header.size_idx) {
		ERR("heap: region / chunk sizes mismatch");
		return -1;
	}
	return 0;
}

/*
 * heap_check -- verifies if the heap is consistent and can be opened properly
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
heap_check(void *heap_start, uint64_t heap_size)
{
	if (heap_size < HEAP_MIN_SIZE) {
		ERR("heap: invalid heap size");
		return -1;
	}

	struct heap_layout *layout = heap_start;

	if (heap_size != layout->header.size) {
		ERR("heap: heap size missmatch");
		return -1;
	}

	if (heap_verify_header(&layout->header))
		return -1;

	for (unsigned i = 0; i < heap_max_zone(layout->header.size); ++i) {
		if (heap_verify_zone(ZID_TO_ZONE(layout, i)))
			return -1;
	}

	return 0;
}

/*
 * heap_check_remote -- verifies if the heap of a remote pool is consistent
 *                      and can be opened properly
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
heap_check_remote(void *heap_start, uint64_t heap_size, struct remote_ops *ops)
{
	if (heap_size < HEAP_MIN_SIZE) {
		ERR("heap: invalid heap size");
		return -1;
	}

	struct heap_layout *layout = heap_start;

	struct heap_header header;
	if (ops->read(ops->ctx, ops->base, &header, &layout->header,
						sizeof(struct heap_header))) {
		ERR("heap: obj_read_remote error");
		return -1;
	}

	if (heap_size != header.size) {
		ERR("heap: heap size mismatch");
		return -1;
	}

	if (heap_verify_header(&header))
		return -1;

	struct zone *zone_buff = (struct zone *)Malloc(sizeof(struct zone));
	if (zone_buff == NULL) {
		ERR("heap: zone_buff malloc error");
		return -1;
	}
	for (unsigned i = 0; i < heap_max_zone(header.size); ++i) {
		if (ops->read(ops->ctx, ops->base, zone_buff,
				ZID_TO_ZONE(layout, i), sizeof(struct zone))) {
			ERR("heap: obj_read_remote error");
			goto out;
		}

		if (heap_verify_zone(zone_buff)) {
			goto out;
		}
	}
	Free(zone_buff);
	return 0;

out:
	Free(zone_buff);
	return -1;
}

/*
 * heap_run_foreach_object -- (internal) iterates through objects in a run
 */
int
heap_run_foreach_object(struct palloc_heap *heap, object_callback cb,
		void *arg, struct memory_block *m)
{
	uint16_t i = m->block_off / BITS_PER_VALUE;
	uint16_t block_start = m->block_off % BITS_PER_VALUE;
	uint16_t block_off;

	struct chunk_run *run = (struct chunk_run *)
		&ZID_TO_ZONE(heap->layout, m->zone_id)->chunks[m->chunk_id];

	struct alloc_class_run_proto run_proto;
	alloc_class_generate_run_proto(&run_proto,
		run->block_size, m->size_idx);

	for (; i < run_proto.bitmap_nval; ++i) {
		uint64_t v = run->bitmap[i];
		block_off = (uint16_t)(BITS_PER_VALUE * i);

		for (uint16_t j = block_start; j < BITS_PER_VALUE; ) {
			if (block_off + j >= (uint16_t)run_proto.bitmap_nallocs)
				break;

			if (!BIT_IS_CLR(v, j)) {
				m->block_off = (uint16_t)(block_off + j);

				/*
				 * The size index of this memory block cannot be
				 * retrieved at this time because the header
				 * might not be initialized in valgrind yet.
				 */
				m->size_idx = 0;

				if (cb(m, arg)
						!= 0)
					return 1;

				m->size_idx = CALC_SIZE_IDX(run->block_size,
					m->m_ops->get_real_size(m));
				j = (uint16_t)(j + m->size_idx);
			} else {
				++j;
			}
		}
		block_start = 0;
	}

	return 0;
}

/*
 * heap_chunk_foreach_object -- (internal) iterates through objects in a chunk
 */
static int
heap_chunk_foreach_object(struct palloc_heap *heap, object_callback cb,
	void *arg, struct memory_block *m)
{
	struct zone *zone = ZID_TO_ZONE(heap->layout, m->zone_id);
	struct chunk_header *hdr = &zone->chunk_headers[m->chunk_id];
	memblock_rebuild_state(heap, m);
	m->size_idx = hdr->size_idx;

	switch (hdr->type) {
		case CHUNK_TYPE_FREE:
			return 0;
		case CHUNK_TYPE_USED:
			return cb(m, arg);
		case CHUNK_TYPE_RUN:
			return heap_run_foreach_object(heap, cb, arg, m);
		default:
			ASSERT(0);
	}

	return 0;
}

/*
 * heap_zone_foreach_object -- (internal) iterates through objects in a zone
 */
static int
heap_zone_foreach_object(struct palloc_heap *heap, object_callback cb,
	void *arg, struct memory_block *m)
{
	struct zone *zone = ZID_TO_ZONE(heap->layout, m->zone_id);
	if (zone->header.magic == 0)
		return 0;

	for (; m->chunk_id < zone->header.size_idx; ) {
		if (heap_chunk_foreach_object(heap, cb, arg, m) != 0)
			return 1;

		m->chunk_id += zone->chunk_headers[m->chunk_id].size_idx;

		/* reset the starting position of memblock */
		m->block_off = 0;
		m->size_idx = 0;
	}

	return 0;
}

/*
 * heap_foreach_object -- (internal) iterates through objects in the heap
 */
void
heap_foreach_object(struct palloc_heap *heap, object_callback cb, void *arg,
	struct memory_block m)
{
	struct heap_layout *layout = heap->layout;

	for (; m.zone_id < heap_max_zone(layout->header.size); ++m.zone_id) {
		if (heap_zone_foreach_object(heap, cb, arg, &m) != 0)
			break;

		m.chunk_id = 0;
	}
}

#ifdef USE_VG_MEMCHECK

/*
 * heap_vg_open_chunk -- (internal) notifies Valgrind about chunk layout
 */
static void
heap_vg_open_chunk(struct palloc_heap *heap,
	object_callback cb, void *arg, int objects,
	struct memory_block *m)
{
	struct zone *z = ZID_TO_ZONE(heap->layout, m->zone_id);
	void *chunk = &z->chunks[m->chunk_id];
	memblock_rebuild_state(heap, m);

	if (m->type == MEMORY_BLOCK_RUN) {
		struct chunk_run *run = chunk;

		ASSERTne(m->size_idx, 0);
		VALGRIND_DO_MAKE_MEM_NOACCESS(run,
			SIZEOF_RUN(run, m->size_idx));

		/* set the run metadata as defined */
		VALGRIND_DO_MAKE_MEM_DEFINED(run,
			sizeof(*run) - sizeof(run->data));

		if (objects) {
			int ret = heap_run_foreach_object(heap, cb, arg, m);
			ASSERTeq(ret, 0);
		}
	} else {
		size_t size = m->m_ops->get_real_size(m);
		VALGRIND_DO_MAKE_MEM_NOACCESS(chunk, size);

		if (objects && m->m_ops->get_state(m) == MEMBLOCK_ALLOCATED) {
			int ret = cb(m, arg);
			ASSERTeq(ret, 0);
		}
	}
}

/*
 * heap_vg_open -- notifies Valgrind about heap layout
 */
void
heap_vg_open(struct palloc_heap *heap, object_callback cb,
	void *arg, int objects)
{
	ASSERTne(cb, NULL);
	VALGRIND_DO_MAKE_MEM_UNDEFINED(heap->layout, heap->size);

	struct heap_layout *layout = heap->layout;

	VALGRIND_DO_MAKE_MEM_DEFINED(&layout->header, sizeof(layout->header));

	unsigned zones = heap_max_zone(heap->size);

	struct memory_block m = MEMORY_BLOCK_NONE;
	for (unsigned i = 0; i < zones; ++i) {
		struct zone *z = ZID_TO_ZONE(layout, i);
		uint32_t chunks;
		m.zone_id = i;
		m.chunk_id = 0;

		VALGRIND_DO_MAKE_MEM_DEFINED(&z->header, sizeof(z->header));
		VALGRIND_DO_MAKE_MEM_DEFINED(&z->regions, sizeof(z->regions));

		if (z->header.magic != ZONE_HEADER_MAGIC)
			continue;

		chunks = z->header.size_idx;

		for (uint32_t c = 0; c < chunks; ) {
			struct chunk_header *hdr = &z->chunk_headers[c];
			m.chunk_id = c;

			VALGRIND_DO_MAKE_MEM_DEFINED(hdr, sizeof(*hdr));

			m.size_idx = hdr->size_idx;
			heap_vg_open_chunk(heap, cb, arg, objects, &m);
			m.block_off = 0;

			ASSERT(hdr->size_idx > 0);

			if (hdr->type == CHUNK_TYPE_RUN) {
				/*
				 * Mark run data headers as defined.
				 */
				for (unsigned j = 1; j < hdr->size_idx; ++j) {
					struct chunk_header *data_hdr =
						&z->chunk_headers[c + j];
					VALGRIND_DO_MAKE_MEM_DEFINED(data_hdr,
						sizeof(struct chunk_header));
					ASSERTeq(data_hdr->type,
						CHUNK_TYPE_RUN_DATA);
				}
			} else {
				/*
				 * Mark unused chunk headers as not accessible.
				 */
				VALGRIND_DO_MAKE_MEM_NOACCESS(
					&z->chunk_headers[c + 1],
					(hdr->size_idx - 1) *
					sizeof(struct chunk_header));
			}

			c += hdr->size_idx;
		}

		/* mark all unused chunk headers after last as not accessible */
		VALGRIND_DO_MAKE_MEM_NOACCESS(&z->chunk_headers[chunks],
			(MAX_CHUNK - chunks) * sizeof(struct chunk_header));
	}
}
#endif
