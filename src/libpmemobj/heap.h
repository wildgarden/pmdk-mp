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
 * heap.h -- internal definitions for heap
 */

#ifndef LIBPMEMOBJ_HEAP_H
#define LIBPMEMOBJ_HEAP_H 1

#include <stddef.h>
#include <stdint.h>

#include "bucket.h"
#include "heap_layout.h"
#include "memblock.h"
#include "memops.h"
#include "palloc.h"
#include "os_thread.h"
#include "registry.h"

#define HEAP_OFF_TO_PTR(heap, off) ((void *)((char *)((heap)->base) + (off)))
#define HEAP_PTR_TO_OFF(heap, ptr)\
	((uintptr_t)(ptr) - (uintptr_t)(heap->base))

#define HEAP_END_OF_REGION(r) ((r)->offset + (r)->size - 1)
#define HEAP_CHUNK_FROM_REGION(region, chunk_id)\
	((chunk_id) >= (region)->offset &&\
	(chunk_id) <= (HEAP_END_OF_REGION(region)))

#define BIT_IS_CLR(a, i)	(!((a) & (1ULL << (i))))

#define REGION_UNCLAIMED UINT32_MAX

typedef int (*lock_fn)(os_mutex_t *__restrict mutex);
typedef int (*populate_bucket_fn)(struct palloc_heap *heap,
	struct bucket *bucket, uint32_t units);
typedef int (*reclaim_garbage_fn)(struct palloc_heap *heap,
	struct bucket *bucket, uint32_t units);

typedef int (*zone_transition_hold_fn)(struct palloc_heap *heap);
typedef void (*zone_transition_release_fn)(struct palloc_heap *heap);

typedef void (*region_transiton_hold_shrd_fn)(struct palloc_heap *heap);
typedef void (*region_transiton_hold_excl_fn)(struct palloc_heap *heap);
typedef void (*region_transiton_release_fn)(struct palloc_heap *heap);


int heap_boot(struct palloc_heap *heap, void *heap_start, uint64_t heap_size,
    uint64_t run_id, void *base, struct pmem_ops *p_ops,
    struct pmemobjpool *pop, int is_primary, unsigned proc_idx);

int heap_boot_env(struct palloc_heap *heap, void *shm_start, size_t shm_size,
	struct registry *registry, int init);

int heap_init(void *heap_start, uint64_t heap_size, struct pmem_ops *p_ops);
void heap_cleanup(struct palloc_heap *heap, int clean_shrd);
void heap_cleanup_shm(struct palloc_heap *h);
int heap_check(void *heap_start, uint64_t heap_size);
int heap_check_remote(void *heap_start, uint64_t heap_size,
		struct remote_ops *ops);
int heap_buckets_init(struct palloc_heap *heap);

struct alloc_class *
heap_get_best_class(struct palloc_heap *heap, size_t size);

struct zone_region *
heap_get_active_region(struct palloc_heap *heap);

struct bucket *
heap_bucket_acquire(struct palloc_heap *heap, struct alloc_class *c);

struct bucket *
heap_bucket_acquire_by_id(struct palloc_heap *heap, uint8_t class_id);

void
heap_bucket_release(struct palloc_heap *heap, struct bucket *b);

int
heap_mutex_lock(struct palloc_heap *h, os_mutex_t *lock);

int heap_get_bestfit_block(struct palloc_heap *heap, struct bucket *b,
	struct memory_block *m);

struct memory_block
heap_coalesce_huge(struct palloc_heap *heap, struct bucket *b,
	const struct memory_block *m, struct zone_region *r);

os_mutex_t *heap_get_huge_lock(struct palloc_heap *heap, uint32_t zone_id,
	uint32_t chunk_id);

os_mutex_t *heap_get_run_lock(struct palloc_heap *heap,
		uint32_t chunk_id);

void heap_region_reset(const struct palloc_heap *heap, unsigned idx);

void heap_region_trans_lock_shrd(struct palloc_heap *heap);
void heap_region_trans_release(struct palloc_heap *heap);

struct zone_region *
heap_get_region_by_chunk_id(struct palloc_heap *heap,
	const struct memory_block *m);

int
heap_memblock_from_act_region(const struct memory_block *m);

int
heap_run_foreach_object(struct palloc_heap *heap, object_callback cb,
	void *arg, struct memory_block *m);
void heap_foreach_object(struct palloc_heap *heap, object_callback cb,
	void *arg, struct memory_block start);

void *heap_end(struct palloc_heap *heap);

void heap_vg_open(struct palloc_heap *heap, object_callback cb,
		void *arg, int objects);

void
heap_free_chunk_reuse(struct palloc_heap *heap,
	struct bucket *bucket, struct memory_block *m);
#endif
