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
 * pmalloc.c -- implementation of pmalloc POSIX-like API
 *
 * This is the front-end part of the persistent memory allocator. It uses both
 * transient and persistent representation of the heap to provide memory blocks
 * in a reasonable time and with an acceptable common-case fragmentation.
 */

#include "valgrind_internal.h"
#include "heap.h"
#include "memops.h"
#include "obj.h"
#include "out.h"
#include "palloc.h"
#include "pmalloc.h"

#ifdef DEBUG
/*
 * In order to prevent allocations from inside of a constructor, each lane hold
 * invocation sets the, otherwise unused, runtime part of the lane section
 * to a value that marks an in progress allocation. Likewise, each lane release
 * sets the runtime variable back to NULL.
 *
 * Because this check requires additional hold/release pair for every single
 * allocation, it's done only for debug builds.
 */
#define ALLOC_INPROGRESS_MARK ((void *)0x1)
#endif

/*
 * pmalloc_redo_hold -- acquires allocator lane section and returns a pointer to
 * it's redo log
 */
struct redo_log *
pmalloc_redo_hold(PMEMobjpool *pop)
{
	struct lane_section *lane;
	lane_hold(pop, &lane, LANE_SECTION_ALLOCATOR);

#ifdef DEBUG
	ASSERTeq(lane->runtime, NULL);
	lane->runtime = ALLOC_INPROGRESS_MARK;
#endif

	struct lane_alloc_layout *sec = (void *)lane->layout;
	return sec->redo;
}

/*
 * pmalloc_redo_release -- releases allocator lane section
 */
void
pmalloc_redo_release(PMEMobjpool *pop)
{
#ifdef DEBUG
	/* there's no easier way, I've tried */
	struct lane_section *lane;
	lane_hold(pop, &lane, LANE_SECTION_ALLOCATOR);
	lane->runtime = NULL;
	lane_release(pop);
#endif
	lane_release(pop);
}

/*
 * pmalloc_operation -- higher level wrapper for basic allocator API
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
pmalloc_operation(PMEMobjpool *pop, uint64_t off, uint64_t *dest_off,
	size_t size, palloc_constr constructor, void *arg,
	uint64_t extra_field, uint16_t flags,
	struct operation_context *ctx)
{
#ifdef USE_VG_MEMCHECK
	uint64_t tmp;
	if (size && On_valgrind && dest_off == NULL)
		dest_off = &tmp;
#endif
	int err;
again:
	err = palloc_operation(&pop->heap, off, dest_off, size,
		constructor, arg, extra_field, flags, ctx);
	if (!err)
		return 0;

	if (pop->mp_mode) {
		switch (errno) {
			case ENOMEM:
				/*
				 * We could run recovery here, to make sure that
				 * no other process left a region behind that
				 * has some free space. However, we might then
				 * have to cope with different threads. Only one
				 * thread should run recovery.
				 *
				 * So its better to leave this decision
				 * up to the caller, such that he can choose
				 * to investigate the situation and when
				 * recovery is started, respectively.
				 */
				break;
			case EOWNERDEAD:
				/*
				 * We encountered a dead process while
				 * acquiring a lock and need to either close and
				 * reopen the pool or run recovery.
				 */
				if (obj_crash_check_and_recover(pop) == 0) {
					LOG(7, "retrying after recovery");
					goto again;
				}
				break;
			case ETIMEDOUT:
				/*
				 * We don't know the exact reason for the
				 * timeout. The culprit might continue his work,
				 * freeze / starve or eventually crash.
				 *
				 * Thus it's best to leave error handling
				 * up to the callers, such that he
				 * can investigate and decide the following
				 * actions
				 */
			default:
				break;
		}
	}

	return -1;
}

/*
 * pmalloc -- allocates a new block of memory
 *
 * The pool offset is written persistently into the off variable.
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
pmalloc(PMEMobjpool *pop, uint64_t *off, size_t size,
	uint64_t extra_field, uint16_t flags)
{
	struct redo_log *redo = pmalloc_redo_hold(pop);

	struct operation_context ctx;
	operation_init(&ctx, pop->base_addr, pop->redo, redo);

	int ret = pmalloc_operation(pop, 0, off, size, NULL, NULL,
		extra_field, flags, &ctx);

	pmalloc_redo_release(pop);

	return ret;
}

/*
 * pmalloc_construct -- allocates a new block of memory with a constructor
 *
 * The block offset is written persistently into the off variable, but only
 * after the constructor function has been called.
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
pmalloc_construct(PMEMobjpool *pop, uint64_t *off, size_t size,
	palloc_constr constructor, void *arg,
	uint64_t extra_field, uint16_t flags)
{
	struct redo_log *redo = pmalloc_redo_hold(pop);
	struct operation_context ctx;

	operation_init(&ctx, pop, pop->redo, redo);

	int ret = pmalloc_operation(pop, 0, off, size, constructor, arg,
			extra_field, flags, &ctx);

	pmalloc_redo_release(pop);

	return ret;
}

/*
 * prealloc -- resizes in-place a previously allocated memory block
 *
 * The block offset is written persistently into the off variable.
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
prealloc(PMEMobjpool *pop, uint64_t *off, size_t size,
	uint64_t extra_field, uint16_t flags)
{
	struct redo_log *redo = pmalloc_redo_hold(pop);
	struct operation_context ctx;

	operation_init(&ctx, pop, pop->redo, redo);

	int ret = pmalloc_operation(pop, *off, off, size, NULL, NULL,
		extra_field, flags, &ctx);

	pmalloc_redo_release(pop);

	return ret;
}

/*
 * pfree -- deallocates a memory block previously allocated by pmalloc
 *
 * A zero value is written persistently into the off variable.
 *
 * If successful function returns zero. Otherwise an error number is returned.
 */
int
pfree(PMEMobjpool *pop, uint64_t *off)
{
	struct redo_log *redo = pmalloc_redo_hold(pop);
	struct operation_context ctx;

	operation_init(&ctx, pop, pop->redo, redo);

	int ret = pmalloc_operation(pop, *off, off, 0, NULL, NULL,
		0, 0, &ctx);

	if (!pop->mp_mode)
		ASSERTeq(ret, 0);

	pmalloc_redo_release(pop);

	return ret;
}

/*
 * pmalloc_construct_rt -- construct runtime part of allocator section
 */
static void *
pmalloc_construct_rt(PMEMobjpool *pop)
{
	return NULL;
}

/*
 * pmalloc_destroy_rt -- destroy runtime part of allocator section
 */
static void
pmalloc_destroy_rt(PMEMobjpool *pop, void *rt)
{
	/* NOP */
}

/*
 * pmalloc_recovery -- recovery of allocator lane section
 */
static int
pmalloc_recovery(PMEMobjpool *pop, void *data, unsigned length)
{
	struct lane_alloc_layout *sec = data;
	ASSERT(sizeof(*sec) <= length);

	redo_log_recover(pop->redo, sec->redo, ALLOC_REDO_LOG_SIZE);

	return 0;
}

/*
 * pmalloc_check -- consistency check of allocator lane section
 */
static int
pmalloc_check(PMEMobjpool *pop, void *data, unsigned length)
{
	LOG(3, "allocator lane %p", data);

	struct lane_alloc_layout *sec = data;

	int ret = redo_log_check(pop->redo, sec->redo, ALLOC_REDO_LOG_SIZE);
	if (ret != 0)
		ERR("allocator lane: redo log check failed");

	return ret;
}

/*
 * pmalloc_boot -- initializes allocator section
 */
static int
pmalloc_boot(PMEMobjpool *pop)
{
	pop->heap.mp_mode = pop->mp_mode;
	int ret = palloc_boot(&pop->heap,
	    (char *)pop->base_addr + pop->pool_desc->heap_offset,
	    pop->pool_desc->heap_size, pop->pool_desc->run_id, pop->base_addr,
	    &pop->p_ops, pop, pop->is_primary, pop->proc_idx);
	if (ret)
		return ret;

#ifdef USE_VG_MEMCHECK
	palloc_heap_vg_open(&pop->heap, pop->vg_boot);
#endif

	ret = palloc_boot_env(&pop->heap, pop->shrd->shm_heap,
		OBJ_SHM_HEAP_SIZE, pop->registry, pop->is_primary);
	if (ret)
		return ret;

	ret = palloc_buckets_init(&pop->heap);
	if (ret) {
		if (pop->mp_mode)
			palloc_heap_cleanup(&pop->heap, pop->is_primary);
	}

	return ret;
}

static struct section_operations allocator_ops = {
	.construct_rt = pmalloc_construct_rt,
	.destroy_rt = pmalloc_destroy_rt,
	.recover = pmalloc_recovery,
	.check = pmalloc_check,
	.boot = pmalloc_boot
};

SECTION_PARM(LANE_SECTION_ALLOCATOR, &allocator_ops);
