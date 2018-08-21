/*
 * Copyright 2014-2017, Intel Corporation
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
 * obj.h -- internal definitions for obj module
 */

#ifndef LIBPMEMOBJ_OBJ_H
#define LIBPMEMOBJ_OBJ_H 1

#include <stddef.h>
#include <stdint.h>
#include <os_thread.h>

#include "lane.h"
#include "pool_hdr.h"
#include "pmalloc.h"
#include "redo.h"
#include "ctl.h"
#include "ringbuf.h"
#include "mp.h"

#define PMEMOBJ_LOG_PREFIX "libpmemobj"
#define PMEMOBJ_LOG_LEVEL_VAR "PMEMOBJ_LOG_LEVEL"
#define PMEMOBJ_LOG_FILE_VAR "PMEMOBJ_LOG_FILE"

/* attributes of the obj memory pool format for the pool header */
#define OBJ_HDR_SIG "PMEMOBJ"	/* must be 8 bytes including '\0' */
#define OBJ_FORMAT_MAJOR 4
#define OBJ_FORMAT_COMPAT 0x0000
#define OBJ_FORMAT_INCOMPAT 0x0000
#define OBJ_FORMAT_RO_COMPAT 0x0000

/* size of the persistent part of PMEMOBJ pool descriptor (2kB) */
#define OBJ_DSC_P_SIZE		2048
/* size of unused part of the persistent part of PMEMOBJ pool descriptor */
#define OBJ_DSC_P_UNUSED	(OBJ_DSC_P_SIZE - PMEMOBJ_MAX_LAYOUT - 40)

/* Unused runtime part of the pool_descriptor */
#define OBJ_DESC_RT_RESERVED	1952

#define OBJ_LANES_OFFSET	8192	/* lanes offset (8kB) */
#define OBJ_NLANES		1024	/* number of lanes */

#define OBJ_OFF_TO_PTR(pop, off) ((void *)((uintptr_t)(pop->base_addr) + (off)))
#define OBJ_PTR_TO_OFF(pop, ptr)\
	((uintptr_t)(ptr) - (uintptr_t)(pop)->base_addr)

#define OBJ_OID_IS_NULL(oid)	((oid).off == 0)
#define OBJ_LIST_EMPTY(head)	OBJ_OID_IS_NULL((head)->pe_first)

#define OBJ_OFF_FROM_HEAP(pop, off)\
	((off) >= (pop)->pool_desc->heap_offset &&\
	(off) < (pop)->pool_desc->heap_offset + (pop)->pool_desc->heap_size)

#define OBJ_OFF_FROM_LANES(pop, off)\
	((off) >= (pop)->pool_desc->lanes_offset &&\
	(off) < (pop)->pool_desc->lanes_offset +\
	(pop)->pool_desc->nlanes * sizeof(struct lane_layout))

#define OBJ_PTR_FROM_POOL(pop, ptr)\
	((uintptr_t)(ptr) >= (uintptr_t)(pop->base_addr) &&\
	(uintptr_t)(ptr) < (uintptr_t)(pop->base_addr) + (pop)->size)

#define OBJ_OFF_IS_VALID(pop, off)\
	(OBJ_OFF_FROM_HEAP(pop, off) ||\
	(OBJ_PTR_TO_OFF(pop, &(pop)->pool_desc->root_offset) == (off)) ||\
	(OBJ_PTR_TO_OFF(pop, &(pop)->pool_desc->root_size) == (off)) ||\
	(OBJ_OFF_FROM_LANES(pop, off)))

#define OBJ_PTR_IS_VALID(pop, ptr)\
	OBJ_OFF_IS_VALID(pop, OBJ_PTR_TO_OFF(pop, ptr))

typedef void (*persist_local_fn)(const void *, size_t);
typedef void (*flush_local_fn)(const void *, size_t);
typedef void (*drain_local_fn)(void);
typedef void *(*memcpy_local_fn)(void *dest, const void *src, size_t len);
typedef void *(*memset_local_fn)(void *dest, int c, size_t len);

typedef void *(*persist_remote_fn)(PMEMobjpool *pop, const void *addr,
					size_t len, unsigned lane);

typedef int (*pmem_lock_fn)(PMEMobjpool *pop, PMEMmutex *lock);
typedef int (*pmem_unlock_fn)(PMEMobjpool *pop, PMEMmutex *lock);

typedef uint64_t type_num_t;

#define CONVERSION_FLAG_OLD_SET_CACHE ((1ULL) << 0)


enum initialization_state {
	UNINITIALIZED,
	MTX_INITIALIZED,
	SHM_RUNTIME_INITIALIZED,
	RECOVERY_RUNNING,
	READY,

	MAX_STATES
};

/*
 * An instance of the following structure is used to store the busy-handler
 * callback for a given sqlite handle.
 *
 * The busy_handler member of the pmemobjpool struct contains the busy
 * callback.
 */
struct busy_handler {
	int (*xFunc)(void *, int);	/* The busy callback */
	void *pArg;			/* First arg to busy callback */
	int nBusy;			/* Incremented with each busy call */
};

/*
 * structure used to represents a shared memory buffer
 *
 * ~ 114 kB
 */
struct obj_shared_env {
	char shm_heap[OBJ_SHM_HEAP_SIZE];
	struct lane lane[OBJ_NLANES];
	uint64_t lane_locks[OBJ_NLANES];
	char shm_registry[OBJ_SHM_REGISTRY_SIZE];

	os_mutex_t lock;
	os_cond_t cond;

	volatile enum initialization_state state;
	volatile unsigned magic;
	size_t area_size; /* size of the shm area */
};

/*
 * Structrure represents the pool descriptor
 */
struct pool_descriptor {
	/* persistent part of PMEMOBJ pool descriptor (2kB) */
	char layout[PMEMOBJ_MAX_LAYOUT];
	uint64_t lanes_offset;
	uint64_t nlanes;
	uint64_t heap_offset;
	uint64_t heap_size;
	unsigned char unused[OBJ_DSC_P_UNUSED]; /* must be zero */
	uint64_t checksum;	/* checksum of above fields */

	/* persistent but not checksummed section */

	PMEMmutex rootlock;	/* persistent root object lock */

	uint64_t root_offset;

	/* unique runID for this program run */
	uint64_t run_id;

	uint64_t root_size;

	/*
	 * These flags can be set from a conversion tool and are set only for
	 * the first recovery of the pool.
	 */
	uint64_t conversion_flags;

	char pmem_reserved[OBJ_DESC_RT_RESERVED]; /* must be zeroed */
};

#define CONVERSION_FLAG_OLD_SET_CACHE ((1ULL) << 0)

struct pmemobjpool {
	struct pool_hdr hdr;	/* memory pool header */
	struct pool_descriptor *pool_desc; /* 4096 bytes */

	/* some run-time state */
	void *addr;		/* mapped region */
	size_t size;		/* size of mapped region */
	int is_pmem;		/* true if pool is PMEM */
	int rdonly;		/* true if pool is opened read-only */
	struct palloc_heap heap;
	struct lane_descriptor lanes_desc;
	uint64_t uuid_lo;
	int is_dev_dax;		/* true if mapped on device dax */

	struct ctl *ctl;
	struct ringbuf *tx_postcommit_tasks;

	struct pool_set *set;		/* pool set info */
	struct pmemobjpool *replica;	/* next replica */
	struct redo_ctx *redo;

	/* per-replica functions: pmem or non-pmem */
	persist_local_fn persist_local;	/* persist function */
	flush_local_fn flush_local;	/* flush function */
	drain_local_fn drain_local;	/* drain function */
	memcpy_local_fn memcpy_persist_local; /* persistent memcpy function */
	memset_local_fn memset_persist_local; /* persistent memset function */

	/* for 'master' replica: with or without data replication */
	struct pmem_ops p_ops;

	int is_master_replica;
	int has_remote_replicas;

	/* remote replica section */
	void *rpp;	/* RPMEMpool opaque handle if it is a remote replica */
	uintptr_t remote_base;	/* beginning of the pool's descriptor */
	char *node_addr;	/* address of a remote node */
	char *rpool_desc;	/* descriptor of a poolset */

	persist_remote_fn persist_remote; /* remote persist function */

	int vg_boot;
	int tx_debug_skip_expensive_checks;

	struct tx_parameters *tx_params;

	/* multi-process section */
	void *base_addr;	/*  points to the beginning of the pool */
				/* (master replica), i.e. */
				/* set->replica[0]->part[0].addr; */

	unsigned mp_mode;	/* true when in multi-processing mode */

	int is_primary; 	/* true if process is responsible */
				/* for  initialization */


	unsigned proc_idx; /* unique process idx assigned via registry */

	struct registry *registry;	/* registry shared */

	struct lane_range *lane_range; 	/* lane range assigned via registry */

	int lock_fd; 			/* file descriptor of lock file */
	int shm_fd;			/* file descriptor of shm file */
	const char *shm_path;		/* path to shm */
	struct obj_shared_env *shrd; 	/* shared memory (shm) */

	int busyTimeout;		/* timeout in ms for busy wait */
	struct busy_handler busy_handler;    /* busy wait handler */

	pmem_lock_fn pmem_lock;		/* pmem lock function */
	pmem_unlock_fn pmem_unlock;	/* pmem unlock function */
};

/*
 * Stored in the 'size' field of oobh header, determines whether the object
 * is internal or not. Internal objects are skipped in pmemobj iteration
 * functions.
 */
#define OBJ_INTERNAL_OBJECT_MASK ((1ULL) << 15)

/*
 * pmemobj_get_uuid_lo -- (internal) evaluates XOR sum of least significant
 * 8 bytes with most significant 8 bytes.
 */
static inline uint64_t
pmemobj_get_uuid_lo(const PMEMobjpool *pop)
{
	uint64_t uuid_lo = 0;

	for (int i = 0; i < 8; i++) {
		uuid_lo = (uuid_lo << 8) |
			(pop->hdr.poolset_uuid[i] ^
				pop->hdr.poolset_uuid[8 + i]);
	}

	return uuid_lo;
}

/*
 * OBJ_OID_IS_VALID -- (internal) checks if 'oid' is valid
 */
static inline int
OBJ_OID_IS_VALID(PMEMobjpool *pop, PMEMoid oid)
{
	return OBJ_OID_IS_NULL(oid) ||
		(oid.pool_uuid_lo == pop->uuid_lo &&
		    oid.off >= pop->pool_desc->heap_offset &&
		    oid.off < pop->pool_desc->heap_offset\
		    + pop->pool_desc->heap_size);
}

void obj_shm_cleanup(PMEMobjpool *pop, int clean_shrd);

PMEMobjpool *pmemobjpool_new(void);
void pmemobjpool_delete(PMEMobjpool *pop);
void obj_init(void);
void obj_fini(void);
void *pmemobj_get_base_addr(void *pop);
int obj_read_remote(void *ctx, uintptr_t base, void *dest, void *addr,
		size_t length);

/*
 * XXX mp-mode --  Code below was taken from SQLITE3 project
 * and should be adapted to our needs.
 *
 * CAPI3REF: Register A Callback To Handle SQLITE_BUSY Errors
 * KEYWORDS: {busy-handler callback} {busy handler}
 * METHOD: sqlite3
 *
 * ^The sqlite3_busy_handler(D,X,P) routine sets a callback function X
 * that might be invoked with argument P whenever
 * an attempt is made to access a database table associated with
 * [database connection] D when another thread
 * or process has the table locked.
 * The sqlite3_busy_handler() interface is used to implement
 * [sqlite3_busy_timeout()] and [PRAGMA busy_timeout].
 *
 * ^If the busy callback is NULL, then [SQLITE_BUSY]
 * is returned immediately upon encountering the lock.  ^If the busy callback
 * is not NULL, then the callback might be invoked with two arguments.
 *
 * ^The first argument to the busy handler is a copy of the void* pointer which
 * is the third argument to sqlite3_busy_handler().  ^The second argument to
 * the busy handler callback is the number of times that the busy handler has
 * been invoked previously for the same locking event.  ^If the
 * busy callback returns 0, then no additional attempts are made to
 * access the database and [SQLITE_BUSY] is returned
 * to the application.
 * ^If the callback returns non-zero, then another attempt
 * is made to access the database and the cycle repeats.
 *
 * The presence of a busy handler does not guarantee that it will be invoked
 * when there is lock contention. ^If SQLite determines that invoking the busy
 * handler could result in a deadlock, it will go ahead and return [SQLITE_BUSY]
 * to the application instead of invoking the
 * busy handler.
 * Consider a scenario where one process is holding a read lock that
 * it is trying to promote to a reserved lock and
 * a second process is holding a reserved lock that it is trying
 * to promote to an exclusive lock.  The first process cannot proceed
 * because it is blocked by the second and the second process cannot
 * proceed because it is blocked by the first.  If both processes
 * invoke the busy handlers, neither will make any progress.  Therefore,
 * SQLite returns [SQLITE_BUSY] for the first process, hoping that this
 * will induce the first process to release its read lock and allow
 * the second process to proceed.
 *
 * ^The default busy callback is NULL.
 *
 * ^(There can only be a single busy handler defined for each
 * [database connection].  Setting a new busy handler clears any
 * previously set handler.)^  ^Note that calling [sqlite3_busy_timeout()]
 * or evaluating [PRAGMA busy_timeout=N] will change the
 * busy handler and thus clear any previously set busy handler.
 *
 * The busy callback should not take any actions which modify the
 * database connection that invoked the busy handler.  In other words,
 * the busy handler is not reentrant.  Any such actions
 * result in undefined behavior.
 *
 * A busy handler must not close the database connection
 * or [prepared statement] that invoked the busy handler.
 */
int obj_register_busy_handler(PMEMobjpool *pop, int (*xBusy)(void *, int),
	void *pArg);

int obj_invoke_busy_handler(struct busy_handler *p);

/*
 * (debug helper macro) logs notice message if used inside a transaction
 */
#ifdef DEBUG
#define _POBJ_DEBUG_NOTICE_IN_TX()\
	_pobj_debug_notice(__func__, NULL, 0)
#else
#define _POBJ_DEBUG_NOTICE_IN_TX() do {} while (0)
#endif

#endif
