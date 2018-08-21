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
 * obj.c -- transactional object store implementation
 */
#include <inttypes.h>
#include <limits.h>
#include <wchar.h>

#include "valgrind_internal.h"
#include "libpmem.h"
#include "ctree.h"
#include "cuckoo.h"
#include "list.h"
#include "mmap.h"
#include "obj.h"
#include "ctl_global.h"

#include "heap_layout.h"
#include "os.h"
#include "os_thread.h"
#include "pmemops.h"
#include "set.h"
#include "sync.h"
#include "tx.h"
#include "registry.h"
#include <sched.h>
#include <os_shm.h>
#include <sys_util.h>

/*
 * The variable from which the config is directly loaded. The contained string
 * cannot contain any comments or extraneous white characters.
 */
#define OBJ_CONFIG_ENV_VARIABLE "PMEMOBJ_CONF"

/*
 * The variable that points to a config file from which the config is loaded.
 */
#define OBJ_CONFIG_FILE_ENV_VARIABLE "PMEMOBJ_CONF_FILE"

/*
 * The variable which overwrites a number of lanes available at runtime.
 */
#define OBJ_NLANES_ENV_VARIABLE "PMEMOBJ_NLANES"

/*
 * The variable which determines whether the pool is opened in
 * multiprocessing mode.
 */
#define OBJ_MULTIPROCESS_ENV_VARIABLE "PMEMOBJ_MULTIPROCESS"

/*
 * The variable which determines whether the pool recovery is run
 * automatically by the process which detected that another process crashed
 * while holding a lock.
 */
#define OBJ_MULTIPROCESS_ROBUSTNESS_ENV_VARIABLE "PMEMOBJ_MULTIPROCESS_ROBUST"

#define OBJ_SHM_MAGIC 0xCAFEBABE

static struct cuckoo *pools_ht; /* hash table used for searching by UUID */
static struct cuckoo *pools_trans_ht; /* maps pool base to transient addr */
static struct ctree *pools_tree; /* tree used for searching by address */

int _pobj_cache_invalidate;

#ifndef _WIN32

__thread struct _pobj_pcache _pobj_cached_pool;

/*
 * pmemobj_direct -- returns the direct pointer of an object
 */
void *
pmemobj_direct(PMEMoid oid)
{
	return pmemobj_direct_inline(oid);
}

#else /* _WIN32 */

/*
 * XXX - this is a temporary implementation
 *
 * Seems like we could still use TLS and simply substitute "__thread" with
 * "__declspec(thread)", however it's not clear if it would work correctly
 * with Windows DLL's.
 * Need to verify that once we have the multi-threaded tests ported.
 */

struct _pobj_pcache {
	PMEMobjpool *pop;
	uint64_t uuid_lo;
	int invalidate;
};

static os_once_t Cached_pool_key_once = OS_ONCE_INIT;
static os_tls_key_t Cached_pool_key;

/*
 * _Cached_pool_key_alloc -- (internal) allocate pool cache pthread key
 */
static void
_Cached_pool_key_alloc(void)
{
	int pth_ret = os_tls_key_create(&Cached_pool_key, free);
	if (pth_ret)
		FATAL("!os_tls_key_create");
}

/*
 * pmemobj_direct -- returns the direct pointer of an object
 */
void *
pmemobj_direct(PMEMoid oid)
{
	if (oid.off == 0 || oid.pool_uuid_lo == 0)
		return NULL;

	struct _pobj_pcache *pcache = os_tls_get(Cached_pool_key);
	if (pcache == NULL) {
		pcache = Zalloc(sizeof(struct _pobj_pcache));
		if (pcache == NULL)
			FATAL("!pcache malloc");
		int ret = os_tls_set(Cached_pool_key, pcache);
		if (ret)
			FATAL("!os_tls_set");
	}

	if (_pobj_cache_invalidate != pcache->invalidate ||
	    pcache->uuid_lo != oid.pool_uuid_lo) {
		pcache->invalidate = _pobj_cache_invalidate;

		if ((pcache->pop = pmemobj_pool_by_oid(oid)) == NULL) {
			pcache->uuid_lo = 0;
			return NULL;
		}

		pcache->uuid_lo = oid.pool_uuid_lo;
	}

	return (void *)((uintptr_t)pcache->pop->base_addr + oid.off);
}

#endif /* _WIN32 */

void *
pmemobj_get_base_addr(void *pop)
{
	return ((PMEMobjpool *)pop)->base_addr;
}

/*
 * obj_ctl_init_and_load -- (static) initializes CTL and loads configuration
 *	from env variable and file
 */
static int
obj_ctl_init_and_load(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	if (pop != NULL && (pop->ctl = ctl_new()) == NULL) {
		ERR("!ctl_new");
		return -1;
	}

	if (pop) {
		tx_ctl_register(pop);
	}

	char *env_config = os_getenv(OBJ_CONFIG_ENV_VARIABLE);
	if (env_config != NULL) {
		if (ctl_load_config_from_string(pop, env_config) != 0) {
			ERR("unable to parse config stored in %s "
				"environment variable",
				OBJ_CONFIG_ENV_VARIABLE);
			return -1;
		}
	}

	char *env_config_file = os_getenv(OBJ_CONFIG_FILE_ENV_VARIABLE);
	if (env_config_file != NULL && env_config_file[0] != '\0') {
		if (ctl_load_config_from_file(pop, env_config_file) != 0) {
			ERR("unable to parse config stored in %s "
				"file (from %s environment variable)",
				env_config_file,
				OBJ_CONFIG_FILE_ENV_VARIABLE);
			return -1;
		}
	}

	return 0;
}

/*
 * obj_pool_init -- (internal) allocate global structs holding all opened pools
 *
 * This is invoked on a first call to pmemobj_open() or pmemobj_create().
 * Memory is released in library destructor.
 */
static void
obj_pool_init(void)
{
	LOG(3, NULL);

	if (pools_ht)
		return;

	pools_ht = cuckoo_new();
	if (pools_ht == NULL)
		FATAL("!cuckoo_new");

	pools_trans_ht = cuckoo_new();
	if (pools_trans_ht == NULL)
		FATAL("!cucko_new");

	pools_tree = ctree_new();
	if (pools_tree == NULL)
		FATAL("!ctree_new");
}

/*
 * pmemobj_oid -- return a PMEMoid based on the virtual address
 *
 * If the address does not belong to any pool OID_NULL is returned.
 */
PMEMoid
pmemobj_oid(const void *addr)
{
	PMEMobjpool *pop = pmemobj_pool_by_ptr(addr);
	if (pop == NULL)
		return OID_NULL;

	PMEMoid oid = {pop->uuid_lo, (uintptr_t)addr -
		    (uintptr_t)pop->base_addr};
	return oid;
}

/*
 * User may decide to map all pools with MAP_PRIVATE flag using
 * PMEMOBJ_COW environment variable.
 */
static int Open_cow;

/*
 * obj_init -- initialization of obj
 *
 * Called by constructor.
 */
void
obj_init(void)
{
	LOG(3, NULL);

	COMPILE_ERROR_ON(sizeof(struct pool_descriptor) !=
		POOL_DESC_SIZE);
#ifdef USE_COW_ENV
	char *env = os_getenv("PMEMOBJ_COW");
	if (env)
		Open_cow = atoi(env);
#endif

#ifdef _WIN32
	/* XXX - temporary implementation (see above) */
	os_once(&Cached_pool_key_once, _Cached_pool_key_alloc);
#endif
	ctl_global_register();

	/*
	 * Load global config, ignore any issues. They will be caught on the
	 * subsequent call to this function for individual pools.
	 */
	obj_ctl_init_and_load(NULL);

	lane_info_boot();

	util_remote_init();
}

static void
obj_env_cleanup(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	/*
	 * "man pthread_mutex_destroy" states:
	 * ["It  shall  be  safe  to  destroy  an  initialized  mutex
	 * that is unlocked.  Attempting to destroy a locked mutex or a
	 * mutex that is referenced (for example, while being used in a
	 * pthread_cond_timedwait() or pthread_cond_wait()) by another
	 * thread results in undefined behavior."]
	 *
	 * Another thread (of a crashed process) might still hold the
	 * lock. So we try to fix it before unlocking.
	 *
	 * We reach this point only when we are the last process. Therefore
	 * we handle only the crash scenario and expect the lock to be unlocked
	 * otherwise.
	 */
	int err = os_mutex_trylock(&pop->shrd->lock);
	switch (err) {
		case EOWNERDEAD:
			if (os_mutex_consistent(&pop->shrd->lock)) {
				ERR("!os_mutex_consistent");
			}
			LOG(3, "Detected crashed process. Shuting down anyway");
			/* no break */
		case 0:
			util_mutex_unlock(&pop->shrd->lock);
			break;
		case EBUSY:
			ERR("Unlocked lock detected. ");
		default:
			ERR("Unexpected lock error during shutdown. "
			    "Destroying the lock anyway. "
			    "Undefined behaviour might happen. "
			    "pop %p", pop);

	}
	/* try unlock mutex */
	util_mutex_destroy(&pop->shrd->lock);
	util_cond_destroy(&pop->shrd->cond);
}

/*
 * obj_shm_cleanup -- (internal) cleanup the shared memory mappings
 */
void
obj_shm_cleanup(PMEMobjpool *pop, int clean_shrd)
{
	LOG(3, "pop %p", pop);

	ASSERTne(pop->shrd, NULL);
	ASSERTne(pop->shrd->area_size, 0);
	ASSERTne(pop->shm_path, NULL);

	if (clean_shrd) {
		obj_env_cleanup(pop);

		if (OBJ_SHM_USE_POSIX)
			os_shm_unlink(pop->shm_path);
		else
			os_unlink(pop->shm_path);
	}

	/*
	 * XXX mp-mode -- (shm) [critical] Implement testcase to illustrate and
	 * further investigate. The parents memory region is unmapped, too
	 *
	 * For unknown reasons unmapping the shared memory during shutdown
	 * (exit(0)) in the child process while it is holding a mutex causes
	 * the parent to crash when accessing the mutex.
	 */
	/* (void) util_unmap(pop->shrd, pop->shrd->area_size); */
	pop->shrd = NULL;
}

/*
 * obj_pool_find_opened -- (internal) returns any opened pool by descending addr
 */
static PMEMobjpool *
obj_pool_find_opened(void)
{
	/* XXX this is a temporary fix, to be fixed properly later */
	if (pools_tree == NULL)
		return NULL;

	uint64_t key = (uint64_t)UINT64_MAX;
	size_t pool_size = ctree_find_le_unlocked(pools_tree, &key);
	ctree_remove_unlocked(pools_tree, key, 1);

	if (pool_size == 0)
		return NULL;

	return cuckoo_get(pools_trans_ht, key);
}

/*
 * obj_drain_empty -- (internal) empty function for drain on non-pmem memory
 */
static void
obj_drain_empty(void)
{
	/* do nothing */
}

/*
 * obj_nopmem_memcpy_persist -- (internal) memcpy followed by an msync
 */
static void *
obj_nopmem_memcpy_persist(void *dest, const void *src, size_t len)
{
	LOG(15, "dest %p src %p len %zu", dest, src, len);

	memcpy(dest, src, len);
	pmem_msync(dest, len);
	return dest;
}

/*
 * obj_nopmem_memset_persist -- (internal) memset followed by an msync
 */
static void *
obj_nopmem_memset_persist(void *dest, int c, size_t len)
{
	LOG(15, "dest %p c 0x%02x len %zu", dest, c, len);

	memset(dest, c, len);
	pmem_msync(dest, len);
	return dest;
}

/*
 * obj_remote_persist -- (internal) remote persist function
 */
static void *
obj_remote_persist(PMEMobjpool *pop, const void *addr, size_t len,
			unsigned lane)
{
	LOG(15, "pop %p addr %p len %zu lane %u", pop, addr, len, lane);

	ASSERTne(pop->rpp, NULL);

	/*
	 * The pool header is not visible on remote node from the local host
	 * perspective. It means the pool descriptor is at offset 0
	 * on remote node.
	 */
	uintptr_t offset = (uintptr_t)addr - pop->remote_base;

	int rv = Rpmem_persist(pop->rpp, offset, len, lane);
	if (rv) {
		ERR("!rpmem_persist(rpp %p offset %zu length %zu lane %u)"
			" FATAL ERROR (returned value %i)",
			pop->rpp, offset, len, lane, rv);
		return NULL;
	}

	return (void *)addr;
}

/*
 * XXX - Consider removing obj_norep_*() wrappers to call *_local()
 * functions directly.  Alternatively, always use obj_rep_*(), even
 * if there are no replicas.  Verify the performance penalty.
 */

/*
 * obj_norep_memcpy_persist -- (internal) memcpy w/o replication
 */
static void *
obj_norep_memcpy_persist(void *ctx, void *dest, const void *src,
	size_t len)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p dest %p src %p len %zu", pop, dest, src, len);

	return pop->memcpy_persist_local(dest, src, len);
}

/*
 * obj_norep_memset_persist -- (internal) memset w/o replication
 */
static void *
obj_norep_memset_persist(void *ctx, void *dest, int c, size_t len)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p dest %p c 0x%02x len %zu", pop, dest, c, len);

	return pop->memset_persist_local(dest, c, len);
}

/*
 * obj_norep_persist -- (internal) persist w/o replication
 */
static void
obj_norep_persist(void *ctx, const void *addr, size_t len)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p addr %p len %zu", pop, addr, len);

	pop->persist_local(addr, len);
}

/*
 * obj_norep_flush -- (internal) flush w/o replication
 */
static void
obj_norep_flush(void *ctx, const void *addr, size_t len)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p addr %p len %zu", pop, addr, len);

	pop->flush_local(addr, len);
}

/*
 * obj_norep_drain -- (internal) drain w/o replication
 */
static void
obj_norep_drain(void *ctx)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p", pop);

	pop->drain_local();
}

static void obj_pool_cleanup(PMEMobjpool *pop);

static int obj_open_mp_files(PMEMobjpool *pop);

/*
 * obj_handle_remote_persist_error -- (internal) handle remote persist
 *                                    fatal error
 */
static void
obj_handle_remote_persist_error(PMEMobjpool *pop)
{
	LOG(1, "pop %p", pop);

	ERR("error clean up...");
	obj_pool_cleanup(pop);

	FATAL("Fatal error of remote persist. Aborting...");
}

/*
 * obj_rep_memcpy_persist -- (internal) memcpy with replication
 */
static void *
obj_rep_memcpy_persist(void *ctx, void *dest, const void *src,
	size_t len)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p dest %p src %p len %zu", pop, dest, src, len);

	unsigned lane = UINT_MAX;

	if (pop->has_remote_replicas)
		lane = lane_hold(pop, NULL, LANE_ID);

	void *ret = pop->memcpy_persist_local(dest, src, len);

	PMEMobjpool *rep = pop->replica;
	while (rep) {
		void *rdest = (char *)rep->base_addr + (uintptr_t)dest -
		    (uintptr_t)pop->base_addr;
		ASSERT(OBJ_PTR_FROM_POOL(rep, rdest));
		if (rep->rpp == NULL) {
			rep->memcpy_persist_local(rdest, src, len);
		} else {
			if (rep->persist_remote(rep, rdest, len, lane) == NULL)
				obj_handle_remote_persist_error(pop);
		}
		rep = rep->replica;
	}

	if (pop->has_remote_replicas)
		lane_release(pop);

	return ret;
}

/*
 * obj_rep_memset_persist -- (internal) memset with replication
 */
static void *
obj_rep_memset_persist(void *ctx, void *dest, int c, size_t len)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p dest %p c 0x%02x len %zu", pop, dest, c, len);

	unsigned lane = UINT_MAX;

	if (pop->has_remote_replicas)
		lane = lane_hold(pop, NULL, LANE_ID);

	void *ret = pop->memset_persist_local(dest, c, len);

	PMEMobjpool *rep = pop->replica;
	while (rep) {
		void *rdest = (char *)rep->base_addr + (uintptr_t)dest -
		    (uintptr_t)pop->base_addr;
		ASSERT(OBJ_PTR_FROM_POOL(rep, rdest));
		if (rep->rpp == NULL) {
			rep->memset_persist_local(rdest, c, len);
		} else {
			if (rep->persist_remote(rep, rdest, len, lane) == NULL)
				obj_handle_remote_persist_error(pop);
		}
		rep = rep->replica;
	}

	if (pop->has_remote_replicas)
		lane_release(pop);

	return ret;
}

/*
 * obj_rep_persist -- (internal) persist with replication
 */
static void
obj_rep_persist(void *ctx, const void *addr, size_t len)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p addr %p len %zu", pop, addr, len);

	unsigned lane = UINT_MAX;

	if (pop->has_remote_replicas)
		lane = lane_hold(pop, NULL, LANE_ID);

	pop->persist_local(addr, len);

	PMEMobjpool *rep = pop->replica;
	while (rep) {
		void *raddr = (char *)rep->base_addr + (uintptr_t)addr -
		    (uintptr_t)pop->base_addr;
		ASSERT(OBJ_PTR_FROM_POOL(rep, raddr));
		if (rep->rpp == NULL) {
			rep->memcpy_persist_local(raddr, addr, len);
		} else {
			if (rep->persist_remote(rep, raddr, len, lane) == NULL)
				obj_handle_remote_persist_error(pop);
		}
		rep = rep->replica;
	}

	if (pop->has_remote_replicas)
		lane_release(pop);
}

/*
 * obj_rep_flush -- (internal) flush with replication
 */
static void
obj_rep_flush(void *ctx, const void *addr, size_t len)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p addr %p len %zu", pop, addr, len);

	unsigned lane = UINT_MAX;

	if (pop->has_remote_replicas)
		lane = lane_hold(pop, NULL, LANE_ID);

	pop->flush_local(addr, len);

	PMEMobjpool *rep = pop->replica;
	while (rep) {
		void *raddr = (char *)rep->base_addr + (uintptr_t)addr -
		    (uintptr_t)pop->base_addr;
		ASSERT(OBJ_PTR_FROM_POOL(rep, raddr));
		if (rep->rpp == NULL) {
			memcpy(raddr, addr, len);
			rep->flush_local(raddr, len);
		} else {
			if (rep->persist_remote(rep, raddr, len, lane) == NULL)
				obj_handle_remote_persist_error(pop);
		}
		rep = rep->replica;
	}

	if (pop->has_remote_replicas)
		lane_release(pop);
}

/*
 * obj_rep_drain -- (internal) drain with replication
 */
static void
obj_rep_drain(void *ctx)
{
	PMEMobjpool *pop = ctx;
	LOG(15, "pop %p", pop);

	pop->drain_local();

	PMEMobjpool *rep = pop->replica;
	while (rep) {
		if (rep->rpp == NULL)
			rep->drain_local();
		rep = rep->replica;
	}
}

#ifdef USE_VG_MEMCHECK
/*
 * Arbitrary value. When there's more undefined regions than MAX_UNDEFS, it's
 * not worth reporting everything - developer should fix the code.
 */
#define MAX_UNDEFS 1000

/*
 * obj_vg_check_no_undef -- (internal) check whether there are any undefined
 *				regions
 */
static void
obj_vg_check_no_undef(struct pmemobjpool *pop)
{
	LOG(4, "pop %p", pop);

	struct {
		void *start, *end;
	} undefs[MAX_UNDEFS];
	int num_undefs = 0;

	VALGRIND_DO_DISABLE_ERROR_REPORTING;
	char *addr_start = pop->addr;
	char *addr_end = addr_start + pop->size;

	while (addr_start < addr_end) {
		char *noaccess = (char *)VALGRIND_CHECK_MEM_IS_ADDRESSABLE(
					addr_start, addr_end - addr_start);
		if (noaccess == NULL)
			noaccess = addr_end;

		while (addr_start < noaccess) {
			char *undefined =
				(char *)VALGRIND_CHECK_MEM_IS_DEFINED(
					addr_start, noaccess - addr_start);

			if (undefined) {
				addr_start = undefined;

#ifdef VALGRIND_CHECK_MEM_IS_UNDEFINED
				addr_start = (char *)
					VALGRIND_CHECK_MEM_IS_UNDEFINED(
					addr_start, noaccess - addr_start);
				if (addr_start == NULL)
					addr_start = noaccess;
#else
				while (addr_start < noaccess &&
						VALGRIND_CHECK_MEM_IS_DEFINED(
								addr_start, 1))
					addr_start++;
#endif

				if (num_undefs < MAX_UNDEFS) {
					undefs[num_undefs].start = undefined;
					undefs[num_undefs].end = addr_start - 1;
					num_undefs++;
				}
			} else
				addr_start = noaccess;
		}

#ifdef VALGRIND_CHECK_MEM_IS_UNADDRESSABLE
		addr_start = (char *)VALGRIND_CHECK_MEM_IS_UNADDRESSABLE(
				addr_start, addr_end - addr_start);
		if (addr_start == NULL)
			addr_start = addr_end;
#else
		while (addr_start < addr_end &&
				(char *)VALGRIND_CHECK_MEM_IS_ADDRESSABLE(
						addr_start, 1) == addr_start)
			addr_start++;
#endif
	}
	VALGRIND_DO_ENABLE_ERROR_REPORTING;

	if (num_undefs) {
		/*
		 * How to resolve this error:
		 * If it's part of the free space Valgrind should be told about
		 * it by VALGRIND_DO_MAKE_MEM_NOACCESS request. If it's
		 * allocated - initialize it or use VALGRIND_DO_MAKE_MEM_DEFINED
		 * request.
		 */

		VALGRIND_PRINTF("Part of the pool is left in undefined state on"
				" boot. This is pmemobj's bug.\nUndefined"
				" regions: [pool address: %p]\n", pop);
		for (int i = 0; i < num_undefs; ++i)
			VALGRIND_PRINTF("   [%p, %p]\n", undefs[i].start,
					undefs[i].end);
		if (num_undefs == MAX_UNDEFS)
			VALGRIND_PRINTF("   ...\n");

		/* Trigger error. */
		VALGRIND_CHECK_MEM_IS_DEFINED(undefs[0].start, 1);
	}
}

/*
 * obj_vg_boot -- (internal) notify Valgrind about pool objects
 */
static void
obj_vg_boot(struct pmemobjpool *pop)
{
	if (!On_valgrind)
		return;

	LOG(4, "pop %p", pop);

	if (os_getenv("PMEMOBJ_VG_CHECK_UNDEF"))
		obj_vg_check_no_undef(pop);
}

#endif

/*
 * obj_assign_lane_range_new -- (internal) assign lanes process exclusive lanes
 */
static struct lane_range *
obj_assign_lane_range_new(PMEMobjpool *pop)
{
	LOG(7, "pop %p", pop);

	struct lane_range *range = lane_range_new();

	if (pop->mp_mode) {
		registry_get_lanes_by_idx(pop->registry, range, pop->proc_idx);
	} else {
		range->idx_start = 0;
		range->idx_end = pop->lanes_desc.runtime_nlanes - 1;
	}

	if (pop->lane_range != NULL)
		lane_range_delete(pop->lane_range);

	pop->lanes_desc.next_lane_idx = range->idx_start;

	return range;
}

enum error_state {
    OK,
    RETRY,
    RECOVER,
    PANIC,
    MAX_ERROR_ACTION
};

/*
 * obj_check_mutex_error -- (internal) translates an errno error code to a
 * internal result code
 */
static int
obj_check_mutex_error(PMEMobjpool *pop, int err)
{
	switch (err) {
		case 0:
			break;
		case EOWNERDEAD:
			util_mutex_consistent(&pop->shrd->lock);
			util_mutex_unlock(&pop->shrd->lock);
			return RECOVER;
		case EAGAIN:
			ERR("EAGAIN shared heap lock");
			return RETRY;
		case EBUSY:
			ERR("EBUSY already locked");
			return RETRY;
		case ETIMEDOUT:
			ERR("ETIMEDOUT");
			return RETRY;
		case ENOTRECOVERABLE:
			ERR("ENOTRECOVERABLE shared heap lock");
			return RECOVER;
		default:
			ASSERT(0);
	}

	return OK;
}

/*
 * obj_change_shared_state -- (internal) helper to change the shared state
 */
static inline int
obj_change_shared_state(PMEMobjpool *pop,
	volatile enum initialization_state state)
{
	LOG(3, "pop %pop state transition from %d -> %d", pop,
		pop->shrd->state, state);
	ASSERT(state > pop->shrd->state);

	struct timespec ts;
	int rc = obj_check_mutex_error(pop,
		os_mutex_timedlock(&pop->shrd->lock, mp_set_mtx_timeout(&ts)));
	if (rc)
		return rc;

	pop->shrd->state = state;
	util_cond_broadcast(&pop->shrd->cond);
	util_mutex_unlock(&pop->shrd->lock);

	return 0;
}

/*
 * obj_wait_until_state -- (internal) convenience wrapper for os_cond_timewait
 */
static int
obj_wait_until_state(PMEMobjpool *pop, enum initialization_state state)
{
	LOG(3, "pop %p current: state %d, waiting for target state >= %d",
	    pop, pop->shrd->state, state);

	struct timespec ts;
	int err = os_mutex_timedlock(&pop->shrd->lock, mp_set_mtx_timeout(&ts));
	int ret = obj_check_mutex_error(pop, err);
	if (ret)
		return ret;

	err = 0;
	while (pop->shrd->state < state && err == 0) {
		err = os_cond_timedwait(&pop->shrd->cond,
			&pop->shrd->lock, &ts);
		if (err == EOWNERDEAD) {
			/*
			 * Another process died. Whether it was during
			 * initialzation or another secondary process remains
			 * unclear.
			 * There is noting we can do here,
			 * we just retry until the timeout is reached.
			 */
			util_mutex_consistent(&pop->shrd->lock);
			LOG(3, "os_cond_timedwait returned EOWNERDEAD");
			err = 0;
		}
	}

	/* pthread_cond_wait returns locked, even in error case */
	util_mutex_unlock(&pop->shrd->lock);

	if (pop->shrd->state >= state) {
		/*
		 * We are optimistic and continue as long as the predicate
		 * is true.
		 */
		return 0;
	}

	return obj_check_mutex_error(pop, err);
}

/*
 * obj_recover -- (internal) recovery for all lanes
 */
static int
obj_recover(PMEMobjpool *pop)
{
	LOG(7, "pop %p", pop);
	/*
	 * Run recovery for all lanes
	 */
	pop->lane_range = Malloc(sizeof(struct lane_range));
	pop->lane_range->idx_start = 0;
	pop->lane_range->idx_end = pop->lanes_desc.runtime_nlanes - 1;

	if (pop->mp_mode && (errno = obj_change_shared_state(pop,
		RECOVERY_RUNNING)) != 0) {
		ERR("!obj_change_shared_state");
		return errno;
	}

	if ((errno = lane_boot(pop)) != 0) {
		ERR("!lane_boot");
		return errno;
	}

	if ((errno = lane_recover_and_section_boot(pop)) != 0) {
		ERR("!lane_recover_and_section_boot");
		return errno;
	}

	/* we immediately destroy the resources */
	for (uint64_t i = pop->lane_range->idx_start;
	    i <= pop->lane_range->idx_end; ++i)
		lane_destroy(pop, &pop->lanes_desc.lane[i]);

	return 0;
}

/*
 * obj_has_multiprocess_support -- determine if the pool supports multiple
 * processes concurrently. The value is 1 (true) when supported, otherwise 0.
 */
static unsigned
obj_has_multiprocess_support(void)
{
	unsigned ret = 0;
	char *env = os_getenv(OBJ_MULTIPROCESS_ENV_VARIABLE);
	if (env) {
		if (strlen(env) > 1 || (env[0] != '0' && env[0] != '1')) {
			ERR("%s variable must be either 0 (false) or 1 (true)",
				OBJ_MULTIPROCESS_ENV_VARIABLE);
			errno = EINVAL;
			goto no_valid_env;
		}

		ret = (unsigned)atoi(env);
	}

	no_valid_env:
	LOG(3, ":%s ", ret ? "true" : "false");
	return ret;
}

/*
 * obj_has_multiprocess_robustness -- determines whether the pool recovery
 * is run automatically by the process which detected that another process
 * crashed while holding a lock. The value is 1 (true) when supported,
 * otherwise 0. Defaults to true.
 */
static unsigned
obj_has_multiprocess_robustness(void)
{
	/* robust by default */
	unsigned ret = 1;
	char *env = os_getenv(OBJ_MULTIPROCESS_ROBUSTNESS_ENV_VARIABLE);
	if (env) {
		if (strlen(env) > 1 || (env[0] != '0' && env[0] != '1')) {
			ERR("%s variable must be either 0 (false) or 1 (true)",
				OBJ_MULTIPROCESS_ROBUSTNESS_ENV_VARIABLE);
			errno = EINVAL;
			goto no_valid_env;
		}

		ret = (unsigned)atoi(env);
	}

no_valid_env:
	LOG(3, ":%s ", ret ? "true" : "false");
	return ret;
}

/*
 * obj_crash_check_and_recover -- checks if all currently attached
 * processes are alive and recovers their lanes otherwise.
 * Returns the number of successfully recovered processes.
 */
int
obj_crash_check_and_recover(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	if (!obj_has_multiprocess_robustness())
		return 1;

	struct registry_entries entries;
	SLIST_INIT(&entries);

	/*
	 * We need to hold that lock for the entire recovery operation to
	 * prevent duplicate recovery from other thread/processes
	 * of the same lanes.
	 */
	int err = registry_hold(pop->registry);
	switch (err) {
		case 0:
			/* proceed */
			break;
		case EOWNERDEAD:
			/*
			 * XXX mp-mode
			 * Another process/thread died while holding the lock.
			 * The underlying shm_list implementation
			 * does not use transactions and thus might be in a
			 * corrupt state. A single logical list operations
			 * comprises at least two stores: updating a tail
			 * pointer and the next pointer.
			 * As a consequence we should not continue.
			 *
			 * But in future (once a transactional reqistration
			 * mechanism is implemented) we might make the lock
			 * consistent and proceed.
			 */
		case ETIMEDOUT:
			/*
			 * XXX mp-mode
			 * The registry is a single point of failure.
			 * While another process holds the lock, we can do
			 * nothing but wait and retry.
			 *
			 * Sadly, in some cases the locked mutex might
			 * return ETIMEDOUT although the lock holder crashed.
			 * In that case there is nothing we can do but abort
			 * until we find a better solution and found the real
			 * cause for that (probably undefined) behaviour.
			 *
			 * Recovery might be already running in another thread
			 * and we have to wait until it is finished.
			 * If we can't obtain the lock in the specified time,
			 * there is probably some greater problem that we
			 * can't resolve and we abort as a safety measure.
			 */
		default:
			ERR("registry_hold");
			errno = err;
			return -1;
	}

	/* check if any processes crashed */
	registry_check_crashed(pop->registry, &entries, pop->proc_idx);

	/* iterate the list of crashed processes and recover */
	int recovered = 0;
	struct lane_range lrange;
	while (!SLIST_EMPTY(&entries)) {
		struct registry_entry *entry = SLIST_FIRST(&entries);

		/*
		 * Process all redo/undo logs
		 *
		 * Regarding the allocator section:
		 * The crashed process could only alloc memory that was
		 * free, before it crashed.
		 * Another process is not allowed to alloc memory until it
		 * acquired the region lock.
		 *
		 * The consequence from the above points:
		 * As long as the crashed process' region remains locked,
		 * the persistent state is protected against modifications
		 * that might corrupt the region.
		 * It is safe to process the redo log while another process
		 * concurrently frees memory from the region that is unrelated
		 * to the entries in the redo log.
		 * If another process tries to operate on the same run that
		 * is already contained in the redo log, then the process
		 * gets EOWNERDEAD while trying to aquire the run lock and
		 * subsequently has to run recovery.
		 */
		/* Lanes */
		registry_get_lanes_by_idx(pop->registry, &lrange,
			(unsigned)entry->idx);
		if (lane_recover(pop, &lrange) != 0) {
			FATAL("lane_recover");
		}

		/*
		 * Regions
		 *
		 * it is important that the region locks are released only
		 * after all lanes are recovered.
		 */
		palloc_region_reset(&pop->heap, (unsigned)entry->idx);

		/*
		 * XXX mp-mode -- handle unlocked locks
		 * A crashed process might hold other shared locks while it
		 * crashed, e.g., runlocks. We don't know exactly which ones
		 * and have no choice other than to iterate all possibilities
		 * or delegate the discovery of those to other processes, which
		 * than in turn have to run recovery again. For simplicity, we
		 * decide for the last option, but checking all possible locks
		 * might be faster. This needs further investigation.
		 */
		registry_remove_by_idx_unlocked(pop->registry,
			(unsigned)entry->idx);

		recovered++;

		SLIST_REMOVE_HEAD(&entries, entry);
		Free(entry);
	}

	registry_release(pop->registry);
	LOG(2, "Recovery found %d dead processes", recovered);

	return 0;
}

/*
 * obj_boot -- (internal) boots the pmemobj pool
 */
static int
obj_boot(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	if (pop->is_primary) {
		if ((errno = obj_recover(pop)) != 0) {
			ERR("!obj_recover");
			return errno;
		}
		pop->pool_desc->conversion_flags = 0;
		pmemops_persist(&pop->p_ops, &pop->pool_desc->conversion_flags,
		    sizeof(pop->pool_desc->conversion_flags));

		if (pop->mp_mode && (errno = obj_change_shared_state(pop,
			READY)) != 0) {
			ERR("!obj_change_shared_state");
			return errno;
		}
	} else {
		if ((errno = obj_wait_until_state(pop, READY)) != 0) {
			ERR("!obj_wait_until_state");
			return errno;
		}
	}

	pop->lane_range = obj_assign_lane_range_new(pop);

	if ((errno = lane_boot(pop)) != 0) {
		ERR("!lane_boot");
		return errno;
	}

	if (!pop->is_primary && ((errno = lane_section_boot(pop)) != 0)) {
		ERR("!lane_section_boot");
		return errno;
	}

	return 0;
}

/*
 * obj_descr_create -- (internal) create obj pool descriptor
 */
static int
obj_descr_create(PMEMobjpool *pop, const char *layout, size_t poolsize)
{
	LOG(3, "pop %p layout %s poolsize %zu", pop, layout, poolsize);

	ASSERTeq(poolsize % Pagesize, 0);

	/* opaque info lives at the beginning of mapped memory pool */
	pop->pool_desc = (struct pool_descriptor *)((uintptr_t)pop->base_addr
	    + POOL_HDR_SIZE);

	/* create the persistent part of pool's descriptor */
	memset(pop->pool_desc, 0, OBJ_DSC_P_SIZE);
	if (layout)
		strncpy(pop->pool_desc->layout, layout, PMEMOBJ_MAX_LAYOUT - 1);
	struct pmem_ops *p_ops = &pop->p_ops;

	pop->pool_desc->lanes_offset = OBJ_LANES_OFFSET;
	pop->pool_desc->nlanes = OBJ_NLANES;

	/* zero all lanes */
	void *lanes_layout = (void *)((uintptr_t)pop->base_addr +
	    pop->pool_desc->lanes_offset);
	size_t lanessize = pop->pool_desc->nlanes * sizeof(struct lane_layout);
	pmemops_memset_persist(p_ops, lanes_layout, 0, lanessize);

	pop->pool_desc->heap_offset = pop->pool_desc->lanes_offset + lanessize;
	pop->pool_desc->heap_offset = (pop->pool_desc->heap_offset +
	    Pagesize - 1) & ~(Pagesize - 1);
	pop->pool_desc->heap_size = poolsize - pop->pool_desc->heap_offset;

	/* initialize heap prior to storing the checksum */
	errno = palloc_init((char *)pop->base_addr +
	    pop->pool_desc->heap_offset, pop->pool_desc->heap_size,
			p_ops);
	if (errno != 0) {
		ERR("!palloc_init");
		return -1;
	}

	util_checksum(pop->pool_desc, OBJ_DSC_P_SIZE,
	    &pop->pool_desc->checksum, 1);

	/* store the persistent part of pool's descriptor (2kB) */
	pmemops_persist(p_ops, pop->pool_desc, OBJ_DSC_P_SIZE);

	/* initialize run_id, it will be incremented later */
	pop->pool_desc->run_id = 0;
	pmemops_persist(p_ops, &pop->pool_desc->run_id,
	    sizeof(pop->pool_desc->run_id));

	pop->pool_desc->root_offset = 0;
	pmemops_persist(p_ops, &pop->pool_desc->root_offset,
	    sizeof(pop->pool_desc->root_offset));
	pop->pool_desc->root_size = 0;
	pmemops_persist(p_ops, &pop->pool_desc->root_size,
	    sizeof(pop->pool_desc->root_size));

	pop->pool_desc->conversion_flags = 0;
	pmemops_persist(p_ops, &pop->pool_desc->conversion_flags,
	    sizeof(pop->pool_desc->conversion_flags));

	pmemops_memset_persist(p_ops, pop->pool_desc->pmem_reserved, 0,
	    sizeof(pop->pool_desc->pmem_reserved));

	return 0;
}

/*
 * obj_descr_check -- (internal) validate obj pool descriptor
 */
static int
obj_descr_check(PMEMobjpool *pop, const char *layout, size_t poolsize)
{
	LOG(3, "pop %p layout %s poolsize %zu", pop, layout, poolsize);

	struct pool_descriptor *dscp = pop->pool_desc;

	if (pop->rpp) {
		/* read remote descriptor */
		if (obj_read_remote(pop->rpp, pop->remote_base, dscp,
				dscp, OBJ_DSC_P_SIZE)) {
			ERR("!obj_read_remote");
			return -1;
		}

		/*
		 * Set size of the replica to the pool size (required minimum).
		 * This condition is checked while opening the remote pool.
		 */
		pop->size = poolsize;
	}

	if (!util_checksum(dscp, OBJ_DSC_P_SIZE, &dscp->checksum, 0)) {
		ERR("invalid checksum of pool descriptor");
		errno = EINVAL;
		return -1;
	}

	if (layout &&
	    strncmp(dscp->layout, layout, PMEMOBJ_MAX_LAYOUT)) {
		ERR("wrong layout (\"%s\"), "
			"pool created with layout \"%s\"",
			layout, dscp->layout);
		errno = EINVAL;
		return -1;
	}

	if (pop->size < poolsize) {
		ERR("replica size smaller than pool size: %zu < %zu",
			pop->size, poolsize);
		errno = EINVAL;
		return -1;
	}

	if (dscp->heap_offset + dscp->heap_size != poolsize) {
		ERR("heap size does not match pool size: %" PRIu64 " != %zu",
			dscp->heap_offset + dscp->heap_size, poolsize);
		errno = EINVAL;
		return -1;
	}

	if (dscp->heap_offset % Pagesize ||
	    dscp->heap_size % Pagesize) {
		ERR("unaligned heap: off %" PRIu64 ", size %" PRIu64,
			dscp->heap_offset, dscp->heap_size);
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/*
 * obj_replica_init_local -- (internal) initialize runtime part
 *                               of the local replicas
 */
static int
obj_replica_init_local(PMEMobjpool *rep, int is_pmem)
{
	LOG(3, "rep %p is_pmem %d", rep, is_pmem);

	/*
	 * Use some of the memory pool area for run-time info.  This
	 * run-time state is never loaded from the file, it is always
	 * created here, so no need to worry about byte-order.
	 */
	rep->is_pmem = is_pmem;

	/* init hooks */
	rep->persist_remote = NULL;

	/*
	 * All replicas, except for master, are ignored as far as valgrind is
	 * concerned. This is to save CPU time and lessen the complexity of
	 * instrumentation.
	 */
	if (!rep->is_master_replica)
		VALGRIND_ADD_TO_GLOBAL_TX_IGNORE(rep, rep->size);

	if (rep->is_pmem) {
		rep->persist_local = pmem_persist;
		rep->flush_local = pmem_flush;
		rep->drain_local = pmem_drain;
		rep->memcpy_persist_local = pmem_memcpy_persist;
		rep->memset_persist_local = pmem_memset_persist;
	} else {
		rep->persist_local = (persist_local_fn)pmem_msync;
		rep->flush_local = (flush_local_fn)pmem_msync;
		rep->drain_local = obj_drain_empty;
		rep->memcpy_persist_local = obj_nopmem_memcpy_persist;
		rep->memset_persist_local = obj_nopmem_memset_persist;
	}

	return 0;
}

/*
 * obj_replica_init_remote -- (internal) initialize runtime part
 *                                of a remote replica
 */
static int
obj_replica_init_remote(PMEMobjpool *rep, struct pool_set *set,
				unsigned repidx, int create)
{
	LOG(3, "rep %p set %p repidx %u", rep, set, repidx);

	struct pool_replica *repset = set->replica[repidx];

	ASSERTne(repset->remote->rpp, NULL);
	ASSERTne(repset->remote->node_addr, NULL);
	ASSERTne(repset->remote->pool_desc, NULL);

	rep->node_addr = Strdup(repset->remote->node_addr);
	if (rep->node_addr == NULL)
		return -1;
	rep->rpool_desc = Strdup(repset->remote->pool_desc);
	if (rep->rpool_desc == NULL) {
		Free(rep->node_addr);
		return -1;
	}

	rep->rpp = repset->remote->rpp;

	/* pop_desc - beginning of the pool's descriptor */
	rep->remote_base = (uintptr_t)rep->addr + sizeof(struct pool_hdr);

	/* init hooks */
	rep->persist_remote = obj_remote_persist;
	rep->persist_local = NULL;
	rep->flush_local = NULL;
	rep->drain_local = NULL;
	rep->memcpy_persist_local = NULL;
	rep->memset_persist_local = NULL;

	rep->p_ops.remote.read = obj_read_remote;
	rep->p_ops.remote.ctx = rep->rpp;
	rep->p_ops.remote.base = rep->remote_base;

	return 0;
}

/*
 * obj_cleanup_remote -- (internal) clean up the remote pools data
 */
static void
obj_cleanup_remote(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	for (; pop != NULL; pop = pop->replica) {
		if (pop->rpp != NULL) {
			Free(pop->node_addr);
			Free(pop->rpool_desc);
			pop->rpp = NULL;
		}
	}
}

/*
 * redo_log_check_offset -- (internal) check if offset is valid
 */
static int
redo_log_check_offset(void *ctx, uint64_t offset)
{
	PMEMobjpool *pop = ctx;
	return OBJ_OFF_IS_VALID(pop, offset);
}

/*
 * pmemobjpool_delete -- free an pmemobjpool
 */
void
pmemobjpool_delete(PMEMobjpool *pop)
{
	LOG(4, "pop %p", pop);
	ASSERTne(pop, NULL);
	Free(pop);
}

/*
 * pmemobjpool_new -- allocates and initializes volatile pmemobjpool instance
 */
PMEMobjpool *
pmemobjpool_new(void)
{
	struct pmemobjpool *p = Zalloc(sizeof(*p));
	if (p == NULL)
		return NULL;
	LOG(4, "allocated new pop %p", p);

	p->lock_fd = -1;
	p->mp_mode = obj_has_multiprocess_support();

	return p;
}

/*
 * obj_replica_init -- (internal) initialize runtime part of the replica
 */
static int
obj_replica_init(PMEMobjpool *rep, struct pool_set *set, unsigned repidx,
			int create)
{
	struct pool_replica *repset = set->replica[repidx];

	if (repidx == 0) {
		/* master replica */
		rep->is_master_replica = 1;
		rep->has_remote_replicas = set->remote;

		if (set->nreplicas > 1) {
			rep->p_ops.persist = obj_rep_persist;
			rep->p_ops.flush = obj_rep_flush;
			rep->p_ops.drain = obj_rep_drain;
			rep->p_ops.memcpy_persist = obj_rep_memcpy_persist;
			rep->p_ops.memset_persist = obj_rep_memset_persist;
		} else {
			rep->p_ops.persist = obj_norep_persist;
			rep->p_ops.flush = obj_norep_flush;
			rep->p_ops.drain = obj_norep_drain;
			rep->p_ops.memcpy_persist = obj_norep_memcpy_persist;
			rep->p_ops.memset_persist = obj_norep_memset_persist;
		}
		rep->p_ops.base = rep;
		rep->p_ops.base_p = rep->base_addr;
		rep->p_ops.pool_size = rep->size;
	} else {
		/* non-master replicas */
		rep->is_master_replica = 0;
		rep->has_remote_replicas = 0;

		rep->p_ops.persist = NULL;
		rep->p_ops.flush = NULL;
		rep->p_ops.drain = NULL;
		rep->p_ops.memcpy_persist = NULL;
		rep->p_ops.memset_persist = NULL;

		rep->p_ops.base = NULL;
		rep->p_ops.base_p = NULL;
		rep->p_ops.pool_size = 0;
	}

	rep->is_dev_dax = repset->part[0].is_dev_dax;

	int ret;
	if (repset->remote)
		ret = obj_replica_init_remote(rep, set, repidx, create);
	else
		ret = obj_replica_init_local(rep, repset->is_pmem);
	if (ret)
		return ret;

	rep->redo = redo_log_config_new(rep->base_addr, &rep->p_ops,
			redo_log_check_offset, rep, REDO_NUM_ENTRIES);
	if (!rep->redo)
		return -1;

	return 0;
}

/*
 * obj_replica_fini -- (internal) deinitialize replica
 */
static void
obj_replica_fini(PMEMobjpool *rep, int has_remote)
{
	if (has_remote)
		obj_cleanup_remote(rep);

	redo_log_config_delete(rep->redo);

	pmemobjpool_delete(rep);
}

/*
 * obj_build_suffix_file -- (internal) create a pathname with a given suffix
 */
static inline const char *
obj_build_suffix_file(PMEMobjpool *pop, const char *fmt)
{
	const char *path = pop->set->replica[0]->part[0].path;
	/* static, thus auto-initialized to zero */
	static char buffer[PATH_MAX];
	snprintf(buffer, sizeof(buffer) - 1, fmt, path);

	return buffer;
}

/*
 * obj_open_suffix_file -- (internal) opens the given file and sets
 * permissions and flags
 */
static int
obj_open_suffix_file(PMEMobjpool *pop, const char *pathname)
{
	LOG(3, "pop %p", pop);

	int fd;
	int openFlags = O_RDWR | O_CREAT;

	/*
	 * XXX mp-mode -- defer chmod until later invocation
	 * of util_poolset_chmod(). Otherwise we have divergent permission.
	 */
	struct stat sStat;

	/*
	 * Call fstat() to figure out the permissions on the pool file. If
	 * a new *-shm file is created, an attempt will be made to create it
	 * with the same permissions.
	 */
	if (os_fstat(pop->set->replica[0]->part[0].fd, &sStat) != 0) {
		ERR("!fstat");
		goto err_stat;
	}

	errno = 0;

	if ((fd = os_open(pathname, openFlags, 0660)) < 0) {
		ERR("open shm file");
		goto err_lock_open;
	}

#ifndef _WIN32
	/*
	 * If this process is running as root, make sure that the SHM file
	 * is owned by the same user that owns the original pool.
	 * Otherwise, the original owner will not be able to connect.
	 */
	if (fchown(fd, sStat.st_uid, sStat.st_gid) == -1) {
		ERR("!chown");
		goto err_shm;
	}
#endif

	int flags;
	/* Make sure file gets correctly closed when process finished.  */
	flags = fcntl(fd, F_GETFD, 0);
	if (flags == -1) {
		/* Cannot get file flags.  */
		goto err_shm;
	}
	flags |= FD_CLOEXEC;		/* Close on exit.  */
	if (fcntl(fd, F_SETFD, flags) < 0) {
		/* Cannot set new flags.  */
		goto err_shm;
	}

	return fd;

err_shm:
	(void) os_close(fd);

err_stat:
err_lock_open:
	return -1;
}

/*
 * obj_shm_setup -- (internal) setup the shared memory
 *
 * Locking procedure:
 * 1. create or open lock file.
 * - try to lock it exclusively
 * 	- on success, we know that no other process is alive and it is safe to
 * 	cleanup
 * 	- on failure, we know cleanup is done from another process
 * - we upgrade the lock to shared or wait until cleanup is finished.
 * 2. Shared memory
 * - first process creates and initializes shared memory
 * - other processes attach and spin until initialization is finished
 * 3. After initialization access to shared memory is protected via mutex
 *
 */
static int
obj_shm_setup(PMEMobjpool *pop, int create)
{
	LOG(3, "pop %p", pop);

	size_t shm_size = MMAP_ALIGN_UP(sizeof(struct obj_shared_env));
	struct obj_shared_env *env;
	int oerrno = errno;
	errno = 0;
	if (create) {
		if (OBJ_SHM_USE_POSIX) {
			size_t len = 1 + strlen(OS_SHM_PREFIX) + 1 + 64 + 1;
			char SEG_NAME[len];
			snprintf(SEG_NAME, sizeof(SEG_NAME), "/%s_%lu",
			    OS_SHM_PREFIX, pop->uuid_lo);

			/* remove former leftovers from crashed processes */
			os_shm_unlink(SEG_NAME);
			if ((env = (struct obj_shared_env *)os_shm_get_posix(
				SEG_NAME, shm_size, O_CREAT | O_EXCL |
						    O_RDWR)) == NULL) {
				ERR("shm initializing failed");

				goto err_shm;
			}
			LOG(3, "Created shared memory segment \"%s\" "
				    " of size %zu\n",
				SEG_NAME, shm_size);
			pop->shm_path = strdup(SEG_NAME);
		} else {
			if (os_ftruncate(pop->shm_fd, (off_t)shm_size) != 0) {
				ERR("ftruncate increase");

				goto err_shm;
			}

			if ((env = (struct obj_shared_env *)os_shm_get_mmap(
			    pop->shm_fd, shm_size)) == NULL) {
				ERR("shm initializing failed");
				goto err_shm;
			}
			memset(env, 0, sizeof(*env));
		}

		if (errno) {
			ERR("!connected to shm, but an error occured");

			goto err_shm_mapped;
		}

		/* successfully mapped, continue with initialzation */
		util_mutex_init_mp(&env->lock);
		util_cond_init_mp(&env->cond);

		env->magic = OBJ_SHM_MAGIC;

		for (unsigned i = 0; i < pop->pool_desc->nlanes; ++i) {
			env->lane_locks[i] = 0;
		}
		env->area_size = shm_size;

		pop->lanes_desc.lane = env->lane;
		pop->lanes_desc.lane_locks = env->lane_locks;
		pop->registry = registry_new(env->shm_registry, pop->lock_fd,
			1 /* initialize */, pop->pool_desc->nlanes);

		pop->shrd = env;

		if (obj_change_shared_state(pop, MTX_INITIALIZED) != 0)
			goto err_obj_change_shared_state;
	} else {
		/* attaching to existing segment */
		if (OBJ_SHM_USE_POSIX) {
			size_t len = 1 + strlen(OS_SHM_PREFIX) + 1 + 64 + 1;
			char SEG_NAME[len];
			snprintf(SEG_NAME, sizeof(SEG_NAME), "/%s_%lu",
			    OS_SHM_PREFIX, pop->uuid_lo);
			env = (struct obj_shared_env *)os_shm_get_posix(
				SEG_NAME, shm_size, O_RDWR);
			LOG(3, "Attached to existing shared memory segment "
			    "\"%s\" of size %zu\n",
				SEG_NAME, shm_size);
			pop->shm_path = strdup(SEG_NAME);
		} else {
			env = (struct obj_shared_env *)os_shm_get_mmap(
			    pop->shm_fd, shm_size);
		}

		if (env == NULL) {
			ERR("!could not mmap shm");
			goto err_shm;
		}

		/*
		 * We block until proper synchronization is available or
		 * the timeout is reached.
		 * We have to rely on a spin lock until shared mutexes
		 * are initialized.
		 */
		while (env->magic != OBJ_SHM_MAGIC &&
		    obj_invoke_busy_handler(&pop->busy_handler))
			__sync_synchronize();

		if (env->magic != OBJ_SHM_MAGIC)
			goto err_shm_timeout;

		pop->lanes_desc.lane = env->lane;
		pop->lanes_desc.lane_locks = env->lane_locks;
		pop->registry = registry_new(env->shm_registry, pop->lock_fd,
			0 /* already initialized */, 0);
		pop->shrd = env;
	}

	errno = oerrno;

	return 0;

err_obj_change_shared_state:
	util_mutex_destroy(&pop->shrd->lock);
	util_cond_destroy(&pop->shrd->cond);

err_shm_timeout:
err_shm_mapped:
	util_unmap(pop->shrd, pop->shrd->area_size);
	if (OBJ_SHM_USE_POSIX)
		os_shm_unlink(pop->shm_path);
err_shm:
	return -1;
}

/*
 * obj_shm_boot -- (internal) boots the shared memory part
 */
static int
obj_shm_boot(PMEMobjpool *pop, int create)
{
	LOG(3, "pop %p", pop);

	ASSERTeq(pop->shrd, NULL);

	if (obj_shm_setup(pop, create) != 0)
		FATAL("!obj_shm_setup");

	ASSERTne(pop->shrd, NULL);

	return 0;
}

static int
obj_runtime_init_primary(PMEMobjpool *pop)
{
	LOG(3, "pid %d is the primary process", getpid());

	/*
	 * when the lock was granted there is no other process and
	 * we are in charge for initialization
	 */
	pop->is_primary = 1;

	if (obj_shm_boot(pop, pop->is_primary /* create */) != 0) {
		ERR("!obj_shm_boot");
		pop->is_primary = 0;

		return -1;
	}

	int ret;
	if ((ret = registry_add(pop->registry)) == -1)
		return -1;
	ASSERT(ret >= 0);
	pop->proc_idx = (unsigned)ret;

	return 0;
}

/*
 * obj_runtime_init_secondary -- (internal) initialization for non-leading
 * processes
 */
static int
obj_runtime_init_secondary(PMEMobjpool *pop)
{
	LOG(4, "Already locked by another (init) process. Waiting...");

	int ret;
	do {
		/*
		 * block until shm is initialized
		 *
		 * The leader might crash during initialization. Thus we could
		 * obtain a read lock and thus gain access to uninitialized
		 * shared memory.
		 *
		 * We check this in obj_shm_boot(). If the shared memory is
		 * uninitialized we will immediately detach and retry in next
		 * round
		 */
		ret = util_read_lock(pop->lock_fd, OBJ_LOCK_POOL, SEEK_SET, 1);
		if (ret != 0 && (errno != EACCES && errno != EAGAIN)) {
			ERR("util_read_lock returned unknown error");
			goto err_lock;
		}
	} while (ret == -1 && obj_invoke_busy_handler(&pop->busy_handler));

	if (ret == -1)
		goto err_timeout;

	/* Finally, we are ready to attach to shm */
	if (obj_shm_boot(pop, 0 /* open only */) != 0) {
		ERR("!obj_shm_boot");
		goto err_shm;
	}

	/*
	 * So far initialization is done,
	 * but we need to block until the leading process has
	 * properly booted the pool.
	 *
	 * From now on we can rely on shared posix mutexes
	 */
	if (obj_wait_until_state(pop, SHM_RUNTIME_INITIALIZED) != 0)
		goto err_obj_wait_until_state;

	if ((ret = registry_add(pop->registry)) == -1) {
		goto err_registry_add;

#if 0
		/*
		 * XXX mp-mode
		 *
		 * execute recovery without booting heap
		 *
		 * With current implentation, we can't run recovery
		 * because the heap functions expect a properly booted heap.
		 * But at this position in code it was not booted, yet.
		 */
		if (errno != ENOMEM)
			goto err_registry_add;

		/*
		 * the registry has no free slots, so check if we
		 * can free some via recovery
		 */
		if (obj_check_liveliness_and_recover(pop) == 0 &&
		    (ret = registry_add(pop->registry, getpid())) == -1)
				goto err_registry_add;
#endif
	}
	ASSERT(ret >= 0);
	pop->proc_idx = (unsigned)ret;

	return 0;

err_registry_add:
err_obj_wait_until_state:
	/*
	 * util_unmap(pop->shrd, pop->shrd->area_size);
	 * if (OBJ_SHM_USE_POSIX)
	 *	os_shm_unlink(pop->shm_path);
	 */
	pop->shrd = NULL;
	pop->shm_path = NULL;
err_timeout:
err_lock:
err_shm:
	return -1;
}

/*
 * obj_runtime_init_boot_mp -- (internal) locked initialization with timeout.
 *  Dead man switch inspired by sqlite3 source (os_unix.c)
 */
static int
obj_runtime_init_boot_mp(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	if (util_write_lock(pop->lock_fd, OBJ_LOCK_POOL, SEEK_SET, 1) == 0) {
		if (os_ftruncate(pop->lock_fd, (off_t)OBJ_LOCKFILE_SIZE) != 0) {
			ERR("!ftruncate");
			return -1;
		}

		int ret = obj_runtime_init_primary(pop);

		/*
		 * We obtained a mutex in obj_runtime_init_primary/obj_shm_boot
		 * that we need to hold until obj_boot completed
		 * Thus, it is safe to downgrade the exclusive lock to shared.
		 */
		if (util_read_lock(pop->lock_fd, OBJ_LOCK_POOL, SEEK_SET, 1)
		    != 0) {
			ERR("run_lock returned unknown error");
			return -1;
		}

		return ret;
	} else {
		if (errno == EACCES || errno == EAGAIN) {
			return obj_runtime_init_secondary(pop);
		} else {
			ERR("F_SETLK unknown error");
			return -1;
		}
	}

	ASSERT(0);
}

#define NDELAY (int)ARRAY_SIZE(delays)

/*
 * This routine implements a busy callback that sleeps and tries
 * again until a timeout value is reached.  The timeout value is
 * an integer number of milliseconds passed in as the first
 * argument.
 *
 * Returns 0 when timeout was exceeded otherwise 1
 */
static int obj_busy_cb_def(void *ptr, int count)
{
	ASSERT(count >= 0);
	static const uint8_t delays[] =
		{ 1, 2, 5, 10, 15, 20, 25, 25,  25,  50,  50, 100 };
	static const uint8_t  totals[] =
		{ 0, 1, 3,  8, 18, 33, 53, 78, 103, 128, 178, 228 };
	PMEMobjpool *pop = (PMEMobjpool *)ptr;
	int timeout = pop->busyTimeout;
	int delay;
	int prior;

	if (count < NDELAY) {
		delay = delays[count];
		prior = totals[count];
	} else {
		delay = delays[NDELAY - 1];
		prior = totals[NDELAY - 1] + delay * (count - (NDELAY - 1));
	}
	if (prior + delay > timeout) {
		delay = timeout - prior;
		if (delay <= 0)
			return 0;
	}
	usleep((useconds_t)delay * 1000);

	return 1;
}

/*
 * obj_mutex_timedlock_mp -- wraps pmemobj_mutex_timedlock_mp
 * to pass in a default timeout
 */
static int
obj_mutex_timedlock_mp(PMEMobjpool *pop, PMEMmutex *__restrict mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);
	struct timespec ts;
	return pmemobj_mutex_timedlock_mp(pop, mutexp, mp_set_mtx_timeout(&ts));
}

/*
 * obj_runtime_init -- (internal) initialize runtime part of the pool header
 */
static int
obj_runtime_init(PMEMobjpool *pop, int rdonly, int boot, unsigned nlanes)
{
	LOG(3, "pop %p rdonly %d boot %d", pop, rdonly, boot);
	struct pmem_ops *p_ops = &pop->p_ops;

	pop->uuid_lo = pmemobj_get_uuid_lo((const PMEMobjpool *)pop->base_addr);

	/*
	 * Use some of the memory pool area for run-time info.  This
	 * run-time state is never loaded from the file, it is always
	 * created here, so no need to worry about byte-order.
	 */
	pop->rdonly = rdonly;

	pop->lanes_desc.runtime_nlanes = nlanes;

	pop->tx_params = tx_params_new();
	if (pop->tx_params == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (obj_ctl_init_and_load(pop) != 0) {
		errno = EINVAL;
		goto err_ctl;
	}

	if (boot) {
		if (pop->mp_mode) {
			pop->pmem_lock = obj_mutex_timedlock_mp;
			pop->pmem_unlock = pmemobj_mutex_unlock_mp;

			obj_register_busy_handler(pop, obj_busy_cb_def,
				(void *) pop);
			pop->busyTimeout = 1000;

			if (obj_open_mp_files(pop) != 0) {
				ERR("obj_open_mp_files");
			}
			int retries = OBJ_SHM_INIT_RETRIES;
			while (obj_runtime_init_boot_mp(pop) != 0) {
				if (errno == EOWNERDEAD) {
					ERR("dead process detected.  registry"
					    " might be corrupted.");
					goto err_mp_init;

				}
				if (errno == ETIMEDOUT) {
					ERR("Could not obtain lock initialize "
					    "in specified time. giving up.");
					goto err_mp_init;

				}
				if (!retries) {
					ERR("obj_runtime_init_boot_mp max "
					    "retries reached. giving up.");
					goto err_mp_init;
				}
				--retries;
				sched_yield();
			}
		} else {
			/* single process init */
			pop->is_primary = 1;

			pop->pmem_lock = pmemobj_mutex_lock;
			pop->pmem_unlock = pmemobj_mutex_unlock;

			pop->lanes_desc.lane =
			    Malloc(OBJ_NLANES * sizeof(struct lane));
			pop->lanes_desc.lane_locks =
			    Zalloc(OBJ_NLANES * sizeof(uint64_t));
		}

		if (pop->is_primary) {
			/*
			 * run_id is made unique by incrementing
			 * the previous value
			 */
			pop->pool_desc->run_id += 2;
			if (pop->pool_desc->run_id == 0)
				pop->pool_desc->run_id += 2;
			pmemops_persist(p_ops,
				&pop->pool_desc->run_id,
				sizeof(pop->pool_desc->run_id));

			if (pop->mp_mode) {
				/*
				 * finally the pool is ready for others to
				 * proceed
				 */
				if (obj_change_shared_state(pop,
					SHM_RUNTIME_INITIALIZED) != 0)
					goto err_primary_change_shared_state;
			}
		}

		LOG(4, "run_id: %" PRIu64, pop->pool_desc->run_id);

		if ((errno = obj_boot(pop)) != 0)
			goto err_boot;


#ifdef USE_VG_MEMCHECK
		if (On_valgrind) {
			/* mark unused part of the pool as not accessible */
			void *end = palloc_heap_end(&pop->heap);
			VALGRIND_DO_MAKE_MEM_NOACCESS(end,
			    (char *)pop->base_addr + pop->size - (char *)end);
		}
#endif

		obj_pool_init();

		pop->tx_postcommit_tasks = NULL;

		if ((errno = cuckoo_insert(pools_ht, pop->uuid_lo, pop)) != 0) {
			ERR("!cuckoo_insert");
			goto err;
		}

		if ((errno = cuckoo_insert(pools_trans_ht,
		    (uint64_t)pop->base_addr, pop)) != 0) {
			ERR("!cuckoo_insert");
			goto err;
		}

		if ((errno = ctree_insert(pools_tree,
		    (uint64_t)pop->base_addr, pop->size))
				!= 0) {
			ERR("!ctree_insert");
			goto err;
		}
	}

	/*
	 * If possible, turn off all permissions on the pool header page.
	 *
	 * The prototype PMFS doesn't allow this when large pages are in
	 * use. It is not considered an error if this fails.
	 */
	RANGE_NONE(pop->base_addr, sizeof(struct pool_hdr), pop->is_dev_dax);

	return 0;
err:
	ctl_delete(pop->ctl);
err_ctl:
	tx_params_delete(pop->tx_params);
err_boot:
err_primary_change_shared_state:
	if (pop->mp_mode) {
		/*
		 * For unknown reasons unmapping the shared memory during
		 * shutdown (exit(0)) in the child process while it is
		 * holding a mutex causes the parent to crash when accessing
		 * the mutex.
		 */
		/* util_unmap(pop->shrd, pop->shrd->area_size); */
		pop->shrd = NULL;
	}
err_mp_init:
	pop->shm_fd = -1;
	(void) os_close(pop->shm_fd);

	return -1;
}

static int
obj_open_mp_files(PMEMobjpool *pop)
{
	/* open lock file */
	const char *lock_path = obj_build_suffix_file(pop,
		FILE_SUFFIX_LOCK);

	/*
	 * XXX mp-mode --  (windows) locking in windows is mandatory
	 * see Sqlite book p.101
	 *
	 * reserve an entire page for locks.
	 * This page must not store data
	 */
	if ((pop->lock_fd = obj_open_suffix_file(pop, lock_path)) < 0) {
		ERR("!obj_open_suffix_file %s", lock_path);
		return -1;
	}

	/*
	 * hold a read lock for entire lifetime (dead man switch)
	 * As long as we hold the lock the shared state of the pool must not be
	 * closed  by others.
	 */
	if (util_read_lock(pop->lock_fd, OBJ_LOCK_DMS, SEEK_SET, 1) != 0 &&
	    obj_invoke_busy_handler(&pop->busy_handler)) {
		/*
		 * This lock is exclusivly held during
		 * pool cleanup. If we reached the timeout
		 * something unforseen happend and we are not
		 * able to recover.
		 */
		FATAL("!util_read_lock OBJ_LOCK_DMS");
	}

	if (!OBJ_SHM_USE_POSIX) {
		/* open shm file */
		pop->shm_path = obj_build_suffix_file(
			pop, FILE_SUFFIX_SHM);

		if ((pop->shm_fd = obj_open_suffix_file(pop,
			pop->shm_path)) < 0) {
			ERR("!obj_open_suffix_file %s", pop->shm_path);
			goto err_shm;
		}
	}

	return 0;
err_shm:
	pop->lock_fd = -1;
	(void) os_close(pop->lock_fd);
return -1;
}

/*
 * obj_get_nlanes -- get a number of lanes available at runtime. If the value
 * provided with the PMEMOBJ_NLANES environment variable is greater than 0 and
 * smaller than OBJ_NLANES constant it returns PMEMOBJ_NLANES. Otherwise it
 * returns OBJ_NLANES.
 */
static unsigned
obj_get_nlanes(void)
{
	LOG(3, NULL);

	char *env_nlanes = os_getenv(OBJ_NLANES_ENV_VARIABLE);
	if (env_nlanes) {
		int nlanes = atoi(env_nlanes);
		if (nlanes <= 0) {
			ERR("%s variable must be a positive integer",
					OBJ_NLANES_ENV_VARIABLE);
			errno = EINVAL;
			goto no_valid_env;
		}

		return (unsigned)(OBJ_NLANES < nlanes ? OBJ_NLANES : nlanes);
	}

no_valid_env:
	return OBJ_NLANES;
}

/*
 * pmemobj_createU -- create a transactional memory pool (set)
 */
#ifndef _WIN32
static inline
#endif
PMEMobjpool *
pmemobj_createU(const char *path, const char *layout,
		size_t poolsize, mode_t mode)
{
	LOG(3, "path %s layout %s poolsize %zu mode %o",
			path, layout, poolsize, mode);

	PMEMobjpool *pop = NULL;
	struct pool_set *set;

	/* check length of layout */
	if (layout && (strlen(layout) >= PMEMOBJ_MAX_LAYOUT)) {
		ERR("Layout too long");
		errno = EINVAL;
		return NULL;
	}

	/*
	 * A number of lanes available at runtime equals the lowest value
	 * from all reported by remote replicas hosts. In the single host mode
	 * the runtime number of lanes is equal to the total number of lanes
	 * available in the pool or the value provided with PMEMOBJ_NLANES
	 * environment variable whichever is lower.
	 */
	unsigned runtime_nlanes = obj_get_nlanes();

	/*
	 * When not in multiprocess mode we lock the file with a mandatory lock.
	 * In mp-mode duplicate open of the same pool is avoided later in the
	 * code.
	 */
	int flock_pool = !obj_has_multiprocess_support();
	if (util_pool_create(&set, path,
			poolsize, PMEMOBJ_MIN_POOL,
			OBJ_HDR_SIG, OBJ_FORMAT_MAJOR,
			OBJ_FORMAT_COMPAT, OBJ_FORMAT_INCOMPAT,
			OBJ_FORMAT_RO_COMPAT, &runtime_nlanes,
			REPLICAS_ENABLED, flock_pool) != 0) {
		LOG(2, "cannot create pool or pool set");
		return NULL;
	}

	ASSERT(set->nreplicas > 0);

	PMEMobjpool *prev = NULL;
	for (unsigned r = 0; r < set->nreplicas; r++) {
		struct pool_replica *repset = set->replica[r];
		PMEMobjpool *rep = pmemobjpool_new();
		if (r == 0)
			pop = rep; /* pop is master replica from now on */

		rep->base_addr = repset->part[0].addr;
		rep->pool_desc =
		    (struct pool_descriptor *)((uintptr_t)rep->base_addr
							    + POOL_HDR_SIZE);
		void *pmem_rt_addr = rep->pool_desc->pmem_reserved;
		memset(pmem_rt_addr, 0, OBJ_DESC_RT_RESERVED);
		VALGRIND_REMOVE_PMEM_MAPPING(pmem_rt_addr, OBJ_DESC_RT_RESERVED);

		rep->addr = rep->base_addr;
		rep->size = repset->repsize;
		rep->replica = NULL;
		rep->rpp = NULL;

		/* initialize replica runtime - is_pmem, funcs, ... */
		if (obj_replica_init(rep, set, r, 1 /* create */) != 0) {
			ERR("initialization of replica #%u failed", r);
			goto err;
		}

		/* link replicas */
		/* set->replica[r + 1]->part[0].addr; */
		if (prev != NULL)
			prev->replica = rep;

		prev = rep;
	}

	pop->set = set;

	/* create pool descriptor */
	if (obj_descr_create(pop, layout, set->poolsize) != 0) {
		LOG(2, "creation of pool descriptor failed");
		goto err;
	}

	/* initialize runtime parts - lanes, obj stores, ... */
	if (obj_runtime_init(pop, 0, 1 /* boot */, runtime_nlanes) != 0) {
		ERR("pool initialization failed");
		goto err;
	}

	if (util_poolset_chmod(set, mode))
		goto err;

	/*
	 * XXX mp-mode -- change permissions for suffix files here
	 */
	util_poolset_fdclose(set);

	LOG(3, "created pop with address %p", pop);

	return pop;

err:
	LOG(4, "error clean up");
	int oerrno = errno;
	if (set->remote)
		obj_cleanup_remote(pop);
	util_poolset_close(set, DELETE_CREATED_PARTS);
	errno = oerrno;
	return NULL;
}

#ifndef _WIN32
/*
 * pmemobj_create -- create a transactional memory pool (set)
 */
PMEMobjpool *
pmemobj_create(const char *path, const char *layout,
		size_t poolsize, mode_t mode)
{
	return pmemobj_createU(path, layout, poolsize, mode);
}
#else
/*
 * pmemobj_createW -- create a transactional memory pool (set)
 */
PMEMobjpool *
pmemobj_createW(const wchar_t *path, const wchar_t *layout, size_t poolsize,
	mode_t mode)
{
	char *upath = util_toUTF8(path);
	if (upath == NULL)
		return NULL;
	char *ulayout = NULL;
	if (layout != NULL) {
		ulayout = util_toUTF8(layout);
		if (ulayout == NULL) {
			util_free_UTF8(upath);
			return NULL;
		}
	}
	PMEMobjpool *ret = pmemobj_createU(upath, ulayout, poolsize, mode);

	util_free_UTF8(upath);
	util_free_UTF8(ulayout);

	return ret;
}
#endif

/*
 * obj_check_basic_local -- (internal) basic pool consistency check
 *                              of a local replica
 */
static int
obj_check_basic_local(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	ASSERTeq(pop->rpp, NULL);

	int consistent = 1;

	if (pop->pool_desc->run_id % 2) {
		ERR("invalid run_id %" PRIu64, pop->pool_desc->run_id);
		consistent = 0;
	}

	if ((errno = lane_check(pop)) != 0) {
		LOG(2, "!lane_check");
		consistent = 0;
	}

	errno = palloc_heap_check((char *)pop->base_addr +
		    pop->pool_desc->heap_offset,
		    pop->pool_desc->heap_size);
	if (errno != 0) {
		LOG(2, "!heap_check");
		consistent = 0;
	}

	return consistent;
}

/*
 * obj_read_remote -- read data from remote replica
 *
 * It reads data of size 'length' from the remote replica 'pop'
 * from address 'addr' and saves it at address 'dest'.
 */
int
obj_read_remote(void *ctx, uintptr_t base, void *dest, void *addr,
		size_t length)
{
	LOG(3, "ctx %p base 0x%lx dest %p addr %p length %zu", ctx, base, dest,
			addr, length);

	ASSERTne(ctx, NULL);
	ASSERT((uintptr_t)addr >= base);

	uintptr_t offset = (uintptr_t)addr - base;
	if (Rpmem_read(ctx, dest, offset, length, RLANE_DEFAULT)) {
		ERR("!rpmem_read");
		return -1;
	}

	return 0;
}

/*
 * obj_check_basic_remote -- (internal) basic pool consistency check
 *                               of a remote replica
 */
static int
obj_check_basic_remote(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	ASSERTne(pop->rpp, NULL);

	int consistent = 1;

	/* read pop->run_id */
	if (obj_read_remote(pop->rpp, pop->remote_base,
	    &pop->pool_desc->run_id, &pop->pool_desc->run_id,
	    sizeof(pop->pool_desc->run_id))) {
		ERR("!obj_read_remote");
		return -1;
	}

	if (pop->pool_desc->run_id % 2) {
		ERR("invalid run_id %" PRIu64, pop->pool_desc->run_id);
		consistent = 0;
	}

	/* XXX add lane_check_remote */

	errno = palloc_heap_check_remote((char *)pop->base_addr +
	    pop->pool_desc->heap_offset,
			pop->pool_desc->heap_size, &pop->p_ops.remote);
	if (errno != 0) {
		LOG(2, "!heap_check_remote");
		consistent = 0;
	}

	return consistent;
}

/*
 * obj_check_basic -- (internal) basic pool consistency check
 *
 * Used to check if all the replicas are consistent prior to pool recovery.
 */
static int
obj_check_basic(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	if (pop->rpp == NULL)
		return obj_check_basic_local(pop);
	else
		return obj_check_basic_remote(pop);
}

/*
 * obj_pool_close -- (internal) close the pool set
 */
static void
obj_pool_close(struct pool_set *set)
{
	int oerrno = errno;
	util_poolset_close(set, DO_NOT_DELETE_PARTS);
	errno = oerrno;
}

/*
 * obj_pool_open -- (internal) open the given pool
 */
static int
obj_pool_open(struct pool_set **set, const char *path, int cow,
	unsigned *nlanes)
{
	if (obj_has_multiprocess_support()) {
		if (util_pool_open_unlocked(set, path, cow, PMEMOBJ_MIN_POOL,
			OBJ_HDR_SIG, OBJ_FORMAT_MAJOR,
			OBJ_FORMAT_COMPAT, OBJ_FORMAT_INCOMPAT,
			OBJ_FORMAT_RO_COMPAT, nlanes) != 0) {
			LOG(2, "cannot open pool or pool set");
			return -1;
		}
	} else {
		if (util_pool_open(set, path, cow, PMEMOBJ_MIN_POOL,
			OBJ_HDR_SIG, OBJ_FORMAT_MAJOR,
			OBJ_FORMAT_COMPAT, OBJ_FORMAT_INCOMPAT,
			OBJ_FORMAT_RO_COMPAT, nlanes) != 0) {
			LOG(2, "cannot open pool or pool set");
			return -1;
		}
	}

	ASSERT((*set)->nreplicas > 0);

	/* read-only mode is not supported in libpmemobj */
	if ((*set)->rdonly) {
		ERR("read-only mode is not supported");
		errno = EINVAL;
		goto err_rdonly;
	}

	return 0;
err_rdonly:
	obj_pool_close(*set);
	return -1;
}

/*
 * obj_replicas_init -- (internal) initialize all replicas
 */
static PMEMobjpool *
obj_replicas_init(struct pool_set *set)
{
	PMEMobjpool *pop = NULL;
	PMEMobjpool *prev_pop = NULL;
	PMEMobjpool *tmp = NULL;
	unsigned r;
	for (r = 0; r < set->nreplicas; r++) {
		struct pool_replica *repset = set->replica[r];
		PMEMobjpool *rep = pmemobjpool_new();

		if (r == 0)
			pop = rep;

		/*
		 * XXX mp-mode -- probably redundant and can be consolidated
		 */
		rep->base_addr = repset->part[0].addr;
		rep->addr = rep->base_addr;

		rep->pool_desc = (void *)((uintptr_t)pop->base_addr
					    + POOL_HDR_SIZE);

		rep->size = repset->repsize;
		rep->replica = NULL;
		rep->rpp = NULL;

		/* initialize replica runtime - is_pmem, funcs, ... */
		if (obj_replica_init(rep, set, r, 0 /* open */) != 0) {
			ERR("initialization of replica #%u failed", r);
			goto err;
		}

		/* link replicas */
		if (prev_pop != NULL)
			prev_pop->replica = rep;

		prev_pop = rep;
	}

	return pop;
err:
	for (unsigned p = 0; p <= r; p++, pop = tmp) {
		if (pop == NULL)
			return NULL;
		tmp = pop->replica;
		obj_replica_fini(pop, set->replica[p]->remote != NULL);
	}

	return NULL;
}

/*
 * obj_replicas_fini -- (internal) deinitialize all replicas
 */
static void
obj_replicas_fini(PMEMobjpool *rep)
{
	int oerrno = errno;
	PMEMobjpool *next = rep;
	do {
		rep = next;
		next = rep->replica;
		obj_replica_fini(rep, rep->rpp != NULL);
	} while (next != NULL);
	errno = oerrno;
}

/*
 * obj_replicas_check_basic -- (internal) perform basic consistency check
 * for all replicas
 */
static int
obj_replicas_check_basic(PMEMobjpool *pop)
{
	for (PMEMobjpool *rep = pop; rep != NULL; rep = rep->replica) {
		if (obj_check_basic(rep) == 0) {
			ERR("inconsistent replica #%p", rep);
			return -1;
		}
	}

	/* copy lanes */
	void *src = (void *)((uintptr_t)pop->base_addr +
	    pop->pool_desc->lanes_offset);
	size_t len = pop->pool_desc->nlanes * sizeof(struct lane_layout);

	for (PMEMobjpool *rep = pop->replica; rep != NULL; rep = rep->replica) {
		void *dst = (void *)((uintptr_t)rep->base_addr +
					pop->pool_desc->lanes_offset);
		if (rep->rpp == NULL) {
			rep->memcpy_persist_local(dst, src, len);
		} else {
			if (rep->persist_remote(rep, dst, len,
					RLANE_DEFAULT) == NULL)
				obj_handle_remote_persist_error(pop);
		}
	}

	return 0;
}

/*
 * obj_open_common -- open a transactional memory pool (set)
 *
 * This routine does all the work, but takes a cow flag so internal
 * calls can map a read-only pool if required.
 */
static PMEMobjpool *
obj_open_common(const char *path, const char *layout, int cow, int boot)
{
	LOG(3, "path %s layout %s cow %d", path, layout, cow);

	PMEMobjpool *pop = NULL;
	struct pool_set *set;

	/*
	 * A number of lanes available at runtime equals the lowest value
	 * from all reported by remote replicas hosts. In the single host mode
	 * the runtime number of lanes is equal to the total number of lanes
	 * available in the pool or the value provided with PMEMOBJ_NLANES
	 * environment variable whichever is lower.
	 */
	unsigned runtime_nlanes = obj_get_nlanes();
	if (obj_pool_open(&set, path, cow, &runtime_nlanes))
		return NULL;

	/* pop is master replica from now on */
	if ((pop = obj_replicas_init(set)) == NULL) {
		goto replicas_init;
	}

	/*
	 * Prevent to open the pool twice within the same process
	 * Until this point the pool file must **not** be written.
	 */
	if (pools_ht) {
		uint64_t uuid_lo = pmemobj_get_uuid_lo(
			(const PMEMobjpool *)pop->base_addr);
		const PMEMobjpool *old = cuckoo_get(pools_ht, uuid_lo);
		if (old && old->uuid_lo == uuid_lo) {
			errno = EWOULDBLOCK;
			ERR("!pool already opened");
			goto err_opened_twice;
		}
	}

	pop->pool_desc = (struct pool_descriptor *)((uintptr_t)pop->base_addr
	    + POOL_HDR_SIZE);

	set->poolsize = pop->pool_desc->heap_offset +
					pop->pool_desc->heap_size;

	for (PMEMobjpool *rep = pop; rep != NULL; rep = rep->replica) {
		/* check descriptor */
		if (obj_descr_check(rep, layout, set->poolsize) != 0) {
			LOG(2, "descriptor check of replica #%p failed", rep);
			goto err_descr_check;
		}
	}

	pop->set = set;

	if (boot) {
		/* check consistency of 'master' replica */
		if (obj_check_basic(pop) == 0) {
			goto err_check_basic;
		}
	}

	if (set->nreplicas > 1) {
		if (obj_replicas_check_basic(pop))
			goto err_replicas_check_basic;
	}

	/*
	 * before runtime initialization lanes are unavailable, remote persists
	 * should use RLANE_DEFAULT
	 */
	pop->lanes_desc.runtime_nlanes = 0;

#ifdef USE_VG_MEMCHECK
	pop->vg_boot = boot;
#endif
	/* initialize runtime parts - lanes, obj stores, ... */
	if (obj_runtime_init(pop, 0, boot, runtime_nlanes) != 0) {
		ERR("pool initialization failed");
		goto err_runtime_init;
	}

#ifdef USE_VG_MEMCHECK
	if (boot)
		obj_vg_boot(pop);
#endif

	util_poolset_fdclose(set);

	LOG(3, "pop %p", pop);

	return pop;
err_runtime_init:
err_replicas_check_basic:
err_check_basic:
err_descr_check:
err_opened_twice:
	obj_replicas_fini(pop);
replicas_init:
	obj_pool_close(set);
	return NULL;
}

/*
 * pmemobj_openU -- open a transactional memory pool
 */
#ifndef _WIN32
static inline
#endif
PMEMobjpool *
pmemobj_openU(const char *path, const char *layout)
{
	LOG(3, "path %s layout %s", path, layout);

	return obj_open_common(path, layout, Open_cow, 1);
}

#ifndef _WIN32
/*
 * pmemobj_open -- open a transactional memory pool
 */
PMEMobjpool *
pmemobj_open(const char *path, const char *layout)
{
	return pmemobj_openU(path, layout);
}
#else
/*
 * pmemobj_openW -- open a transactional memory pool
 */
PMEMobjpool *
pmemobj_openW(const wchar_t *path, const wchar_t *layout)
{
	char *upath = util_toUTF8(path);
	if (upath == NULL)
		return NULL;

	char *ulayout = NULL;
	if (layout != NULL) {
		ulayout = util_toUTF8(layout);
		if (ulayout == NULL) {
			util_free_UTF8(upath);
			return NULL;
		}
	}

	PMEMobjpool *ret = pmemobj_openU(upath, ulayout);
	util_free_UTF8(upath);
	util_free_UTF8(ulayout);
	return ret;
}
#endif

#if 0

#endif

/*
 * obj_pool_mp_cleanup -- (internal) cleanup or unmap resources used
 * for multi-process support
 */
static void
obj_pool_mp_cleanup(PMEMobjpool *pop, int clean_shrd)
{
	LOG(3, "pop %p", pop);

	if (!pop->mp_mode)
		return;

	/* detach from registry */
	registry_remove_by_idx(pop->registry, pop->proc_idx);
	registry_delete(pop->registry, clean_shrd);

	/* unmap, cleanup and close shm */
	obj_shm_cleanup(pop, clean_shrd);
	(void) os_close(pop->shm_fd);

	/* close and release held locks */
	(void) os_close(pop->lock_fd);
}

/*
 * obj_pool_cleanup -- (internal) cleanup the pool and unmap
 */
static void
obj_pool_cleanup(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	tx_params_delete(pop->tx_params);
	ctl_delete(pop->ctl);

	int clean_shrd = 0;
	if (pop->mp_mode) {
		/*
		 * Try upgrading the shared lock. If successfull, we are the
		 * only user of the pool and responsible for cleaning up the
		 * shared transient state.
		 *
		 * Since other processes are not able to obtain read access in
		 * function obj_open_mp_files(), no other process can open the
		 * pool until we cleaned the shared state.
		 *
		 * An alternative implementation could introduced the
		 * a new initialization_state, e.g., 'SHUTDOWN'.
		 *
		 * For locking, we rely on advisory locks. Alternatively we
		 * could use SysV semaphores. This would allow us to use a
		 * refcount in conjunction with SEM_UNDO to correctly
		 * decrement on process crash, but comes of the cost for more
		 * overhead, complexity and less portability.
		 */
		if (util_write_lock(pop->lock_fd, OBJ_LOCK_DMS, SEEK_SET, 1)
		    == 0) {
			clean_shrd = 1;

			/*
			 * we are the last process. while cleaning up we must
			 * prevent others from attaching
			 */
			if (util_write_lock(pop->lock_fd, OBJ_LOCK_POOL,
			    SEEK_SET, 1))
				FATAL("!util_write_lock OBJ_LOCK_POOL");
		}

		/*
		 * the call to palloc_heap_cleanup releases the region and
		 * has to happen before the process detaches from the registry
		 */
		palloc_heap_cleanup(&pop->heap, clean_shrd);
		obj_pool_mp_cleanup(pop, clean_shrd);
	} else {
		palloc_heap_cleanup(&pop->heap, clean_shrd);
	}

	/* release locks */
	if (pop->mp_mode) {
		if (clean_shrd) {
			if (!util_un_lock(pop->lock_fd, OBJ_LOCK_POOL,
			    SEEK_SET, 1))
				ERR("un_lock OBJ_LOCK_POOL");
		}

		if (util_un_lock(pop->lock_fd, OBJ_LOCK_DMS, SEEK_SET, 1) != 0)
			ERR("un_lock OBJ_LOCK_DMS");
	}

	/* continue cleaning up local state */

	lane_cleanup(pop);

	/* unmap and free all replicas */
	util_poolset_close(pop->set, DO_NOT_DELETE_PARTS);
	obj_replicas_fini(pop);
}

/*
 *  sqlite3 style busy handler registration
 *
 * This routine sets the busy callback to the
 * given callback function with the given argument.
 */
int obj_register_busy_handler(PMEMobjpool *pop, int (*xBusy)(void *, int),
	void *pArg) {
	pop->busy_handler.xFunc = xBusy;
	pop->busy_handler.pArg = pArg;
	pop->busy_handler.nBusy = 0;
	pop->busyTimeout = 0;

	return 0;
}

/*
 * obj_env_fini -- (internal) shm cleanup for still open pools (on destructor)
 */
static void
obj_env_fini()
{
	PMEMobjpool *pop = NULL;
	while ((pop = obj_pool_find_opened()) != NULL) {
		LOG(3, "found open pop %p", pop);
		if (pop->mp_mode) {
			obj_pool_cleanup(pop);
		}
	}
}

/*
 * obj_fini -- cleanup of obj
 *
 * Called by destructor.
 */
void
obj_fini(void)
{
	LOG(3, NULL);

	obj_env_fini();

	if (pools_ht)
		cuckoo_delete(pools_ht);
	if (pools_trans_ht)
		cuckoo_delete(pools_trans_ht);
	if (pools_tree)
		ctree_delete(pools_tree);
	lane_info_destroy();
	util_remote_fini();
}

/*
 * Slightly modified SQLITE busy handler.
 *
 * Invokes the given busy handler.
 *
 * This routine is called when an operation failed with a lock.
 * If this routine returns non-zero, the lock is retried.  If it
 * returns 0, the operation aborts with an SQLITE_BUSY error.
 *
 * The handler will sleep multiple times until at least "ms" milliseconds
 * of sleeping  have accumulated.  After at least "ms" milliseconds of sleeping,
 * the handler returns 0.
 */
int obj_invoke_busy_handler(struct busy_handler *p) {
	LOG(4, "handler %p cb %p timeout %d", p, p->xFunc, p->nBusy);

	ASSERT(p != NULL);
	ASSERT(p->xFunc != NULL);
	ASSERT(p->nBusy >= 0);

	int rc;
	rc = p->xFunc(p->pArg, p->nBusy);
	if (rc == 0) {
		p->nBusy = -1;
	} else {
		p->nBusy++;
	}

	return rc;
}

/*
 * pmemobj_close -- close a transactional memory pool
 */
void
pmemobj_close(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	_pobj_cache_invalidate++;

	if (cuckoo_remove(pools_ht, pop->uuid_lo) != pop) {
		ERR("cuckoo_remove");
	}

	if (cuckoo_remove(pools_trans_ht, (uint64_t)pop->base_addr) != pop) {
		ERR("cuckoo_remove");
	}

	if (ctree_remove(pools_tree, (uint64_t)pop->base_addr, 1) !=
	    (uint64_t)pop->base_addr) {
		ERR("ctree_remove");
	}

	if (pop->tx_postcommit_tasks != NULL) {
		ringbuf_delete(pop->tx_postcommit_tasks);
	}

#ifndef _WIN32

	if (_pobj_cached_pool.pop == pop) {
		_pobj_cached_pool.pop = NULL;
		_pobj_cached_pool.uuid_lo = 0;
	}

#else /* _WIN32 */

	struct _pobj_pcache *pcache = os_tls_get(Cached_pool_key);
	if (pcache != NULL) {
		if (pcache->pop == pop) {
			pcache->pop = NULL;
			pcache->uuid_lo = 0;
		}
	}

#endif /* _WIN32 */

	obj_pool_cleanup(pop);
}

/*
 * pmemobj_checkU -- transactional memory pool consistency check
 */
#ifndef _WIN32
static inline
#endif
int
pmemobj_checkU(const char *path, const char *layout)
{
	LOG(3, "path %s layout %s", path, layout);

	PMEMobjpool *pop = obj_open_common(path, layout, 1, 0);
	if (pop == NULL)
		return -1;	/* errno set by obj_open_common() */

	int consistent = 1;

	/*
	 * For replicated pools, basic consistency check is performed
	 * in obj_open_common().
	 */
	if (pop->replica == NULL)
		consistent = obj_check_basic(pop);

	if (consistent) {
		/* single process init */
		pop->is_primary = 1;

		/*
		 * disable mp-mode irrespective of current environment settings.
		 * This is because due to reduce complexity and has no impact
		 * on pool consistency.
		 */
		pop->mp_mode = 0;

		/* workaround to satisfy lane cleanup */
		pop->lanes_desc.lane =
		    Malloc(OBJ_NLANES * sizeof(struct lane));
		pop->lanes_desc.lane_locks =
		    Zalloc(OBJ_NLANES * sizeof(uint64_t));
	}

	if (consistent && (errno = obj_boot(pop)) != 0) {
		LOG(3, "!obj_boot");
		consistent = 0;
	}

	if (consistent) {
		obj_pool_cleanup(pop);
	} else {
		tx_params_delete(pop->tx_params);
		ctl_delete(pop->ctl);

		Free(pop->lane_range);

		/* unmap all the replicas */
		util_poolset_close(pop->set, DO_NOT_DELETE_PARTS);
		obj_replicas_fini(pop);
	}

	if (consistent)
		LOG(4, "pool consistency check OK");

	return consistent;
}

#ifndef _WIN32
/*
 * pmemobj_check -- transactional memory pool consistency check
 *
 * always opens the pool in non-multi processing mode, since this function
 * should be invoked from a single process only.
 */
int
pmemobj_check(const char *path, const char *layout)
{
	return pmemobj_checkU(path, layout);
}
#else
/*
 * pmemobj_checkW -- transactional memory pool consistency check
 */
int
pmemobj_checkW(const wchar_t *path, const wchar_t *layout)
{
	char *upath = util_toUTF8(path);
	if (upath == NULL)
		return -1;

	char *ulayout = NULL;
	if (layout != NULL) {
		ulayout = util_toUTF8(layout);
		if (ulayout == NULL) {
			util_free_UTF8(upath);
			return -1;
		}
	}

	int ret = pmemobj_checkU(upath, ulayout);

	util_free_UTF8(upath);
	util_free_UTF8(ulayout);

	return ret;
}
#endif

/*
 * pmemobj_pool_by_oid -- returns the pool handle associated with the oid
 */
PMEMobjpool *
pmemobj_pool_by_oid(PMEMoid oid)
{
	LOG(3, "oid.off 0x%016" PRIx64, oid.off);

	/* XXX this is a temporary fix, to be fixed properly later */
	if (pools_ht == NULL)
		return NULL;

	return cuckoo_get(pools_ht, oid.pool_uuid_lo);
}

/*
 * pmemobj_pool_by_ptr -- returns the pool handle associated with the address
 */
PMEMobjpool *
pmemobj_pool_by_ptr(const void *addr)
{
	LOG(3, "addr %p", addr);

	/* fast path for transactions */
	PMEMobjpool *pop = tx_get_pop();

	if ((pop != NULL) && OBJ_PTR_FROM_POOL(pop, addr))
		return pop;

	/* XXX this is a temporary fix, to be fixed properly later */
	if (pools_tree == NULL)
		return NULL;

	uint64_t key = (uint64_t)addr;
	size_t pool_size = ctree_find_le_unlocked(pools_tree, &key);

	if (pool_size == 0)
		return NULL;

	ASSERT((uint64_t)addr >= key);
	uint64_t addr_off = (uint64_t)addr - key;

	if (pool_size <= addr_off)
		return NULL;

	return cuckoo_get(pools_trans_ht, key);
}

/* arguments for constructor_alloc_bytype */
struct carg_bytype {
	type_num_t user_type;
	int zero_init;
	pmemobj_constr constructor;
	void *arg;
};

/*
 * constructor_alloc_bytype -- (internal) constructor for obj_alloc_construct
 */
static int
constructor_alloc_bytype(void *ctx, void *ptr, size_t usable_size, void *arg)
{
	PMEMobjpool *pop = ctx;
	LOG(3, "pop %p ptr %p arg %p", pop, ptr, arg);
	struct pmem_ops *p_ops = &pop->p_ops;

	ASSERTne(ptr, NULL);
	ASSERTne(arg, NULL);

	struct carg_bytype *carg = arg;

	if (carg->zero_init)
		pmemops_memset_persist(p_ops, ptr, 0, usable_size);

	int ret = 0;
	if (carg->constructor)
		ret = carg->constructor(pop, ptr, carg->arg);

	return ret;
}

/*
 * obj_alloc_construct -- (internal) allocates a new object with constructor
 */
static int
obj_alloc_construct(PMEMobjpool *pop, PMEMoid *oidp, size_t size,
	type_num_t type_num, int zero_init,
	pmemobj_constr constructor,
	void *arg)
{
	if (size > PMEMOBJ_MAX_ALLOC_SIZE) {
		ERR("requested size too large");
		errno = ENOMEM;
		return -1;
	}

	struct carg_bytype carg;

	carg.user_type = type_num;
	carg.zero_init = zero_init;
	carg.constructor = constructor;
	carg.arg = arg;

	struct redo_log *redo = pmalloc_redo_hold(pop);

	struct operation_context ctx;
	operation_init(&ctx, pop->base_addr, pop->redo, redo);

	if (oidp)
		operation_add_entry(&ctx, &oidp->pool_uuid_lo, pop->uuid_lo,
				OPERATION_SET);

	int ret = pmalloc_operation(pop, 0,
			oidp != NULL ? &oidp->off : NULL, size,
			constructor_alloc_bytype, &carg, type_num, 0, &ctx);

	pmalloc_redo_release(pop);

	return ret;
}

/*
 * pmemobj_alloc -- allocates a new object
 */
int
pmemobj_alloc(PMEMobjpool *pop, PMEMoid *oidp, size_t size,
	uint64_t type_num, pmemobj_constr constructor, void *arg)
{
	LOG(3, "pop %p oidp %p size %zu type_num %llx constructor %p arg %p",
		pop, oidp, size, (unsigned long long)type_num,
		constructor, arg);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();

	if (size == 0) {
		ERR("allocation with size 0");
		errno = EINVAL;
		return -1;
	}

	return obj_alloc_construct(pop, oidp, size, type_num,
			0, constructor, arg);
}

/* arguments for constructor_realloc and constructor_zrealloc */
struct carg_realloc {
	void *ptr;
	size_t old_size;
	size_t new_size;
	int zero_init;
	type_num_t user_type;
	pmemobj_constr constructor;
	void *arg;
};

/*
 * pmemobj_zalloc -- allocates a new zeroed object
 */
int
pmemobj_zalloc(PMEMobjpool *pop, PMEMoid *oidp, size_t size,
		uint64_t type_num)
{
	LOG(3, "pop %p oidp %p size %zu type_num %llx",
			pop, oidp, size, (unsigned long long)type_num);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();

	if (size == 0) {
		ERR("allocation with size 0");
		errno = EINVAL;
		return -1;
	}

	return obj_alloc_construct(pop, oidp, size, type_num,
					1, NULL, NULL);
}

/*
 * obj_free -- (internal) free an object
 */
static void
obj_free(PMEMobjpool *pop, PMEMoid *oidp)
{
	ASSERTne(oidp, NULL);

	struct redo_log *redo = pmalloc_redo_hold(pop);

	struct operation_context ctx;
	operation_init(&ctx, pop, pop->redo, redo);

	operation_add_entry(&ctx, &oidp->pool_uuid_lo, 0, OPERATION_SET);

	pmalloc_operation(pop, oidp->off, &oidp->off, 0, NULL, NULL,
			0, 0, &ctx);

	pmalloc_redo_release(pop);
}

/*
 * constructor_realloc -- (internal) constructor for pmemobj_realloc
 */
static int
constructor_realloc(void *ctx, void *ptr, size_t usable_size, void *arg)
{
	PMEMobjpool *pop = ctx;
	LOG(3, "pop %p ptr %p arg %p", pop, ptr, arg);
	struct pmem_ops *p_ops = &pop->p_ops;

	ASSERTne(ptr, NULL);
	ASSERTne(arg, NULL);

	struct carg_realloc *carg = arg;

	if (!carg->zero_init)
		return 0;

	if (usable_size > carg->old_size) {
		size_t grow_len = usable_size - carg->old_size;
		void *new_data_ptr = (void *)((uintptr_t)ptr + carg->old_size);

		pmemops_memset_persist(p_ops, new_data_ptr, 0, grow_len);
	}

	return 0;
}

/*
 * obj_realloc_common -- (internal) common routine for resizing
 *                          existing objects
 */
static int
obj_realloc_common(PMEMobjpool *pop,
	PMEMoid *oidp, size_t size, type_num_t type_num, int zero_init)
{
	/* if OID is NULL just allocate memory */
	if (OBJ_OID_IS_NULL(*oidp)) {
		/* if size is 0 - do nothing */
		if (size == 0)
			return 0;

		return obj_alloc_construct(pop, oidp, size, type_num,
				zero_init, NULL, NULL);
	}

	if (size > PMEMOBJ_MAX_ALLOC_SIZE) {
		ERR("requested size too large");
		errno = ENOMEM;
		return -1;
	}

	/* if size is 0 just free */
	if (size == 0) {
		obj_free(pop, oidp);
		return 0;
	}

	struct carg_realloc carg;
	carg.ptr = OBJ_OFF_TO_PTR(pop, oidp->off);
	carg.new_size = size;
	carg.old_size = pmemobj_alloc_usable_size(*oidp);
	carg.user_type = type_num;
	carg.constructor = NULL;
	carg.arg = NULL;
	carg.zero_init = zero_init;

	struct redo_log *redo = pmalloc_redo_hold(pop);

	struct operation_context ctx;
	operation_init(&ctx, pop, pop->redo, redo);

	int ret = pmalloc_operation(pop, oidp->off, &oidp->off,
			size, constructor_realloc, &carg, type_num, 0, &ctx);

	pmalloc_redo_release(pop);

	return ret;
}

/*
 * constructor_zrealloc_root -- (internal) constructor for pmemobj_root
 */
static int
constructor_zrealloc_root(void *ctx, void *ptr, size_t usable_size, void *arg)
{
	PMEMobjpool *pop = ctx;
	LOG(3, "pop %p ptr %p arg %p", pop, ptr, arg);

	ASSERTne(ptr, NULL);
	ASSERTne(arg, NULL);

	VALGRIND_ADD_TO_TX(ptr, usable_size);

	struct carg_realloc *carg = arg;

	constructor_realloc(pop, ptr, usable_size, arg);
	int ret = 0;
	if (carg->constructor)
		ret = carg->constructor(pop, ptr, carg->arg);

	VALGRIND_REMOVE_FROM_TX(ptr, usable_size);

	return ret;
}

/*
 * pmemobj_realloc -- resizes an existing object
 */
int
pmemobj_realloc(PMEMobjpool *pop, PMEMoid *oidp, size_t size,
		uint64_t type_num)
{
	ASSERTne(oidp, NULL);

	LOG(3, "pop %p oid.off 0x%016" PRIx64 " size %zu type_num %" PRIu64,
		pop, oidp->off, size, type_num);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();
	ASSERT(OBJ_OID_IS_VALID(pop, *oidp));

	return obj_realloc_common(pop, oidp, size, (type_num_t)type_num, 0);
}

/*
 * pmemobj_zrealloc -- resizes an existing object, any new space is zeroed.
 */
int
pmemobj_zrealloc(PMEMobjpool *pop, PMEMoid *oidp, size_t size,
		uint64_t type_num)
{
	ASSERTne(oidp, NULL);

	LOG(3, "pop %p oid.off 0x%016" PRIx64 " size %zu type_num %" PRIu64,
		pop, oidp->off, size, type_num);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();
	ASSERT(OBJ_OID_IS_VALID(pop, *oidp));

	return obj_realloc_common(pop, oidp, size, (type_num_t)type_num, 1);
}

/* arguments for constructor_strdup */
struct carg_strdup {
	size_t size;
	const char *s;
};

/*
 * constructor_strdup -- (internal) constructor of pmemobj_strdup
 */
static int
constructor_strdup(PMEMobjpool *pop, void *ptr, void *arg)
{
	LOG(3, "pop %p ptr %p arg %p", pop, ptr, arg);

	ASSERTne(ptr, NULL);
	ASSERTne(arg, NULL);

	struct carg_strdup *carg = arg;

	/* copy string */
	pmemops_memcpy_persist(&pop->p_ops, ptr, carg->s, carg->size);

	return 0;
}

/*
 * pmemobj_strdup -- allocates a new object with duplicate of the string s.
 */
int
pmemobj_strdup(PMEMobjpool *pop, PMEMoid *oidp, const char *s,
		uint64_t type_num)
{
	LOG(3, "pop %p oidp %p string %s type_num %" PRIu64,
	    pop, oidp, s, type_num);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();

	if (NULL == s) {
		errno = EINVAL;
		return -1;
	}

	struct carg_strdup carg;
	carg.size = (strlen(s) + 1) * sizeof(char);
	carg.s = s;

	return obj_alloc_construct(pop, oidp, carg.size,
		(type_num_t)type_num, 0, constructor_strdup, &carg);
}

/* arguments for constructor_wcsdup */
struct carg_wcsdup {
	size_t size;
	const wchar_t *s;
};

/*
 * constructor_wcsdup -- (internal) constructor of pmemobj_wcsdup
 */
static int
constructor_wcsdup(PMEMobjpool *pop, void *ptr, void *arg)
{
	LOG(3, "pop %p ptr %p arg %p", pop, ptr, arg);

	ASSERTne(ptr, NULL);
	ASSERTne(arg, NULL);

	struct carg_wcsdup *carg = arg;

	/* copy string */
	pmemops_memcpy_persist(&pop->p_ops, ptr, carg->s, carg->size);

	return 0;
}

/*
 * pmemobj_wcsdup -- allocates a new object with duplicate of the wide character
 * string s.
 */
int
pmemobj_wcsdup(PMEMobjpool *pop, PMEMoid *oidp, const wchar_t *s,
	uint64_t type_num)
{
	LOG(3, "pop %p oidp %p string %S type_num %" PRIu64,
		    pop, oidp, s, type_num);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();

	if (NULL == s) {
		errno = EINVAL;
		return -1;
	}

	struct carg_wcsdup carg;
	carg.size = (wcslen(s) + 1) * sizeof(wchar_t);
	carg.s = s;

	return obj_alloc_construct(pop, oidp, carg.size,
		(type_num_t)type_num, 0, constructor_wcsdup, &carg);
}

/*
 * pmemobj_free -- frees an existing object
 */
void
pmemobj_free(PMEMoid *oidp)
{
	ASSERTne(oidp, NULL);

	LOG(3, "oid.off 0x%016" PRIx64, oidp->off);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();

	if (oidp->off == 0)
		return;

	PMEMobjpool *pop = pmemobj_pool_by_oid(*oidp);

	ASSERTne(pop, NULL);
	ASSERT(OBJ_OID_IS_VALID(pop, *oidp));

	obj_free(pop, oidp);
}

/*
 * pmemobj_alloc_usable_size -- returns usable size of object
 */
size_t
pmemobj_alloc_usable_size(PMEMoid oid)
{
	LOG(3, "oid.off 0x%016" PRIx64, oid.off);

	if (oid.off == 0)
		return 0;

	PMEMobjpool *pop = pmemobj_pool_by_oid(oid);

	ASSERTne(pop, NULL);
	ASSERT(OBJ_OID_IS_VALID(pop, oid));

	return (palloc_usable_size(&pop->heap, oid.off));
}

/*
 * pmemobj_memcpy_persist -- pmemobj version of memcpy
 */
void *
pmemobj_memcpy_persist(PMEMobjpool *pop, void *dest, const void *src,
	size_t len)
{
	LOG(15, "pop %p dest %p src %p len %zu", pop, dest, src, len);

	return pmemops_memcpy_persist(&pop->p_ops, dest, src, len);
}

/*
 * pmemobj_memset_persist -- pmemobj version of memset
 */
void *
pmemobj_memset_persist(PMEMobjpool *pop, void *dest, int c, size_t len)
{
	LOG(15, "pop %p dest %p c 0x%02x len %zu", pop, dest, c, len);

	return pmemops_memset_persist(&pop->p_ops, dest, c, len);
}

/*
 * pmemobj_persist -- pmemobj version of pmem_persist
 */
void
pmemobj_persist(PMEMobjpool *pop, const void *addr, size_t len)
{
	LOG(15, "pop %p addr %p len %zu", pop, addr, len);

	pmemops_persist(&pop->p_ops, addr, len);
}

/*
 * pmemobj_flush -- pmemobj version of pmem_flush
 */
void
pmemobj_flush(PMEMobjpool *pop, const void *addr, size_t len)
{
	LOG(15, "pop %p addr %p len %zu", pop, addr, len);

	pmemops_flush(&pop->p_ops, addr, len);
}

/*
 * pmemobj_drain -- pmemobj version of pmem_drain
 */
void
pmemobj_drain(PMEMobjpool *pop)
{
	LOG(15, "pop %p", pop);

	pmemops_drain(&pop->p_ops);
}

/*
 * pmemobj_type_num -- returns type number of object
 */
uint64_t
pmemobj_type_num(PMEMoid oid)
{
	LOG(3, "oid.off 0x%016" PRIx64, oid.off);

	ASSERT(!OID_IS_NULL(oid));

	PMEMobjpool *pop = pmemobj_pool_by_oid(oid);

	ASSERTne(pop, NULL);
	ASSERT(OBJ_OID_IS_VALID(pop, oid));

	return (palloc_extra(&pop->heap, oid.off));
}

/* arguments for constructor_alloc_root */
struct carg_root {
	size_t size;
	pmemobj_constr constructor;
	void *arg;
};

/*
 * obj_realloc_root -- (internal) reallocate root object
 */
static int
obj_alloc_root(PMEMobjpool *pop, size_t size,
	pmemobj_constr constructor, void *arg)
{
	LOG(3, "pop %p size %zu", pop, size);

	struct carg_realloc carg;

	carg.ptr = OBJ_OFF_TO_PTR(pop, pop->pool_desc->root_offset);
	carg.old_size = pop->pool_desc->root_size;
	carg.new_size = size;
	carg.user_type = POBJ_ROOT_TYPE_NUM;
	carg.constructor = constructor;
	carg.zero_init = 1;
	carg.arg = arg;

	struct redo_log *redo = pmalloc_redo_hold(pop);

	struct operation_context ctx;
	operation_init(&ctx, pop, pop->redo, redo);

	operation_add_entry(&ctx, &pop->pool_desc->root_size, size,
	    OPERATION_SET);

	int ret = pmalloc_operation(pop, pop->pool_desc->root_offset,
			&pop->pool_desc->root_offset, size,
			constructor_zrealloc_root, &carg,
			POBJ_ROOT_TYPE_NUM, OBJ_INTERNAL_OBJECT_MASK, &ctx);

	pmalloc_redo_release(pop);

	return ret;
}

/*
 * pmemobj_root_size -- returns size of the root object
 */
size_t
pmemobj_root_size(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	if (pop->pool_desc->root_offset && pop->pool_desc->root_size) {
		return pop->pool_desc->root_size;
	} else
		return 0;
}

/*
 * pmemobj_root_construct -- returns root object
 */
PMEMoid
pmemobj_root_construct(PMEMobjpool *pop, size_t size,
	pmemobj_constr constructor, void *arg)
{
	LOG(3, "pop %p size %zu constructor %p args %p", pop, size, constructor,
		arg);

	if (size > PMEMOBJ_MAX_ALLOC_SIZE) {
		ERR("requested size too large");
		errno = ENOMEM;
		return OID_NULL;
	}

	PMEMoid root;
	pmemobj_mutex_lock_nofail(pop, &pop->pool_desc->rootlock);

	if (size > pop->pool_desc->root_size &&
		obj_alloc_root(pop, size, constructor, arg)) {
		pmemobj_mutex_unlock_nofail(pop, &pop->pool_desc->rootlock);
		LOG(2, "obj_realloc_root failed");
		return OID_NULL;
	}

	root.pool_uuid_lo = pop->uuid_lo;
	root.off = pop->pool_desc->root_offset;

	pmemobj_mutex_unlock_nofail(pop, &pop->pool_desc->rootlock);
	return root;
}

/*
 * pmemobj_root -- returns root object
 */
PMEMoid
pmemobj_root(PMEMobjpool *pop, size_t size)
{
	LOG(3, "pop %p size %zu", pop, size);

	return pmemobj_root_construct(pop, size, NULL, NULL);
}

/*
 * pmemobj_first - returns first object of specified type
 */
PMEMoid
pmemobj_first(PMEMobjpool *pop)
{
	LOG(3, "pop %p", pop);

	PMEMoid ret = {0, 0};

	uint64_t off = palloc_first(&pop->heap);
	if (off != 0) {
		ret.off = off;
		ret.pool_uuid_lo = pop->uuid_lo;

		if (palloc_flags(&pop->heap, off) & OBJ_INTERNAL_OBJECT_MASK) {
			return pmemobj_next(ret);
		}
	}

	return ret;
}

/*
 * pmemobj_next - returns next object of specified type
 */
PMEMoid
pmemobj_next(PMEMoid oid)
{
	LOG(3, "oid.off 0x%016" PRIx64, oid.off);

	if (oid.off == 0)
		return OID_NULL;

	PMEMobjpool *pop = pmemobj_pool_by_oid(oid);

	ASSERTne(pop, NULL);
	ASSERT(OBJ_OID_IS_VALID(pop, oid));

	PMEMoid ret = {0, 0};
	uint64_t off = palloc_next(&pop->heap, oid.off);
	if (off != 0) {
		ret.off = off;
		ret.pool_uuid_lo = pop->uuid_lo;

		if (palloc_flags(&pop->heap, off) & OBJ_INTERNAL_OBJECT_MASK) {
			return pmemobj_next(ret);
		}
	}

	return ret;
}

/*
 * pmemobj_list_insert -- adds object to a list
 */
int
pmemobj_list_insert(PMEMobjpool *pop, size_t pe_offset, void *head,
		    PMEMoid dest, int before, PMEMoid oid)
{
	LOG(3, "pop %p pe_offset %zu head %p dest.off 0x%016" PRIx64
	    " before %d oid.off 0x%016" PRIx64,
	    pop, pe_offset, head, dest.off, before, oid.off);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();
	ASSERT(OBJ_OID_IS_VALID(pop, oid));
	ASSERT(OBJ_OID_IS_VALID(pop, dest));

	if (pe_offset >= pop->size) {
		ERR("pe_offset (%lu) too big", pe_offset);
		errno = EINVAL;
		return -1;
	}

	return list_insert(pop, (ssize_t)pe_offset, head, dest, before, oid);
}

/*
 * pmemobj_list_insert_new -- adds new object to a list
 */
PMEMoid
pmemobj_list_insert_new(PMEMobjpool *pop, size_t pe_offset, void *head,
			PMEMoid dest, int before, size_t size,
			uint64_t type_num,
			pmemobj_constr constructor, void *arg)
{
	LOG(3, "pop %p pe_offset %zu head %p dest.off 0x%016" PRIx64
	    " before %d size %zu type_num %" PRIu64,
	    pop, pe_offset, head, dest.off, before, size, type_num);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();
	ASSERT(OBJ_OID_IS_VALID(pop, dest));

	if (size > PMEMOBJ_MAX_ALLOC_SIZE) {
		ERR("requested size too large");
		errno = ENOMEM;
		return OID_NULL;
	}

	if (pe_offset >= pop->size) {
		ERR("pe_offset (%lu) too big", pe_offset);
		errno = EINVAL;
		return OID_NULL;
	}

	struct carg_bytype carg;

	carg.user_type = (type_num_t)type_num;
	carg.constructor = constructor;
	carg.arg = arg;
	carg.zero_init = 0;

	PMEMoid retoid = OID_NULL;
	list_insert_new_user(pop,
			pe_offset, head, dest, before,
			size, constructor_alloc_bytype, &carg, &retoid);
	return retoid;
}

/*
 * pmemobj_list_remove -- removes object from a list
 */
int
pmemobj_list_remove(PMEMobjpool *pop, size_t pe_offset, void *head,
		    PMEMoid oid, int free)
{
	LOG(3, "pop %p pe_offset %zu head %p oid.off 0x%016" PRIx64 " free %d",
	    pop, pe_offset, head, oid.off, free);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();
	ASSERT(OBJ_OID_IS_VALID(pop, oid));

	if (pe_offset >= pop->size) {
		ERR("pe_offset (%lu) too big", pe_offset);
		errno = EINVAL;
		return -1;
	}

	if (free) {
		return list_remove_free_user(pop, pe_offset, head, &oid);
	} else {
		return list_remove(pop, (ssize_t)pe_offset, head, oid);
	}
}

/*
 * pmemobj_list_move -- moves object between lists
 */
int
pmemobj_list_move(PMEMobjpool *pop, size_t pe_old_offset, void *head_old,
			size_t pe_new_offset, void *head_new,
			PMEMoid dest, int before, PMEMoid oid)
{
	LOG(3, "pop %p pe_old_offset %zu pe_new_offset %zu"
	    " head_old %p head_new %p dest.off 0x%016" PRIx64
	    " before %d oid.off 0x%016" PRIx64 "",
	    pop, pe_old_offset, pe_new_offset,
	    head_old, head_new, dest.off, before, oid.off);

	/* log notice message if used inside a transaction */
	_POBJ_DEBUG_NOTICE_IN_TX();

	ASSERT(OBJ_OID_IS_VALID(pop, oid));
	ASSERT(OBJ_OID_IS_VALID(pop, dest));

	if (pe_old_offset >= pop->size) {
		ERR("pe_old_offset (%lu) too big", pe_old_offset);
		errno = EINVAL;
		return -1;
	}

	if (pe_new_offset >= pop->size) {
		ERR("pe_new_offset (%lu) too big", pe_new_offset);
		errno = EINVAL;
		return -1;
	}

	return list_move(pop, pe_old_offset, head_old,
				pe_new_offset, head_new,
				dest, before, oid);
}

/*
 * _pobj_debug_notice -- logs notice message if used inside a transaction
 */
void
_pobj_debug_notice(const char *api_name, const char *file, int line)
{
#ifdef DEBUG
	if (pmemobj_tx_stage() != TX_STAGE_NONE) {
		if (file)
			LOG(4, "Notice: non-transactional API"
				" used inside a transaction (%s in %s:%d)",
				api_name, file, line);
		else
			LOG(4, "Notice: non-transactional API"
				" used inside a transaction (%s)", api_name);
	}
#endif /* DEBUG */
}

#ifdef _MSC_VER
/*
 * libpmemobj constructor/destructor functions
 */
MSVC_CONSTR(libpmemobj_init)
MSVC_DESTR(libpmemobj_fini)
#endif
