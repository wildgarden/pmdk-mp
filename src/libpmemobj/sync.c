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
 * sync.c -- persistent memory resident synchronization primitives
 */

#include <inttypes.h>

#include "obj.h"
#include "out.h"
#include "util.h"
#include "sync.h"
#include "sys_util.h"
#include "valgrind_internal.h"

#define GET_MUTEX(pop, mutexp)\
get_lock((pop)->pool_desc->run_id,\
	&(mutexp)->pmemmutex.runid,\
	&(mutexp)->pmemmutex.mutex,\
	(void *)os_mutex_init,\
	sizeof((mutexp)->pmemmutex.mutex))

#define GET_RWLOCK(pop, rwlockp)\
get_lock((pop)->pool_desc->run_id,\
	&(rwlockp)->pmemrwlock.runid,\
	&(rwlockp)->pmemrwlock.rwlock,\
	(void *)os_rwlock_init,\
	sizeof((rwlockp)->pmemrwlock.rwlock))

#if 0
/*
 * XXX not yet implemented
 * see pthread_rwlockattr_getpshared for details
 */
#define GET_RWLOCK(pop, rwlockp)\
get_lock((pop)->pool_desc->run_id,\
	&(rwlockp)->pmemrwlock.runid,\
	&(rwlockp)->pmemrwlock.rwlock,\
	(void *)os_rwlock_init_mp,\
	sizeof((rwlockp)->pmemrwlock.rwlock))
#endif

#define GET_COND(pop, condp)\
get_lock((pop)->pool_desc->run_id,\
	&(condp)->pmemcond.runid,\
	&(condp)->pmemcond.cond,\
	(void *)os_cond_init,\
	sizeof((condp)->pmemcond.cond))

#define GET_SHARED_MUTEX(pop, mutexp)\
get_lock((pop)->pool_desc->run_id,\
	&(mutexp)->pmemmutex.runid,\
	&(mutexp)->pmemmutex.mutex,\
	(void *)os_mutex_init_mp,\
	sizeof((mutexp)->pmemmutex.mutex))

#define GET_SHARED_COND(pop, condp)\
get_lock((pop)->pool_desc->run_id,\
	&(condp)->pmemcond.runid,\
	&(condp)->pmemcond.cond,\
	(void *)os_cond_init_mp,\
	sizeof((condp)->pmemcond.cond))

/*
 * _get_lock -- (internal) atomically initialize and return a lock
 */
static void *
_get_lock(uint64_t pop_runid, volatile uint64_t *runid, void *lock,
	int (*init_lock)(void *lock, void *arg), size_t size)
{
	LOG(15, "pop_runid %" PRIu64 " runid %" PRIu64 " lock %p init_lock %p",
		pop_runid, *runid, lock, init_lock);

	ASSERTeq((uintptr_t)runid % util_alignof(uint64_t), 0);

	COMPILE_ERROR_ON(sizeof(PMEMmutex)
		!= sizeof(PMEMmutex_internal));
	COMPILE_ERROR_ON(sizeof(PMEMrwlock)
		!= sizeof(PMEMrwlock_internal));
	COMPILE_ERROR_ON(sizeof(PMEMcond)
		!= sizeof(PMEMcond_internal));

	COMPILE_ERROR_ON(util_alignof(PMEMmutex)
		!= util_alignof(os_mutex_t));
	COMPILE_ERROR_ON(util_alignof(PMEMrwlock)
		!= util_alignof(os_rwlock_t));
	COMPILE_ERROR_ON(util_alignof(PMEMcond)
		!= util_alignof(os_cond_t));

	uint64_t tmp_runid;

	VALGRIND_REMOVE_PMEM_MAPPING(runid, sizeof(*runid));
	VALGRIND_REMOVE_PMEM_MAPPING(lock, size);

	for (unsigned cnt = 0; (tmp_runid = *runid) != pop_runid; cnt++) {

		/*
		 * Avoid spinning forever if there is a protocol error
		 *
		 * Inpired by sqlite 3 (wal.c::walTryBeginRead()):
		 * "[...]Take steps to avoid spinning forever if there is a
		 * protocol error.
		 *
		 * Circumstances that cause a RETRY should only last for the
		 * briefest instances of time. No I/O or other system calls
		 * are done while the locks are held, so the locks should not
		 * be held for very long. But if we are unlucky, another
		 * process that is holding a lock might get paged out or take
		 * a page-fault that is time-consuming to resolve, during the
		 * few nanoseconds that it is holding the lock.  In that
		 * case, it might take longer than normal for the lock to
		 * free. After 5 RETRYs, we begin calling sqlite3OsSleep().
		 * The first few calls to sqlite3OsSleep() have a delay of 1
		 * microsecond.  Really this is more of a scheduler yield
		 * than an actual delay. But on the 10th an subsequent
		 * retries, the delays start becoming longer and longer, so
		 * that on the 100th (and last) RETRY we delay for 323
		 * milliseconds. The total delay time before giving up is
		 * less than 10 seconds.[...]"
		 */
		if (cnt > 5) {
			unsigned nDelay = 1; /* Pause time in microseconds */
			if (cnt > 100)
				return NULL;

			if (cnt >= 10)
				nDelay = (cnt - 9) * (cnt - 9) * 39;

			usleep(nDelay);
		}

		if (tmp_runid == pop_runid - 1)
			continue;

		if (!util_bool_compare_and_swap64(runid, tmp_runid,
						    pop_runid - 1))
			continue;

		if (init_lock(lock, NULL)) {
			ERR("error initializing lock");
			__sync_fetch_and_and(runid, 0);
			return NULL;
		}

		if (util_bool_compare_and_swap64(runid, pop_runid - 1,
		    pop_runid) == 0) {
			ERR("error setting lock runid");
			return NULL;
		}
	}

	return lock;
}

/*
 * get_lock -- (internal) atomically initialize and return a lock
 */
static inline void *
get_lock(uint64_t pop_runid, volatile uint64_t *runid, void *lock,
	int (*init_lock)(void *lock, void *arg), size_t size)
{
	if (likely(*runid == pop_runid))
		return lock;

	return _get_lock(pop_runid, runid, lock, init_lock, size);
}

/*
 * pmemobj_mutex_zero -- zero-initialize a pmem resident mutex
 *
 * This function is not MT safe.
 */
void
pmemobj_mutex_zero(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));

	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;
	mutexip->pmemmutex.runid = 0;
	pmemops_persist(&pop->p_ops, &mutexip->pmemmutex.runid,
				sizeof(mutexip->pmemmutex.runid));
}

/*
 * pmemobj_mutex_lock_internal -- lock a pmem resident mutex
 */
static int
pmemobj_mutex_lock_internal(PMEMobjpool *pop, PMEMmutex *mutexp, int shared)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));

	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;
	os_mutex_t *mutex = shared
			    ? GET_SHARED_MUTEX(pop, mutexip)
			    : GET_MUTEX(pop, mutexip);

	if (mutex == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)mutex % util_alignof(os_mutex_t), 0);

	return os_mutex_lock(mutex);
}

/*
 * pmemobj_mutex_lock -- lock a pmem resident mutex
 *
 * Atomically initializes and locks a PMEMmutex, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_mutex_lock(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	return pmemobj_mutex_lock_internal(pop, mutexp, 0);
}

/*
 * pmemobj_mutex_lock_mp -- lock a pmem resident mutex used in multi-processing
 *
 * Atomically initializes and locks a PMEMmutex, otherwise behaves as its
 * robust shared POSIX counterpart.
 */
int
pmemobj_mutex_lock_mp(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	return pmemobj_mutex_lock_internal(pop, mutexp, 1);
}

/*
 * pmemobj_mutex_assert_locked -- checks whether mutex is locked.
 *
 * Returns 0 when mutex is locked.
 */
int
pmemobj_mutex_assert_locked(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));

	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;
	os_mutex_t *mutex = GET_MUTEX(pop, mutexip);
	if (mutex == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)mutex % util_alignof(os_mutex_t), 0);

	int ret = os_mutex_trylock(mutex);
	if (ret == EBUSY)
		return 0;
	if (ret == 0) {
		util_mutex_unlock(mutex);
		/*
		 * There's no good error code for this case. EINVAL is used for
		 * something else here.
		 */
		return ENODEV;
	}
	return ret;
}

/*
 * pmemobj_mutex_timedlock_internal -- lock a pmem resident mutex
 */
static int
pmemobj_mutex_timedlock_internal(PMEMobjpool *pop, PMEMmutex *__restrict mutexp,
		const struct timespec *__restrict abs_timeout, int shared)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));

	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;
	os_mutex_t *mutex = shared
			    ? GET_SHARED_MUTEX(pop, mutexip)
			    : GET_MUTEX(pop, mutexip);
	if (mutex == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)mutex % util_alignof(os_mutex_t), 0);

	return os_mutex_timedlock(mutex, abs_timeout);
}

/*
 * pmemobj_mutex_timedlock -- lock a pmem resident mutex
 *
 * Atomically initializes and locks a PMEMmutex, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_mutex_timedlock(PMEMobjpool *pop, PMEMmutex *__restrict mutexp,
	const struct timespec *__restrict abs_timeout)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	return pmemobj_mutex_timedlock_internal(pop, mutexp, abs_timeout, 0);
}

/*
 * pmemobj_mutex_timedlock -- lock a pmem resident mutex
 *
 * Atomically initializes and locks a PMEMmutex, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_mutex_timedlock_mp(PMEMobjpool *pop, PMEMmutex *__restrict mutexp,
	const struct timespec *__restrict abs_timeout)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);
	return pmemobj_mutex_timedlock_internal(pop, mutexp, abs_timeout, 1);
}

/*
 * pmemobj_mutex_trylock -- trylock a pmem resident mutex
 *
 * Atomically initializes and trylocks a PMEMmutex, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_mutex_trylock(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));

	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;
	os_mutex_t *mutex = GET_MUTEX(pop, mutexip);
	if (mutex == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)mutex % util_alignof(os_mutex_t), 0);

	return os_mutex_trylock(mutex);
}

/*
 * pmemobj_mutex_unlock_internal -- unlock a pmem resident mutex
 */
static int
pmemobj_mutex_unlock_internal(PMEMobjpool *pop, PMEMmutex *mutexp, int shared)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));

	/* XXX potential performance improvement - move GET to debug version */
	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;
	os_mutex_t *mutex = shared
			    ? GET_SHARED_MUTEX(pop, mutexip)
			    : GET_MUTEX(pop, mutexip);

	if (mutex == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)mutex % util_alignof(os_mutex_t), 0);

	return os_mutex_unlock(mutex);
}

/*
 * pmemobj_mutex_unlock -- unlock a pmem resident mutex
 */
int
pmemobj_mutex_unlock(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	return pmemobj_mutex_unlock_internal(pop, mutexp, 0);
}

/*
 * pmemobj_mutex_unlock -- unlock a pmem resident shared robust mutex
 */
int
pmemobj_mutex_unlock_mp(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	return pmemobj_mutex_unlock_internal(pop, mutexp, 1);
}

/*
 * pmemobj_mutex_consistent -- mark state protected by robust mutex as
 * consistent
 */
int
pmemobj_mutex_consistent(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	LOG(3, "pop %p mutex %p", pop, mutexp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));

	/* XXX potential performance improvement - move GET to debug version */
	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;

	if (pop->pool_desc->run_id != mutexip->pmemmutex.runid) {
		LOG(1, "wrong run id");
		return EINVAL;
	}

	return os_mutex_consistent(&mutexip->pmemmutex.mutex);
}

/*
 * pmemobj_rwlock_zero -- zero-initialize a pmem resident rwlock
 *
 * This function is not MT safe.
 */
void
pmemobj_rwlock_zero(PMEMobjpool *pop, PMEMrwlock *rwlockp)
{
	LOG(3, "pop %p rwlock %p", pop, rwlockp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(rwlockp));

	PMEMrwlock_internal *rwlockip = (PMEMrwlock_internal *)rwlockp;
	rwlockip->pmemrwlock.runid = 0;
	pmemops_persist(&pop->p_ops, &rwlockip->pmemrwlock.runid,
				sizeof(rwlockip->pmemrwlock.runid));
}

/*
 * pmemobj_rwlock_rdlock -- rdlock a pmem resident mutex
 *
 * Atomically initializes and rdlocks a PMEMrwlock, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_rwlock_rdlock(PMEMobjpool *pop, PMEMrwlock *rwlockp)
{
	LOG(3, "pop %p rwlock %p", pop, rwlockp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(rwlockp));

	PMEMrwlock_internal *rwlockip = (PMEMrwlock_internal *)rwlockp;
	os_rwlock_t *rwlock = GET_RWLOCK(pop, rwlockip);
	if (rwlock == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)rwlock % util_alignof(os_rwlock_t), 0);

	return os_rwlock_rdlock(rwlock);
}

/*
 * pmemobj_rwlock_wrlock -- wrlock a pmem resident mutex
 *
 * Atomically initializes and wrlocks a PMEMrwlock, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_rwlock_wrlock(PMEMobjpool *pop, PMEMrwlock *rwlockp)
{
	LOG(3, "pop %p rwlock %p", pop, rwlockp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(rwlockp));

	PMEMrwlock_internal *rwlockip = (PMEMrwlock_internal *)rwlockp;
	os_rwlock_t *rwlock = GET_RWLOCK(pop, rwlockip);
	if (rwlock == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)rwlock % util_alignof(os_rwlock_t), 0);

	return os_rwlock_wrlock(rwlock);
}

/*
 * pmemobj_rwlock_timedrdlock -- timedrdlock a pmem resident mutex
 *
 * Atomically initializes and timedrdlocks a PMEMrwlock, otherwise behaves as
 * its POSIX counterpart.
 */
int
pmemobj_rwlock_timedrdlock(PMEMobjpool *pop, PMEMrwlock *__restrict rwlockp,
			const struct timespec *__restrict abs_timeout)
{
	LOG(3, "pop %p rwlock %p timeout sec %ld nsec %ld", pop, rwlockp,
		abs_timeout->tv_sec, abs_timeout->tv_nsec);

	ASSERTeq(pop, pmemobj_pool_by_ptr(rwlockp));

	PMEMrwlock_internal *rwlockip = (PMEMrwlock_internal *)rwlockp;
	os_rwlock_t *rwlock = GET_RWLOCK(pop, rwlockip);
	if (rwlock == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)rwlock % util_alignof(os_rwlock_t), 0);

	return os_rwlock_timedrdlock(rwlock, abs_timeout);
}

/*
 * pmemobj_rwlock_timedwrlock -- timedwrlock a pmem resident mutex
 *
 * Atomically initializes and timedwrlocks a PMEMrwlock, otherwise behaves as
 * its POSIX counterpart.
 */
int
pmemobj_rwlock_timedwrlock(PMEMobjpool *pop, PMEMrwlock *__restrict rwlockp,
			const struct timespec *__restrict abs_timeout)
{
	LOG(3, "pop %p rwlock %p timeout sec %ld nsec %ld", pop, rwlockp,
		abs_timeout->tv_sec, abs_timeout->tv_nsec);

	ASSERTeq(pop, pmemobj_pool_by_ptr(rwlockp));

	PMEMrwlock_internal *rwlockip = (PMEMrwlock_internal *)rwlockp;
	os_rwlock_t *rwlock = GET_RWLOCK(pop, rwlockip);
	if (rwlock == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)rwlock % util_alignof(os_rwlock_t), 0);

	return os_rwlock_timedwrlock(rwlock, abs_timeout);
}

/*
 * pmemobj_rwlock_tryrdlock -- tryrdlock a pmem resident mutex
 *
 * Atomically initializes and tryrdlocks a PMEMrwlock, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_rwlock_tryrdlock(PMEMobjpool *pop, PMEMrwlock *rwlockp)
{
	LOG(3, "pop %p rwlock %p", pop, rwlockp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(rwlockp));

	PMEMrwlock_internal *rwlockip = (PMEMrwlock_internal *)rwlockp;
	os_rwlock_t *rwlock = GET_RWLOCK(pop, rwlockip);
	if (rwlock == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)rwlock % util_alignof(os_rwlock_t), 0);

	return os_rwlock_tryrdlock(rwlock);
}

/*
 * pmemobj_rwlock_trywrlock -- trywrlock a pmem resident mutex
 *
 * Atomically initializes and trywrlocks a PMEMrwlock, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_rwlock_trywrlock(PMEMobjpool *pop, PMEMrwlock *rwlockp)
{
	LOG(3, "pop %p rwlock %p", pop, rwlockp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(rwlockp));

	PMEMrwlock_internal *rwlockip = (PMEMrwlock_internal *)rwlockp;
	os_rwlock_t *rwlock = GET_RWLOCK(pop, rwlockip);
	if (rwlock == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)rwlock % util_alignof(os_rwlock_t), 0);

	return os_rwlock_trywrlock(rwlock);
}

/*
 * pmemobj_rwlock_unlock -- unlock a pmem resident rwlock
 */
int
pmemobj_rwlock_unlock(PMEMobjpool *pop, PMEMrwlock *rwlockp)
{
	LOG(3, "pop %p rwlock %p", pop, rwlockp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(rwlockp));

	/* XXX potential performance improvement - move GET to debug version */
	PMEMrwlock_internal *rwlockip = (PMEMrwlock_internal *)rwlockp;
	os_rwlock_t *rwlock = GET_RWLOCK(pop, rwlockip);
	if (rwlock == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)rwlock % util_alignof(os_rwlock_t), 0);

	return os_rwlock_unlock(rwlock);
}

/*
 * pmemobj_cond_zero -- zero-initialize a pmem resident condition variable
 *
 * This function is not MT safe.
 */
void
pmemobj_cond_zero(PMEMobjpool *pop, PMEMcond *condp)
{
	LOG(3, "pop %p cond %p", pop, condp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(condp));

	PMEMcond_internal *condip = (PMEMcond_internal *)condp;
	condip->pmemcond.runid = 0;
	pmemops_persist(&pop->p_ops, &condip->pmemcond.runid,
			sizeof(condip->pmemcond.runid));
}

/*
 * pmemobj_cond_broadcast -- broadcast a pmem resident condition variable
 */
static int
pmemobj_cond_broadcast_internal(PMEMobjpool *pop, PMEMcond *condp, int shared)
{
	LOG(3, "pop %p cond %p", pop, condp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(condp));

	PMEMcond_internal *condip = (PMEMcond_internal *)condp;
	os_cond_t *cond = shared
			    ? GET_SHARED_COND(pop, condip)
			    : GET_COND(pop, condip);
	if (cond == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)cond % util_alignof(os_cond_t), 0);

	return os_cond_broadcast(cond);
}

/*
 * pmemobj_cond_broadcast -- broadcast a pmem resident condition variable
 *
 * Atomically initializes and broadcast a PMEMcond, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_cond_broadcast(PMEMobjpool *pop, PMEMcond *condp)
{
	return pmemobj_cond_broadcast_internal(pop, condp, 0);
}

/*
 * pmemobj_cond_broadcast -- broadcast a pmem resident shared condition variable
 *
 * Atomically initializes and broadcast a PMEMcond, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_cond_broadcast_mp(PMEMobjpool *pop, PMEMcond *condp)
{
	return pmemobj_cond_broadcast_internal(pop, condp, 1);
}

/*
 * pmemobj_cond_signal_internal -- signal a pmem resident condition variable
 */
static int
pmemobj_cond_signal_internal(PMEMobjpool *pop, PMEMcond *condp, int shared)
{
	LOG(3, "pop %p cond %p", pop, condp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(condp));

	PMEMcond_internal *condip = (PMEMcond_internal *)condp;
	os_cond_t *cond = shared
		? GET_SHARED_COND(pop, condip)
		: GET_COND(pop, condip);
	if (cond == NULL)
		return EINVAL;

	ASSERTeq((uintptr_t)cond % util_alignof(os_cond_t), 0);

	return os_cond_signal(cond);
}

/*
 * pmemobj_cond_signal -- signal a pmem resident condition variable
 *
 * Atomically initializes and signal a PMEMcond, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_cond_signal(PMEMobjpool *pop, PMEMcond *condp)
{
	return pmemobj_cond_signal_internal(pop, condp, 0);
}

/*
 * pmemobj_cond_signal -- signal a pmem resident shared condition variable
 *
 * Atomically initializes and signal a PMEMcond, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_cond_signal_mp(PMEMobjpool *pop, PMEMcond *condp)
{
	return pmemobj_cond_signal_internal(pop, condp, 1);
}

/*
 * pmemobj_cond_timedwait -- timedwait on a pmem resident condition variable
 */
static int
pmemobj_cond_timedwait_internal(PMEMobjpool *pop, PMEMcond *__restrict condp,
	PMEMmutex *__restrict mutexp,
	const struct timespec *__restrict abs_timeout, int shared)
{
	LOG(3, "pop %p cond %p mutex %p abstime sec %ld nsec %ld", pop, condp,
		mutexp, abs_timeout->tv_sec, abs_timeout->tv_nsec);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));
	ASSERTeq(pop, pmemobj_pool_by_ptr(condp));

	PMEMcond_internal *condip = (PMEMcond_internal *)condp;
	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;
	os_cond_t *cond = shared
			    ? GET_SHARED_COND(pop, condip)
			    : GET_COND(pop, condip);

	os_mutex_t *mutex = shared
			    ? GET_SHARED_MUTEX(pop, mutexip)
			    : GET_MUTEX(pop, mutexip);

	if ((cond == NULL) || (mutex == NULL))
		return EINVAL;

	ASSERTeq((uintptr_t)mutex % util_alignof(os_mutex_t), 0);
	ASSERTeq((uintptr_t)cond % util_alignof(os_cond_t), 0);

	return os_cond_timedwait(cond, mutex, abs_timeout);
}

/*
 * pmemobj_cond_timedwait -- timedwait on a pmem resident condition variable
 *
 * Atomically initializes and timedwait on a PMEMcond, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_cond_timedwait(PMEMobjpool *pop, PMEMcond *__restrict condp,
	PMEMmutex *__restrict mutexp,
	const struct timespec *__restrict abs_timeout)
{
	LOG(3, "pop %p cond %p mutex %p abstime sec %ld nsec %ld", pop, condp,
		mutexp, abs_timeout->tv_sec, abs_timeout->tv_nsec);
	return pmemobj_cond_timedwait_internal(pop, condp, mutexp,
		abs_timeout, 0);
}

/*
 * pmemobj_cond_timedwait_mp -- timedwait on a pmem resident shared condition
 * variable
 *
 * Atomically initializes and timedwait on a shared PMEMcond, otherwise behaves
 * as its POSIX counterpart.
 */
int
pmemobj_cond_timedwait_mp(PMEMobjpool *pop, PMEMcond *__restrict condp,
	PMEMmutex *__restrict mutexp,
	const struct timespec *__restrict abs_timeout)
{
	LOG(3, "pop %p cond %p mutex %p abstime sec %ld nsec %ld", pop, condp,
		mutexp, abs_timeout->tv_sec, abs_timeout->tv_nsec);
	return pmemobj_cond_timedwait_internal(pop, condp, mutexp,
		abs_timeout, 1);
}

/*
 * pmemobj_cond_wait_internal -- wait on a pmem resident condition variable
 */
static int
pmemobj_cond_wait_internal(PMEMobjpool *pop, PMEMcond *condp,
	PMEMmutex *__restrict mutexp, int shared)
{
	LOG(3, "pop %p cond %p mutex %p", pop, condp, mutexp);

	ASSERTeq(pop, pmemobj_pool_by_ptr(mutexp));
	ASSERTeq(pop, pmemobj_pool_by_ptr(condp));

	PMEMcond_internal *condip = (PMEMcond_internal *)condp;
	PMEMmutex_internal *mutexip = (PMEMmutex_internal *)mutexp;
	os_cond_t *cond = shared
			    ? GET_SHARED_COND(pop, condip)
			    : GET_COND(pop, condip);

	os_mutex_t *mutex = shared
			    ? GET_SHARED_MUTEX(pop, mutexip)
			    : GET_MUTEX(pop, mutexip);

	if ((cond == NULL) || (mutex == NULL))
		return EINVAL;

	ASSERTeq((uintptr_t)mutex % util_alignof(os_mutex_t), 0);
	ASSERTeq((uintptr_t)cond % util_alignof(os_cond_t), 0);

	return os_cond_wait(cond, mutex);
}

/*
 * pmemobj_cond_wait -- wait on a pmem resident condition variable
 *
 * Atomically initializes and wait on a PMEMcond, otherwise behaves as its
 * POSIX counterpart.
 */
int
pmemobj_cond_wait(PMEMobjpool *pop, PMEMcond *condp,
	PMEMmutex *__restrict mutexp)
{
	LOG(3, "pop %p cond %p mutex %p", pop, condp, mutexp);

	return pmemobj_cond_wait_internal(pop, condp, mutexp, 0);
}

/*
 * pmemobj_cond_wait -- wait on a pmem resident shared condition variable
 *
 * Atomically initializes and wait on a shared PMEMcond, otherwise behaves as
 * its POSIX counterpart.
 */
int
pmemobj_cond_wait_mp(PMEMobjpool *pop, PMEMcond *condp,
	PMEMmutex *__restrict mutexp)
{
	LOG(3, "pop %p cond %p mutex %p", pop, condp, mutexp);

	return pmemobj_cond_wait_internal(pop, condp, mutexp, 1);
}
