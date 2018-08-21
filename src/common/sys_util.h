/*
 * Copyright 2016-2017, Intel Corporation
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
 * sys_util.h -- internal utility wrappers around system functions
 */

#ifndef NVML_SYS_UTIL_H
#define NVML_SYS_UTIL_H 1

#include <errno.h>
#include <fcntl.h>

#include "os_thread.h"

/*
 * macros for file locking
 * copied from APUE
 */
static inline int
util_lock_reg(int, int, short int, off_t, short int, off_t);
#define util_read_lock(fd, offset, whence, len) \
util_lock_reg((fd), F_SETLK, F_RDLCK, (offset), (whence), (len))

#define util_readw_lock(fd, offset, whence, len) \
util_lock_reg((fd), F_SETLKW, F_RDLCK, (offset), (whence), (len))

#define util_write_lock(fd, offset, whence, len) \
util_lock_reg((fd), F_SETLK, F_WRLCK, (offset), (whence), (len))

#define util_writew_lock(fd, offset, whence, len) \
util_lock_reg((fd), F_SETLKW, F_WRLCK, (offset), (whence), (len))

#define util_un_lock(fd, offset, whence, len) \
util_lock_reg((fd), F_SETLK, F_UNLCK, (offset), (whence), (len))

static inline pid_t
util_lock_test(int, short int, off_t, short int, off_t);

#define util_is_read_lockable(fd, offset, whence, len) \
(util_lock_test((fd), F_RDLCK, (offset), (whence), (len)) == 0)

#define util_is_write_lockable(fd, offset, whence, len) \
(util_lock_test((fd), F_WRLCK, (offset), (whence), (len)) == 0)


/*
 * util_log_reg -- wrapper for convenient use of fcntl syscall file locking
 * Textbook implementation taken from APUE
 */
static inline int
util_lock_reg(int fd, int cmd, short int type, off_t offset, short int whence,
    off_t len)
{
	/* read locks span never more than one byte */
	ASSERT(len == 1 || type == F_WRLCK || type == F_UNLCK);

	struct flock lock;
	lock.l_type = type; /* F_RDLCK, F_WRLCK, F_UNLCK */
	lock.l_start = offset; /* byte offset, relative to l_whence */
	lock.l_whence = whence; /* SEEK_SET, SEEK_CUR, SEEK_END */
	lock.l_len = len; /* #bytes (0 means to EOF) */

	int ret;
	while ((ret = fcntl(fd, cmd, &lock)) < 0 && errno == EINTR);

	return ret;
}

/*
 * util_log_test -- wrapper for convenient use of fcntl syscall to determine
 * if a lock is set on the given byte.
 *
 * Textbook implementation taken from APUE
 *
 * Please note:
 * Returns information about conflicting locks, e.g. if the same process is
 * the single holder of a read lock and we could upgrade that lock to a write
 * lock, then it returns F_UNLCK instead of F_RLCK.
 *
 * Quote from man 2 fcntl;
 * "[...]If the lock could be placed, fcntl() does not actually place it, but
 * returns F_UNLCK in the l_type field of lock and leaves the other fields of
 * the structure unchanged.[...]"
 */
static inline pid_t
util_lock_test(int fd, short int type, off_t offset, short int whence,
    off_t len)
{
	/* read locks span never more than one byte */
	ASSERT(len == 1 || type == F_WRLCK);

	struct flock lock;
	lock.l_type = type;	/* F_RDLCK or F_WRLCK */
	lock.l_start = offset;	/* byte offset, relative to l_whence */
	lock.l_whence = whence;	/* SEEK_SET, SEEK_CUR, SEEK_END */
	lock.l_len = len;	/* #bytes (0 means to EOF) */

	int ret;
	while ((ret = fcntl(fd, F_GETLK, &lock)) < 0 && errno == EINTR);

	if (ret < 0)
		FATAL("fcntl error");
	if (lock.l_type == F_UNLCK)
		return 0;
	/* false, region isn’t locked by another proc */
	return lock.l_pid; /* true, return pid of lock owner */
}

/*
 * util_mutex_init -- os_mutex_init variant that never fails from
 * caller perspective. If os_mutex_init failed, this function aborts
 * the program.
 */
static inline void
util_mutex_init(os_mutex_t *m)
{
	int tmp = os_mutex_init(m);
	if (tmp) {
		errno = tmp;
		FATAL("!os_mutex_init");
	}
}

static inline void
util_mutex_init_with_attr(os_mutex_t *m, os_mutexattr_t *attr)
{
	int tmp = os_mutex_init_with_attr(m, attr);
	if (tmp) {
		errno = tmp;
		FATAL("!util_mutex_init_with_attr");
	}
}

/*
 * util_cond_init_mp -- os_cond_init shared variant
 * that never fails from caller perspective. If os_cond_init failed,
 * this function aborts the program.
 */
static inline void
util_cond_init_mp(os_cond_t *cond)
{
	int err;
	os_condattr_t attr;
	err = os_condattr_init(&attr);
	if (err != 0) {
		errno = err;
		FATAL("!os_condattr_init");
	}
	err = os_condattr_setpshared(&attr);
	if (err != 0) {
		errno = err;
		FATAL("!os_condattr_setpshared");
	}
	err = os_cond_init_with_attr(cond, &attr);
	if (err) {
		errno = err;
		FATAL("!util_mutex_init_with_attr");
	}

	/*
	 * Immediately destroy the attribute after condition initialization.
	 *
	 * Reasoning from man phtread_condattr_destroy:
	 * "After a condition variable attributes object has been used to
	 * initialize one or more condition variables, any function affecting
	 * the  attributes  object  (including  destruction) shall not affect
	 * any previously initialized condition variables."
	 */
	err = os_condattr_destroy(&attr);
	if (err) {
		errno = err;
		FATAL("!util_mutex_init_with_attr");
	}
}

/*
 * util_mutex_init_mp -- robust and shared os_mutex_init variant
 * that never fails from caller perspective. If os_mutex_init failed,
 * this function aborts the program.
 */
static inline void
util_mutex_init_mp(os_mutex_t *m)
{
	int err;
	os_mutexattr_t attr;
	err = os_mutexattr_init(&attr);
	if (err != 0) {
		errno = err;
		FATAL("!os_mutexattr_init error \"%i\"", err);
	}

	err = os_mutexattr_setpshared(&attr);
	if (err != 0) {
		errno = err;
		FATAL("!os_mutexattr_setpshared error \"%i\"", err);
	}

	err = os_mutexattr_setrobust(&attr);
	if (err != 0) {
		errno = err;
		FATAL("!os_mutexattr_setrobust error \"%i\"", err);
	}

	err = os_mutex_init_with_attr(m, &attr);
	if (err) {
		errno = err;
		FATAL("!util_mutex_init_with_attr");
	}

	err = os_mutexattr_destroy(&attr);
	if (err) {
		errno = err;
		FATAL("!util_mutex_init_with_attr");
	}
}

/*
 * util_mutex_destroy -- os_mutex_destroy variant that never fails from
 * caller perspective. If os_mutex_destroy failed, this function aborts
 * the program.
 */
static inline void
util_mutex_destroy(os_mutex_t *m)
{
	int tmp = os_mutex_destroy(m);
	if (tmp) {
		errno = tmp;
		FATAL("!os_mutex_destroy");
	}
}

/*
 * util_mutex_lock -- os_mutex_lock variant that never fails from
 * caller perspective. If os_mutex_lock failed, this function aborts
 * the program.
 */
static inline void
util_mutex_lock(os_mutex_t *m)
{
	int tmp = os_mutex_lock(m);
	if (tmp) {
		errno = tmp;
		FATAL("!os_mutex_lock");
	}
}

/*
 * util_mutex_unlock -- os_mutex_unlock variant that never fails from
 * caller perspective. If os_mutex_unlock failed, this function aborts
 * the program.
 */
static inline void
util_mutex_unlock(os_mutex_t *m)
{
	int tmp = os_mutex_unlock(m);
	if (tmp) {
		errno = tmp;
		FATAL("!os_mutex_unlock");
	}
}

/*
 * util_rwlock_rdlock -- os_rwlock_rdlock variant that never fails from
 * caller perspective. If os_rwlock_rdlock failed, this function aborts
 * the program.
 */
static inline void
util_rwlock_rdlock(os_rwlock_t *m)
{
	int tmp = os_rwlock_rdlock(m);
	if (tmp) {
		errno = tmp;
		FATAL("!os_rwlock_rdlock");
	}
}

/*
 * util_rwlock_wrlock -- os_rwlock_wrlock variant that never fails from
 * caller perspective. If os_rwlock_wrlock failed, this function aborts
 * the program.
 */
static inline void
util_rwlock_wrlock(os_rwlock_t *m)
{
	int tmp = os_rwlock_wrlock(m);
	if (tmp) {
		errno = tmp;
		FATAL("!os_rwlock_wrlock");
	}
}


/*
 * util_rwlock_unlock -- os_rwlock_unlock variant that never fails from
 * caller perspective. If os_rwlock_unlock failed, this function aborts
 * the program.
 */
static inline void
util_rwlock_unlock(os_rwlock_t *m)
{
	int tmp = os_rwlock_unlock(m);
	if (tmp) {
		errno = tmp;
		FATAL("!os_rwlock_unlock");
	}
}

/*
 * util_rwlock_destroy -- os_rwlock_t variant that never fails from
 * caller perspective. If os_rwlock_t failed, this function aborts
 * the program.
 */
static inline void
util_rwlock_destroy(os_rwlock_t *m)
{
	int tmp = os_rwlock_destroy(m);
	if (tmp) {
		errno = tmp;
		FATAL("!os_rwlock_t");
	}
}

/*
 * util_spin_init -- os_spin_init variant that logs on fail and sets errno.
 */
static inline int
util_spin_init(os_spinlock_t *lock, int pshared)
{
	int tmp = os_spin_init(lock, pshared);
	if (tmp) {
		errno = tmp;
		ERR("!os_spin_init");
	}
	return tmp;
}

/*
 * util_spin_destroy -- os_spin_destroy variant that never fails from
 * caller perspective. If os_spin_destroy failed, this function aborts
 * the program.
 */
static inline void
util_spin_destroy(os_spinlock_t *lock)
{
	int tmp = os_spin_destroy(lock);
	if (tmp) {
		errno = tmp;
		FATAL("!os_spin_destroy");
	}
}

/*
 * util_spin_lock -- os_spin_lock variant that never fails from caller
 * perspective. If os_spin_lock failed, this function aborts the program.
 */
static inline void
util_spin_lock(os_spinlock_t *lock)
{
	int tmp = os_spin_lock(lock);
	if (tmp) {
		errno = tmp;
		FATAL("!os_spin_lock");
	}
}

/*
 * util_spin_unlock -- os_spin_unlock variant that never fails
 * from caller perspective. If os_spin_unlock failed,
 * this function aborts the program.
 */
static inline void
util_spin_unlock(os_spinlock_t *lock)
{
	int tmp = os_spin_unlock(lock);
	if (tmp) {
		errno = tmp;
		FATAL("!os_spin_unlock");
	}
}

/*
 * util_semaphore_init -- os_semaphore_init variant that never fails
 * from caller perspective. If os_semaphore_init failed,
 * this function aborts the program.
 */
static inline void
util_semaphore_init(os_semaphore_t *sem, unsigned value)
{
	if (os_semaphore_init(sem, value))
		FATAL("!os_semaphore_init");
}

/*
 * util_semaphore_destroy -- deletes a semaphore instance
 */
static inline void
util_semaphore_destroy(os_semaphore_t *sem)
{
	if (os_semaphore_destroy(sem) != 0)
		FATAL("!os_semaphore_destroy");
}

/*
 * util_semaphore_wait -- decreases the value of the semaphore
 */
static inline void
util_semaphore_wait(os_semaphore_t *sem)
{
	errno = 0;

	int ret;
	do {
		ret = os_semaphore_wait(sem);
	} while (errno == EINTR); /* signal interrupt */

	if (ret != 0)
		FATAL("!os_semaphore_wait");
}

/*
 * util_semaphore_trywait -- tries to decrease the value of the semaphore
 */
static inline int
util_semaphore_trywait(os_semaphore_t *sem)
{
	errno = 0;
	int ret;
	do {
		ret = os_semaphore_trywait(sem);
	} while (errno == EINTR); /* signal interrupt */

	if (ret != 0 && errno != EAGAIN)
		FATAL("!os_semaphore_trywait");

	return ret;
}

/*
 * util_semaphore_post -- increases the value of the semaphore
 */
static inline void
util_semaphore_post(os_semaphore_t *sem)
{
	if (os_semaphore_post(sem) != 0)
		FATAL("!os_semaphore_post");
}

/*
 * util_mutex_timedlock -- os_mutex_timedlock variant that never fails from
 * caller perspective. If os_mutex_lock failed, this function aborts
 * the program.
 */
static inline void
util_mutex_timedlock(os_mutex_t *m, struct timespec *ts)
{
	int tmp = os_mutex_timedlock(m, ts);
	if (tmp) {
		errno = tmp;
		FATAL("!os_mutex_timedlock");
	}
}

/*
 * util_cond_destroy -- os_cond_destroy variant that never fails from
 * caller perspective. If os_cond_destroy failed, this function aborts
 * the program.
 */
static inline void
util_cond_destroy(os_cond_t *cond)
{
	if (os_cond_destroy(cond) != 0)
		FATAL("!os_cond_destrox");
}

/*
 * os_cond_broadcast -- os_cond_broadcast variant that never fails from
 * caller perspective. If os_cond_broadcast failed, this function aborts
 * the program.
 */
static inline void
util_cond_broadcast(os_cond_t *cond)
{
	if (os_cond_broadcast(cond) != 0)
		FATAL("!os_cond_broadcast");
}

/*
 * util_mutex_consistent -- os_mutex_consistent variant that never fails from
 * caller perspective. If os_mutex_consistent failed, this function aborts
 * the program.
 */
static inline void
util_mutex_consistent(os_mutex_t *m)
{
	if (os_mutex_consistent(m))
		FATAL("!os_mutex_consistent");

}

/*
 * util_mutex_destroy_shrd -- util_mutex_destroy variant for robust shared
 * locks. Locks that were locked while a process crashed are set to
 * consistent state before they are destroyed.
 */
static inline void
util_mutex_destroy_shrd(os_mutex_t *lock)
{
	int err = os_mutex_trylock(lock);
	switch (err) {
		case EOWNERDEAD:
			util_mutex_consistent(lock);
			ERR("Detected crashed process. Shuting down anyway");
			/* no break */
		case 0:
			util_mutex_unlock(lock);
			break;
		case EBUSY:
			ERR("Unlocked lock detected. ");
		default:
			ERR("Unexpected lock error during shutdown. "
			    "Destroying the lock anyway. "
			    "Undefined behaviour might happen.");

	}
	util_mutex_destroy(lock);
}

#endif
