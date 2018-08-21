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
 * sync.h -- internal to obj synchronization API
 */

#ifndef LIBPMEMOBJ_SYNC_H
#define LIBPMEMOBJ_SYNC_H 1

#include <errno.h>
#include <stdint.h>
#include <fcntl.h>

#include "libpmemobj.h"
#include "out.h"
#include "os_thread.h"
#include "obj.h"

/*
 * macros for file locking
 * copied from APUE
 */
int
lock_reg(int, int, short int, off_t, short int, off_t);
#define read_lock(fd, offset, whence, len) \
lock_reg((fd), F_SETLK, F_RDLCK, (offset), (whence), (len))

#define readw_lock(fd, offset, whence, len) \
lock_reg((fd), F_SETLKW, F_RDLCK, (offset), (whence), (len))

#define write_lock(fd, offset, whence, len) \
lock_reg((fd), F_SETLK, F_WRLCK, (offset), (whence), (len))

#define writew_lock(fd, offset, whence, len) \
lock_reg((fd), F_SETLKW, F_WRLCK, (offset), (whence), (len))

#define un_lock(fd, offset, whence, len) \
lock_reg((fd), F_SETLK, F_UNLCK, (offset), (whence), (len))

pid_t
lock_test(int, short int, off_t, short int, off_t);

#define is_read_lockable(fd, offset, whence, len) \
(lock_test((fd), F_RDLCK, (offset), (whence), (len)) == 0)

#define is_write_lockable(fd, offset, whence, len) \
(lock_test((fd), F_WRLCK, (offset), (whence), (len)) == 0)

/*
 * internal definitions of PMEM-locks
 */
typedef union padded_pmemmutex {
	char padding[_POBJ_CL_SIZE];
	struct {
		uint64_t runid;
		os_mutex_t mutex;
	} pmemmutex;
} PMEMmutex_internal;

typedef union padded_pmemrwlock {
	char padding[_POBJ_CL_SIZE];
	struct {
		uint64_t runid;
		os_rwlock_t rwlock;
	} pmemrwlock;
} PMEMrwlock_internal;

typedef union padded_pmemcond {
	char padding[_POBJ_CL_SIZE];
	struct {
		uint64_t runid;
		os_cond_t cond;
	} pmemcond;
} PMEMcond_internal;

/*
 * pmemobj_mutex_lock_nofail -- pmemobj_mutex_lock variant that never
 * fails from caller perspective. If pmemobj_mutex_lock failed, this function
 * aborts the program.
 */
static inline void
pmemobj_mutex_lock_nofail(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	int ret = pop->pmem_lock(pop, mutexp);
	if (ret) {
		errno = ret;
		FATAL("!pmemobj_mutex_lock");
	}
}

/*
 * pmemobj_mutex_unlock_nofail -- pmemobj_mutex_unlock variant that never
 * fails from caller perspective. If pmemobj_mutex_unlock failed, this function
 * aborts the program.
 */
static inline void
pmemobj_mutex_unlock_nofail(PMEMobjpool *pop, PMEMmutex *mutexp)
{
	int ret = pop->pmem_unlock(pop, mutexp);
	if (ret) {
		errno = ret;
		FATAL("!pmemobj_mutex_unlock");
	}
}

int pmemobj_mutex_assert_locked(PMEMobjpool *pop, PMEMmutex *mutexp);

#endif
