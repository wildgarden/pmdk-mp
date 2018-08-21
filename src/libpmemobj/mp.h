/*
 * mp.h -- internal definitions for obj module multiprocess support
 */
#ifndef NVML_MP_H
#define NVML_MP_H

#include <os.h>
#include "../include/libpmemobj/mp_base.h"

/* global attributes */
#define MAX_REGIONS (MAX_PROCS)

/*
 * determines how we obtain shared memory
 * if true POSIX shared memory will be used
 * else we use a just mmap() a file from  the filesystem
 */
#define OBJ_SHM_USE_POSIX 0

/*
 * number of retries to attach to shared memory
 */
#define OBJ_SHM_INIT_RETRIES 3

/*
 * Suffixes
 */
#define FILE_SUFFIX_SHM "%s-shm" 	/* shared memory (mapp()ed) */
#define FILE_SUFFIX_LOCK "%s-lock" 	/* file for advisory locks */

/*
 * byte positions of locks inside the lock file
 */
#define OBJ_LOCK_DMS 1		/* dead man switch */
#define OBJ_LOCK_POOL 2		/* pool operations */
#define OBJ_LOCK_PROCS 8	/* start proc locks */
#define OBJ_LOCKFILE_SIZE (OBJ_LOCK_PROCS + MAX_PROCS)	/* Size of lock range */

/* sizeof(struct heap_rt_shm) */
#define OBJ_SHM_HEAP_SIZE (1024 * 1024 * 3) /* 3 MiB */

/*  This limit is set arbitrary to incorporate a struct registry_shm */
#define OBJ_SHM_REGISTRY_SIZE (512)

/*
 * Timeout in seconds until aquiring a mutex lock fails
 */
#define OBJ_SHM_MTX_TIMEOUT 10

/*
 * Set the timout on the given timespec
 */
static inline struct timespec *
mp_set_mtx_timeout(struct timespec *ts)
{
	os_clock_gettime(CLOCK_REALTIME, ts);
	ts->tv_sec += OBJ_SHM_MTX_TIMEOUT;

	return ts;
}
#endif // NVML_MP_H
