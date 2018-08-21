#include <libpmemobj/base.h>
#include <util.h>
#include <out.h>
#include <sys_util.h>
#include <queue.h>
#include "mp.h"
#include "registry.h"
#include "shm_list.h"

struct registry_shm {
    uint64_t nlanes; 	/* number of available lanes */
    os_mutex_t lock;
    struct shm_list list;
};

struct registry {
    int lock_fd; /* local memory */
    struct registry_shm *shared; /* shared memory */
};

/*
 * registry_new -- allocates and initializes (if flagged) a registry.
 * 'nlanes' needs only be set on initialization.
 */
struct registry *
registry_new(void *base, int lock_fd, int init, uint64_t nlanes)
{
	COMPILE_ERROR_ON(OBJ_SHM_REGISTRY_SIZE < sizeof(struct registry_shm));

	struct registry *r = Malloc(sizeof(struct registry));
	r->lock_fd = lock_fd;

	r->shared = (struct registry_shm *)base;
	if (init) {
		ASSERT(nlanes > 0);
		r->shared->nlanes = nlanes;
		util_mutex_init_mp(&r->shared->lock);
		shm_list_new(&r->shared->list);
	}

	return r;
}

/*
 * registry_delete - cleanups and deallocated the registry
 */
void
registry_delete(struct registry *r, int clean_shared)
{
	LOG(3, NULL);
	if (clean_shared)
		shm_list_delete(&r->shared->list);

	ASSERTne(r, NULL);
	free(r);
}

/*
 * registry_add -- registers the process and in return obtains an unique
 * process handle that is valid for the current run.
 *
 * returns -1 on error
 */
int
registry_add(struct registry *r)
{
	LOG(3, NULL);

	struct shm_list_entry *entry;

	if ((errno = registry_hold(r)) != 0)
		return -1;

	entry = shm_list_insert_unlocked(&r->shared->list, 0);
	registry_release(r);

	if (entry == NULL) {
		errno = ENOMEM;
		return -1;
	}
	size_t idx = SHM_LIST_GET_IDX(&r->shared->list, entry);
	if (util_write_lock(r->lock_fd,
		    (off_t)(OBJ_LOCK_PROCS + idx), SEEK_SET, 1) != 0) {
		FATAL("util_write_lock");
	}

	return (int)idx;
}

/*
 * registry_remove_by_idx -- removes the entry with the given idx
 */
int
registry_remove_by_idx(struct registry *r, unsigned idx)
{
	LOG(3, "registry %p, idx %d", r, idx);
	if ((errno = registry_hold(r)) != 0) {
		return -1;
	}
	registry_remove_by_idx_unlocked(r, idx);
	registry_release(r);


	return 0;
}

void
registry_remove_by_idx_unlocked(struct registry *r, unsigned idx)
{
	LOG(3, "registry %p idx %i", r, idx);
	ASSERT(idx >= 0 && idx <= MAX_PROCS);

	if (util_un_lock(r->lock_fd, OBJ_LOCK_PROCS + idx, SEEK_SET, 1) != 0) {
		FATAL("util_un_lock");

	}
	shm_list_remove(&r->shared->list, shm_list_get(&r->shared->list, idx));
}

/*
 * registry_get_lanes_by_idx -- takes an 'idx' as input and assigns a range of
 * lanes to 'range' as output
 */
void
registry_get_lanes_by_idx(struct registry *r, struct lane_range *range,
	unsigned idx)
{
	LOG(7, NULL);
	unsigned lanes_per_proc =
		    (unsigned)((double)r->shared->nlanes / MAX_PROCS);
	ASSERT(lanes_per_proc > 0);
	ASSERT(idx < MAX_PROCS);

	range->idx_start = (lanes_per_proc * idx);
	range->idx_end = (lanes_per_proc * idx + (lanes_per_proc - 1));
}

/*
 * registry_checked_failed_procs -- checks if all registered processes
 * are alive. Dead processes are written to the 'rentries' linked list.
 * registry_check_crashed shall be preceded by registry_hold and the lock
 * only released after recovery is done.
 */
void
registry_check_crashed(struct registry *r, struct registry_entries *rentries,
    unsigned self_idx)
{
	LOG(3, "registry %p rentries %p self_idx %d", r, rentries, self_idx);

	struct shm_list_entry *entry =
		shm_list_get(&r->shared->list, r->shared->list.tail);

	while (entry != NULL) {
		size_t idx = SHM_LIST_GET_IDX(&r->shared->list, entry);
		if ((util_is_write_lockable(r->lock_fd,
			(off_t)(OBJ_LOCK_PROCS + idx),	SEEK_SET, 1))) {
			/*
			 * we obtained the lock, but the
			 * process was supposed to hold the lock for its
			 * entire lifetime.
			 * In other words: The process died.
			 */
			if (idx != self_idx) {
				struct registry_entry *rentry = NULL;
				rentry = Malloc(sizeof(*rentry));
				if (rentry == NULL)
					FATAL("Could not alloc list entry");

				rentry->idx = idx;
				SLIST_INSERT_HEAD(rentries, rentry, entry);
			}
		}
		entry = shm_list_prev(&r->shared->list, entry);
	}
}

void
registry_release(struct registry *r)
{
	util_mutex_unlock(&r->shared->lock);
}

int
registry_hold(struct registry *r)
{
	struct timespec ts;
	return os_mutex_timedlock(&r->shared->lock, mp_set_mtx_timeout(&ts));
}