#ifndef NVML_REGISTRY_H
#define NVML_REGISTRY_H 1

#include <sys/types.h>
#include "lane.h"
#include "queue.h"

/* opaque handle */
struct registry;

/*
 * list holding infos about registrered processes
 * list is only used localy (not shared).
 */
struct registry_entry {
    size_t idx;
    SLIST_ENTRY(registry_entry) entry;
};

SLIST_HEAD(registry_entries, registry_entry);

struct registry *
registry_new(void *base, int lock_fd, int init, uint64_t nlanes);
void registry_delete(struct registry *r, int clean_shared);

int registry_add(struct registry *r);
int registry_remove_by_idx(struct registry *r, unsigned idx);
void registry_remove_by_idx_unlocked(struct registry *r, unsigned idx);

void registry_check_crashed(struct registry *r,
    struct registry_entries *rentries, unsigned self_idx);
void registry_get_lanes_by_idx(struct registry *r, struct lane_range *range,
	unsigned idx);

int registry_hold(struct registry *r);
void registry_release(struct registry *r);
#endif // NVML_REGISTRY_H
