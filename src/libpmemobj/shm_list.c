/*
 * Copyright 2018, Oliver Janssen
 *
 * This file is partly based on source code released by
 * the PMDK project found at https://github.com/pmem/pmdk which is covered
 * by the license found under the file LICENSE in the root folder.
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

#include <out.h>
#include <sys_util.h>
#include "shm_list.h"

/*
 *  shm_list.c
 *
 *  shared memory doubly linked list implementation
 *
 *  uses array indexes instead of pointers + offset
 */

/*
 * shm_list_delete -- cleanups the shm_list
 */
void
shm_list_delete(struct shm_list *list)
{
	ASSERTne(list, NULL);
	util_mutex_destroy_shrd(&list->lock);
	/* nothing to free */
}

/*
 * shm_list_new -- initialises a new shm_list at the given memory position
 */
struct shm_list *
shm_list_new(void *base)
{
	struct shm_list *list = (struct shm_list *)base;
	memset(&list->pool, 0, sizeof(list->pool));
	list->pfree = ENTRY_NULL;
	list->tail = ENTRY_NULL;
	list->exhausted = 0;
	util_mutex_init_mp(&list->lock);

	return list;
}

/*
 * shm_list_attach --  attaches to an existing shm_list at the given memory
 * position
 */
struct shm_list *
shm_list_attach(void *base)
{
	struct shm_list *list = (struct shm_list *)base;

	return list;
}

/*
 * shm_list_alloc -- allocates a new shm_list_entry from the pool containing
 * free entries
 */
static struct shm_list_entry *
shm_list_alloc(struct shm_list *list)
{
	struct shm_list_entry *entry;
	if (list->pfree != ENTRY_NULL) {
		if (list->pfree >= MAX_LIST_ENTRIES)
			FATAL("MAX_LIST_ENTRIES");

		entry = list->pool + list->pfree;
		list->pfree = list->pool[list->pfree].prev;
	} else if (list->exhausted < MAX_LIST_ENTRIES) {
		entry = &list->pool[list->exhausted++];
	} else {
		return NULL;
	}
	entry->data = 0;

	return entry;
}

/*
 * shm_list_insert_unlocked -- puts the data in a new shm_list_entry
 * prior to this call the shm_list hast to be protected by a lock
 */
struct shm_list_entry *
shm_list_insert_unlocked(struct shm_list *list, int data)
{
	struct shm_list_entry *entry = shm_list_alloc(list);
	if (entry == NULL)
		return NULL;

	entry->data = data;
	entry->prev = list->tail;
	entry->next = ENTRY_NULL;

	size_t current = SHM_LIST_GET_IDX(list, entry);
	if (entry->prev != ENTRY_NULL)
		list->pool[entry->prev].next = current;

	list->tail = current;

	return entry;
}

/*
 * shm_list_insert -- puts the data in a new shm_list_entry
 */
struct shm_list_entry *
shm_list_insert(struct shm_list *list, int data)
{
	util_mutex_lock(&list->lock);
	struct shm_list_entry *entry = shm_list_insert_unlocked(list, data);
	util_mutex_unlock(&list->lock);

	return entry;
}

/*
 * entry_free -- moves te given entry to the free pool
 */
static void
entry_free(struct shm_list *list, struct shm_list_entry *entry)
{
	ASSERTne(entry, NULL);

	entry->prev = list->pfree;
	list->pfree = SHM_LIST_GET_IDX(list, entry);
	entry->next = ENTRY_NULL;
}

/*
 * shm_list_remove -- removes the given entry from the shm_list
 */
void
shm_list_remove(struct shm_list *list, struct shm_list_entry *entry)
{
	ASSERTne(list->tail, ENTRY_NULL);
	util_mutex_lock(&list->lock);

	struct shm_list_entry *next = shm_list_next(list, entry);
	struct shm_list_entry *prev = shm_list_prev(list, entry);

	if (prev != NULL)
		prev->next = entry->next;
	if (next != NULL)
		next->prev = entry->prev;
	else
		list->tail = entry->prev;

	entry_free(list, entry);

	util_mutex_unlock(&list->lock);
}

/*
 * shm_list_pop -- pops an entry from the shm_List
 */
void
shm_list_pop(struct shm_list *list)
{
	ASSERTne(list->tail, ENTRY_NULL);

	util_mutex_lock(&list->lock);

	size_t prev = list->pool[list->tail].prev;
	entry_free(list, &list->pool[list->tail]);
	list->tail = prev;

	util_mutex_unlock(&list->lock);
}

/*
 * shm_list_get -- returns the entry at the given idx
 */
struct shm_list_entry *
shm_list_get(struct shm_list *list, size_t idx)
{
	ASSERT(idx >= 0 && idx <= ENTRY_NULL);

	struct shm_list_entry *entry = (idx == ENTRY_NULL)
					    ? NULL
					    : list->pool + idx;

	return entry;

}

struct shm_list_entry *
shm_list_prev(struct shm_list *list, const struct shm_list_entry *entry)
{
	return shm_list_get(list, entry->prev);
}

struct shm_list_entry *
shm_list_next(struct shm_list *list, const struct shm_list_entry *entry)
{
	return shm_list_get(list, entry->next);
}
