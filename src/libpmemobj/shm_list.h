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

#ifndef NVML_SHM_LIST_H
#define NVML_SHM_LIST_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <stdio.h>
#include "../include/libpmemobj/mp_base.h"

#include "libpmemobj.h"
#include "../common/os_thread.h"

/* maximum number of nodes */
#define MAX_LIST_ENTRIES MAX_PROCS

/* special NULL entry because 0 is a valid offset */
#define ENTRY_NULL (MAX_LIST_ENTRIES + 1)

#define SHM_LIST_GET_IDX(list, entry) ((size_t)(entry - (list)->pool))

struct shm_list_entry {
    size_t prev;	/* relative pointer to prev entry */
    size_t next;	/* relative pointer to next entry */
    int data;
};

struct shm_list {
    struct shm_list_entry pool[MAX_LIST_ENTRIES];
    size_t pfree; 	/* pointer to free list */
    size_t tail;	/* point to end of the list */
    int exhausted;
    os_mutex_t lock;
};

struct shm_list *shm_list_new(void *base);
struct shm_list *shm_list_attach(void *base);
struct shm_list_entry *shm_list_insert(struct shm_list *list, int data);
struct shm_list_entry *
shm_list_insert_unlocked(struct shm_list *list, int data);

void shm_list_pop(struct shm_list *list);
void shm_list_remove(struct shm_list *list, struct shm_list_entry *entry);

struct shm_list_entry *shm_list_get(struct shm_list *list, size_t idx);

struct shm_list_entry *
shm_list_prev(struct shm_list *list, const struct shm_list_entry *node);

struct shm_list_entry *
shm_list_next(struct shm_list *list, const struct shm_list_entry *node);

void shm_list_delete(struct shm_list *list);
#endif // NVML_SHM_LIST_H
