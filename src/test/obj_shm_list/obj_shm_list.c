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

#include "unittest.h"
#include "util.h"
#include "shm_list.h"

static void
test_prev(struct shm_list *list)
{
	for (int i = 0; i < 10; ++i) {
		shm_list_insert(list, i);
	}

	struct shm_list_entry *entry = shm_list_get(list, list->tail);

	while (entry != NULL) {
		UT_OUT("%d", entry->data);
		entry = shm_list_prev(list, entry);
	}
}

static void
test_next(struct shm_list *list)
{
	struct shm_list_entry *entry = shm_list_get(list, 0);

	while (entry != NULL) {
		UT_OUT("%d", entry->data);
		entry = shm_list_next(list, entry);
	}
}

static void
test_remove(struct shm_list *list)
{
	struct shm_list_entry *entry = shm_list_get(list, 0);

	shm_list_remove(list, shm_list_get(list, 4)); /* shortcut to entry 4 */

	while (entry != NULL) {
		UT_OUT("%d", entry->data);
		entry = shm_list_next(list, entry);
	}
}

static void
test_mixed(struct shm_list *list)
{
	struct shm_list_entry *entry = shm_list_insert(list, 11);
	shm_list_remove(list, entry);

	struct shm_list_entry *entry_12 = shm_list_insert(list, 12);
	shm_list_insert(list, 13);
	shm_list_insert(list, 14);
	shm_list_remove(list, entry_12);
	shm_list_insert(list, 13);
	shm_list_pop(list);
	shm_list_insert(list, 1);
	entry = shm_list_insert(list, 13);

	while (entry != NULL) {
		UT_OUT("%d", entry->data);
		entry = shm_list_prev(list, entry);
	}
}

static void
test_get_pop(struct shm_list *list)
{
	for (int i = 0; i < 10; ++i) {
		shm_list_insert(list, i);
	}

	while (list->tail != ENTRY_NULL) {
		UT_OUT("%d", shm_list_get(list, list->tail)->data);
		shm_list_pop(list);
	}
}

static void
test_oom(void)
{
	struct shm_list *list = shm_list_new(MALLOC(sizeof(struct shm_list)));
	int count = 0;
	while (shm_list_insert(list, 0) != NULL) {
		count++;
	}
	UT_ASSERTeq(MAX_PROCS, count);
	shm_list_delete(list);
}

int
main(int argc, char *argv[])
{
	START(argc, argv, "obj_shm_list");
	if (argc != 1)
		UT_FATAL("test expects no args");

	util_init(); /* to initialize On_valgrind flag */

	struct shm_list *list = shm_list_new(MALLOC(sizeof(struct shm_list)));

	test_get_pop(list);
	test_prev(list);
	test_next(list);
	test_remove(list);
	test_mixed(list);

	shm_list_delete(list);

	test_oom();

	DONE(NULL);
}
