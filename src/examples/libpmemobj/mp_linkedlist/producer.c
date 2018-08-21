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

#include <stdlib.h>
#include <stdio.h>
#include <ex_common.h>
#include "layout.h"

int Verbose;

static void
show_progress(int current_count)
{
	if (Verbose || current_count % 1000 == 0) {
		printf("\nAdded node %d to FIFO\n", current_count);
	} else if (current_count % 100 == 0) {
		printf(".");
	}
}

static void
produce(PMEMobjpool *pop, int ops)
{
	TOID(struct fifo_root) root = POBJ_ROOT(pop, struct fifo_root);
	struct tqueuehead *tqhead = &D_RW(root)->head;
	TOID(struct tqnode) node;

	int current_count = 0;
	int retries = 5;
	for (int i = 0; i < ops; ++i) {
		TX_BEGIN_LOCK(pop, TX_PARAM_MUTEX, &D_RW(root)->lock) {
			node = TX_NEW(struct tqnode);
			D_RW(node)->data = D_RW(root)->counter++;
			current_count = D_RW(node)->data;
			POBJ_TAILQ_INSERT_HEAD(tqhead, node, tnd);
		} TX_ONCOMMIT {
			show_progress(current_count);
		} TX_ONABORT {
			if (--retries == 0) {
				printf("\nmax retries reached. aborting!\n");
				exit(1);
			}
			if (errno == EOWNERDEAD) {
				/*
				 * Another process crashed while holding the
				 * lock. Since this lock is not internal to
				 * the library, the user is reponsible to
				 * repair the current state. Thus we should
				 * run recovery, before continuing.
				 */
				printf("\nEOWNERDEAD..runing recovery...\n");
				if (obj_crash_check_and_recover(pop)) {
					perror("\n"
				    "obj_check_liveliness_and_recover");
					exit(1);
				}
				if (pmemobj_mutex_consistent(pop,
				    &D_RW(root)->lock)) {
					perror("\npmemobj_mutex_consistent");
					exit(1);
				}
				printf("done\n");
			} else if (errno == ENOTRECOVERABLE) {
				perror("Aborting...");
				exit(1);
			}
			printf("tx_abort retrying...\n");
		} TX_END
	}
}

static void
print_help(void)
{
	printf("usage: fifo <pool> <ops> [<verbose>]\n");
	printf("\tAvailable options:\n");
	printf("\tops, number of elements to insert\n");
	printf("\tverbose, 'v' for verbose output\n");
}


int
main(int argc, const char *argv[])
{
	PMEMobjpool *pop;
	const char *path;

	if (argc < 3) {
		print_help();
		return 0;
	}
	path = argv[1];

	if (argc == 4 && argv[3][0] == 'v')
		Verbose = 1;

	putenv("PMEMOBJ_MULTIPROCESS=1");
	putenv("PMEMOBJ_MULTIPROCESS_ROBUST=1");

	if (file_exists(path) != 0) {
		if ((pop = pmemobj_create(path, POBJ_LAYOUT_NAME(list),
			PMEMOBJ_MIN_POOL, 0666)) == NULL) {
			perror("failed to create pool\n");
			return -1;
		}
	} else {
		if ((pop = pmemobj_open(path,
			POBJ_LAYOUT_NAME(list))) == NULL) {
			perror("failed to open pool\n");
			return -1;
		}
	}
	produce(pop, atoi(argv[2]));

	pmemobj_close(pop);

	exit(0);
}