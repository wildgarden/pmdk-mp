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


#include <stdio.h>
#include <libpmemobj.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "layout.h"

/* pointer to array containing all child pids */
static pid_t *Pids;

static void
init_root_obj(PMEMobjpool *pop)
{
	TOID(struct my_root) root = POBJ_ROOT(pop, struct my_root);

	pmemobj_mutex_zero(pop, &D_RW(root)->mtx);
	pmemobj_cond_zero(pop, &D_RW(root)->r_cond);
	pmemobj_cond_zero(pop, &D_RW(root)->w_cond);

	D_RW(root)->counter = 0;
	D_RW(root)->writers = 0;
	D_RW(root)->writing = 0;
	D_RW(root)->reading = 0;
}

static void
clear_childs(int num_procs, int j)
{
	for (int i = 0; i < num_procs; ++i) {
		if (i != j)
			kill(Pids[i], SIGKILL);
	}
}

int
main(int argc, char *argv[])
{

	if (argc != 4) {
		printf("usage: %s file num_procs num_ops", argv[0]);
		exit(1);
	}
	printf("cmdl args given: %s %s %s\n", argv[1], argv[2], argv[3]);

	const char *path = argv[1];
	int num_procs = atoi(argv[2]);

	/* prepare pool */
	putenv("PMEMOBJ_MULTIPROCESS=1");
	Pids = calloc((size_t)num_procs, sizeof(pid_t));
	PMEMobjpool *pop;
	if (access(path, F_OK) != 0) {
		pop = pmemobj_create(path, POBJ_LAYOUT_NAME(reader_writer),
			PMEMOBJ_MIN_POOL, 0666);
	} else {
		pop = pmemobj_open(path, POBJ_LAYOUT_NAME(reader_writer));
	}
	if (pop == NULL) {
		perror("pmemobj_create");
		return 1;
	}

	init_root_obj(pop);

	pmemobj_close(pop);

	/* Start children. */
	for (int i = 0; i < num_procs; ++i) {
		if ((Pids[i] = fork()) < 0) {
			printf("error during fork. aborting!");
			exit(1);
		} else if (Pids[i] == 0) {
			if (i % 2 == 0) {
				if (execl(
					"/home/oli/Development/masterthesis/nvml/src/examples/libpmemobj/mp/reader_writer/writer",
					"writer",
					path, argv[3], NULL) < 0) {
					printf("error during execl aborting!");
					exit(1);
				}
			} else {
				if (execl(
					"/home/oli/Development/masterthesis/nvml/src/examples/libpmemobj/mp/reader_writer/reader",
					"reader",
					path, argv[3], NULL) < 0) {
					printf("error during execl. aborting!");
					exit(1);
				}
			}
			exit(0);
		}
	}

	/* parent */
	for (int j = 0; j < num_procs; j++) {
		int status;
		if (waitpid(Pids[j], &status, 0) < 0) {
			printf("error during waitpid. aborting!");
			clear_childs(num_procs, j);
			exit(1);
		}

		if (!WIFEXITED(status)) {
			printf("[%d] WEXITSTATUS status %d", Pids[j],
				WEXITSTATUS(status));
			printf("WTERMSIG status %d", WTERMSIG(status));
			printf("error during waitpid. aborting!");
			exit(1);
		}

		if (WEXITSTATUS(status) != 0) {
			printf("unexpected exit status. aborting!");
			exit(1);
		}
	}

	free(Pids);
}
