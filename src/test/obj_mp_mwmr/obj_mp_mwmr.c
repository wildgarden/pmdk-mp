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
 *
 * obj_mp_mwmr.c -- integration test for multiple reader and writer processes
 * using the same pool concurrently.
 *
 * usage: obj_mp_mwmr file num_procs num_ops
 *
 */

#include <pthread.h>
#include "unittest.h"
#include "../../examples/libpmemobj/mp/reader_writer/layout.h"

#define READER_WRITER_RATIO 4

#define PATH_WRITER_S "../../examples/libpmemobj/mp/reader_writer_sync/writer"
#define PATH_READER_S "../../examples/libpmemobj/mp/reader_writer_sync/reader"
#define PATH_WRITER "../../examples/libpmemobj/mp/reader_writer/writer"
#define PATH_READER "../../examples/libpmemobj/mp/reader_writer/reader"
/* pointer to array containing all child pids */
static pid_t *Pids;

/* common arguments for worker functions */
struct worker_args {
	const char *path;
	int num_procs;
	const char *num_ops;
};

typedef void (*fn_worker)(struct worker_args *);
typedef void (*fn_verify)(const char *, int, int);

static void
worker_reader_writer_sync(struct worker_args *args)
{
	/* Start children. */
	for (int i = 0; i < args->num_procs; ++i) {
		if ((Pids[i] = fork()) < 0) {
			UT_FATAL("!fork");
		} else if (Pids[i] == 0) {
			if (i % READER_WRITER_RATIO == 0) {
				if (execl(PATH_WRITER_S,
					"writer",
					args->path, args->num_ops, NULL) < 0) {
					UT_FATAL("!execl writer");
				}
			} else {
				if (execl(PATH_READER_S,
					"reader",
					args->path, args->num_ops, NULL) < 0) {
					UT_FATAL("!execl reader");
				}
			}
			exit(0);
		}
	}
}

static void
verify_reader_writer(const char *path, int num_procs, int num_ops)
{
	/* assert counter */
	int expected = (num_procs / READER_WRITER_RATIO) * num_ops * 2;

	PMEMobjpool *pop = pmemobj_open(path, POBJ_LAYOUT_NAME(reader_writer));
	if (pop == NULL) {
		UT_FATAL("pmemobj_create");
	}

	PMEMoid root = pmemobj_root(pop, sizeof(struct my_root));
	struct my_root *rootp = pmemobj_direct(root);
	UT_ASSERTeq(rootp->counter, expected);

	pmemobj_close(pop);
}

static void
worker_reader_writer(struct worker_args *args)
{
	/* Start children. */
	for (int i = 0; i < args->num_procs; ++i) {
		if ((Pids[i] = fork()) < 0) {
			UT_FATAL("!fork");
		} else if (Pids[i] == 0) {
			if (i % READER_WRITER_RATIO == 0) {
				if (execl(PATH_WRITER,
					"writer",
					args->path, args->num_ops, NULL) < 0) {
					UT_FATAL("!execl writer");
				}
			} else {
				if (execl(PATH_READER,
					"reader",
					args->path, args->num_ops, NULL) < 0) {
					UT_FATAL("!execl reader");
				}
			}
			exit(0);
		}
	}
}

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
	START(argc, argv, "obj_mp_mwmr");

	if (argc != 5)
		UT_FATAL("usage: %s file testcase num_procs num_ops", argv[0]);

	const char *path = argv[1];
	int test_case = atoi(argv[2]);
	int num_procs = atoi(argv[3]);
	int num_ops = atoi(argv[4]);
	UT_ASSERT(num_procs >= 0);
	UT_ASSERT(num_procs <= MAX_PROCS);
	UT_ASSERT(num_ops >= 0);

	fn_worker worker;
	fn_verify verify;

	switch (test_case) {
		case 0:
			worker = worker_reader_writer_sync;
			verify = verify_reader_writer;
			break;
		case 1:
			worker = worker_reader_writer;
			verify = verify_reader_writer;
			break;
		/*
		 * XXX mp-mode -- (test) [high] testcase for killed proc
		 * case 2:
		 */

		default:
			UT_FATAL("unknown testcase");
	}

	/* prepare the pool */
	Pids = ZALLOC(num_procs * sizeof(pid_t));
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

	struct worker_args args = {
		.path = path,
		.num_procs = num_procs,
		.num_ops = argv[4]
	};

	/* start childs */
	worker(&args);

	/* parent */
	for (int j = 0; j < num_procs; j++) {
		UT_ASSERTne(Pids[j], 0);

		int status;
		if (waitpid(Pids[j], &status, 0) < 0) {
			clear_childs(num_procs, j);
			UT_FATAL("!waitpid failed");
		}

		if (!WIFEXITED(status)) {
			UT_ERR("[%d] WEXITSTATUS status %d", Pids[j],
				WEXITSTATUS(status));
			UT_ERR("WTERMSIG status %d", WTERMSIG(status));
			UT_FATAL("child process failed");
		}

		UT_ASSERTeq(WEXITSTATUS(status), 0);
	}

	verify(path, num_procs, num_ops);

	FREE(Pids);
	DONE(NULL);
}
