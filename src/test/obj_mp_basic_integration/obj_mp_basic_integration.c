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
 * obj_mp_basic_integration.c -- integration test loosly modeled after
 * obj_basic_integration.c
 *
 * usage: obj_mp_basic_integration file num_procs num_ops
 *
 */

#include <pthread.h>
#include "unittest.h"

#define TEST_STR_LEN 8

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

/*
 * Layout definition
 */
POBJ_LAYOUT_BEGIN(basic);
POBJ_LAYOUT_ROOT(basic, struct dummy_root);
POBJ_LAYOUT_TOID(basic, struct dummy_node);
POBJ_LAYOUT_TOID(basic, struct dummy_node_c);
POBJ_LAYOUT_END(basic);

struct dummy_node {
    int value;
    char teststr[TEST_STR_LEN];
    POBJ_LIST_ENTRY(struct dummy_node) plist;
    POBJ_LIST_ENTRY(struct dummy_node) plist_m;
};

struct dummy_node_c {
    int value;
    char teststr[TEST_STR_LEN];
    POBJ_LIST_ENTRY(struct dummy_node) plist;
    POBJ_LIST_ENTRY(struct dummy_node) plist_m;
};

struct dummy_root {
    int value;
    PMEMmutex lock;
    TOID(struct dummy_node) node;
    POBJ_LIST_HEAD(dummy_list, struct dummy_node) dummies;
    POBJ_LIST_HEAD(moved_list, struct dummy_node) moved;
};

static int
dummy_node_constructor(PMEMobjpool *pop, void *ptr, void *arg)
{
	struct dummy_node *n = (struct dummy_node *)ptr;
	int *test_val = (int *)arg;
	n->value = *test_val;
	pmemobj_persist(pop, &n->value, sizeof(n->value));

	return 0;
}

/*
 * fn_compare -- comparator to sort integers in ascending order
 */
static int
fn_compare(const void *a, const void *b)
{
	return (*(int *)a - *(int *)b);
}

/*
 * worker_alloc_api -- work that is executed in each child process
 * tests concurrent fail-safe atomic allocations
 */
static void
worker_alloc_api(struct worker_args *args)
{
	/* child */

	PMEMobjpool *pop = pmemobj_open(args->path,
		POBJ_LAYOUT_NAME(basic));

	TOID(struct dummy_node) node_zeroed;
	TOID(struct dummy_node_c) node_constructed;

	POBJ_ZNEW(pop, &node_zeroed, struct dummy_node);

	UT_ASSERT_rt(OID_INSTANCEOF(node_zeroed.oid, struct dummy_node));

	int *test_val = (int *)MALLOC(sizeof(*test_val));
	*test_val = getpid();
	for (int j = 0; j < atoi(args->num_ops); ++j) {
		POBJ_NEW(pop, &node_constructed, struct dummy_node_c,
			dummy_node_constructor, test_val);
	}

	FREE(test_val);

	pmemobj_close(pop);

}

static void
verify_alloc_api(const char *path, int num_procs, int num_ops)
{
	PMEMobjpool *pop = pmemobj_open(path,
		POBJ_LAYOUT_NAME(basic));

	TOID(struct dummy_node) iter;

	POBJ_FOREACH_TYPE(pop, iter) {
		UT_ASSERTeq(D_RO(iter)->value, 0);
	}

	/* populate result array */
	int nodes_count = 0;
	int *result_pids = MALLOC(sizeof(pid_t) * num_procs * num_ops);
	TOID(struct dummy_node_c) iter_c;
	POBJ_FOREACH_TYPE(pop, iter_c) {
		result_pids[nodes_count] = D_RO(iter_c)->value;
			nodes_count++;
	}
	UT_ASSERTeq(nodes_count, num_procs * num_ops);

	/* sort arrays and compare contents */
	qsort(result_pids, num_procs * num_ops, sizeof(int), fn_compare);
	qsort(Pids, num_procs, sizeof(int), fn_compare);

	for (int i = 0; i < num_procs; ++i) {
		for (int j = 0; j < num_ops; ++j) {
			UT_ASSERTeq(Pids[i], result_pids[i * num_ops + j]);
		}
	}

	pmemobj_close(pop);

	FREE(result_pids);
}

/*
 * worker_list_api -- work that is executed in each child process.
 * tests concurrent access to the list api
 */
static void
worker_list_api(struct worker_args *args)
{
/* child */
	PMEMobjpool *pop = pmemobj_open(args->path,
		POBJ_LAYOUT_NAME(basic));

	TOID(struct dummy_root) root;
	root = POBJ_ROOT(pop, struct dummy_root);

	int *test_val = (int *)MALLOC(sizeof(*test_val));
	*test_val = getpid();

	for (int j = 0; j < atoi(args->num_ops); ++j) {
		POBJ_LIST_INSERT_NEW_TAIL(pop, &D_RW(root)->dummies, plist,
			sizeof(struct dummy_node), dummy_node_constructor,
			test_val);

	}

	FREE(test_val);

	pmemobj_close(pop);
}

/*
 * verify_list_api - verifies that the list contains the expected values
 */
static void
verify_list_api(const char *path, int num_procs, int num_ops)
{
	PMEMobjpool *pop = pmemobj_open(path,
		POBJ_LAYOUT_NAME(basic));

	TOID(struct dummy_root) root;
	root = POBJ_ROOT(pop, struct dummy_root);

	TOID(struct dummy_node) iter;
	int nodes_count = 0;
	int *result_pids = MALLOC(sizeof(pid_t) * num_procs * num_ops);

	POBJ_LIST_FOREACH(iter, &D_RO(root)->dummies, plist) {
		result_pids[nodes_count++] = D_RO(iter)->value;
		/* UT_OUT("POBJ_LIST_FOREACH: pid %d", D_RO(iter)->value); */
	}

	UT_ASSERTeq(nodes_count, num_procs * num_ops);

	/* sort arrays and compare contents */
	qsort(result_pids, num_procs * num_ops, sizeof(int), fn_compare);
	qsort(Pids, num_procs, sizeof(int), fn_compare);

	for (int i = 0; i < num_procs; ++i) {
		for (int j = 0; j < num_ops; ++j) {
			UT_ASSERTeq(Pids[i], result_pids[i * num_ops + j]);
		}
	}

	FREE(result_pids);

	pmemobj_close(pop);
}

/*
 * worker_tx_api -- work that is executed in each child process.
 * tests concurrent access to the tx api
 */
static void
worker_tx_api(struct worker_args *args)
{
	PMEMobjpool *pop = pmemobj_open(args->path,
		POBJ_LAYOUT_NAME(basic));

	TOID(struct dummy_root) root;
	TOID_ASSIGN(root, pmemobj_root(pop, sizeof(struct dummy_root)));


	int *test_val = (int *)MALLOC(sizeof(*test_val));
	*test_val = getpid();

	for (int j = 0; j < atoi(args->num_ops); ++j) {
		TX_BEGIN_PARAM(pop, TX_PARAM_MUTEX, &D_RW(root)->lock) {
			TX_BEGIN(pop) {
				TX_ADD(root);
					D_RW(root)->node =
					    TX_ZNEW(struct dummy_node);
				TX_SET(D_RW(root)->node, value, *test_val);
			} TX_ONABORT {
				UT_ASSERT(0);
			} TX_END
			UT_ASSERTeq(D_RW(D_RW(root)->node)->value, *test_val);
		} TX_ONABORT {
			UT_ASSERT(0);
		} TX_END
	}

	FREE(test_val);

	pmemobj_close(pop);
}

static void
verify_tx_api(const char *path, int num_procs, int num_ops)
{
	PMEMobjpool *pop = pmemobj_open(path,
		POBJ_LAYOUT_NAME(basic));

	/* populate result array */
	int nodes_count = 0;
	int *result_pids = MALLOC(sizeof(pid_t) * num_procs * num_ops);

	TOID(struct dummy_node) iter;
	POBJ_FOREACH_TYPE(pop, iter) {
		result_pids[nodes_count] = D_RO(iter)->value;
		nodes_count++;
	}
	UT_ASSERTeq(nodes_count, num_procs * num_ops);

	/* sort arrays and compare contents */
	qsort(result_pids, num_procs * num_ops, sizeof(int), fn_compare);
	qsort(Pids, num_procs, sizeof(int), fn_compare);

	for (int i = 0; i < num_procs; ++i) {
		for (int j = 0; j < num_ops; ++j) {
			UT_ASSERTeq(Pids[i], result_pids[i * num_ops + j]);
		}
	}

	pmemobj_close(pop);

	FREE(result_pids);
}

/*
 * run_worker - creates child processes and executes the workers' code in the
 * child.
 */
static void
run_worker(fn_worker worker_func, struct worker_args *args)
{
	for (int i = 0; i < args->num_procs; ++i) {
		if ((Pids[i] = fork()) < 0) {
			UT_FATAL("!fork");
		} else if (Pids[i] == 0) {
			/* child */

			worker_func(args);

			exit(0);
		} else {
			/* parent does nothing */
		}
	}
}

int
main(int argc, char *argv[])
{
	START(argc, argv, "obj_mp_basic_integration");

	/* root doesn't count */
	UT_COMPILE_ERROR_ON(POBJ_LAYOUT_TYPES_NUM(basic) != 2);

	if (argc != 5)
		UT_FATAL("usage: %s file num_procs num_ops", argv[0]);

	const char *path = argv[1];
	int test_case = atoi(argv[2]);
	int num_procs = atoi(argv[3]);
	int num_ops = atoi(argv[4]);
	UT_ASSERT(num_procs >= 0);
	UT_ASSERT(num_procs <= MAX_PROCS);
	UT_ASSERT(num_ops >= 0);

	/* create pool if not existent */
	Pids = MALLOC(num_procs * sizeof(pid_t));
	if (access(path, F_OK) != 0) {
		PMEMobjpool *pop = pmemobj_create(path, POBJ_LAYOUT_NAME(basic),
			PMEMOBJ_MIN_POOL, 0666);

		if (pop == NULL) {
			perror("pmemobj_create");
			return 1;
		}
		pmemobj_close(pop);
	}

	struct worker_args args = {
		.path = path,
		.num_procs = num_procs,
		.num_ops = argv[4]
	};

	fn_worker worker;
	fn_verify verify;

	switch (test_case) {
		case 0:
			worker = worker_alloc_api;
			verify = verify_alloc_api;
			break;
		case 1:
			worker = worker_list_api;
			verify = verify_list_api;
			break;
		case 2: worker = worker_tx_api;
			verify = verify_tx_api;
			break;
		default:
			UT_FATAL("unknown testcase");
	}

	run_worker(worker, &args);

	/* parent waits for its childs to finish their work */
	for (int j = 0; j < num_procs; j++) {
		int status;
		if (waitpid(Pids[j], &status, 0) < 0)
			UT_FATAL("!waitpid failed");

		if (!WIFEXITED(status)) {
			UT_ERR("[%d] WEXITSTATUS status %d", Pids[j],
				WEXITSTATUS(status));
			UT_ERR("WTERMSIG status %d", WTERMSIG(status));
			UT_FATAL("child process failed");
		}

		UT_ASSERTeq(WEXITSTATUS(status), 0);
	}

	verify(path, num_procs, num_ops);

	int result = pmemobj_check(path, POBJ_LAYOUT_NAME(basic));
	if (result < 0)
		UT_OUT("!%s: pmemobj_check", path);
	else if (result == 0)
		UT_OUT("%s: pmemobj_check: not consistent", path);

	FREE(Pids);
	DONE(NULL);
}
