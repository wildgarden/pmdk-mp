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

/*
 * mp_bench -- multiprocess benchmark
 */
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "libpmem.h"
#include "libpmemobj.h"
#include "os.h"
#include <pthread.h>
#include <sys/wait.h>

#include "pmalloc.h"


//#include "../benchmarks/benchmark_time.hpp"


//#include "obj.h"
//#include "pmalloc.h"
//#include "unittest.h"

#define THREADS 8
#define PROCS 4
#define OPS_PER_THREAD 10000
#define ALLOC_SIZE 104
//#define REALLOC_SIZE (ALLOC_SIZE * 3)
#define MIX_RERUNS 2

#define CHUNKSIZE (1 << 18)
#define CHUNKS_PER_THREAD 3

#define ASSERT assert

/* average time required to get a current time from the system */
unsigned long long Get_time_avg;

struct root {
    uint64_t offs[PROCS][THREADS][OPS_PER_THREAD];
};

struct worker_args {
    PMEMobjpool *pop;
    struct root *r;
    int p_idx;
    int t_idx;
};

///*
// * pmembench_run_worker -- run worker with benchmark operation
// */
//static int
//pmembench_run_worker(struct benchmark *bench, struct worker_info *winfo)
//{
//    benchmark_time_get(&winfo->beg);
//    for (size_t i = 0; i < winfo->nops; i++) {
//        if (bench->info->operation(bench, &winfo->opinfo[i]))
//            return -1;
//        benchmark_time_get(&winfo->opinfo[i].end);
//    }
//    benchmark_time_get(&winfo->end);
//
//    return 0;
//}

static void *
alloc_worker(void *arg)
{
    struct worker_args *a = arg;

    for (int i = 0; i < OPS_PER_THREAD; ++i) {
        pmalloc(a->pop, &a->r->offs[a->p_idx][a->t_idx][i],
                ALLOC_SIZE, 0, 0);
        ASSERT(a->r->offs[a->p_idx][a->t_idx][i] != 0);
    }

    return NULL;
}

//static void *
//realloc_worker(void *arg)
//{
//    struct worker_args *a = arg;
//
//    for (int i = 0; i < OPS_PER_THREAD; ++i) {
//        prealloc(a->pop, &a->r->offs[a->p_idx][a->t_idx][i],
//                 REALLOC_SIZE, 0, 0);
//        ASSERT(a->r->offs[a->p_idx][a->t_idx][i] != 0);
//    }
//
//    return NULL;
//}


static void *
free_worker(void *arg)
{
    struct worker_args *a = arg;

    for (int i = 0; i < OPS_PER_THREAD; ++i) {
        pfree(a->pop, &a->r->offs[a->p_idx][a->t_idx][i]);
        ASSERT(a->r->offs[a->p_idx][a->t_idx][i] == 0);
    }

    return NULL;
}

static void *
mix_worker(void *arg)
{
    struct worker_args *a = arg;

    /*
     * The mix scenario is ran twice to increase the chances of run
     * contention.
     */
    for (int j = 0; j < MIX_RERUNS; ++j) {
        for (int i = 0; i < OPS_PER_THREAD; ++i) {
            pmalloc(a->pop, &a->r->offs[a->p_idx][a->t_idx][i],
                    ALLOC_SIZE, 0, 0);
            ASSERT(a->r->offs[a->p_idx][a->t_idx][i] != 0);
        }

        for (int i = 0; i < OPS_PER_THREAD; ++i) {
            pfree(a->pop, &a->r->offs[a->p_idx][a->t_idx][i]);
            ASSERT(a->r->offs[a->p_idx][a->t_idx][i] == 0);
        }
    }

    return NULL;
}

#if 0
/*
 * disabled, due to mtx timeouts. Enable once thread scheduling priority is
 * changed.
 */

static void *
tx_worker(void *arg)
{
	struct worker_args *a = arg;

	/*
	 * Allocate objects until exhaustion, once that happens the transaction
	 * will automatically abort and all of the objects will be freed.
	 */
	TX_BEGIN(a->pop) {
		for (;;) /* this is NOT an infinite loop */
			pmemobj_tx_alloc(ALLOC_SIZE, a->t_idx);
	} TX_END

	return NULL;
}
#endif

static void *
alloc_free_worker(void *arg)
{
    struct worker_args *a = arg;

    PMEMoid oid;
    for (int i = 0; i < OPS_PER_THREAD; ++i) {
        int err = pmemobj_alloc(a->pop, &oid, ALLOC_SIZE,
                                0, NULL, NULL);
        ASSERT(err == 0);
        pmemobj_free(&oid);
    }

    return NULL;
}


static void
run_worker(void *(worker_func)(void *arg), struct worker_args args[])
{
    os_thread_t t[THREADS];

    for (int i = 0; i < THREADS; ++i) {
        if ((errno = pthread_create(&t[i], NULL, worker_func, &args[i])) != 0) {
            fprintf(stderr, "!os_thread_create");
            abort();
        }
    }

    for (int i = 0; i < THREADS; ++i) {
        if ((errno = pthread_join(t[i], NULL)) != 0) {
            fprintf(stderr, "!os_thread_create");
            abort();
        }
    }

}

static int
obj_pmalloc_mt_main(const char *path, int proc_idx)
{
    PMEMobjpool *pop;

    if ((pop = pmemobj_open(path, "TEST")) == NULL) {
        printf("failed to open pool\n");
        return 1;
    }

    if (pop == NULL) {
        fprintf(stderr, "!pmemobj_create");
        abort();
    }

    PMEMoid oid = pmemobj_root(pop, sizeof(struct root));
    struct root *r = pmemobj_direct(oid);
    ASSERT(r != NULL);

    struct worker_args args[THREADS];

    for (int t = 0; t < THREADS; ++t) {
        args[t].p_idx = proc_idx;
        args[t].pop = pop;
        args[t].r = r;
        args[t].t_idx = t;
    }

    run_worker(alloc_worker, args);
//    run_worker(realloc_worker, args);
    run_worker(free_worker, args);
    run_worker(mix_worker, args);
    run_worker(alloc_free_worker, args);

#if 0
    /*
	 * This workload might create many allocation classes due to pvector,
	 * keep it last.
	 */
	run_worker(tx_worker, args);
#endif

    pmemobj_close(pop);

    exit(0);
}

/*
 * obj_mp_pmalloc_mt
 */

/* pointer to array containing all child pids */
static pid_t *Pids;

/* common arguments for worker functions */
struct runner_args {
    const char *path;
    int num_procs;
};

/*
 * run_worker - creates child processes and executes the workers' code in the
 * child.
 */
static void
run_fork_worker(struct runner_args *args)
{
    for (int i = 0; i < args->num_procs; ++i) {
        if ((Pids[i] = fork()) < 0) {
            fprintf(stderr, "!fork");
            abort();
        } else if (Pids[i] == 0) {
            /* child */
            obj_pmalloc_mt_main(args->path, i);

            /* if we get here, something unexpected happened */
            ASSERT(0);
        } else {
            /* parent does nothing */
        }
    }
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
    if (argc != 2) {
        fprintf(stderr, "usage: mp_bench [file]");
        abort();
    }

//    Get_time_avg = benchmark_get_avg_get_time();

    const char *path = argv[1];

    /* create pool prior to forking to prevent races (TOCTOU) */
    if (os_access(path, F_OK) != 0) {
        PMEMobjpool *pop = pmemobj_create(path, "TEST",
                                          (PMEMOBJ_MIN_POOL) + (PROCS * THREADS * CHUNKSIZE *
                                                                CHUNKS_PER_THREAD), 0666);
        pmemobj_close(pop);
    }

    Pids = malloc(PROCS * sizeof(pid_t));

    struct runner_args args = {
            .path = path,
            .num_procs = PROCS,
    };

    run_fork_worker(&args);

    /* parent */
    for (int j = 0; j < PROCS; j++) {
        int status;
        if (waitpid(Pids[j], &status, 0) < 0) {
            clear_childs(PROCS, j);
            fprintf(stderr, "!waitpid failed");
            abort();
        }

        if (!WIFEXITED(status)) {
            fprintf(stderr, "[%d] WEXITSTATUS status %d", Pids[j], WEXITSTATUS(status));
            fprintf(stderr, "WTERMSIG status %d", WTERMSIG(status));

            clear_childs(PROCS, j);
            fprintf(stderr, "!child process failed");
            abort();
        }

        ASSERT(WEXITSTATUS(status) == 0);
    }

    free(Pids);
    printf("benchmark run successful");
}
