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

#include <stdio.h>
#include <time.h>

#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <libpmem.h>
#include <libpmemobj.h>
#include <pthread.h>
#include <os.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <limits.h>

#include "pmalloc.h"

#include "benchmark_time.h"

#define LAYOUT "mylayout"

/*
 * The factor used for PMEM pool size calculation, accounts for metadata,
 * fragmentation and etc.
 */
#define FACTOR 8


/* The minimum allocation size that pmalloc can perform */
#define ALLOC_MIN_SIZE 64

/* OOB and allocation header size */
#define OOB_HEADER_SIZE 64

#define ASSERT assert

#define FILE_SUFFIX_SHM "%s-shm_bench" 	/* shared memory (mapp()ed) */

/* average time required to get a current time from the system */
unsigned long long Get_time_avg;

/* pointer to array containing all child pids */
static pid_t *Pids;

/* holds the path for shm segment*/
static char SHM_PATH[PATH_MAX];

pthread_barrier_t *shared_mem_barrier_for_parent;

/* arguments for workers */
struct worker_args {
    const char *path;
    size_t alloc_size;
    size_t nops;
};

typedef void (*fn_worker)(struct worker_args *);

static pthread_barrier_t *
mmap_barrier(int fd) {
	void *base;
	if ((base = mmap(NULL, sizeof(pthread_barrier_t),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	return (pthread_barrier_t *) base;
}

/*
 * attach_to_barrier_and_wait -- attaches and waits to a existing shared memory barrier
 */
static void
attach_to_barrier_and_wait() {
	int fd = open(SHM_PATH, O_RDWR, (mode_t) 0666);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	pthread_barrier_t *barrier = mmap_barrier(fd);

	close(fd);
	int ret = pthread_barrier_wait(barrier);
	if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
		perror("pthread_barrier_wait");
		exit(1);
	}
}

/*
 * This function does all the work inside a new process
 */
static void
do_pmalloc(struct worker_args *args)
{
	pid_t my_pid = getpid();
	printf("[%i] running pmalloc worker\n", my_pid);

	/* Create pmemobj pool. */
	if (args->alloc_size < ALLOC_MIN_SIZE)
	args->alloc_size = ALLOC_MIN_SIZE;

	double sec_acc = 0;
	int rounds = 0;

	benchmark_time_t time_start;
	benchmark_time_t time_curr;
	benchmark_time_t Ttot_ove;

	/* estimate total penalty of getting time from the system */
	benchmark_time_t Tget;
	unsigned long long nsecs = args->nops * Get_time_avg;
	benchmark_time_set(&Tget, nsecs);


	PMEMobjpool *pop = pmemobj_open(args->path, LAYOUT);
	if (!pop) {
		fprintf(stderr, "!pmemobj_open");
		exit(1);
	}

	attach_to_barrier_and_wait();

	benchmark_time_get(&time_start);
	uint64_t offs[args->nops];
	int ret;
	for (unsigned i = 0; i < args->nops; ++i) {

		ret = pmalloc(pop, &offs[i], args->alloc_size, 0, 0);

	if (ret) {
	    fprintf(stderr, "pmalloc at idx %d ret: %s\n",
		    i, pmemobj_errormsg());
	    /* free the allocated memory */
	    while (i != 0) {
		pfree(pop, &offs[i - 1]);
		i--;
	    }
	    perror("pmalloc");
	    exit(1);
	}
	if (i != 0 && i % 10000 == 0) {
	    benchmark_time_get(&time_curr);
	    benchmark_time_diff(&Ttot_ove, &time_start, &time_curr);

	    /*
	     * subtract time used for getting the current time from the
	     * system
	     */
	//            benchmark_time_t Ttot;
	//            benchmark_time_diff(&Ttot, &Tget, &Ttot_ove);

	//            double Stot = benchmark_time_get_secs(&Ttot);
	    double Stot = benchmark_time_get_secs(&Ttot_ove);
	    sec_acc += Stot;
	    ++rounds;

	    printf("[%i] perf: %lf\n", my_pid, Stot);
	    benchmark_time_get(&time_start);
	}
    }

    printf("[%i] avg. perf: %lf\n", my_pid, sec_acc / rounds);

    pmemobj_close(pop);

    exit(0);
}


/*
 * This function does all the work inside a new process
 */
static void
do_pfree(struct worker_args *args)
{
	pid_t my_pid = getpid();
	printf("[%i] running pfree worker\n", my_pid);

	/* Create pmemobj pool. */
	if (args->alloc_size < ALLOC_MIN_SIZE)
		args->alloc_size = ALLOC_MIN_SIZE;

	double sec_acc = 0;
	int rounds = 0;

	benchmark_time_t time_start;
	benchmark_time_t time_curr;
	benchmark_time_t Ttot_ove;

	/* estimate total penalty of getting time from the system */
	benchmark_time_t Tget;
	unsigned long long nsecs = args->nops * Get_time_avg;
	benchmark_time_set(&Tget, nsecs);

	PMEMobjpool *pop = pmemobj_open(args->path, LAYOUT);
	if (!pop) {
		fprintf(stderr, "!pmemobj_open");
		exit(1);
	}

	attach_to_barrier_and_wait();

	uint64_t offs[args->nops];
	int ret;

	for (unsigned i = 0; i < args->nops; ++i) {

		ret = pmalloc(pop, &offs[i], args->alloc_size, 0, 0);

		if (ret) {
			fprintf(stderr, "pmalloc at idx %d ret: %s\n", i,
			    pmemobj_errormsg());
			/* free the allocated memory */
			while (i != 0) {
				pfree(pop, &offs[i - 1]);
				i--;
			}
			perror("pmalloc");
			exit(1);
		}
	}

	benchmark_time_get(&time_start);
	for (unsigned i = 0; i < args->nops; ++i) {
		ret = pfree(pop, &offs[i]);

		if (ret) {
			fprintf(stderr, "pmalloc at idx %d ret: %s\n",
			    i, pmemobj_errormsg());
			/* free the allocated memory */
			while (i != 0) {
				pfree(pop, &offs[i - 1]);
				i--;
			}
			perror("pmalloc");
			exit(1);
		}
		if (i != 0 && i % 10000 == 0) {
			benchmark_time_get(&time_curr);
			benchmark_time_diff(&Ttot_ove, &time_start, &time_curr);

			/*
			 * subtract time used for getting the current time from the
			 * system
			 */
//            benchmark_time_t Ttot;
//            benchmark_time_diff(&Ttot, &Tget, &Ttot_ove);

			double Stot = benchmark_time_get_secs(&Ttot_ove);
//            double Stot = benchmark_time_get_secs(&Ttot);
			sec_acc += Stot;
			++rounds;

//            printf("[%i] perf: %lf\n", my_pid, Stot);
			benchmark_time_get(&time_start);
		}
	}

	printf("[%i] avg. perf: %lf\n", my_pid, sec_acc / rounds);

	pmemobj_close(pop);

	exit(0);
}


/*
 * run_worker - creates child processes and executes the workers' code in the
 * child.
 */
static void
run_fork_worker(fn_worker worker_func, struct worker_args *args, size_t num_procs)
{
    for (unsigned i = 0; i < num_procs; ++i) {
        if ((Pids[i] = fork()) < 0) {
            fprintf(stderr, "!fork");
            exit(1);
        } else if (Pids[i] == 0) {
            /* child */
            worker_func(args);

            /* if we get here, something unexpected happened */
                    ASSERT(0);
        } else {
            /* parent does nothing */
        }
    }
}


/*
 * init_barrier -- intializes a barrier in shared memory
 */
static void
init_barrier(const char *path, unsigned num_procs) {
	pthread_barrierattr_t attr;
	pthread_barrierattr_init(&attr);
	if (pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
		perror("pthread_barrierattr_setpshared");
		exit(1);
	};

	snprintf(SHM_PATH, sizeof(SHM_PATH) - 1, FILE_SUFFIX_SHM, path);

	unlink(SHM_PATH);
	int fd = open(SHM_PATH, O_RDWR | O_CREAT, (mode_t) 0666);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (ftruncate(fd, sizeof(pthread_barrier_t))) {
		perror("ftruncate");
		exit(1);
	}

	shared_mem_barrier_for_parent = mmap_barrier(fd);
	int err = pthread_barrier_init(shared_mem_barrier_for_parent, &attr,
	    num_procs);
	if (err) {
		perror("pthread_barrier_init");
		exit(1);
	}
	close(fd);
}

int main(int argc, const char *argv[])
{
	if (argc < 6) {
		printf(
		    "usage: mp_bench_worker <poolfile> <type> <num_procs> <nops_per_proc> <alloc_size>");
		exit(EXIT_FAILURE);
	}

	const char *path = argv[1];
	char bench = argv[2][0];
	size_t num_procs = atoi(argv[3]);
	size_t nops_per_proc = atoi(argv[4]);
	size_t alloc_size = atoi(argv[5]);
	    ASSERT(num_procs <= MAX_PROCS);
	    ASSERT(alloc_size < PMEMOBJ_MAX_ALLOC_SIZE);

	printf("running benchmark with given params:\n");
	printf("num_procs:\t%lu\n", num_procs);
	printf("nops_per_proc:\t%lu\n", nops_per_proc);
	printf("alloc_size:\t%lu\n", alloc_size);

	putenv("PMEMOBJ_MULTIPROCESS=1");

	init_barrier(path, num_procs);
	Get_time_avg = benchmark_get_avg_get_time();

	fn_worker worker;

	switch (bench) {
		case 'm':
			worker = do_pmalloc;
			break;
		case 'f':
			worker = do_pfree;
			break;
		default:
			fprintf(stderr, "unknown testcase");
			exit(1);
	}

	size_t n_ops_total = nops_per_proc * num_procs;
	assert(n_ops_total != 0);

	/* Create pmemobj pool. */
	if (alloc_size < ALLOC_MIN_SIZE) {
		alloc_size = ALLOC_MIN_SIZE;
	}

	size_t pool_size = n_ops_total * (alloc_size + OOB_HEADER_SIZE);

	/* multiply by FACTOR for metadata, fragmentation, etc. */
	pool_size = pool_size * FACTOR;

	if (pool_size < PMEMOBJ_MIN_POOL) {
		pool_size = PMEMOBJ_MIN_POOL;
	}

	printf("preparing pool with size %lu\t", pool_size);
	printf("in GB: %lu\n", pool_size / (1024 * 1024 * 1024));

	// create empty poolfile
	unlink(argv[1]);
	PMEMobjpool *pop = pmemobj_create(path, LAYOUT, pool_size, 0666);
	if (pop == NULL) {
		perror("!pmemobj_create");
		exit(1);
	}

	pmemobj_close(pop);

	Pids = malloc(num_procs * sizeof(pid_t));

	struct worker_args args = {
	    .alloc_size = alloc_size,
	    .nops = nops_per_proc,
	    .path = path
	};

	// run worker
	run_fork_worker(worker, &args, num_procs);

	/* parent waits until its childs finished their work */
	for (unsigned j = 0; j < num_procs; j++) {
		int status;
		if (waitpid(Pids[j], &status, 0) < 0) {
			perror("!waitpid failed");
			exit(1);
		}

		if (!WIFEXITED(status)) {
			fprintf(stderr, "[%d] WEXITSTATUS status %d", Pids[j],
			    WEXITSTATUS(status));
			fprintf(stderr, "WTERMSIG status %d", WTERMSIG(status));
			fprintf(stderr, "child process failed");
		}

		    ASSERT(WEXITSTATUS(status) == 0);
	}

	free(Pids);
	printf("benchmark run successful");
}