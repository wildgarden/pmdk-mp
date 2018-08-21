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
 * malloc.cpp -- external transient malloc benchmarks definition
 */

#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "../benchmarks/benchmark.hpp"
#include "os.h"
#ifdef __cplusplus
extern "C" {
#endif
#ifdef __cplusplus
}
#endif

/*
 * prog_args - command line parsed arguments
 */
struct prog_args {
	size_t minsize;       /* minimum size for random allocation size */
	bool use_random_size; /* if set, use random size allocations */
	unsigned seed;	/* PRNG seed */
};

/*
 * obj_bench - variables used in benchmark, passed within functions
 */
struct obj_bench {
	struct prog_args *pa;      /* prog_args structure */
	size_t *sizes;		   /* sizes for allocations */
	void **offs;		   /* pointer to the vector of offsets */
};

/*
 * obj_init -- common part of the benchmark initialization for malloc and
 * free. It allocates the necessary offset vector.
 */
static int
obj_init(struct benchmark *bench, struct benchmark_args *args)
{
	assert(bench != NULL);
	assert(args != NULL);
	assert(args->opts != NULL);

	if (((struct prog_args *)(args->opts))->minsize >= args->dsize) {
		fprintf(stderr, "Wrong params - allocation size\n");
		return -1;
	}
    size_t n_ops_total = args->n_ops_per_thread * args->n_threads;
    assert(n_ops_total != 0);

	struct obj_bench *ob =
		(struct obj_bench *)malloc(sizeof(struct obj_bench));
	if (ob == NULL) {
		perror("malloc");
		return -1;
	}
	ob->offs = (void **)malloc(n_ops_total * sizeof(void *));

	pmembench_set_priv(bench, ob);

	ob->pa = (struct prog_args *)args->opts;

	ob->sizes = (size_t *)malloc(n_ops_total * sizeof(size_t));
	if (ob->sizes == NULL) {
		fprintf(stderr, "malloc rand size vect err\n");
		goto free_pop;
	}

	if (ob->pa->use_random_size) {
		size_t width = args->dsize - ob->pa->minsize;
		for (size_t i = 0; i < n_ops_total; i++) {
			uint32_t hr = (uint32_t)os_rand_r(&ob->pa->seed);
			uint32_t lr = (uint32_t)os_rand_r(&ob->pa->seed);
			uint64_t r64 = (uint64_t)hr << 32 | lr;
			ob->sizes[i] = r64 % width + ob->pa->minsize;
		}
	} else {
		for (size_t i = 0; i < n_ops_total; i++)
			ob->sizes[i] = args->dsize;
	}

	return 0;

free_pop:
	return -1;
}

/*
 * obj_exit -- common part for the exit function for malloc and free
 * benchmarks. It frees the allocated offset vector and the memory pool.
 */
static int
obj_exit(struct benchmark *bench, struct benchmark_args *args)
{
	struct obj_bench *ob = (struct obj_bench *)pmembench_get_priv(bench);

	free(ob->sizes);
	free(ob->offs);

	return 0;
}

/*
 * malloc_init -- initialization for the malloc benchmark. Performs only the
 * common initialization.
 */
static int
malloc_init(struct benchmark *bench, struct benchmark_args *args)
{
	return obj_init(bench, args);
}

/*
 * malloc_operation -- actual benchmark operation. Performs the malloc allocations.
 */
static int
malloc_operation(struct benchmark *bench, struct operation_info *info)
{
	struct obj_bench *ob = (struct obj_bench *)pmembench_get_priv(bench);

	uint64_t i = info->index +
		info->worker->index * info->args->n_ops_per_thread;

	ob->offs[i] = malloc(ob->sizes[i]);
	if (ob->offs[i] == NULL) {
		fprintf(stderr, "malloc returned NULL \n");
		return -1;
	}

	return 0;
}

/*
 * malloc_exit -- the end of the malloc benchmark. Frees the memory allocated
 * during malloc_operation and performs the common exit operations.
 */
static int
malloc_exit(struct benchmark *bench, struct benchmark_args *args)
{
	struct obj_bench *ob = (struct obj_bench *)pmembench_get_priv(bench);

	for (size_t i = 0; i < args->n_ops_per_thread * args->n_threads; i++) {
		if (ob->offs[i])
			free(ob->offs[i]);
	}

	return obj_exit(bench, args);
}

/*
 * free_init -- initialization for the free benchmark. Performs the common
 * initialization and allocates the memory to be freed during free_op.
 */
static int
free_init(struct benchmark *bench, struct benchmark_args *args)
{
	int ret = obj_init(bench, args);
	if (ret)
		return ret;

	struct obj_bench *ob = (struct obj_bench *)pmembench_get_priv(bench);

	for (size_t i = 0; i < args->n_ops_per_thread * args->n_threads; i++) {
        ob->offs[i] = malloc(ob->sizes[i]);

		if (ob->offs[i] == NULL) {
			fprintf(stderr, "malloc at idx %" PRIu64 " ret null\n", i);
			/* free the allocated memory */
			while (i != 0) {
				free(ob->offs[i - 1]);
				i--;
			}
			obj_exit(bench, args);
			return ret;
		}
	}

	return 0;
}

/*
 * malloc_operation -- actual benchmark operation. Performs the free operation.
 */
static int
free_op(struct benchmark *bench, struct operation_info *info)
{
	struct obj_bench *ob = (struct obj_bench *)pmembench_get_priv(bench);

	uint64_t i = info->index +
		info->worker->index * info->args->n_ops_per_thread;

	if (ob->offs[i] == NULL) {
        fprintf(stderr, "free at idx %" PRIu64 " ret null\n", i);
        return -1;
	}

	free(ob->offs[i]);
	ob->offs[i] = NULL;

	return 0;
}

/* command line options definition */
static struct benchmark_clo malloc_clo[3];
/*
 * Stores information about malloc benchmark.
 */
static struct benchmark_info malloc_info;
/*
 * Stores information about free benchmark.
 */
static struct benchmark_info free_info;

CONSTRUCTOR(obj_malloc_costructor)
void
obj_malloc_costructor(void)
{
	malloc_clo[0].opt_short = 'r';
	malloc_clo[0].opt_long = "random";
	malloc_clo[0].descr = "Use random size allocations - "
			       "from min-size to data-size";
	malloc_clo[0].off =
		clo_field_offset(struct prog_args, use_random_size);
	malloc_clo[0].type = CLO_TYPE_FLAG;

	malloc_clo[1].opt_short = 'm';
	malloc_clo[1].opt_long = "min-size";
	malloc_clo[1].descr = "Minimum size of allocation for "
			       "random mode";
	malloc_clo[1].type = CLO_TYPE_UINT;
	malloc_clo[1].off = clo_field_offset(struct prog_args, minsize);
	malloc_clo[1].def = "1";
	malloc_clo[1].type_uint.size =
		clo_field_size(struct prog_args, minsize);
	malloc_clo[1].type_uint.base = CLO_INT_BASE_DEC;
	malloc_clo[1].type_uint.min = 1;
	malloc_clo[1].type_uint.max = UINT64_MAX;

	malloc_clo[2].opt_short = 'S';
	malloc_clo[2].opt_long = "seed";
	malloc_clo[2].descr = "Random mode seed value";
	malloc_clo[2].off = clo_field_offset(struct prog_args, seed);
	malloc_clo[2].def = "1";
	malloc_clo[2].type = CLO_TYPE_UINT;
	malloc_clo[2].type_uint.size = clo_field_size(struct prog_args, seed);
	malloc_clo[2].type_uint.base = CLO_INT_BASE_DEC;
	malloc_clo[2].type_uint.min = 1;
	malloc_clo[2].type_uint.max = UINT_MAX;

	malloc_info.name = "malloc",
	malloc_info.brief = "Benchmark for external, transient memory malloc() "
			     "operation\n"
        "uses by default standart glib malloc; for jemalloc use: LD_PRELOAD=../nondebug/jemalloc/lib/libjemalloc.so ";
	malloc_info.init = malloc_init;
	malloc_info.exit = malloc_exit;
	malloc_info.multithread = true;
	malloc_info.multiops = true;
	malloc_info.operation = malloc_operation;
	malloc_info.measure_time = true;
	malloc_info.clos = malloc_clo;
	malloc_info.nclos = ARRAY_SIZE(malloc_clo);
	malloc_info.opts_size = sizeof(struct prog_args);
	REGISTER_BENCHMARK(malloc_info);

	free_info.name = "free";
	free_info.brief = "Benchmark for internal free() "
			   "operation";
	free_info.init = free_init;

	free_info.exit = malloc_exit; /* same as for malloc */
	free_info.multithread = true;
	free_info.multiops = true;
	free_info.operation = free_op;
	free_info.measure_time = true;
	free_info.clos = malloc_clo;
	free_info.nclos = ARRAY_SIZE(malloc_clo);
	free_info.opts_size = sizeof(struct prog_args);
	REGISTER_BENCHMARK(free_info);
};
