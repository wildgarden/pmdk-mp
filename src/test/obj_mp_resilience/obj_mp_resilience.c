/*
 * Copyright 2015-2017, Intel Corporation
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
 * obj_mp_resilience.c -- unit test which checks libpmemobj's fault resilience
 * to errors that happen in a different process, while running in multiprocess
 * mode.
 *
 * inspired by obj_heap_interrupt.c
 */

#include "pmalloc.h"
#include "heap_layout.h"
#include "memops.h"
#include "unittest.h"
#define LAYOUT "obj_mp_resilience"

#define SLEEP_TIMEOUT (OBJ_SHM_MTX_TIMEOUT + 5)
static int scenario;
const char *path_sync_file;

enum actions {
    EXIT_ON_PROCESS,
    LAG,
    REAL
};

POBJ_LAYOUT_BEGIN(obj_mp_resilience);
POBJ_LAYOUT_ROOT(obj_mp_resilience, struct my_root);
POBJ_LAYOUT_END(obj_mp_resilience);

struct my_root {
    uint64_t offset;
};


PMEMoid Oids[3];

/*
 * When true, recovery is run, otherwise mocked.
 */
static int run_recovery = 0;

/*
 * obj_check_liveliness_and_recover -- obj_crash_check_and_recover mock
 *
 * Always returns zero recovered processes when mocked.
 */
FUNC_MOCK(obj_crash_check_and_recover, int,
	PMEMobjpool *pop)
		FUNC_MOCK_RUN_DEFAULT {
			switch (run_recovery) {
				case 0:
					return 1;
				case 1:
					return _FUNC_REAL(
					    obj_crash_check_and_recover)(pop);
				default:
					UT_ASSERT(0);
			}
		}
FUNC_MOCK_END

static enum actions action = REAL;
FUNC_MOCK(operation_process, void, struct operation_context *ctx)
		FUNC_MOCK_RUN_DEFAULT {
			switch (action) {
				case EXIT_ON_PROCESS:
					exit(0);
				case LAG:
					UT_OUT("[%ld] operation_process() "
	    "hangs (sleeps) for %d seconds", (long)getpid(), SLEEP_TIMEOUT);
					sleep(SLEEP_TIMEOUT);
					break;
				case REAL:
					_FUNC_REAL(operation_process)(ctx);
					break;
				default:
					UT_ASSERT(0);
			}
		}
FUNC_MOCK_END

#ifndef _WIN32
/*
 * obj_build_suffix_file -- (internal) create a pathname with a given suffix
 */
static inline const char *
build_suffix_file(const char *path, const char *fmt)
{
	/* static, thus auto-initialized to zero */
	static char buffer[PATH_MAX];
	snprintf(buffer, sizeof(buffer) - 1, fmt, path);

	return buffer;
}


static void
sc2_create(char *path)
{
	PMEMobjpool *pop = pmemobj_create(path, LAYOUT, PMEMOBJ_MIN_POOL,
		S_IWUSR | S_IRUSR);
	if (!pop)
		UT_FATAL("!create");

	TX_BEGIN(pop) {
		Oids[0] = pmemobj_tx_alloc(CHUNKSIZE - 100, 0);
		Oids[1] = pmemobj_tx_alloc(CHUNKSIZE * 20, 0); /* def. bucket */
	} TX_END

	pmemobj_free(&Oids[0]);

	TOID(struct my_root) root = POBJ_ROOT(pop, struct my_root);

	D_RW(root)->offset = Oids[1].off;

	/* wait until the other process opened the pool */
	while (os_access(path_sync_file, R_OK))
		usleep(100 * 1000);

	action = EXIT_ON_PROCESS;
	UT_OUT("Simulated crash in next function call");
	pmemobj_realloc(pop, &Oids[1], CHUNKSIZE * 21, 0);

	/* if we get here, something is wrong with function mocking */
	UT_ASSERT(0);
}

/*
 * sc2_verify -- verify that recovery works as expected and no error is returned
 */
static void
sc2_verify(PMEMobjpool *pop, pid_t pid)
{
	int status;

	/*
	 * wait for the other process to finish its work
	 * This is an ugly workaround. It needs proper (more robust) syncing.
	 */
	sleep(1);

	run_recovery = 1;

	if (waitpid(pid, &status, 0) < 0)
		UT_FATAL("!waitpid failed");

	if (!WIFEXITED(status))
		UT_FATAL("child process failed");

	PMEMoid oid = {0, 0};
	int ret = pmalloc(pop, &oid.off, 100, 0, 0);

	UT_ASSERTeq(ret, 0);
	UT_ASSERTeq(errno, 0);
	/* XXX mp-mode implement redo_log_check() */
	/* ret = redo_log_check(pop->redo, redo, redo_cnt); */
	/* UT_OUT("C:%d", ret); */
}

static void
sc1_create(char *path)
{
	/* runs in child */
	PMEMobjpool *pop = pmemobj_create(path, LAYOUT, PMEMOBJ_MIN_POOL,
		S_IWUSR | S_IRUSR);
	if (!pop)
		UT_FATAL("!create");

	TX_BEGIN(pop) {
		Oids[0] = pmemobj_tx_alloc(CHUNKSIZE - 100, 0);
		Oids[1] = pmemobj_tx_alloc(CHUNKSIZE * 20, 0); /* def. bucket */
	} TX_END

	pmemobj_free(&Oids[0]);

	TOID(struct my_root) root = POBJ_ROOT(pop, struct my_root);

	D_RW(root)->offset = Oids[1].off;

	/* wait until the other process opened the pool */
	while (os_access(path_sync_file, R_OK))
		usleep(100 * 1000);
	UT_OUT("[%ld] found sync file", (long)getpid());

	action = LAG;
	UT_ASSERT_rt(SLEEP_TIMEOUT > OBJ_SHM_MTX_TIMEOUT);
	UT_OUT("[%ld] Simulating long lag in next function call"
	    " (pmemobj_free())", (long)getpid());
	pmemobj_realloc(pop, &Oids[1], CHUNKSIZE * 21, 0);
	UT_OUT("[%ld] long running pmemobj_free finished", (long)getpid());

	pmemobj_close(pop);
	exit(0);
}

/*
 * sc1_verify -- verify that ETIMEDOUT is returned when a lock could not be
 * obtained in the defined timeout.
 */
static void
sc1_verify(PMEMobjpool *pop, pid_t pid)
{
	int status;

	/*
	 * XXX mp-mode -- (test) [normal] needs proper (more robust) syncing.
	 * wait for the other process to finish its work.
	 * This is an ugly workaround.
	 */
	sleep(1);

	run_recovery = 0;
	action = REAL;
	UT_OUT("[%ld] pmalloc() start", (long)getpid());
	TOID(struct my_root) root = POBJ_ROOT(pop, struct my_root);
	uint64_t offset = D_RO(root)->offset;

	int ret = pfree(pop, &offset);

	UT_OUT("[%ld] pmalloc() finished", (long)getpid());
	UT_ASSERTeq(ret, -1);
	UT_ASSERTeq(errno, ETIMEDOUT);

	if (waitpid(pid, &status, 0) < 0)
		UT_FATAL("!waitpid failed");

	if (!WIFEXITED(status))
		UT_FATAL("child process failed");
}

static void
sc0_create(char *path)
{
	PMEMobjpool *pop = pmemobj_create(path, LAYOUT, PMEMOBJ_MIN_POOL,
		S_IWUSR | S_IRUSR);
	if (!pop)
		UT_FATAL("!create");

	TX_BEGIN(pop) {
		Oids[0] = pmemobj_tx_alloc(CHUNKSIZE - 100, 0);
		Oids[1] = pmemobj_tx_alloc(CHUNKSIZE * 20, 0); /* def. bucket */
	} TX_END

	pmemobj_free(&Oids[0]);

	TOID(struct my_root) root = POBJ_ROOT(pop, struct my_root);

		D_RW(root)->offset = Oids[1].off;

	/* wait until the other process opened the pool */
	while (os_access(path_sync_file, R_OK))
		usleep(100 * 1000);

	action = EXIT_ON_PROCESS;
	run_recovery = 0;
	UT_OUT("Simulated crash in next function call");
	pmemobj_realloc(pop, &Oids[1], CHUNKSIZE * 21, 0);

	/* if we get here, something is wrong with function mocking */
	UT_ASSERT(0);
}

/*
 * sc0_verify -- verify that ENOTRECOVERABLE is returned when a process crashed
 * while holding a lock, and recovery is dissabled
 */
static void
sc0_verify(PMEMobjpool *pop, pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) < 0)
		UT_FATAL("!waitpid failed");

	if (!WIFEXITED(status))
		UT_FATAL("child process failed");

	run_recovery = 0;

	TOID(struct my_root) root = POBJ_ROOT(pop, struct my_root);
	uint64_t offset = D_RO(root)->offset;

	int ret = pfree(pop, &offset);
	UT_ASSERTeq(ret, -1);

	UT_ASSERTeq(errno, ENOTRECOVERABLE);
}

typedef void (*scenario_create_func)(char *path);
typedef void (*scenario_verify_func)(PMEMobjpool *pop, pid_t pid);

static struct {
    scenario_create_func create;
    scenario_verify_func verify;
} scenarios[] = {
	{sc0_create, sc0_verify},
	{sc1_create, sc1_verify},
	{sc2_create, sc2_verify},
};

static void
test_pmalloc(int argc, char **argv)
{
	char *path = argv[1];
	path_sync_file = build_suffix_file(path, "%s_sc0");
	unlink(path);
	unlink(path_sync_file);

	pid_t pid = fork();
	if (pid < 0)
		UT_FATAL("fork failed");

	if (pid == 0) {
		/* child */

		scenarios[scenario].create(path);

		/* if we get here, something is wrong with function mocking */
		UT_ASSERT(0);
	}

	/* wait until the child created the pool */
	UT_OUT("[%ld] wait until child created the pool", (long)getpid());
	while (os_access(path, R_OK))
		usleep(100 * 1000);

	PMEMobjpool *pop = pmemobj_open(path, LAYOUT);
	if (!pop)
		UT_FATAL("pmemobj_open from another process"
			"should succeed");

	/*
	 * Same pool is now open in both processes.
	 * The other process is waiting for this file before it continues.
	 */
	int fd;
	if ((fd = open(path_sync_file,
	    O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH)) < 0) {
		UT_FATAL("open sync file");
	}
	UT_OUT("[%ld] created sync file", (long)getpid());
	/* give the other process some time to proceed and finish its work */
	sleep(1);

	/* verify 'our' pool */
	scenarios[scenario].verify(pop, pid);
	CLOSE(fd);
	pmemobj_close(pop);

	UNLINK(path);
}
#endif


int
main(int argc, char *argv[])
{
	START(argc, argv, "obj_mp_resilience");

	if (argc < 3)
		UT_FATAL("usage: %s file [scenario]", argv[0]);

	scenario = atoi(argv[2]);
	if (argc == 3) {
		test_pmalloc(argc, argv);
	} else if (argc == 4) {
		UT_FATAL("Not yet implemented");

		PMEMobjpool *pop;
		/* 2nd arg used by windows for 2 process test */
		pop = pmemobj_open(argv[1], LAYOUT);
		if (!pop)
			UT_FATAL("pmemobj_open should succeed");
	}

	DONE(NULL);
}
