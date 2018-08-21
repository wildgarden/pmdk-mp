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
 * obj_mp_swmr.c -- integration test for multiple-processes (single writer
 * multiple reader)running on same pool
 *
 * usage: obj_mp_swmr file num_procs num_ops
 *
 */

#include <pthread.h>
#include "unittest.h"
#include "../../examples/libpmemobj/mp/reader_writer/layout.h"

#define PATH_WRITER_S "../../examples/libpmemobj/mp/reader_writer_sync/writer"
#define PATH_READER_S "../../examples/libpmemobj/mp/reader_writer_sync/reader"

int
main(int argc, char *argv[])
{
	START(argc, argv, "obj_mp_swmr");

	if (argc != 4)
		UT_FATAL("usage: %s file num_procs num_ops", argv[0]);

	int num_procs = atoi(argv[2]);
	int num_ops = atoi(argv[3]);
	UT_ASSERT(num_procs >= 0);
	UT_ASSERT(num_ops >= 0);

	const char *path = argv[1];
	if (access(path, F_OK) != 0) {
		PMEMobjpool *pop;
		if ((pop = pmemobj_create(path, POBJ_LAYOUT_NAME(reader_writer),
			PMEMOBJ_MIN_POOL, S_IWUSR | S_IRUSR)) == NULL)
			UT_FATAL("!pmemobj_create: %s", path);
		pmemobj_close(pop);
	}

	pid_t pids[num_procs];
	int n = num_procs;
	int i;

	/* Start children. */
	for (i = 0; i < n; ++i) {
		if ((pids[i] = fork()) < 0) {
			UT_FATAL("!fork");
		} else if (pids[i] == 0) {
			if (i == 0) {
				if (execl(PATH_WRITER_S,
					"writer",
					argv[1], argv[3], NULL) < 0) {
					UT_FATAL("!execl writer");
				}
			} else {
				if (execl(PATH_READER_S,
					"reader",
					argv[1], argv[3], NULL) < 0) {
					UT_FATAL("!execl reader");
				}
			}
			exit(0);
		}
	}

	/* parent */
	for (int j = 0; j < num_procs; j++) {
		int status;
		if (waitpid(pids[j], &status, 0) < 0)
			UT_FATAL("!waitpid failed");

		if (!WIFEXITED(status)) {
			UT_ERR("WEXITSTATUS status %d", WEXITSTATUS(status));
			UT_ERR("WTERMSIG status %d", WTERMSIG(status));
			UT_FATAL("child process failed");
		}

		UT_ASSERTeq(WEXITSTATUS(status), 0);
	}

	DONE(NULL);
}
