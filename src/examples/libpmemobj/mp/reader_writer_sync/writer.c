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
 */

/*
 * writer.c -- writer for multi process test
 */

#include <stdio.h>
#include <libpmemobj.h>
#include <stdlib.h>
#include <unistd.h>
#include "../reader_writer/layout.h"

/*
 * write -- the work the writer performs
 */
static int
do_write(PMEMobjpool *pop, int nops)
{
	PMEMoid root = pmemobj_root(pop, sizeof(struct my_root));
	struct my_root *rootp = pmemobj_direct(root);
	printf("hello from writer with pid: %d\n", getpid());
	for (int i = 0; i < nops; ++i) {
		pmemobj_mutex_lock_mp(pop, &rootp->mtx);
		++(rootp->counter);
		++(rootp->counter);
		pmemobj_mutex_unlock_mp(pop, &rootp->mtx);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	if (argc != 3) {
		printf("usage: %s file-name nops\n", argv[0]);
		return -1;
	}

	int nops = atoi(argv[2]);

	PMEMobjpool *pop = pmemobj_open(argv[1],
		POBJ_LAYOUT_NAME(reader_writer));
	if (pop == NULL) {
		perror("pmemobj_open");
		return -1;
	}

	int ret = do_write(pop, nops);

	pmemobj_close(pop);

	return ret;
}
