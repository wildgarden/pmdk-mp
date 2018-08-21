#include <unistd.h>
#include <out.h>
#ifdef _POSIX_SHARED_MEMORY_OBJECTS
#include <sys/mman.h>
#else /* _POSIX_SHARED_MEMORY_OBJECTS */
#error "_POSIX_SHARED_MEMORY_OBJECTS is not present on this system!"
#endif
#include "os_shm.h"
#include "mmap.h"
#include "os.h"

void *
os_shm_get_mmap(int fd, size_t size)
{
	ASSERT(fd > 0);

	void *addr;

	addr = util_map(fd, size, MAP_SHARED, 0, 0);
	if (addr == NULL) {
		LOG(2, "failed to map shm fd \"%d\"", fd);
		goto err;
	}

	return addr;

err:
	return NULL;
}

void *
os_shm_get_posix(const char *name, size_t size, int flags)
{
	LOG(3, "name %s len %zu flags %d", name, size, flags);

	mode_t mode = 0777;

	/*
	 * XXX mp-mode (shm) [normal] handle fork
	 * The FD_CLOEXEC flag (see fcntl(2)) is set for the file descriptor.
	 * FD_CLOEXEC, the close-on-exec flag. If the FD_CLOEXEC bit is 0,
	 * the file descriptor will remain open across an execve(2), otherwise
	 * it will be closed.
	 */
	int fd = shm_open(name, flags, mode);
	if (fd < 0) {
		perror("In shm_open()");

		return NULL;
	}

	void *addr = NULL;

	/*
	 * adjusting mapped file size operation
	 * is idempotent as long as the same size is used
	 */
	if (ftruncate(fd, (off_t)size) < 0) {
		ERR("ftruncate");

		goto err;
	}

	addr = util_map(fd, size, MAP_SHARED, 0, 0);
	if (addr == NULL) {
		LOG(2, "failed to map shm file \"%s\"", name);
		goto err;
	}

err:
	(void) os_close(fd); /* does not affect the mapping */

	return addr;
}


int
os_shm_unlink(const char *name)
{
	LOG(3, "os_shm_unlink shm file: %s", name);

	/*
	 * Only call unlink in the last attached process.
	 *
	 * After a successful shm_unlink(), attempts to shm_open() an object
	 * with the same name will fail (unless O_CREAT was specified, in which
	 * case a new, distinct object is created).
	 */
	return shm_unlink(name);
}