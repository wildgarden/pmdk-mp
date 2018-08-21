#ifndef NVML_SHM_UTILS_H
#define NVML_SHM_UTILS_H 1

#define OS_SHM_PREFIX "NVML_MULTIPROCESS"

void *os_shm_get_mmap(int fd, size_t size);

void *os_shm_get_posix(const char *name, size_t size, int flags);

int os_shm_unlink(const char *name);

#endif
