#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "kdks_event.h"
#include "spintable.h"

int kdks_open(void)
{
	return open("/dev/kdks", O_RDWR);
}

int kdks_close(int fd)
{
	return close(fd);
}

struct ring_buffer_shm_t *kdks_create_evbuf(int fd, size_t size)
{
	void *evbuf = NULL;
	struct ring_buffer_shm_t *rb_shm = NULL;

	/* size should be page-aligned */
	if (size & ~PAGE_MASK || size < (2 * PAGE_SIZE))
		return NULL;

	/* mmap evbuf */
	evbuf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (evbuf == MAP_FAILED)
		return NULL;

	/* create a shadow buffer on the mmap evbuf */
	rb_shm = (struct ring_buffer_shm_t *)malloc(sizeof(*rb_shm));
	if (!rb_shm) {
		munmap(evbuf, size);
		return NULL;
	}

	if (ring_buffer_shm_create_shadow(evbuf, RING_BUFFER_CONSUMER, NULL, NULL, rb_shm)) {
		munmap(evbuf, size);
		free(rb_shm);
		return NULL;
	}

	return rb_shm;
}

void kdks_destroy_evbuf(struct ring_buffer_shm_t *rbshm)
{
	void *evbuf;
	size_t size;

	// Why do we offset buffer address by PAGE_SIZE?
	evbuf = rbshm->rb->buff - PAGE_SIZE;
	size  = rbshm->rb->size;
	munmap(evbuf, size);

	/* destroy shadow */
	ring_buffer_shm_destroy_shadow(rbshm);
	free(rbshm);
}

int kdks_evbuf_bind_cpu(int fd, unsigned int cpu)
{
	return ioctl(fd, KDKS_IOC_BIND_CPU, cpu);
}

int kdks_evbuf_get(struct ring_buffer_shm_t *rbshm, struct ring_buffer_req_t *req)
{
	ring_buffer_get_req_init(req, BLOCKING);
	return ring_buffer_shm_get_nolock(rbshm, req);
}

void kdks_evbuf_get_done(struct ring_buffer_shm_t *rbshm,
			 struct ring_buffer_req_t *req)
{
	ring_buffer_shm_elm_set_done(rbshm, req->data);
}

int kdks_start_profile_all(int fd, struct kdks_attr *attr)
{
	return ioctl(fd, KDKS_IOC_START_ALL, attr);
}

int kdks_stop_profile_all(int fd)
{
	return ioctl(fd, KDKS_IOC_STOP_ALL);
}

int kdks_push_spininfo(int fd, struct spininfo *spininfo)
{
	return ioctl(fd, KDKS_IOC_PUSH_SPININFO, spininfo);
}
