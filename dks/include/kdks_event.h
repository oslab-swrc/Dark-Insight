#ifndef __DKS_KDKS_EVENT_H__
#define __DKS_KDKS_EVENT_H__
#include <kdks.h>
#include <ring_buffer_shm.h>
#include <ring_buffer.h>

int  kdks_open(void);
int  kdks_close(int fd);
int  kdks_evbuf_bind_cpu(int fd, unsigned int cpu);

struct ring_buffer_shm_t *kdks_create_evbuf(int fd, size_t size);
void kdks_destroy_evbuf(struct ring_buffer_shm_t *rbshm);

int  kdks_evbuf_get(struct ring_buffer_shm_t *rbshm,
		   struct ring_buffer_req_t *req);
void kdks_evbuf_get_done(struct ring_buffer_shm_t *rbshm,
			 struct ring_buffer_req_t *req);

int  kdks_start_profile_all(int fd, struct kdks_attr *attr);
int  kdks_stop_profile_all(int fd);

int  kdks_push_spininfo(int fd, struct spininfo *spininfo);
#endif /* __DKS_KDKS_EVENT_H__ */
