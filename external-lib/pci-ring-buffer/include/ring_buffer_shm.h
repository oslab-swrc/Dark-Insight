#ifndef _RING_BUFFER_SHM_H_
#define _RING_BUFFER_SHM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ring_buffer_common.h>

/*
 * ring buffer across accress spaces
 */
struct ring_buffer_t;

struct ring_buffer_shm_t {
	struct ring_buffer_t *rb;    /* ring buffer object */
	int                  type;   /* producer or consumer */
	int        is_master;        /* master or slave */
} ____cacheline_aligned;


/*
 * ring buffer shm API
 */
int __ring_buffer_shm_create_master(
	const char *where, unsigned int line, const char *var,
	size_t size_hint, size_t align,
	int is_blocking, int type,
	ring_buffer_reap_cb_t reap_cb, void* reap_cb_arg,
	struct ring_buffer_shm_t *rbs);

#define ring_buffer_shm_create_master(size_hint, align, is_blocking, type, \
				       reap_cb, reap_cb_arg, rbs)	\
	__ring_buffer_shm_create_master(__func__, __LINE__, #rbs, \
					 size_hint, align, is_blocking, \
					 type, reap_cb, reap_cb_arg, rbs)
void ring_buffer_shm_destroy_master(struct ring_buffer_shm_t *rbs);

int __ring_buffer_shm_create_shadow(
	const char *where, unsigned int line, const char *var,
	void *map_addr, int type, ring_buffer_reap_cb_t reap_cb,
	void* reap_cb_arg, struct ring_buffer_shm_t *rbs);

#define ring_buffer_shm_create_shadow(map_addr, type, reap_cb, reap_cb_arg, rbs) \
	__ring_buffer_shm_create_shadow(__func__, __LINE__, #rbs,	\
					map_addr, type, \
					reap_cb, reap_cb_arg, rbs)
void ring_buffer_shm_destroy_shadow(struct ring_buffer_shm_t *rbs);

int  ring_buffer_shm_put(struct ring_buffer_shm_t *rbs,
			  struct ring_buffer_req_t *req);
int  ring_buffer_shm_get(struct ring_buffer_shm_t *rbs,
			  struct ring_buffer_req_t *req);
int  ring_buffer_shm_put_nolock(struct ring_buffer_shm_t *rbs,
				 struct ring_buffer_req_t *req);
int  ring_buffer_shm_get_nolock(struct ring_buffer_shm_t *rbs,
				 struct ring_buffer_req_t *req);

void ring_buffer_shm_elm_set_ready(struct ring_buffer_shm_t *rbs,
				    void *data);
void ring_buffer_shm_elm_set_done(struct ring_buffer_shm_t *rbs,
				   void *data);

int  copy_from_ring_buffer_shm(struct ring_buffer_shm_t *rbs,
				void *dest_mem, const void *src_rbs, size_t n);
int  copy_to_ring_buffer_shm(struct ring_buffer_shm_t *rbs,
			      void *dest_rbs, const void *src_mem, size_t n);

int    ring_buffer_shm_is_empty(struct ring_buffer_shm_t *rbs);
int    ring_buffer_shm_is_full(struct ring_buffer_shm_t *rbs);
size_t ring_buffer_shm_free_space(struct ring_buffer_shm_t *rbs, int level);
#ifdef __cplusplus
}
#endif
#endif /* _RING_BUFFER_SHM_H_ */
