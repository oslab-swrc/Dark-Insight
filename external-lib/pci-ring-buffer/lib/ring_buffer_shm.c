#include <ring_buffer_shm.h>
#include <ring_buffer.h>
#include "ring_buffer_porting.h"
#include "ring_buffer_i.h"

int __ring_buffer_shm_create_master(
	const char *where, unsigned int line, const char *var,
	size_t size_hint, size_t align,
	int is_blocking, int type,
	ring_buffer_reap_cb_t reap_cb, void* reap_cb_arg,
	struct ring_buffer_shm_t *rbs)
{
	int rc;

	/* sanity check */
	if ( (type != RING_BUFFER_PRODUCER) &&
	     (type != RING_BUFFER_CONSUMER) )
		return -EINVAL;

	/* init rbs */
	memset(rbs, 0, sizeof(*rbs));
	rbs->is_master   = 1;
	rbs->type        = type;

	/* allocate a ring buffer */
	rc = __ring_buffer_create(where, line, var,
				  size_hint, align, is_blocking,
				  reap_cb, reap_cb_arg, &rbs->rb);
	if (rc)
		goto err_out;

	return 0;
err_out:
	/* clean up a partially created ring buffer */
	ring_buffer_shm_destroy_master(rbs);
	return rc;
}
EXPORT_SYMBOL(__ring_buffer_shm_create_master);

void ring_buffer_shm_destroy_master(struct ring_buffer_shm_t *rbs)
{
	if (!rbs)
		return;
	ring_buffer_destroy(rbs->rb);
}
EXPORT_SYMBOL(ring_buffer_shm_destroy_master);

int __ring_buffer_shm_create_shadow(
	const char *where, unsigned int line, const char *var,
	void *map_addr, int type, ring_buffer_reap_cb_t reap_cb,
	void* reap_cb_arg, struct ring_buffer_shm_t *rbs)
{
	struct ring_buffer_t *remote_rb;
	int rc = 0;

	/* init rbs */
	memset(rbs, 0, sizeof(*rbs));
	rbs->rb = __rb_calloc(1, sizeof(struct ring_buffer_t));
	if (!rbs->rb) {
		rc = -ENOMEM;
		goto err_out;
	}
	rbs->type = type;

	/* init shadow ring buffer */
	remote_rb              = map_addr;
	rbs->rb->size          = remote_rb->size;
	rbs->rb->buff          = __map_addr_to_rb_buff(map_addr);
	rbs->rb->align_mask    = remote_rb->align_mask;
	rbs->rb->head          = remote_rb->head;
	rbs->rb->tail          = remote_rb->tail;
	rbs->rb->tail2         = remote_rb->tail2;
	rbs->rb->is_blocking   = remote_rb->is_blocking;

	/* init nap time */
	rc = _ring_buffer_init_nap_time(rbs->rb);
	if (rc)
		goto err_out;

	/* instal an user-defined reap callback */
	rbs->rb->reap_cb     = reap_cb;
	rbs->rb->reap_cb_arg = reap_cb_arg;

	/* record my name */
	snprintf(rbs->rb->name, RING_BUFFER_NAME_MAX,
		 "%s@%s:%d", var, where, line);
	rbs->rb->name[RING_BUFFER_NAME_MAX - 1] = '\0';

#ifndef RING_BUFFER_CONF_NO_DOUBLE_MMAP
	/* check whether a ring buffer is a really ring */
	int *p, *q;
	p = (int *)rbs->rb->buff;
	q = (int *)(rbs->rb->buff + rbs->rb->size);
	if (p != q) {
		rb_assert(*p == *q,
			  "ring buffer is not a ring");
	}
#endif
	return 0;
err_out:
	/* clean up a partially created ring buffer */
	rb_dbg("fail to create a shadow: %d\n", rc);
	ring_buffer_shm_destroy_shadow(rbs);
	return rc;
}
EXPORT_SYMBOL(__ring_buffer_shm_create_shadow);

void ring_buffer_shm_destroy_shadow(struct ring_buffer_shm_t *rbs)
{
	if (!rbs)
		return;

	/* then release resources */
	if (rbs->rb) {
		_ring_buffer_deinit_nap_time(rbs->rb);
		__rb_free(rbs->rb);
	}
	memset(rbs, 0, sizeof(*rbs));
}
EXPORT_SYMBOL(ring_buffer_shm_destroy_shadow);

int  ring_buffer_shm_put(struct ring_buffer_shm_t *rbs,
			  struct ring_buffer_req_t *req)
{
	/* sanity check */
	if ( unlikely(rbs->type != RING_BUFFER_PRODUCER) )
		return -EOPNOTSUPP;

	/* ring buffer operation */
	return ring_buffer_put(rbs->rb, req);
}
EXPORT_SYMBOL(ring_buffer_shm_put);

int  ring_buffer_shm_put_nolock(struct ring_buffer_shm_t *rbs,
				 struct ring_buffer_req_t *req)
{
	/* sanity check */
	if ( unlikely(rbs->type != RING_BUFFER_PRODUCER) )
		return -EOPNOTSUPP;

	/* ring buffer operation */
	return ring_buffer_put_nolock(rbs->rb, req);
}
EXPORT_SYMBOL(ring_buffer_shm_put_nolock);

int  ring_buffer_shm_get(struct ring_buffer_shm_t *rbs,
			  struct ring_buffer_req_t *req)
{
	/* sanity check */
	if ( unlikely(rbs->type != RING_BUFFER_CONSUMER) )
		return -EOPNOTSUPP;

	/* ring buffer operation */
	return ring_buffer_get(rbs->rb, req);
}
EXPORT_SYMBOL(ring_buffer_shm_get);

int ring_buffer_shm_get_nolock(struct ring_buffer_shm_t *rbs, struct ring_buffer_req_t *req)
{
	/* sanity check */
	if (unlikely(rbs->type != RING_BUFFER_CONSUMER))
		return -EOPNOTSUPP;

	/* ring buffer operation */
	return ring_buffer_get_nolock(rbs->rb, req);
}
EXPORT_SYMBOL(ring_buffer_shm_get_nolock);

void ring_buffer_shm_elm_set_ready(struct ring_buffer_shm_t *rbs,
				    void *data)
{
	/* sanity check: siliently ignore an error */
	if ( unlikely(rbs->type != RING_BUFFER_PRODUCER) ) {
		rb_assert(0, "set-ready is not allowed");
		return;
	}

	/* set ready */
	ring_buffer_elm_set_ready(rbs->rb, data);
}
EXPORT_SYMBOL(ring_buffer_shm_elm_set_ready);

void ring_buffer_shm_elm_set_done(struct ring_buffer_shm_t *rbs, void *data)
{
	/* sanity check: siliently ignore an error */
	if ( unlikely(rbs->type != RING_BUFFER_CONSUMER) ) {
		rb_assert(0, "set-done is not allowed");
		return;
	}

	/* set done */
	ring_buffer_elm_set_done(rbs->rb, data);
}
EXPORT_SYMBOL(ring_buffer_shm_elm_set_done);

int copy_from_ring_buffer_shm(struct ring_buffer_shm_t *rbs,
			      void *dest_mem, const void *src_rbs, size_t n)
{
	return copy_from_ring_buffer(rbs->rb, dest_mem, src_rbs, n);
}
EXPORT_SYMBOL(copy_from_ring_buffer_shm);

int copy_to_ring_buffer_shm(struct ring_buffer_shm_t *rbs,
			    void *dest_rbs, const void *src_mem, size_t n)
{
	return copy_to_ring_buffer(rbs->rb, dest_rbs, src_mem, n);
}
EXPORT_SYMBOL(copy_to_ring_buffer_shm);

int ring_buffer_shm_is_empty(struct ring_buffer_shm_t *rbs)
{
	return ring_buffer_is_empty(rbs->rb);
}
EXPORT_SYMBOL(ring_buffer_shm_is_empty);

int  ring_buffer_shm_is_full(struct ring_buffer_shm_t *rbs)
{
	return ring_buffer_is_full(rbs->rb);
}
EXPORT_SYMBOL(ring_buffer_shm_is_full);

size_t ring_buffer_shm_free_space(struct ring_buffer_shm_t *rbs, int level)
{
	/* NOTE: only a producer can reap elements */
	if (level && rbs->type != RING_BUFFER_PRODUCER) {
		level = 0;
	}
	return ring_buffer_free_space(rbs->rb, level);
}
EXPORT_SYMBOL(ring_buffer_shm_free_space);
