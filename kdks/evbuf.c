#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/printk.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <ring_buffer.h>
#include <kdks.h>
#include "kdks_i.h"

static DEFINE_PER_CPU(bool, has_rbshm);
static DEFINE_PER_CPU(struct ring_buffer_shm_t, rbshm);
static DEFINE_PER_CPU(wait_queue_head_t, waitq);

#define INVALID_CPU_ID     ((unsigned int)-1)

static void evbuf_cpu_deinit(unsigned int cpu);


int evbuf_open(struct inode *inode, struct file *filp)
{
	int ret;

	ret = generic_file_open(inode, filp);
	if (likely(ret >= 0))
		filp->private_data = (void*)INVALID_CPU_ID;

	return ret;
}

int evbuf_release(struct inode *inode, struct file *filp)
{
	unsigned int cpu;

	/* if it is set to one of possible CPUs,
	 * deinitialize evbuf if any. */
	cpu = (unsigned long)filp->private_data;
	if (cpu != INVALID_CPU_ID && cpu_possible(cpu))
		evbuf_cpu_deinit(cpu);
	return 0;
}

int evbuf_bind_cpu(struct file *filp, unsigned int cpu)
{
	if (!cpu_possible(cpu))
		return -EINVAL;

	filp->private_data = (void *)((unsigned long)cpu);
	return 0;
}

static int alloc_evbuf(unsigned long len, unsigned int cpu)
{
	int ret;

	if (per_cpu(has_rbshm, cpu))
		return -EEXIST;

	ret = ring_buffer_shm_create_master(len - PAGE_SIZE, L1_CACHE_BYTES,
		RING_BUFFER_NON_BLOCKING, RING_BUFFER_PRODUCER, NULL, NULL,
		&per_cpu(rbshm, cpu));
	if (unlikely(ret))
		return ret;

	per_cpu(rbshm, cpu).rb->private_value = &per_cpu(waitq, cpu);
	per_cpu(has_rbshm, cpu) = true;
	return 0;
}

static void free_evbuf(unsigned int cpu)
{
	if (per_cpu(has_rbshm, cpu)) {
		ring_buffer_shm_destroy_master(&per_cpu(rbshm, cpu));
		per_cpu(has_rbshm, cpu) = false;
	}
}

int evbuf_mmap(struct file *filp, struct vm_area_struct *vm_area)
{
	unsigned long len;
	unsigned int  cpu;
	struct ring_buffer_shm_t *prbshm;
	void *vmalloc_start;
	int ret;

	/* check if cpu id is valid */
	cpu = (unsigned long)filp->private_data;
	if (cpu == INVALID_CPU_ID || !cpu_possible(cpu))
		return -EINVAL;

	/* check if all are page-aligend */
	len = vm_area->vm_end - vm_area->vm_start;
	if (len & ~PAGE_MASK || vm_area->vm_pgoff)
		return -EINVAL;

	/* check if it is shared to avoid d-cache aliasing problem */
	if (!(vm_area->vm_flags & VM_SHARED))
		return -EINVAL;

	/* alloc per-cpu event buffer */
	ret = alloc_evbuf(len, cpu);
	if (unlikely(ret < 0)) {
		kdks_pr_error("Fail to alloc evbuf: %d\n", ret);
		return ret;
	}

	/* update the len */
	prbshm = &per_cpu(rbshm, cpu);
	BUG_ON(prbshm->rb->size + PAGE_SIZE != len);

	/* map the allocated event buffer */
	vmalloc_start = prbshm->rb;
	ret = remap_vmalloc_range(vm_area, vmalloc_start, 0);
	if (unlikely(ret < 0)) {
		kdks_pr_error("Fail to remap evbuf: %d\n", ret);
		return ret;
	}

	return ret;
}

static struct ring_buffer_shm_t *get_bound_evbuf(struct file *filp)
{
	unsigned cpu = (unsigned long)filp->private_data;
	if (cpu == INVALID_CPU_ID || !cpu_possible(cpu) || !per_cpu(has_rbshm, cpu))
		return NULL;
	return &per_cpu(rbshm, cpu);
}

static int enough_events(struct ring_buffer_shm_t *prbshm, int level)
{
	/* Is an event buffer filled more than half?
	 * I.e., is free space less than half? */
	return (prbshm->rb->size >> 1) >= ring_buffer_shm_free_space(prbshm, level);
}

unsigned int evbuf_poll(struct file *filp, poll_table *wait)
{
	struct ring_buffer_shm_t *rb_shm;
	unsigned int cpu;

	/* It is okay to poll on unbound cpu */
	cpu = (unsigned long)filp->private_data;
	poll_wait(filp, &per_cpu(waitq, cpu), wait);
	smp_mb();

	/* To have enough events,
	 * filp must have an bound event buffer
	 * and the buffer should be filled more than half. */
	rb_shm = get_bound_evbuf(filp);
	if (rb_shm && enough_events(rb_shm, 0) && enough_events(rb_shm, 1))
		return POLLIN | POLLRDNORM;
	return 0;
}

struct ring_buffer_shm_t * get_evbuf(unsigned int cpu)
{
	return per_cpu(has_rbshm, cpu) ? &per_cpu(rbshm, cpu) : NULL;
}

struct ring_buffer_shm_t * get_this_evbuf(void)
{
	return get_evbuf(get_cpu());
}

void put_this_evbuf(void)
{
	put_cpu();
}

int evbuf_put(struct ring_buffer_shm_t *prbshm,
	      struct ring_buffer_req_t *req, size_t size)
{
	ring_buffer_put_req_init(req, BLOCKING, size);
	return ring_buffer_shm_put_nolock(prbshm, req);
}

void evbuf_put_done(struct ring_buffer_shm_t *prbshm,
		    struct ring_buffer_req_t *req)
{
	/* set done */
	ring_buffer_shm_elm_set_ready(prbshm, req->data);

	/* wake up if there are enough number of events */
	if (enough_events(prbshm, 0)) {
		wait_queue_head_t *pwaitq;
		pwaitq = (wait_queue_head_t *)prbshm->rb->private_value;
		wake_up(pwaitq);
	}
}

static void evbuf_cpu_init(unsigned int cpu)
{
	per_cpu(has_rbshm, cpu) = false;
	init_waitqueue_head(&per_cpu(waitq, cpu));
}

static void evbuf_cpu_deinit(unsigned int cpu)
{
	free_evbuf(cpu);
	init_waitqueue_head(&per_cpu(waitq, cpu));
}

void init_evbuf(void)
{
	unsigned long cpu;
	for_each_possible_cpu(cpu)
		evbuf_cpu_init(cpu);
}

void deinit_evbuf(void)
{
	unsigned long cpu;

	/* deinit per-cpu structures */
	for_each_possible_cpu(cpu)
		evbuf_cpu_deinit(cpu);
}

int __evbuf_put_3(struct file *filp)
{
	struct ring_buffer_shm_t *rb_shm;
	unsigned long mark;
	struct ring_buffer_req_t rb_req;
	int ret;
	int i;

	rb_shm = get_bound_evbuf(filp);
	if (!rb_shm)
		return -EINVAL;

	mark = __KDKS_POISON;
	i = 3;
	while (i--) {
		ret = evbuf_put(rb_shm, &rb_req, sizeof(mark));
		if (ret)
			return ret;

		copy_to_ring_buffer_shm(rb_shm, rb_req.data, &mark, sizeof(mark));
		evbuf_put_done(rb_shm, &rb_req);
		++mark;
	}

	return 0;
}

int __evbuf_put_enough(struct file *filp)
{
	struct ring_buffer_shm_t *prbshm;
	struct ring_buffer_req_t request;
	unsigned long mark = __KDKS_POISON;
	int count = 0;

	prbshm = get_bound_evbuf(filp);
	if (!prbshm)
		return -EINVAL;

	enough_events(prbshm, 1);
	while (!enough_events(prbshm, 0)) {
		// FIXME: Where does 2048 come from?
		int result = evbuf_put(prbshm, &request, sizeof(2048));
		if (result)
			return result;

		copy_to_ring_buffer_shm(prbshm, request.data, &mark, sizeof(mark));
		evbuf_put_done(prbshm, &request);
		++count;
		++mark;
	}
	return count;
}
