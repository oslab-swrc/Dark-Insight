#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>

#include "dks.h"
#include "spintable.h"

#include "util/util.h"
#include "util/debug.h"

#define EV_BUF_SZ (256*1024*1024)

static int *kdks_fds = NULL;		/* kdks file desc.*/
static struct ring_buffer_shm_t	**kdks_ev_queues = NULL;

/*init kdks files*/
static int kdks__init_event_files(int nr_cpus)
{
	// Create perf_fds
	kdks_fds = (int *)malloc(nr_cpus * sizeof(int));
	if (!kdks_fds)
		return -ENOMEM;

	while (nr_cpus--)
		kdks_fds[nr_cpus] = -1;

	return 0;
}

/*close all open files and free fds*/
static void kdks__free_event_files(int nr_cpus)
{
	if (!kdks_fds)
		return;

	if (nr_cpus < 0)
		return;

	while (nr_cpus--) {
		if (kdks_fds[nr_cpus] == -1)
			continue;
		close(kdks_fds[nr_cpus]);
	}

	free(kdks_fds);
	kdks_fds = NULL;
}

static int kdks__init_event_queues(int nr_cpus)
{
	if (nr_cpus < 0)
		return -EINVAL;

	kdks_ev_queues = (struct ring_buffer_shm_t **)malloc(sizeof(struct ring_buffer_shm_t *) * nr_cpus);
	if (!kdks_ev_queues)
		return -ENOMEM;

	while (nr_cpus--)
		kdks_ev_queues[nr_cpus] = NULL;

	return 0;
}

static void kdks__free_event_queues(int nr_cpus)
{
	if (!kdks_ev_queues || nr_cpus < 0)
		return;

	while (nr_cpus--) {
		if (!kdks_ev_queues[nr_cpus])
			continue;
		kdks_destroy_evbuf(kdks_ev_queues[nr_cpus]);
	}

	free(kdks_ev_queues);
	kdks_ev_queues = NULL;
}

int kdks__evbuf_get(int idx, struct ring_buffer_req_t *ev_req)
{
#if 0
	dks_debug("CPU-%d:prb size %lu, free %lu\n", idx,
			(kdks_ev_queues[idx])->rb->size,
			ring_buffer_shm_free_space(kdks_ev_queues[idx]));
#endif
	return kdks_evbuf_get(kdks_ev_queues[idx], ev_req);
}

void kdks__evbuf_get_done(int idx, struct ring_buffer_req_t *ev_req)
{
	return kdks_evbuf_get_done(kdks_ev_queues[idx], ev_req);
}

int kdks__event_open_allcpus(struct dks_ctrl *ctrl)
{
	int err;
	int i;
	int nr_cpus;

	if (!ctrl->init)
		return -EFAULT;

	nr_cpus = ctrl->nr_cpus;

	err = kdks__init_event_files(nr_cpus);
	if (err < 0)
		return err;

	/*init ev_queues*/
	err = kdks__init_event_queues(nr_cpus);
	if (err < 0)
		goto exit_free_kdks_files;

	/*init poll events*/
	err = kdks__init_pollfds(nr_cpus);
	if (err)
		goto exit_free_event_queues;

	/*open perf event, set mmap addr and poll event*/
	for (i = 0; i < nr_cpus; ++i) {
		/*open this for # of cpus*/
		int kdks_fd = kdks_open();
		if (kdks_fd < 0) {
			pr_err("CPU-%d, Error opening dark insight kernel module",i);
			err = -1;
			goto exit_kdks_open;
		}

		kdks_fds[i] = kdks_fd;
		err = kdks_evbuf_bind_cpu(kdks_fd, i);
		if (err) {
			pr_err("CPU-%d, bind event-buffer to cpu fail\n", i);
			goto exit_kdks_open;
		}

		kdks_ev_queues[i] = kdks_create_evbuf(kdks_fd, EV_BUF_SZ);
		if (!kdks_ev_queues[i]) {
			pr_err("CPU-%d, create kernel event-buffer fail\n", i);
			err = errno;
			goto exit_kdks_open;
		}

		/*assign pollfd*/
		kdks__assign_pollfd(i, kdks_fd);
	}

	/*stop before starting - to make sure*/
	kdks_stop_profile_all(kdks_fds[0]);
	return 0;

exit_kdks_open:
	kdks__free_pollfds();
exit_free_event_queues:
	kdks__free_event_queues(nr_cpus);
exit_free_kdks_files:
	kdks__free_event_files(nr_cpus);
	return err;
}

int kdks__start_profile_all(struct kdks_attr *attr)
{
	if (!kdks_fds) {
		pr_err("No valid kdks fd yet.\n");
		return -ENOENT;
	}
	return kdks_start_profile_all(kdks_fds[0], (void *)attr);
}

int kdks__stop_profile_all(void)
{
	if (!kdks_fds) {
		pr_info("No kdks fd to stop.\n");
		return -ENOENT;
	}
	return kdks_stop_profile_all(kdks_fds[0]);
}

int kdks__push_spininfo(struct spininfo *spin_info)
{
	if (!spin_info) {
		pr_err("Spinloop info is empty\n");
		return -EINVAL;
	}
	if (!kdks_fds) {
		pr_err("Kernel dks file is not open yet\n");
		return -ENOENT;
	}

	return kdks_push_spininfo(kdks_fds[0], (void *)spin_info);
}

void kdks__exit(struct dks_ctrl *ctrl)
{
	int nr_cpus = ctrl->nr_cpus;
	kdks__free_pollfds();
	kdks__free_event_queues(nr_cpus);

	kdks__stop_profile_all();
	kdks__free_event_files(nr_cpus);
}

// Open events before calling this function.
// FIXME: Is there a caller for this?
void kdks__run_test(int nr_cpus)
{
	int ret;
	int cpu;
	struct ring_buffer_req_t ev_req;
	unsigned long mark1 = -1, mark2 = -1;

	/* try to fetch an event from an empty event queue */
	for (cpu = 0; cpu < nr_cpus; ++cpu) {
		ret = kdks_evbuf_get(kdks_ev_queues[cpu], &ev_req);
		mtest(ret == -EAGAIN, "an event queue should be empty initially");

		/* ask the kernel to push three fake events */
		ret = ioctl(kdks_fds[cpu], __KDKS_IOC_EVBUF_PUT_3);
		mtest(ret == 0, "kernel puts three fake events: %d", ret);

		/* get three fake events */
		int i;
		for (i = 0, mark1 = __KDKS_POISON; i < 3; ++i, ++mark1) {
			ret = kdks_evbuf_get(kdks_ev_queues[cpu], &ev_req);
			mtest(ret == 0, "<[%d] TC gets a fake events: %d", i, ret);

			mark2 = *((unsigned long *)ev_req.data);
			mtest(mark1 == mark2, " [%d] check mark: %lx == %lx", i, mark1, mark2);

			kdks_evbuf_get_done(kdks_ev_queues[cpu], &ev_req);
			mtest(1, ">[%d] get done", i);
		}

	}
}

