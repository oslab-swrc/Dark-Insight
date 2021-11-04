#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <mtest.h>
#include "kdks_event.h"

static int n_enough_events;

static void *generate_events(void *x)
{
	int fd = (int)(long)x;
	int ret;

	/* sleep for a while */
	sleep(3);
	mtest(1, "[EV_GEN] slept for a while");

	/* ask the kernel to push enough fake events */
	ret = ioctl(fd, __KDKS_IOC_EVBUF_PUT_ENOUGH);
	n_enough_events = ret;
	mtest(ret <= 0, "[EV_GEN] kernel puts enough events: %d", ret);
	sleep(1);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct ring_buffer_shm_t *ev_queue;
	struct ring_buffer_req_t ev_req;
	int fd, ret, i;
	struct pollfd fds[1];
	pthread_t thr;
	unsigned long mark1 = -1, mark2 = -1;

	/* open */
	fd = kdks_open();
	mtest(fd > 0, "open /dev/kdks: %d", fd);

	/* create an event buffer before cpu binding */
	ev_queue = kdks_create_evbuf(fd, 4 * 1024 * 1024);
	mtest(ev_queue == NULL && errno == EINVAL,
	      "create an event buffer before binding cpu id: %d", errno);
	
	/* set cpu */
	ret = kdks_evbuf_bind_cpu(fd, 0);
	mtest(ret == 0, "bind fd to cpu 0: %d", ret);

	/* create an event buffer after cpu binding */
	ev_queue = kdks_create_evbuf(fd, 512 * 1024);
	mtest(ev_queue != NULL,
	      "create an event buffer after binding cpu id: %p", ev_queue);

	/* try to fetch an event from an empty event queue */
	ret = kdks_evbuf_get(ev_queue, &ev_req);
	mtest(ret == -EAGAIN, "an event queue should be empty initially");

	/* ask the kernel to push three fake events */
	ret = ioctl(fd, __KDKS_IOC_EVBUF_PUT_3);
	mtest(ret == 0, "kernel puts three fake events: %d", ret);

	/* get three fake events */
	for (i = 0, mark1 = __KDKS_POISON; i < 3; ++i, ++mark1) {
		ret = kdks_evbuf_get(ev_queue, &ev_req);
		mtest(ret == 0, "<[%d] TC gets a fake events: %d", i, ret);

		mark2 = *((unsigned long *)ev_req.data);
		mtest(mark1 == mark2, " [%d] check mark: %lx == %lx",
		      i, mark1, mark2);
		
		kdks_evbuf_get_done(ev_queue, &ev_req);
		mtest(1, ">[%d] get done", i);
	}

	/* launch a background event generation thread */
	ret = pthread_create(&thr, NULL, generate_events, (void*)(long)fd);
	mtest(ret == 0, "a event generation thread is launched: %d", ret);

	/* poll on fd */
	memset(fds, 0 , sizeof(fds));
	fds[0].fd = fd;
	fds[0].events = POLLIN;
	ret = poll(fds, 1, -1 );
	mtest(ret > 0, "poll events: ret: %d   errno: %d", ret, errno);
	
	/* get fake events */
	for (i = 0, mark1 = __KDKS_POISON; 1; ++i, ++mark1) {
		ret = kdks_evbuf_get(ev_queue, &ev_req);
		if (ret == -EAGAIN) {
			sleep(1);
			mtest(n_enough_events == i,
			      "<[%d] no more events: %d == %d",
			      i, n_enough_events, i);
			break;
		}
		mtest(ret == 0, "<[%d] TC gets a fake events: %d", i, ret);

		mark2 = *((unsigned long *)ev_req.data);
		mtest(mark1 == mark2, " [%d] check mark: %lx == %lx",
		      i, mark1, mark2);
		
		kdks_evbuf_get_done(ev_queue, &ev_req);
		mtest(1, ">[%d] get done", i);
	}

	mtest(fds[0].revents & POLLIN, "receive event : POLLIN");

	/* destroy event buffer */
	kdks_destroy_evbuf(ev_queue);
	mtest(1, "an event queue is detroyed");

	/* close fd */
	kdks_close(fd);
	mtest(1, "an event buffer descriptor is closed");
	return 0;
}
