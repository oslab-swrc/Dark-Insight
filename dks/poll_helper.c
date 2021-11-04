#include <errno.h>
#include <poll.h>

#include "poll_helper.h"
#include "util/util.h"

//#define DEFAULT_EVENT_TIMEOUT (-1)
#define DEFAULT_EVENT_TIMEOUT (1000)

static struct pollfd *pfds = NULL;
static struct pollfd *kfds = NULL;

/*init poll fds */
static struct pollfd *init_pollfds(int nr)
{
	return (struct pollfd *)malloc(sizeof(struct pollfd) * nr);
}

/*assign poll fd and event*/
static void assign_pollfd(struct pollfd *fds, int idx, int fd)
{
	assert(fd > 0);
	assert(fds);

	fds[idx].fd = fd;
	fds[idx].events = POLLIN | POLLERR | POLLHUP;
}

/*Poll nr files*/
static int event_poll(struct pollfd *fds, int nr, int timeout)
{
	assert(fds);
	return poll(fds, nr, timeout);
}

static short get_poll_revent(struct pollfd *fds, int idx)
{
	assert(fds);
	return fds[idx].revents;
}

static void set_poll_revent(struct pollfd *fds, int idx, short val)
{
	assert(fds);
	fds[idx].revents = val;
}

/*init perf event poll fds */
int perf__init_pollfds(int nr)
{
	pfds = init_pollfds(nr);
	return pfds ? 0 : -ENOMEM;
}

/*assign poll fd and event*/
void perf__assign_pollfd(int idx, int fd)
{
	assign_pollfd(pfds, idx, fd);
}

int perf__event_poll(int nr)
{
	return event_poll(pfds, nr, DEFAULT_EVENT_TIMEOUT);
}

void perf__free_pollfds(void)
{
	if (!pfds)
		return;

	free(pfds);
	pfds = NULL;
}

short perf__get_poll_revent(int index)
{
	return get_poll_revent(pfds, index);
}

void perf__set_poll_revent(int index, short val)
{
	set_poll_revent(pfds, index, val);
}

/*init kdks event poll fds */
int kdks__init_pollfds(int nr)
{
	kfds = init_pollfds(nr);
	return kfds ? 0 : -ENOMEM;
}

/*assign poll fd and event*/
void kdks__assign_pollfd(int idx, int fd)
{
	assign_pollfd(kfds, idx, fd);
}

/*Poll nr files*/
int kdks__event_poll(int nr)
{
	return event_poll(kfds, nr, DEFAULT_EVENT_TIMEOUT);
}

/*free*/
void kdks__free_pollfds(void)
{
	if (!kfds)
		return;
	free(kfds);
	kfds = NULL;
}

short kdks__get_poll_revent(int idx)
{
	return get_poll_revent(kfds, idx);
}

void kdks__set_poll_revent(int idx, short val)
{
	set_poll_revent(kfds, idx, val);
}
