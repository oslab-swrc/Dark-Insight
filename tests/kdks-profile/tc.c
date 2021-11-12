#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <poll.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/types.h>

#include <mtest.h>
#include "kdks_event.h"

#define EV_BUF_SZ (4*1024*1024)

struct sample_event{
	struct perf_event_header header;
	__u64 sample_type;
	__u64 array[];
};

struct ip_callchain {
	__u64 nr;
	__u64 ips[0];
};

union u64_swap {
	__u64 val64;
	__u32 val32[2];
};

struct perf_sample {
	__u64 ip;
	__u32 pid, tid;
	__u64 time;
	__u64 addr;
	__u64 id;
	__u64 stream_id;
	__u32 cpu;
	__u64 period;
	__u64 data_src;
	struct ip_callchain *callchain;
};

/*global vars*/
int nr_cpus = 0;
static bool done = false;

static char *cpumode_str(__u8 cpumode) {
	int mode = cpumode & PERF_RECORD_MISC_CPUMODE_MASK;

	switch(mode){
		case PERF_RECORD_MISC_KERNEL:
			return "KERNEL";
			break;
		case PERF_RECORD_MISC_USER:
			return "USER";
			break;
		case PERF_RECORD_MISC_HYPERVISOR:
			return "HYPERVISOR";
			break;
		case PERF_RECORD_MISC_GUEST_KERNEL:
			return "GUEST_KERNEL";
			break;
		case PERF_RECORD_MISC_GUEST_USER:
			return "GUEST_USER";
			break;
		default:
			return "UNKNOWN";
	}

	return "UNKNOWN";
}

/*static functions*/
static void callchain__printf(struct perf_sample *sample)
{
	unsigned int i;
	struct ip_callchain *callchain = sample->callchain;

	printf("... FP chain: nr:%llu\n", callchain->nr);

	for (i = 0; i < callchain->nr; i++)
		printf("..... %2d: %016llu\n",
				i, callchain->ips[i]);
}

static inline bool overflow(const void *endp, __u16 max_size, const void *offset,
		__u64 size)
{
	return size > max_size || offset + size > endp;
}
#define OVERFLOW_CHECK(offset, size, max_size)                          \
	do {                                                            \
		if (overflow(endp, (max_size), (offset), (size)))       \
		return -EFAULT;                                 \
	} while (0)

#define OVERFLOW_CHECK_u64(offset) \
	OVERFLOW_CHECK(offset, sizeof(__u64), sizeof(__u64))

static int dump_sample(struct sample_event *sample_data) {
	struct perf_event_header *header = &(sample_data->header);
	__u64 type = sample_data->sample_type;
	struct perf_sample data;
	const __u64 *array = sample_data->array;
	__u16 max_size = header->size;
	const void *endp = (void *)sample_data+ max_size;
	__u64 sz;

	union u64_swap u;

	/*parse sampled data*/
	data.id = -1ULL;
	if (type & PERF_SAMPLE_IDENTIFIER) {
		data.id = *array;
		array++;
	}

	if (type & PERF_SAMPLE_IP) {
		data.ip = *array;
		array++;
	}

	if (type & PERF_SAMPLE_TID) {
		u.val64 = *array;
		data.pid = u.val32[0];
		data.tid = u.val32[1];
		array++;
	}

	if (type & PERF_SAMPLE_TIME) {
		data.time = *array;
		array++;
	}

	data.addr = 0;
	if (type & PERF_SAMPLE_ADDR) {
		data.addr = *array;
		array++;
	}

	if (type & PERF_SAMPLE_ID) {
		data.id = *array;
		array++;
	}

	if (type & PERF_SAMPLE_STREAM_ID) {
		data.stream_id = *array;
		array++;
	}

	if (type & PERF_SAMPLE_CPU) {
		u.val64 = *array;

		data.cpu = u.val32[0];
		array++;
	}

	if (type & PERF_SAMPLE_PERIOD) {
		data.period = *array;
		array++;
	}

	if (type & PERF_SAMPLE_CALLCHAIN) {
		const __u64 max_callchain_nr = UINT64_MAX / sizeof(__u64);

		OVERFLOW_CHECK_u64(array);
		data.callchain = (struct ip_callchain *)array++;

		if (data.callchain->nr > max_callchain_nr)
			return -EFAULT;
		sz = data.callchain->nr * sizeof(__u64);
		OVERFLOW_CHECK(array, sz, max_size);
		array = (void *)array + sz;
	}

	printf("ID[%llu] %d/%d: %#llx cpu:%u (%s mode) period: %llu\n",
			data.id, data.pid, data.tid, data.ip, data.cpu,
			cpumode_str(header->misc),
			data.period);

	if (type & PERF_SAMPLE_CALLCHAIN)
		callchain__printf(&data);

	return 0;
}

/*init files*/
static int *init_event_files(void){
	int i;
	int *fds;

	/*create event fds*/
	fds = (int *) malloc(nr_cpus * sizeof(int));

	if (!fds)
		return fds;

	/*init */
	for(i=0; i < nr_cpus; i++)
		fds[i] = -1;

	return fds;
}

/*init poll files*/
static struct pollfd *init_poll_fds(void){
	struct pollfd *fds;

	/*create event fds*/
	fds = (struct pollfd *)malloc(sizeof(struct pollfd)*nr_cpus);

	if (!fds)
		return NULL;

	return fds;
}

static struct ring_buffer_shm_t **init_event_queues(void) {
	int i;
	struct ring_buffer_shm_t **ev_qs;

	ev_qs = malloc(sizeof(struct ring_buffer_shm_t *)*nr_cpus);

	if (!ev_qs)
		return NULL;

	for(i=0; i < nr_cpus; i++)
		ev_qs[i] = NULL;

	return ev_qs;
}

static int free_event_queues(struct ring_buffer_shm_t **ev_qs) {
	int i;

	if(ev_qs == NULL)
		return 0;

	for(i=0; i < nr_cpus; i++) {
		if(ev_qs[i])
			kdks_destroy_evbuf(ev_qs[i]);
	}

	free(ev_qs);

	return 0;
}
/*close all open files and free fds*/
static void free_event_files(int *kdks_fds){
	int i;

	for(i=0; i < nr_cpus; i++) {
		if (kdks_fds[i] != -1)
			kdks_close(kdks_fds[i]);
	}

	free(kdks_fds);
}

int main(int argc, char *argv[])
{
	int i;
	int err;
	int *kdks_fds = NULL;
	struct pollfd *poll_fds = NULL;
	struct ring_buffer_shm_t **kdks_ev_qs = NULL;

	/*set nr_cpus*/
	nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	if(nr_cpus < 1) {
		fprintf(stderr, "# of cpus should be larger than 1\n");
		return -1;
	}

	mtest(nr_cpus > 1, "# of cpus :%d", nr_cpus);

	/*init event files*/
	kdks_fds = init_event_files();

	mtest(kdks_fds != NULL, "kdks_fds addr:%p", kdks_fds);

	if(kdks_fds == NULL)
		return -ENOMEM;

	 /*init ev_queues*/
	kdks_ev_qs = init_event_queues();

	if (kdks_ev_qs == NULL ) {
		err = -1;
		fprintf(stderr, "failed to init event queues\n");
		goto exit_free_event_files;
	}

	mtest(kdks_ev_qs != NULL, "kdks_ev_qs addr:%p", kdks_ev_qs);

	/*init poll files*/
	poll_fds = init_poll_fds();

	if(poll_fds == NULL) {
		err = -1;
		fprintf(stderr, "failed to init poll fds\n");
		goto exit_free_event_queues;
	}

	mtest(poll_fds != NULL, "poll_fds addr:%p\n", poll_fds);

	/*open kdks event, create event buffer and bind cpus*/
	for(i=0; i < nr_cpus; i++) {
		/*open kdks module*/
		kdks_fds[i] = kdks_open();

		if (kdks_fds[i] < 0) {
			fprintf(stderr, "CPU-%d, Error opening dark insight kernel module",i);
			err = -1;
			goto exit_kdks_open;
		}

		/*bind cpu*/
		err = kdks_evbuf_bind_cpu(kdks_fds[i], i);

		if(err) {
			fprintf(stderr, "CPU-%d, bind event-buffer to cpu fail\n",i);
			goto exit_kdks_open;
		}

		/*create buffer*/
		kdks_ev_qs[i] = kdks_create_evbuf(kdks_fds[i], EV_BUF_SZ);

		if(!kdks_ev_qs[i]) {
			fprintf(stderr, "CPU-%d, create kernel event-buffer fail\n",i);
			err = errno;
			goto exit_kdks_open;
		}

		/*assign pollfd*/
		poll_fds[i].fd = kdks_fds[i];
		poll_fds[i].events = POLLIN;
	}

	/*Now we're ready to profile*/

	/*stop profile - to make sure */
	kdks_stop_profile_all(kdks_fds[0]);

	/*start profile - kprobe perf_output_sample */
	err = kdks_start_profile_all(kdks_fds[0], NULL);

	mtest(err == 0, "start profile all err:%d", err);

	if(err < 0)
		goto exit_kdks_open;

	mtest(1, "Wait on poll event");

	int nloops = 0;

	/*Run perf and poll on output*/
	while(true) {

		/*if we receive 100th events, then finish it*/
		if(nloops == 1000 || done)
			break;

		err = poll(poll_fds, nr_cpus, -1);

		/*TODO: add error handling*/

		for(i=0; i < nr_cpus; i++){
			if(poll_fds[i].revents & POLLIN){
				struct ring_buffer_req_t ev_req;
				struct sample_event *ev_data;

				err = kdks_evbuf_get(kdks_ev_qs[i], &ev_req);

				if(err == -EAGAIN) {
					mtest(true, "evbuf[%d] Continue to check next event", i);

					/*TODO: kdks_evbuf empty*/
					continue;
				}

				mtest(err == 0, "<[%d] TC gets a event, err:%d", i, err);

				ev_data = (struct sample_event*) ev_req.data;

				mtest(0 == dump_sample(ev_data), "dump sample data");

				poll_fds[i].revents = 0;
				kdks_evbuf_get_done(kdks_ev_qs[i], &ev_req);
				//mtest(1, ">[%d] get done", i);
			}
		}

		nloops++;
	}

	/*stop profile*/
	kdks_stop_profile_all(kdks_fds[0]);

	/*exit nomarlly*/
	err = 0;

exit_kdks_open:
	free(poll_fds);
exit_free_event_queues:
	free_event_queues(kdks_ev_qs);
exit_free_event_files:
	free_event_files(kdks_fds);

	return err;
}
