#ifndef _PERF_PERF_H
#define _PERF_PERF_H

#include <time.h>
#include <stdbool.h>
#include <linux/types.h>
#include <linux/perf_event.h>

/*this for fixed event attrs*/
#define DKS_NR_ATTRS	(4)

extern bool test_attr__enabled;
void test_attr__init(void);
void test_attr__open(struct perf_event_attr *attr, pid_t pid, int cpu,
		     int fd, int group_fd, unsigned long flags);

#define HAVE_ATTR_TEST
#include "perf-sys.h"

#ifndef NSEC_PER_SEC
# define NSEC_PER_SEC			1000000000ULL
#endif
#ifndef NSEC_PER_USEC
# define NSEC_PER_USEC			1000ULL
#endif

static inline unsigned long long rdclock(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

#define MAX_NR_CPUS			1024

extern const char *input_file_name;
extern bool perf_host, perf_guest;
extern const char perf_version_string[];

void pthread__unblock_sigwinch(void);

#include "util/target.h"

struct record_opts {
	struct target target;
	bool	     group;
	bool	     inherit_stat;
	bool	     no_buffering;
	bool	     no_inherit;
	bool	     no_inherit_set;
	bool	     no_samples;
	bool	     raw_samples;
	bool	     sample_address;
	bool	     sample_weight;
	bool	     sample_time;
	bool	     sample_time_set;
	bool	     callgraph_set;
	bool	     period;
	bool	     running_time;
	bool	     record_switch_events;
	bool	     all_kernel;
	bool	     all_user;
	unsigned int freq;
	unsigned int mmap_pages;
	unsigned int user_freq;
	u64          branch_stack;
	u64	     sample_intr_regs;
	u64	     default_interval;
	u64	     user_interval;
	bool	     sample_transaction;
	unsigned     initial_delay;
	bool         use_clockid;
	clockid_t    clockid;
	unsigned int proc_map_timeout;
};

struct option;
extern const char * const *record_usage;
extern struct option *record_options;
#endif
