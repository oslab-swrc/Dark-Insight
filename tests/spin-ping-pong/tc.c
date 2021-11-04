#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <getopt.h>
#include <malloc.h>
#include <signal.h>
#include <pthread.h>

#include "arch.h"


#define DEFAULT_LOCK_HOLDING_TIME 2
#define DEFAULT_NUM_THREADS       2

#define atomic_inc(x) __sync_fetch_and_add(&x, 1)
#define atomic_dec(x) __sync_fetch_and_sub(&x, 1)

struct cmd_opt {
	/* command line options */
	int time;
	int nthreads;

	/* benchmark control */
	volatile int      go;
};

struct cmd_opt opt;
static volatile int lock = 0;	/* unlocked*/
static volatile unsigned waiter_count = 0;

static void spin_ts_lock()
{
	atomic_inc(waiter_count);
	while(smp_swap(&lock, 1)) {
	};
	atomic_dec(waiter_count);
}

static void spin_unlock()
{
	smp_rmb();
	lock = 0;
}

static int parse_option(int argc,
                        char *argv[],
                        struct cmd_opt *opt)
{
	static struct option options[] = {
		{"time",        required_argument, 0, 't'},
		{"nthreads",    required_argument, 0, 'n'},
		{0,             0,                 0, 0},
	};

	int arg_cnt;
	int c, idx;

	memset(opt, 0, sizeof(struct cmd_opt));
	opt->time     = DEFAULT_LOCK_HOLDING_TIME;
	opt->nthreads = DEFAULT_NUM_THREADS;
	for (arg_cnt = 0; 1; ++arg_cnt) {
		c = getopt_long(argc, argv,"t:n:", options, &idx);
		if (c == -1)
			break;
		switch(c) {
		case 't':
			opt->time = atoi(optarg);
			break;
		case 'n':
			opt->nthreads = atoi(optarg);
			break;
		default:
			return -EINVAL;
		}
	}
	return arg_cnt;
}

static void usage(void)
{
	extern char *__progname;
	fprintf(stderr,
		"Usage: %s\n", __progname);
	fprintf(stderr,
		" --time     = lock holding in seconds (default %d)\n",
		DEFAULT_LOCK_HOLDING_TIME);
	fprintf(stderr,
		" --nthreads = number of threads (default %d)\n",
		DEFAULT_NUM_THREADS);
}

static void *thread_main(void *x)
{
	unsigned int id = (long)x;
	unsigned long i, j;

	for (i = 0; 1; i++) {
		spin_ts_lock(); {
			printf("==[%010lu] thread %d acquires the spinlock, waiters: %d\n",
				i, id, waiter_count);
			sleep(opt.time);
		} spin_unlock();

		/* We enforce fairness hear by pausing a little bit
		 * since pthread_spinlock does not guarantee fairness. */
		for (j = 0; j < 32; j++) {
			__asm__ __volatile__("mfence":::"memory");
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t *threads = NULL;
	int err = 0;
	int i;

	/* parse option */
	memset(&opt, 0, sizeof(opt));
	if (parse_option(argc, argv, &opt) < 0) {
		usage();
		err = 1;
		goto main_out;
	}

	/* do spin-ping-pong forever */
	printf("*** %d threds will comptete "
		"for a spinlock holding it for %d seconds.***\n",
		opt.nthreads, opt.time);
	threads = (pthread_t *)malloc(sizeof(*threads) * opt.nthreads);
	for (i = 1; i < opt.nthreads; ++i) {
		err = pthread_create(&threads[i], NULL,
				thread_main, (void*)(long)i);
		if (err)
			goto main_out;
	}
	thread_main(0);

 main_out:
	free(threads);
	return err;
}
