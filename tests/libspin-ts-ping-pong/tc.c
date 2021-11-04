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
#include <sys/types.h>
#include <sys/syscall.h>
#include <getopt.h>
#include <malloc.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <arch.h>

#include "spin.h"

#define DEFAULT_LOCK_HOLDING_TIME (500000)
#define THREAD_NAP_TIME 	  (50)
#define DEFAULT_NUM_THREADS       (4)
#define DEFAULT_NLOOPS		  (50000000)
#define DEFAULT_CS_TYPE		  (0)

#define gettid()	((pid_t) syscall(SYS_gettid))
#define atomic_inc(x) __sync_fetch_and_add(&x, 1)
#define atomic_dec(x) __sync_fetch_and_sub(&x, 1)
static volatile int lock = 0;	/* unlocked*/
static volatile unsigned n_waiters = 0;

void (*spin_lock_func)(volatile int *lock, volatile unsigned *waiter_count) = NULL;
void (*spin_unlock_func)(volatile int *lock) = NULL;
void (*work_func)(void) = NULL;

struct thread_data {
	unsigned id;
	pid_t tid;
};

char *spin_type_name[4] = {
	"Test and Spin Lock",
	"Test, test and spin Lock",
	"Pthread Spin Lock"
	"Test and Spin Lock from a shared lib"
};

char *cs_type_name[2]= {
	"uSleep()",
	"for loop "
};

struct cmd_opt {
	/* command line options */
	int time;
	int nthreads;
	int spin_type;
	int cs;

	/* benchmark control */
	volatile int      go;
};

struct cmd_opt opt;

static void spin_ts_lock(volatile int *lock, volatile unsigned *waiter_count)
{
	atomic_inc(*waiter_count);
	while(smp_swap(lock, 1)) {
	};
	atomic_dec(*waiter_count);
}

static void spin_tts_lock(volatile int *lock, volatile unsigned *waiter_count)
{
	while (1) {
		if (*lock == 0 && smp_swap(lock, 1) == 0)
			return;
	}
}

static void spin_pthread_lock(volatile int *lock, volatile unsigned *waiter_count)
{
	int ret;

	atomic_inc(*waiter_count);
	ret = pthread_spin_lock((pthread_spinlock_t *)lock);
	atomic_dec(*waiter_count);

	if (ret)
		fprintf(stderr, "fail to get spinlock\n");
}

static void spin_unlock(volatile int *lock)
{
	smp_rmb();
	*lock = 0;
}

static void spin_pthread_unlock(volatile int *lock)
{
	pthread_spin_unlock((pthread_spinlock_t *) lock);
}

static void do_sleep(void)
{
	usleep(opt.time);
}

static void do_loop(void)
{
	int i;

	for (i = 0; i < DEFAULT_NLOOPS; i++)
	{}
}

static void set_spin_func(int arg)
{
	switch(arg) {
	case 0:
		/*spin ts lock*/
		spin_lock_func = spin_ts_lock;
		spin_unlock_func = spin_unlock;
		break;
	case 1: /*spin tts lock*/
		spin_lock_func = spin_tts_lock;
		spin_unlock_func = spin_unlock;
		break;
	case 2: /*pthread_spin_lock */
		spin_lock_func = spin_pthread_lock;
		spin_unlock_func = spin_pthread_unlock;
		pthread_spin_init((pthread_spinlock_t *) &lock, PTHREAD_PROCESS_SHARED);
		break;
	case 3: /* spin ts lock from a shared lib */
		spin_lock_func = libspin_ts_lock;
		spin_unlock_func = libspin_unlock;
		break;
	default:
		fprintf(stderr, "Choose wrong spin_func_type\n"
			"set default: spin_ts_lock \n");
		break;
	}
}

static int parse_option(int argc, char *argv[], struct cmd_opt *opt)
{
	static struct option options[] = {
		{"time",        required_argument, 0, 't'},
		{"nthreads",    required_argument, 0, 'n'},
		{"spin",    	required_argument, 0, 's'},
		{"cs",    	required_argument, 0, 'c'},
		{0,             0,                 0, 0},
	};

	int arg_cnt;
	int c, idx;

	memset(opt, 0, sizeof(struct cmd_opt));
	opt->time     = DEFAULT_LOCK_HOLDING_TIME;
	opt->nthreads = DEFAULT_NUM_THREADS;
	/*set default spin func*/
	spin_lock_func = libspin_ts_lock;
	spin_unlock_func = libspin_unlock;
	work_func = do_sleep;
	for (arg_cnt = 0; 1; ++arg_cnt) {
		c = getopt_long(argc, argv, "t:n:s:c:", options, &idx);
		if (c == -1)
			break;
		switch(c) {
		case 't':
			opt->time = atoi(optarg);
			break;
		case 'n':
			opt->nthreads = atoi(optarg);
			break;
		case 's':
			opt->spin_type = atoi(optarg);
			set_spin_func(opt->spin_type);
			break;
		case 'c':
			if(atoi(optarg) != 0)
				work_func = do_loop;
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
		" --time     = lock holding in micro seconds (default %d)\n",
		DEFAULT_LOCK_HOLDING_TIME);
	fprintf(stderr,
		" --nthreads = number of threads (default %d)\n",
		DEFAULT_NUM_THREADS);
	fprintf(stderr,
		" --spin     = spining type (default test and set spin lock)\n"
		" 	       spining type 0: test and set spin lock\n"
		" 	       spining type 1: test, test and set spin lock\n"
		" 	       spining type 2: pthread spin lock.\n");
	fprintf(stderr,
		" --cs = type of critical section 0:sleep, 1:loop (default %d)\n",
		DEFAULT_CS_TYPE);
}

static void *thread_main(void *arg)
{
	struct thread_data *td = (struct thread_data *) arg;
	unsigned long i;

	td->tid = gettid();

	for (i = 0; 1; i++) {
		spin_lock_func(&lock, &n_waiters); {
			work_func();
			printf("==[%010lu] thread %d(%u) leave the cs n_waiter:%d\n",
			       i, td->id, td->tid, n_waiters);
		} spin_unlock_func(&lock);

		/*if current thread has been serviced,
		  then take a nap to give some chances
		  to other threads get serviced*/
		usleep(THREAD_NAP_TIME);
	}

        return NULL;
}

static void show_exec_env(void)
{
	printf("*** Execution environments ***\n");
	printf("Lock holding in micro seconds : %d\n", opt.time);
	printf("Number of threads             : %d\n", opt.nthreads);
	printf("Spin type                     : %s\n", spin_type_name[opt.spin_type]);
	printf("Critical section type         : %s\n", cs_type_name[opt.cs]);
}

int main(int argc, char *argv[])
{
	int err = 0, i;
        pthread_t *th = NULL;
	struct thread_data *td;

	/* parse option */
	memset(&opt, 0, sizeof(opt));
	if (parse_option(argc, argv, &opt) < 0) {
		usage();
		err = 1;
		goto main_out;
	}

	/*print execution env */
	show_exec_env();
	/* do mutex-ping-pong forever */
	printf("*** %d threds will comptete for a spin lock holding it for %d seconds.***\n",
	       opt.nthreads, opt.time);
	th = (pthread_t *)malloc(sizeof(*th) * opt.nthreads);
	td = (struct thread_data *)malloc(sizeof(*td) * opt.nthreads);

	for (i = 1; i < opt.nthreads; ++i) {
		td[i].id = i;
                err = pthread_create(&th[i], NULL, thread_main, (void*) &td[i]);
                if (err) {
			printf("thread %d creation fail\n", i);
                        goto main_out;
		}
	}

	td[0].id = 0;
	thread_main(&td[0]);

main_out:
	free(th);
	return err;
}
