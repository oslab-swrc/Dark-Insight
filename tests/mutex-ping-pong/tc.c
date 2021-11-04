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
#include <sys/syscall.h>
#include <getopt.h>
#include <malloc.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>

#define DEFAULT_LOCK_HOLDING_TIME (500000)
#define THREAD_NAP_TIME 	  (50)
#define DEFAULT_NUM_THREADS       (4)

#define gettid() ((pid_t) syscall(SYS_gettid))

struct cmd_opt {
	/* command line options */
	int time;
	int nthreads;

	/* benchmark control */
	volatile int go;
};

struct cmd_opt opt;
static pthread_mutex_t mutex;// = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;

struct thread_data {
	unsigned id;
	pid_t tid;
};

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
		c = getopt_long(argc, argv, "t:n:", options, &idx);
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
		" --time     = lock holding in micro seconds (default %d)\n",
		DEFAULT_LOCK_HOLDING_TIME);
	fprintf(stderr,
		" --nthreads = number of threads (default %d)\n",
		DEFAULT_NUM_THREADS);
}

static void *thread_main(void *x)
{
	struct thread_data *td = (struct thread_data *)x;
	unsigned long i;

	td->tid = gettid();

	for (i = 0; 1; i++) {
		volatile bool serviced=false;

		pthread_mutex_lock(&mutex); {
			printf("==[%010lu] thread %d(%u) acquires the mutex\n",
			       i, td->id, td->tid);
			usleep(opt.time);
			serviced=true;
		} pthread_mutex_unlock(&mutex);

		/*if current thread has been serviced,
		  then take a nap to give some chances 
		  to other threads get serviced*/
		if(serviced)
			usleep(THREAD_NAP_TIME);

		serviced = false;
	}

	return NULL;
}

void init_thread_data(struct thread_data *td, int id){
	td->id = id;
}

static inline int init_mutex_lock(void){
	return pthread_mutex_init(&mutex, NULL);
}

int main(int argc, char *argv[])
{
	pthread_t *th = NULL;
	struct thread_data *td;
	int err = 0;
	int i;

	/* parse option */
	memset(&opt, 0, sizeof(opt));
	if (parse_option(argc, argv, &opt) < 0) {
		usage();
		err = 1;
		goto main_out;
	}

	/* init mutex */
	err = init_mutex_lock();

	if(err)
		return err;

	/* do mutex-ping-pong forever */
	printf("*** %d threds will comptete "
	       "for a mutex holding it for %d seconds.***\n",
	       opt.nthreads, opt.time);
	th = (pthread_t *)malloc(sizeof(*th) * opt.nthreads);
	td = (struct thread_data *)malloc(sizeof(*td) * opt.nthreads);
	for (i = 1; i < opt.nthreads; ++i) {
		init_thread_data(&td[i], i);
		err = pthread_create(&th[i], NULL,
				     thread_main, (void*) &td[i]);
		if (err)
			goto main_out;
	}
	init_thread_data(&td[0], 0);
	thread_main(&td[0]);

main_out:
	free(th);
	return err;
}
