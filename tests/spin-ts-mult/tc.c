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

#define DEFAULT_LOCK_HOLDING_TIME (500000)
#define THREAD_NAP_TIME 	  (50)
#define DEFAULT_NUM_THREADS       (4)
#define DEFAULT_NLOOPS		  (50000000)
#define DEFAULT_CS_TYPE		  (0)

#define gettid()	((pid_t) syscall(SYS_gettid))
#define atomic_inc(x) __sync_fetch_and_add(&x, 1)
#define atomic_dec(x) __sync_fetch_and_sub(&x, 1)

struct lock_var {
        /* lock data */
        union{
                pthread_mutex_t _mutex;
                volatile int _spin;
        } data;
        unsigned n_waiters; /* # of waiters */
};

struct lock_var *locks;

struct thread_data {
	unsigned id;
	pid_t tid;
	unsigned lock_id;
        struct lock_var *lock;
};

char *spin_type_name[3]={
	"Test and Spin Lock",
	"Test, test and spin Lock",
	"Pthread Spin Lock"
	"Pthread Mutex Lock"
};

char *cs_type_name[2]={
	"uSleep()",
	"for loop "
};

struct cmd_opt {
	/* command line options */
	int time;
	int nthreads;
	int spin_type;
	bool mutex;
	int cs;
	int nr_cpus;

	/* benchmark control */
	volatile int      go;
};

struct cmd_opt opt;

void (*spin_lock_func)(struct lock_var *lock) = NULL;
void (*spin_unlock_func)(struct lock_var *lock) = NULL;
void (*work_func)(void) = NULL;

static inline void inc_waiters(unsigned *counter){
	atomic_inc(*counter);
}

static inline void dec_waiters(unsigned *counter){
	atomic_dec(*counter);
}

static void spin_ts_lock(struct lock_var *lock)
{
        inc_waiters(&lock->n_waiters);
        while(smp_swap(&(lock->data._spin), 1)) {
        };
	dec_waiters(&lock->n_waiters);
}

static void spin_tts_lock(struct lock_var *lock)
{
	inc_waiters(&lock->n_waiters);
	while(1) {
		if (lock->data._spin == 0 && smp_swap(&(lock->data._spin), 1) == 0)
			return;
	}
	dec_waiters(&lock->n_waiters);
}

static void spin_unlock(struct lock_var *lock)
{
	smp_rmb();
	lock->data._spin = 0;
}


static void spin_pthread_lock(struct lock_var *lock)
{
	int ret;

	inc_waiters(&lock->n_waiters);
	ret = pthread_spin_lock((pthread_spinlock_t *) &(lock->data._spin));
	dec_waiters(&lock->n_waiters);

	if(ret)
		fprintf(stderr, "fail to get spinlock\n");
}

static void spin_pthread_unlock(struct lock_var *lock)
{
	pthread_spin_unlock((pthread_spinlock_t *) &(lock->data._spin));
}

static void mutex_pthread_lock(struct lock_var *lock)
{
	int ret;

	inc_waiters(&lock->n_waiters);
	ret = pthread_mutex_lock((pthread_mutex_t *) &(lock->data._mutex));
	dec_waiters(&lock->n_waiters);

	if(ret)
		fprintf(stderr, "fail to get mutex_lock\n");
}

static void mutex_pthread_unlock(struct lock_var *lock)
{
	pthread_mutex_unlock((pthread_mutex_t *) &(lock->data._mutex));
}

static void do_sleep(void){
	usleep(opt.time);
}

static void do_loop(void){
	int i;
	
	for(i=0; i < DEFAULT_NLOOPS; i++)
	{}
}

static void set_spin_func(int arg) {
	switch(arg){
		case 0:
			/*nothing to do*/
			break;
		case 1: /*spin tts lock*/
			spin_lock_func = spin_tts_lock; 
			break;
		case 2: /*pthread_spin_lock */
			spin_lock_func = spin_pthread_lock; 
			spin_unlock_func = spin_pthread_unlock; 
			break;
		case 3: /*pthread_mutex_lock */
			spin_lock_func = mutex_pthread_lock; 
			spin_unlock_func = mutex_pthread_unlock; 
			break;
		default:
			fprintf(stderr, "Choose wrong spin_func_type\n"
					"set default: spin_ts_lock \n");
			break;
	}
}

static int parse_option(int argc,
                        char *argv[],
                        struct cmd_opt *opt)
{
	static struct option options[] = {
		{"time",        required_argument, 0, 't'},
		{"nthreads",    required_argument, 0, 'n'},
		{"mutex",       no_argument, 0, 'm'},
		{"spin",    	required_argument, 0, 's'},
		{"cs",    	required_argument, 0, 'c'},
		{"nproc",    	required_argument, 0, 'p'},
		{0,             0,                 0, 0},
	};

	int arg_cnt;
	int c, idx;
	int nr_cpus;

	/*set default cpus*/
	nr_cpus = sysconf(_SC_NPROCESSORS_ONLN); //this might be supported only in Linux
	if(nr_cpus <= 0){
		printf("No cpus is online\n");
		return -EFAULT;
	}

	opt->time     = DEFAULT_LOCK_HOLDING_TIME;
	opt->nthreads = nr_cpus*DEFAULT_NUM_THREADS;
	opt->nr_cpus  = nr_cpus;

	/*set default spin func*/
	spin_lock_func = spin_ts_lock;
	spin_unlock_func = spin_unlock;
	work_func = do_sleep;
	for (arg_cnt = 0; 1; ++arg_cnt) {
		c = getopt_long(argc, argv,
				"t:n:m:s:c:p:", options, &idx);
		if (c == -1)
			break;
		switch(c) {
		case 't':
			opt->time = atoi(optarg);
			break;
		case 'n':
			opt->nthreads = atoi(optarg);
			break;
		case 'm':
			opt->mutex = true;
			set_spin_func(3); /* type 3 == mutex spin lock */
			break;
		case 's':
			opt->spin_type = atoi(optarg);
			set_spin_func(opt->spin_type);
			break;
		case 'c':
			opt->cs = atoi(optarg);
			if(atoi(optarg) != 0)
				work_func = do_loop;
			break;
		case 'p':
			opt->nr_cpus = atoi(optarg);
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
		" --mutex = lock with mutex\n");
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
		td->lock = &locks[td->lock_id];
                spin_lock_func(td->lock); {
                        work_func();
                        printf("==[%010lu] thread %d(%u) lockid %d addr 0x%p waiters %d\n",
                                        i, td->id, td->tid, td->lock_id,
                                        (void *) td->lock, td->lock->n_waiters);
                }
                spin_unlock_func(td->lock);

                /*if current thread has been serviced,
                  then take a nap to give some chances 
                  to other threads get serviced*/
                usleep(THREAD_NAP_TIME);
                td->lock_id = (td->lock_id+1)%opt.nr_cpus;
        }

        return NULL;
}

static void show_exec_env(void) {
	printf("*** Execution environments ***\n");
	printf("Lock holding in micro seconds : %d\n", opt.time);
	printf("Number of ONLN CPUS           : %d\n", opt.nr_cpus);
	printf("Number of threads             : %d\n", opt.nthreads);
	printf("Mutex Lock or Spin Lock       : %s\n", opt.mutex ? "Mutex":"Spin");
	printf("Critical section type         : %s\n", cs_type_name[opt.cs]);

        if(!opt.mutex)
                printf("Spin type                     : %s\n", spin_type_name[opt.spin_type]);
}

static int init_lock_variables(void){
	int i, nr_cpus = opt.nr_cpus;
	/***************************
	   init locks - # of cores
	 ***************************/
	locks = (struct lock_var *) calloc(nr_cpus, sizeof(struct lock_var));

	for(i=0; i < nr_cpus; i++){
		struct lock_var *lock = &locks[i];
		switch(opt.spin_type){
			case 0:
			case 1:
				lock->data._spin = 0;
				break;
			case 2:
				pthread_spin_init((pthread_spinlock_t *) &(lock->data._spin),
						PTHREAD_PROCESS_SHARED);
				break;
			default:
				break;
		}

		if(opt.mutex)
			pthread_mutex_init(&(lock->data._mutex), NULL);

		lock->n_waiters = 0;

		printf("init lock variable thread #%d %p\n",
				i, lock);
	}

	return 0;
}

void init_thread_data(struct thread_data *td, int tid){
	td->id = tid;
	td->lock_id = tid % opt.nr_cpus;
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
	printf("*** %d threds will comptete "
	       "for a mutex holding it for %d seconds.***\n",
	       opt.nthreads, opt.time);
	th = (pthread_t *)malloc(sizeof(*th) * opt.nthreads);
	td = (struct thread_data *)malloc(sizeof(*td) * opt.nthreads);

	/*init lock variables*/
	err = init_lock_variables();
	if(err)
		return 0;

	/*Set lock variable - map to M-threads to N-CPUS*/
	for (i = 1; i < opt.nthreads; ++i) {
                init_thread_data(&td[i], i);
		err = pthread_create(&th[i], NULL,
				thread_main, (void*) &td[i]);
		if (err){
			printf("thread %d creation fail\n", i);
			goto main_out;
		}
	}

	init_thread_data(&td[0], 0);
	thread_main(&td[0]);

main_out:
	free(th);
	return err;
}
