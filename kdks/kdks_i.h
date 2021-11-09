// SPDX-License-Identifier: MIT
#ifndef _KDKS_I_H
#define _KDKS_I_H
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/perf_event.h>
#include <linux/perf_regs.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/futex.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/clock.h>
#endif

#  ifdef CONFIG_DEBUG_MUTEXES
       #include <linux/mutex.h>        /*for fedora debug kernel*/
#  endif /* CONFIG_DEBUG_MUTEXES */

#include <kdks.h>
#include <dks_common.h>
#include <spintable.h>
#include <ring_buffer_shm.h>

#define KDKS_INVALID_TIME_VAL	(-1)
#define KDKS_INVALID_HBP_SLOT 	(-1)
#define KDKS_NUM_SAMPLE_RECORDS (256)
#define KDKS_INVALID_PID	(pid_t)(-1)
#define KDKS_INVALID_TID	(pid_t)(-1)
#define KDKS_INVALID_TIME	(u64)(-1)

#define KDKS_CALLCHAIN_FAST_CMP 0
#define KDKS_IDLEID_FAST_CMP 	0
#define KDKS_USE_SPINPROBE_IPS 1

/**
 * utility
 */
enum kdks_debug_flags {
	LOG_ERR	 	= 0,
	LOG_INFO 	= 1,
	LOG_DEBUG  	= 2,
	LOG_VERBOSE 	= 3,
};

enum kdks_callchain_flags {
	KDKS_IPS_SHIPPED   = (1<<0),
	KDKS_IPS_FLAGS_MAX = (1<<7),
};

enum kdks_hbp_slot_status{
	HBP_SLOT_EMPTY 	 =     0,
	HBP_SLOT_SAME	 =     1,
	HBP_SLOT_EVICTED =     2,
	HBP_SLOT_STATUS_MAX =  3,
};

enum kdks_work_type{
	KDKS_FUTEX_WAIT    =     FUTEX_WAIT,
	KDKS_FUTEX_WAKE    =     FUTEX_WAKE,
	KDKS_FUTEX_WAKE_OP =     FUTEX_WAKE_OP,
};

enum kdks_run_modes{
	KDKS_RUN_MODE_SPIN_ONLY = 1,
	KDKS_RUN_MODE_FTEX_ONLY = 2,
	KDKS_RUN_MODE_ALL 	= 3,
	KDKS_RUN_MODE_MAX 	= 4,
};

extern unsigned int kdks_debug_level;
extern unsigned int kdks_run_mode;
void _kdks_debug(enum kdks_debug_flags level, const char *func,
		 const unsigned int line, const char *fmt, ...);

/*print debug message to kernel debug message*/
#define kdks_pr_error(fmt, ...) do { \
		_kdks_debug(LOG_ERR, __func__, __LINE__, fmt, ##__VA_ARGS__); \
	} while (0)
#define kdks_pr_info(fmt, ...) do { \
		_kdks_debug(LOG_INFO, __func__, __LINE__, fmt, ##__VA_ARGS__); \
	} while (0)
#define kdks_pr_debug(fmt, ...) do { \
		_kdks_debug(LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__); \
	} while (0)
#define kdks_pr_verbose(fmt, ...) do { \
		_kdks_debug(LOG_VERBOSE, __func__, __LINE__, fmt, ##__VA_ARGS__); \
	} while (0)

/*print debug message to trace print buffer */
#define kdks_pr_trace(level, fmt, ...) do { \
	if(kdks_debug_level >= level) \
		trace_printk(fmt, ##__VA_ARGS__); \
	} while (0)

int get_arg_from_pt_regs(struct pt_regs *regs, int n, unsigned long *arg);

/**
 * event buffer
 */
void init_evbuf(void);
void deinit_evbuf(void);

int evbuf_open(struct inode *inode, struct file *filp);
int evbuf_release(struct inode *inode, struct file *filp);
int evbuf_bind_cpu(struct file *filp, unsigned int cpu);

int  evbuf_mmap(struct file *filp, struct vm_area_struct *vma);
unsigned int evbuf_poll(struct file *filp, poll_table *wait);

struct ring_buffer_shm_t * get_evbuf(unsigned int cpu);
struct ring_buffer_shm_t * get_this_evbuf(void);
void put_this_evbuf(void);
int  evbuf_put(struct ring_buffer_shm_t *prbshm,
	       struct ring_buffer_req_t *req, size_t size);
void evbuf_put_done(struct ring_buffer_shm_t *prbshm,
		    struct ring_buffer_req_t *req);

int  __evbuf_put_3(struct file *filp);      /* test scaffold */
int  __evbuf_put_enough(struct file *filp); /* test scaffold */

/**
 * common data structures 
 */
int init_common(void);
void exit_common(void);
void kdks_flush_wq(struct workqueue_struct *wq);

/**
 * spin wait
 */
int init_spinprobe(struct kdks_attr kdks_attr);
void exit_spinprobe(void);

/**
 * blocking wait - futex
 */
int init_futexprobe(struct kdks_attr kdks_attr);
void exit_futexprobe(void);
void futex_do_work(struct work_struct *work);

extern struct workqueue_struct *futex_wq;

#define clock_to_us(x)	((x)/1000ULL)
#define clock_to_ms(x)	((x)/1000000ULL)

/*get current time in ns*/
static inline u64 kdks_get_current_time(void){
	/*NMI safe access to clock monotonic*/
	return local_clock();
}

/**
 * copy sample data to ringbuffer
 */
struct perf_event_header;
struct perf_sample_data;
struct perf_event;

/*define work struct for handle copy data to ringbuffer*/
struct sample_output_work{
	struct work_struct work;
	struct kdks_sample_data data;
};

struct ring_buffer_shm_t *prb__alloc_buffer(struct ring_buffer_req_t *req, size_t len);
void prb__copy_done(struct ring_buffer_shm_t *prbshm,
		struct ring_buffer_req_t *req);
inline void * prb__copy_data(struct ring_buffer_shm_t *prbshm,
		void *dest, const void *src, size_t size);
int copy_kdks_data_to_prb(struct kdks_sample_data *data);

size_t copy_perf_data_to_prb(struct perf_event_header *header,
		struct perf_sample_data *data,
		struct perf_event *event);
struct perf_callchain_entry *perf_data_get_callchain(struct perf_sample_data *data);
pid_t perf_data_get_pid(struct perf_sample_data *data);
pid_t perf_data_get_tid(struct perf_sample_data *data);
u64 perf_data_get_time(struct perf_sample_data *data);

static inline void kdks_set_perf_header(struct perf_event_header *perf_header){
	perf_header->type = PERF_RECORD_KDKS_SAMPLE;
	perf_header->size = sizeof(struct perf_event_header);
}

/**
 * callchain hash table
 */
#define get_callchain_flag(n, flag) (n->flags & flag)
#define set_callchain_flag(n, flag) (n->flags |= flag)
#if 0
#define is_callchain_shipped(n) (get_callchain_flag(n, KDKS_IPS_SHIPPED))
#define set_callchain_shipped(n) (set_callchain_flag(n, KDKS_IPS_SHIPPED))
#endif

#define is_callchain_shipped(n) (n->flags)
#define set_callchain_shipped(n) (n->flags = true)

typedef struct callchain_node{
	struct hlist_node node;
	u32	hash;	/*value of hash*/
	//u8	flags;	/*status of shipped*/
	bool	flags;	/*status of shipped*/
	callchain_t ips; /*# of callchain entries and callchain*/
} callchain_node_t;

int init_callchain_ht(void);
void exit_callchain_ht(void);
void perf_print_callchain(callchain_t *ips);
/*search perf_callchain_entry and add it*/
struct callchain_node *callchain_ht_get_node(callchain_t *ips);

/*return estimated data size for the kdks_record*/
static inline size_t
get_kdks_record_size(callchain_node_t *ips_node){
	/*update callchain shipping status*/
	if(!is_callchain_shipped(ips_node)){
		return sizeof__kdks_record(ips_node->ips.nr);
	}
	return sizeof(kdks_record_t);
}

/**
 * idle table - idletable.c
 */
struct lock_id;

struct __attribute__((packed)) idle_id {
	u64 addr;
	pid_t pid;
	pid_t tid;
	callchain_t *ips; /*this should point to callchain hash entry*/
};

/*idle entry */
struct idle_obj{
	struct hlist_node node;	 	/*idle hashtable node*/
	struct list_head link_node; 	/*linked list node for waiters list*/
	struct idle_id id;		/*id - pid/addr/tid/ips*/
	struct lock_id *lid;	/*point to lock_object*/
	u32 hash; 		/*hash value for current*/
	u64 last_time;		/*last time hit*/
	u64 acc_waiting_time;	/*accumulated wait time*/
	u64 tot_waiting_time;	/*accumulated wait time*/
	u64 last_print_time;	/*for DEBUG*/
};

int init_idle_ht(void);
void exit_idle_ht(void);
struct idle_obj *idle_ht_get_obj(struct idle_id id);

/**
 * lock object table - lock_ht_obj.c
 */
/*status of idle entry*/
typedef enum lock_status {
	LOCKOBJ_NEW_WAIT 	= 0,
	LOCKOBJ_MAY_WAIT	= 1,
	LOCKOBJ_SURE_WAIT	= 2,
	LOCKOBJ_STATUS_MAX	= 4,
} lock_status;

/*lock object*/
struct __attribute__((packed)) lock_id {
	u64 addr;		/*sync memory address*/
	pid_t pid;		/*process id : tgid*/
};

/*lock obj for hashtable*/
struct lock_obj {
	struct hlist_node node;
	struct lock_id id;
	struct list_head waiters; /*waiter thread list*/
	spinlock_t lock;	/*protect current node*/
	u16 n_waiters;
	size_t waiters_data_len;/*prepare copy data out*/
	u64 acc_waiting_time;	/*accumulated waiting time*/
	u64 avg_time_diff;	/*average time difference*/
	u64 last_time;		/*prev hbp set time*/
	lock_status status;	/*status*/
	int hbp_slot;
};

int init_lock_obj_ht(void);
void exit_lock_obj_ht(void);
struct lock_obj *lock_obj_ht_get_obj(struct lock_id id);
struct lock_obj *lock_obj_ht_lookup(pid_t pid, u64 addr);

/*add idle_object to lock_object*/
static inline void idle_obj_add_to_waiters(struct lock_obj *lock_obj,
		struct idle_obj *idle_obj){
	list_add_tail_rcu(&idle_obj->link_node, &lock_obj->waiters);
	idle_obj->lid = &lock_obj->id;
	(lock_obj->n_waiters)++;
}

static inline u64
update_acc_time(struct lock_obj *lock_obj, struct idle_obj *idle_obj)
{
	u64 time_diff, cur_time;
	cur_time = kdks_get_current_time();

	time_diff = cur_time - max(idle_obj->last_time, lock_obj->last_time);
	idle_obj->last_time = cur_time;
	idle_obj->acc_waiting_time += time_diff;
	idle_obj->tot_waiting_time += time_diff;

	return time_diff;
}

 /* copy record info into kdks record temp buffer */
size_t copy_kdks_record(struct kdks_record *record, pid_t pid, pid_t tid,
		u64 acc_time, callchain_t *ips,	bool shipping_callchain);

/**
 * object id
 */
union object_id {
	struct lock_id lock_id;
	struct idle_id idle_id;
};

/**
 * spintable
 */
/*spin-loop sync table data structures,
  - a spin loop entry describes :
  -- spin range = (start_addr, end addr)
  -- sync variable = (disp(%reg))
 */
struct spin_node {
	struct rb_node rb_node;
	struct spin_entry *e;      /*point to spin entry*/
};

int init_spintable(void);
void exit_spintable(void);
struct spin_node *spintable_find(u64 ip);
inline struct sync_var * new_sync_var(void);

int spintable__push_spininfo(unsigned long arg);

/**
 * hw-breakpoint
 */

struct work_desc {
	u64 addr;
	u64 time;
	pid_t pid;
	pid_t tid;
	u8 op;
	callchain_t *ips;
};

/*define work struct for handling bottom half of kprobe*/
struct work_request {
	struct work_struct work;
	struct work_desc desc;
};

int init_kdks_hbp(void);
void exit_kdks_hbp(void);
void hbp_handle_work_request(struct work_struct *work);
void hbp_wide_unregister_bp(pid_t pid);
struct task_struct *hbp_get_task_struct(pid_t nr);
extern struct workqueue_struct *hbp_wq;

/**
 * arguments from pt_regs
 */
#if defined(__x86_64__)
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)
#endif

/**
 * perf_regs
 */
/*get required register from perf_sample_data*/
inline u64 ut_get_reg_value(struct perf_sample_data *data, u16 idx);
u64 perf_regs__get_reg_value(struct pt_regs *regs, int idx);
const char *perf_regs__get_reg_name(u16 idx);

/**
 * perf_callchain
 */

/*get perf callchain user*/
int perf_get_callchain_buffers(void);
void perf_put_callchain_buffers(void);
bool perf_has_callchain_buffers(void);
callchain_t *perf_get_callchain(struct pt_regs *regs, u32 init_nr, bool kernel, bool user,
		bool crosstask, bool add_mark);

/**
 * utilities for sync variable
 */
u64 ut_decode_sync_var(struct perf_sample_data *data, struct spin_entry *e, struct sync_var *v, int *sign_bit, int depth);

#endif /* _KDKS_I_H */
