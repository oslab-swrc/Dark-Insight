// SPDX-License-Identifier: MIT
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>

#include <linux/kprobes.h>
#include <linux/futex.h>

#include "kdks_i.h"

struct futex_args {
	 int op;
	 u32 __user *uaddr;
	 u32 __user *uaddr2;
};

#define DISABLE_PROBE_FUTEX_HANDLER 0
#define PROF_RUN_DKS_WORKQUEUE 1

#define KDKS_MAX_CALLCHAIN_SIZE	(sizeof__kdks_record(PERF_MAX_STACK_DEPTH))

/*workqueue for futex handler*/
struct workqueue_struct *futex_wq = NULL;

// FIXME: We need to support multiple target PIDs.
static pid_t target_pid = KDKS_INVALID_PID;
static inline bool is_overflow(const void *endp, u64 max_size, const void *offset, u64 size)
{
	return size > max_size || offset + size > endp;
}

static int futexprobe_submit_request(u8 op, pid_t pid, pid_t tid, u64 futex_addr,
	u64 time, callchain_t *callchain)
{
	struct work_request *req = NULL;
	struct work_desc *desc = NULL;
	const u64 stack_depth = callchain->nr;
	u64 callchain_length;

	// FIXME: We might reuse pre-alocated memory such as ring buffer.
	req = (struct work_request*)kmalloc(sizeof(*req), GFP_ATOMIC);
	if (!req) {
		kdks_pr_verbose(LOG_ERR, "Can't allocate work queue memory\n");
		return -ENOMEM;
	}
	kdks_pr_trace(LOG_VERBOSE, "[%u/%u] futex request - cmd %s uaddr 0x%llx at %llu\n",
		pid, tid, op == KDKS_FUTEX_WAIT ? "FUTEX_WAIT" : "FUTEX_WAKE",
		futex_addr, time);

	INIT_WORK(&req->work, futex_do_work);
	desc = &req->desc;
	desc->addr = futex_addr;
	desc->time = time;
	desc->pid = pid;
	desc->tid = tid;
	desc->op = op;

	if (stack_depth > PERF_MAX_STACK_DEPTH) {
		kdks_pr_error("Callchain has too big %lld (MAX: %d)",
			stack_depth, PERF_MAX_STACK_DEPTH);
		kfree(req);
		return 0;
	}

	// Copy callchain data.
	// The perf_callchain_entry might contain garbage at the end of callchain.
	callchain_length = sizeof(*callchain) + (sizeof(u64) * stack_depth);
	desc->ips = (callchain_t *)kmalloc(callchain_length, GFP_ATOMIC);
	desc->ips->nr = stack_depth;
	if (stack_depth) {
		memcpy((void *)&(desc->ips->ip[0]), (void *)&(callchain->ip[0]),
			sizeof(u64) * stack_depth);
	}

#if PROF_RUN_DKS_WORKQUEUE
	queue_work(futex_wq, &req->work);
#else
	// We do nothing.
	if (desc->ips)
		kfree(desc->ips);
	if (req)
		kfree(req);
#endif
	return 0;
}

// We probes do_futex() to profile blocking synchronization.
// pid/tid, callchain, and time are necessary.
static int futex_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// Prototype of do_futex for linux kernel 4.13.9
	// long do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
	//               u32 __user *uaddr2, u32 val2, u32 val3)
	u32 __user *uaddr = (u32 __user *)PT_REGS_PARM1(regs);
	u32 __user *uaddr2 = (u32 __user *)PT_REGS_PARM5(regs);
	callchain_t *callchain = NULL;
	int op = (int)PT_REGS_PARM2(regs);
	int cmd = op & FUTEX_CMD_MASK;
	char cmd_str[128];
	pid_t pid, tid;
	u64 cur_time;
	u64 target_addr;
	int ret = 0;

#if DISABLE_PROBE_FUTEX_HANDLER
	// For baseline performance comparison
	goto out;
#endif
	pid = task_tgid_nr(current);
	tid = task_pid_nr(current);

	// FIXME : We need to handle mulitple target PIDs.
	if (pid != target_pid || target_pid == KDKS_INVALID_PID)
		goto out;

	switch (cmd) {
	case FUTEX_WAIT:
	case FUTEX_WAKE:	/*pthread_mutex_unlock*/
	case FUTEX_CMP_REQUEUE:
		target_addr = (u64)((uintptr_t)uaddr);
		// FIXME: What is uaddr2?
		//target_addr = (u64)((uintptr_t) uaddr2);
		cur_time = kdks_get_current_time();
		break;
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAKE_BITSET:
	case FUTEX_REQUEUE:
	case FUTEX_LOCK_PI:
	case FUTEX_UNLOCK_PI:
	case FUTEX_TRYLOCK_PI:
	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_CMP_REQUEUE_PI:
		sprintf(cmd_str, "%s[%d]", "FUTEX_OTHER", cmd);
		ret = -1;
	case FUTEX_WAKE_OP:
	default:
		goto out;
	}

	callchain = perf_get_callchain(regs, 0, false, true, false, true);

	// Submit a request to handle a futex event.
	ret = futexprobe_submit_request((u8)cmd, pid, tid, target_addr, cur_time, callchain);
out:
	if (ret) {
		kdks_pr_debug("[%u/%u] error to handle futex - cmd %s uaddr 0x%p \n",
			pid, tid, cmd_str, uaddr);
	}

	// FIXME: Why do we save futex arguments?
	if (current->mm) {
		struct futex_args *args = (struct futex_args *)ri->data;
		args->uaddr = uaddr;
		args->uaddr2 = uaddr2;
		args->op = op;
	}

	return 0;
}

static int futex_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// Prototype of do_futex for linux kernel 4.13.9
	// long do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
	//               u32 __user *uaddr2, u32 val2, u32 val3)
	int ret = 0;
	struct futex_args *args = (struct futex_args *)ri->data;
	u32 __user *uaddr = args->uaddr;
	callchain_t *callchain = NULL;
	pid_t pid, tid;
	u64 cur_time;
	int cmd;
//	long rval;

#if DISABLE_PROBE_FUTEX_HANDLER
	// For baseline performance comparison
	goto out;
#endif

	if (!current->mm || !is_syscall_success(regs))
		goto out;

	pid = task_tgid_nr(current);
	tid = task_pid_nr(current);
	if (pid != target_pid)
		goto out;

	cmd = args->op & FUTEX_CMD_MASK;
	switch (cmd) {
	case FUTEX_WAKE_OP:
		cur_time = kdks_get_current_time();
		break;
	// We check the return value to see how many tasks are unlocked.
	case FUTEX_CMP_REQUEUE:
#if 0
		rval = regs_return_value(regs);
		if (rval)
			kdks_trace("return val of CMP_REQUEUE %ld\n", rval);
#endif
		goto out;
	case FUTEX_WAIT:
	case FUTEX_WAKE:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAKE_BITSET:
	case FUTEX_REQUEUE:
	case FUTEX_LOCK_PI:
	case FUTEX_UNLOCK_PI:
	case FUTEX_TRYLOCK_PI:
	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_CMP_REQUEUE_PI:
	default:
		goto out;
	}

	callchain = perf_get_callchain(regs, 0, false, true, false, true);
	// Submit a request to handle a futex event.
	ret = futexprobe_submit_request((u8)cmd, pid, tid, (u64)((uintptr_t)uaddr),
		cur_time, callchain);
out:
	if (ret)
		kdks_pr_verbose("failed to handle futex post (op %d, uaddr %p).\n", cmd, uaddr);

	return 0;
}

/*set probe point at do_futex,
  it should be pre-hanlder becasue mutex_lock will be blocked
  until it gets the lock*/
static struct kretprobe kretp = {
	.entry_handler = futex_pre_handler,
	.handler = futex_post_handler,
	.data_size = sizeof(struct futex_args),
	.maxactive = 512,	/*this will automatically limited to 2*n_cpus*/
};

static int init_futex_wq(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
	futex_wq = create_singlethread_workqueue("kdks_futex_wq");
#else
	/* WQ_UNBOUND & max active 1 results in sequential behavior */
	futex_wq = alloc_workqueue("kdks_futex_wq", WQ_UNBOUND,	2 /*max active per CPU*/);
#endif
	return unlikely(!futex_wq) ? -ENOMEM : 0;
}

static void exit_futex_wq(void)
{
	kdks_flush_wq(futex_wq);
}

/*FIXME : multi target*/
int init_futexprobe(struct kdks_attr kdks_attr)
{
	int ret;

	ret = init_futex_wq();
	if (unlikely(ret < 0)) {
		kdks_pr_error("Fail to create workqueue for futex handler %d\n", ret);
		goto err_out;
	}

	kretp.kp.symbol_name = "do_futex",
	ret = register_kretprobe(&kretp);
	if (unlikely(ret < 0)) {
		kdks_pr_error("Fail to register futex kretprobe %d\n", ret);
		goto err_out;
	}

	if (kdks_attr.pid == KDKS_INVALID_PID) // System wide mode
		pr_info("Planted futex kretprobe at 0x%p all pid\n", kretp.kp.addr);
	else {
		pr_info("Planted futex kretprobe at 0x%p for pid %u\n", kretp.kp.addr, kdks_attr.pid);
		target_pid = kdks_attr.pid;
	}

	return 0;
err_out:
	exit_futex_wq();
	return ret;
}

void exit_futexprobe(void)
{
	if (kretp.kp.addr) {
		unregister_kretprobe(&kretp);
		kdks_pr_info("Unregister kprobe at : 0x%p, missed:%d\n",
			kretp.kp.addr, kretp.nmissed);
	}
	exit_futex_wq();
}

/*this is invoked by pthread_mutex_lock()*/
void process_futex_wait(union object_id id, u64 time)
{
	struct callchain_node *ips_node;
	struct lock_obj *lock_obj = NULL;
	struct idle_obj *idle_obj = NULL;

	/*get lock object*/
	lock_obj = lock_obj_ht_get_obj(id.lock_id);
	if (IS_ERR(lock_obj)) {
		kdks_pr_error("failed to allocate memory for lock object\n");
		return;
	}

	idle_obj = idle_ht_get_obj(id.idle_id);
	if (IS_ERR(idle_obj)) {
		kdks_pr_error("failed to allocate memory for idle object errno %ld\n",
			PTR_ERR(idle_obj));
		if (PTR_ERR(idle_obj) == -E2BIG)
			kdks_pr_error("callchain length %lld\n", id.idle_id.ips->nr);
		return;
	}

	/*get ips_node to check shipped status*/
	ips_node = container_of(idle_obj->id.ips, struct callchain_node, ips);

	kdks_pr_verbose("print ips_node's callchain for debug, hash:0x%llx\n", (u64)ips_node->hash);

	/*get spinlock on lock obj*/
	spin_lock(&lock_obj->lock); {
		/*set current time to calculate waiting time*/
		idle_obj->last_time = time;
		idle_obj->acc_waiting_time = 0;

		/*FIXME -
		  1) To add waiters is not working without spinlock
		  2) find a safe way to update lock object status*/
		if(!idle_obj->lid) {
			idle_obj_add_to_waiters(lock_obj, idle_obj);
			/*keep track of data_len*/
			if (!is_callchain_shipped(ips_node))
				lock_obj->waiters_data_len += sizeof__kdks_record(idle_obj->id.ips->nr);
			else
				lock_obj->waiters_data_len += sizeof(kdks_record_t);
		}

#if 0
		if (lock_obj->waiters_data_len > lock_obj->n_waiters*KDKS_MAX_CALLCHAIN_SIZE) {
			kdks_pr_trace(LOG_INFO, "Waiter's data length is too long? "
				"Mutex waiter tid %u, "
				"addr 0x%llx, "
				"lock obj's waiter size %ld, "
				"lock obj's estimated maximum size %ld, "
				"last_time %llu\n",
				id.idle_id.tid,
				id.idle_id.addr,
				lock_obj->waiters_data_len,
				lock_obj->n_waiters*KDKS_MAX_CALLCHAIN_SIZE,
				idle_obj->last_time);
		} else {
			kdks_pr_trace(LOG_INFO,
				"Mutex waiter tid %u, "
				"addr 0x%llx, "
				"lock obj's waiter size %ld, "
				"last_time %llu\n",
				id.idle_id.tid,
				id.idle_id.addr,
				lock_obj->waiters_data_len,
				idle_obj->last_time);
		}
#endif
	} spin_unlock(&lock_obj->lock);
}

/*check overflow */
static inline bool check_record_overflow(const void *endp, size_t alloc_len,
	const void *offset, u64 ips_nr, bool callchain_shipped)
{
	size_t waiter_ips_size = 0;

	/* check correct callchain size,
	   if current waiter's ips node is already shipped,
	   then we would not send it again
	 */
	waiter_ips_size = callchain_shipped ? sizeof(kdks_record_t) : sizeof__kdks_record(ips_nr);
	return is_overflow(endp, alloc_len, offset, waiter_ips_size);
}

/* wake all waiters in the futex queue,
   This is called by pthread_cond_broadcast */
static void process_futex_wake_all(u8 lock_type, union object_id id, u64 time)
{
	pid_t pid, tid;
	u64 addr;
	s64 diff_time;
	int n_waiters = 0;
	u64 this_waiting_time = 0;
	size_t alloc_len, pos = 0;
	struct lock_obj *lock_obj = NULL;
	struct callchain_node *holder_ips_node = NULL;
	struct callchain_node *waiter_ips_node = NULL;
	struct kdks_sample_data *data = NULL;
	char *array = NULL;
	struct kdks_record *record = NULL;
	struct list_head *waiter, *tmp;
	const void *endp;
	callchain_t *ips = id.idle_id.ips;

	addr = id.lock_id.addr;
	pid = id.lock_id.pid;
	tid = id.idle_id.tid;

	lock_obj = lock_obj_ht_get_obj(id.lock_id);

	holder_ips_node = callchain_ht_get_node(ips);
	if (IS_ERR(holder_ips_node)) {
		kdks_pr_trace(LOG_DEBUG, "unable to allocate kdks callchain entry ret :%ld\n",
			PTR_ERR(holder_ips_node));
		return;
	}

	spin_lock(&lock_obj->lock);

	/*lock holder has no waiters
	  This is because of glibc's locking implementation,
	  Use lock/unlock internally.*/
	if (!lock_obj->n_waiters)
		goto out;

	/*Calculate data len - header, holder, and waiter*/
	alloc_len = sizeof(kdks_sample_header_t) /*header*/
		+ sizeof__kdks_record(ips->nr) /*holder*/
		+ lock_obj->waiters_data_len; /*waiters*/

	kdks_pr_trace(LOG_DEBUG, "alloc_len:%lu\n", alloc_len);

	data = (struct kdks_sample_data *)kmalloc(alloc_len, GFP_ATOMIC);
	array = (char *)data;
	/* set endp - check overflow */
	endp = (void *)(array + alloc_len);

	/*copy lock holder*/
	pos += offsetof(struct kdks_sample_data, holder);
	record = (kdks_record_t *)(array+ pos);

	/* Holder's callchain always shipped to user */
	pos += copy_kdks_record(record, pid, tid, lock_obj->acc_waiting_time,
		&holder_ips_node->ips, true);

	set_callchain_shipped(holder_ips_node);

	/*copy lock waiters*/
	list_for_each_safe(waiter, tmp, &lock_obj->waiters) {
		struct idle_obj *waiter_obj = container_of(waiter, struct idle_obj, link_node);
		waiter_ips_node = container_of(waiter_obj->id.ips, struct callchain_node, ips);

		kdks_pr_trace(LOG_DEBUG, "copy pos:%lu\n", pos);

		// Set record position where to copy.
		record = (kdks_record_t *)(array + pos);

		if (alloc_len < pos) {
			kdks_pr_trace(LOG_ERR,
				"futex copy datasize mismatch!! "
				"Mutex %s Holder tid %u, "
				"addr 0x%llx, n_waiters %d, "
				"waiters_d_len %lu, alloc_len %lu, pos %lu\n",
				lock_type==KDKS_MUTEXLOCK?"LOCK":"COND", tid,
				id.lock_id.addr, n_waiters,
				lock_obj->waiters_data_len, alloc_len, pos);
			break;
		}

		/*There's a lock holder among lock waiters
		  because we don't trace lock holder trasition*/
		/*current waiter was lock holder*/
		if (waiter_obj->id.tid != tid) {
			/*calculate current waiter's waiting time*/
			diff_time = time - waiter_obj->last_time;

			/*FIXME - if diff is less than zero,
			  then it was alomost happened at the same time.
			  we going to set it to zero*/
			if (diff_time < 0) {
				kdks_pr_trace(LOG_DEBUG,
					"Mutex diff time less than zero - "
					"Mutex holder[%u/%u] at 0x%llx, "
					"waiter [%u/%u] cur:%llu, last:%llu \n",
					pid, tid, lock_obj->id.addr,
					waiter_obj->id.pid, waiter_obj->id.tid,
					time, waiter_obj->last_time);
				diff_time = 0;
			}

			waiter_obj->last_time = time;

			/*need to update waiting time*/
			waiter_obj->acc_waiting_time = diff_time;
			waiter_obj->tot_waiting_time += diff_time;

			/*check overflow if we copy current waiter */
			if (check_record_overflow(endp, alloc_len, record,
				waiter_obj->id.ips->nr, is_callchain_shipped(waiter_ips_node))) {
				kdks_pr_error("copy datasize overflow!! "
					"Mutex %s Holder tid %u, "
					"addr 0x%llx, n_waiters %d, "
					"waiters_d_len %lu, alloc_len %lu,"
					"pos %lu, "
					"callchain shipped? %s, "
					"callchain size : %llu, "
					"ptr 0x%p, end ptr 0x%p ",
					lock_type==KDKS_MUTEXLOCK?"LOCK":"COND",
					tid, id.lock_id.addr, n_waiters,
					lock_obj->waiters_data_len, 
					alloc_len, pos,
					is_callchain_shipped(waiter_ips_node)?
					"True":"False",
					is_callchain_shipped(waiter_ips_node)?
					sizeof(kdks_record_t):
					sizeof__kdks_record(waiter_obj->id.ips->nr),
					(uintptr_t)record, (uintptr_t)endp);
				break;
			}

			pos += copy_kdks_record(record,	waiter_obj->id.pid,
				waiter_obj->id.tid, waiter_obj->acc_waiting_time,
				waiter_obj->id.ips, !is_callchain_shipped(waiter_ips_node));
			set_callchain_shipped(waiter_ips_node);

			this_waiting_time += waiter_obj->acc_waiting_time;

			n_waiters++;

			kdks_pr_trace(LOG_DEBUG,
				"Mutex Waiter tid %u at 0x%llx, "
				"wait_time %llu us, total %llu us\n",
				waiter_obj->id.tid, waiter_obj->id.addr,
				clock_to_us(waiter_obj->acc_waiting_time),
				clock_to_us(waiter_obj->tot_waiting_time) );
		}

		/*remove current node from waiter list*/
		waiter_obj->lid = NULL; /*cut link*/
		waiter_obj->last_time = KDKS_INVALID_TIME_VAL;

		/*delete from list*/
		list_del_rcu(waiter);
		lock_obj->n_waiters--;

		/*update info*/
		waiter_obj->acc_waiting_time = 0;
	}

	/*send data only we have waiters*/
	if (n_waiters && this_waiting_time > 0) {
		/*update info*/
		lock_obj->acc_waiting_time += this_waiting_time;

		/*set perf_header */
		/*set kdks header we have real size in 'data_len'*/
		kdks_set_perf_header(&data->header.perf_header);
		data->header.lock_type = lock_type;
		data->header.n_waiters = n_waiters;
		data->header.addr = addr;
		data->header.data_len = pos;

		if (lock_obj->n_waiters != n_waiters) {
			kdks_pr_trace(LOG_DEBUG,"Mutex sample data/copy mismatch, "
				"# of copied samples %d, n_waiters %d\n",
				n_waiters, lock_obj->n_waiters);
		}

		copy_kdks_data_to_prb(data);

		/* adjust data length */
		lock_obj->waiters_data_len = 0;
		kdks_pr_trace(LOG_DEBUG,
			"Mutex %s Holder tid %u, "
			"addr 0x%llx, ips_hash:0x%llx, ips_mem:0x%llx, n_waiters %d, "
			"waiting %llu us, alloc %luB, sent %luB\n",
			lock_type==KDKS_MUTEXLOCK?"LOCK":"COND", tid,
			id.lock_id.addr, (u64) holder_ips_node->hash, 
			(u64)(&holder_ips_node->ips), n_waiters, 
			clock_to_us(this_waiting_time),
			alloc_len, pos);
	}

out:
	if (data)
		kfree(data);
	spin_unlock(&lock_obj->lock);
}

/*this is invoked by pthread_mutex_unlock() */
void process_futex_wake(u8 lock_type, union object_id id, u64 time)
{
	pid_t pid, tid;
	u64 addr;
	s64 diff_time;
	int n_waiters = 0;
	u64 this_waiting_time = 0;
	size_t alloc_len, pos = 0;
	struct lock_obj *lock_obj = NULL;
	struct callchain_node *holder_ips_node = NULL;
	struct callchain_node *waiter_ips_node = NULL;
	struct kdks_sample_data *data = NULL;
	char *array = NULL;
	struct kdks_record *record = NULL;
	struct list_head *waiter, *tmp;
	const void *endp;
	callchain_t *ips = id.idle_id.ips;

	addr = id.lock_id.addr;
	pid = id.lock_id.pid;
	tid = id.idle_id.tid;

	lock_obj = lock_obj_ht_get_obj(id.lock_id);
	holder_ips_node = callchain_ht_get_node(ips);
	if (IS_ERR(holder_ips_node)) {
		kdks_pr_trace(LOG_DEBUG, "unable to allocate kdks callchain entry ret :%ld\n",
			PTR_ERR(holder_ips_node));
		return;
	}

	spin_lock(&lock_obj->lock); {
		/*lock holder has no waiters
		  This is because of glibc's locking implementation,
		  Use lock/unlock internally.*/
		if (!lock_obj->n_waiters)
			goto out;

		/*Calculate data len - header, holder, and waiter*/
		alloc_len = sizeof(kdks_sample_header_t)	/*header*/
			+ sizeof__kdks_record(ips->nr)		/*holder*/
			+ lock_obj->waiters_data_len;		/*waiters*/
		kdks_pr_trace(LOG_DEBUG, "alloc_len:%lu\n", alloc_len);

		data = (struct kdks_sample_data *)kmalloc(alloc_len, GFP_ATOMIC);
		array = (char *)data;
		/* set endp - check overflow */
		endp = (void *)(array + alloc_len);

		/*copy lock holder*/
		pos += offsetof(struct kdks_sample_data, holder);
		record = (kdks_record_t *)(array + pos);

		/* Holder's callchain always shipped to user */
		pos += copy_kdks_record(record, pid, tid, lock_obj->acc_waiting_time,
			&holder_ips_node->ips, true);
		set_callchain_shipped(holder_ips_node);

		/*copy lock waiters*/
		list_for_each_safe(waiter, tmp, &lock_obj->waiters){
			struct idle_obj *waiter_obj = container_of(waiter, struct idle_obj, link_node);
			waiter_ips_node = container_of(waiter_obj->id.ips, struct callchain_node, ips);

			kdks_pr_trace(LOG_DEBUG, "copy pos:%lu\n", pos);

			// Set the record position to where we copy to.
			record = (kdks_record_t *)(array + pos);
			if (alloc_len < pos){
				kdks_pr_error("futex copy datasize mismatch!! "
					"Mutex %s Holder tid %u, "
					"addr 0x%llx, n_waiters %d, "
					"waiters_d_len %lu, alloc_len %lu, pos %lu\n",
					lock_type == KDKS_MUTEXLOCK ? "LOCK"  :"COND", tid,
					id.lock_id.addr, n_waiters,
					lock_obj->waiters_data_len, alloc_len, pos);
				break;
			}

			/*There's a lock holder among lock waiters
			  because we don't trace lock holder trasition*/
			/*current waiter was lock holder*/
			if (waiter_obj->id.tid == tid) {
				/*remove current node from waiter list*/
				waiter_obj->lid = NULL; /*cut link*/
				waiter_obj->last_time = KDKS_INVALID_TIME_VAL;

				/*delete from list*/
				list_del_rcu(waiter);
				lock_obj->n_waiters--;
			} else {
				/*calculate current waiter's waiting time*/
				diff_time = time - waiter_obj->last_time;

				/*FIXME - if diff is less than zero,
				  then it was alomost happened at the same time.
				  we going to set it to zero*/
				if (diff_time < 0 ) {
					kdks_pr_trace(LOG_DEBUG,
						"Mutex diff time less than zero - "
						"Mutex holder[%u/%u] at 0x%llx, "
						"waiter [%u/%u] cur:%llu, last:%llu \n",
						pid, tid, lock_obj->id.addr,
						waiter_obj->id.pid, waiter_obj->id.tid,
						time, waiter_obj->last_time);
					diff_time = 0;
				}

				waiter_obj->last_time = time;

				/*need to update waiting time*/
				waiter_obj->acc_waiting_time = diff_time;
				waiter_obj->tot_waiting_time += diff_time;

				/*check overflow if we copy current waiter */
				if (check_record_overflow(endp, alloc_len, record,
					waiter_obj->id.ips->nr,	is_callchain_shipped(waiter_ips_node))) {
					kdks_pr_error("copy datasize overflow!! "
						"Mutex %s Holder tid %u, "
						"addr 0x%llx, n_waiters %d, "
						"waiters_d_len %lu, alloc_len %lu,"
						"pos %lu, "
						"callchain shipped? %s, "
						"callchain size : %llu, "
						"ptr 0x%p, end ptr 0x%p ",
						lock_type == KDKS_MUTEXLOCK ? "LOCK" : "COND",
						tid, id.lock_id.addr, n_waiters,
						lock_obj->waiters_data_len,
						alloc_len, pos,
						is_callchain_shipped(waiter_ips_node)?
						"True":"False",
						is_callchain_shipped(waiter_ips_node)?
						sizeof(kdks_record_t):
						sizeof__kdks_record(waiter_obj->id.ips->nr),
						(uintptr_t)record, (uintptr_t)endp);
					break;
				}

				pos += copy_kdks_record(record, waiter_obj->id.pid,
					waiter_obj->id.tid, waiter_obj->acc_waiting_time,
					waiter_obj->id.ips, !is_callchain_shipped(waiter_ips_node));
				set_callchain_shipped(waiter_ips_node);

				this_waiting_time += waiter_obj->acc_waiting_time;
				n_waiters++;

				/*debug*/
				kdks_pr_trace(LOG_DEBUG, "Mutex Waiter tid %u at 0x%llx, "
					"wait_time %llu us, total %llu us\n",
					waiter_obj->id.tid, waiter_obj->id.addr,
					clock_to_us(waiter_obj->acc_waiting_time),
					clock_to_us(waiter_obj->tot_waiting_time));
			}

			// Update info
			waiter_obj->acc_waiting_time = 0;
		}

		/*send data only we have waiters*/
		if (n_waiters && this_waiting_time > 0) {
			size_t adjust_len = sizeof(struct kdks_sample_header) +
				sizeof__kdks_record(ips->nr);

			/*update info*/
			lock_obj->acc_waiting_time += this_waiting_time;

			/*set perf_header */
			/*set kdks header we have real size in 'data_len'*/
			kdks_set_perf_header(&data->header.perf_header);
			data->header.lock_type = lock_type;
			data->header.n_waiters = n_waiters;
			data->header.addr = addr;
			data->header.data_len = pos;

			if(lock_obj->n_waiters != n_waiters) {
				kdks_pr_trace(LOG_DEBUG,"Mutex sample data/copy mismatch, "
					"# of copied samples %d, n_waiters %d\n",
					n_waiters, lock_obj->n_waiters);
			}

			// Copy sampled data
			copy_kdks_data_to_prb(data);

			/* adjust data length */
			if (adjust_len > pos) {
				/* FIXME - need to debug, data length calculation smashed */
				lock_obj->waiters_data_len = 0;
				kdks_pr_trace(LOG_ERR, "Sent data length calculation smashed"
					"Mutex %s Holder tid %u, "
					"addr 0x%llx, ips_hash:0x%llx, n_waiters %d, "
					"waiting %llu us, alloc %luB, sent %luB"
					"adjust size %lu \n",
					lock_type == KDKS_MUTEXLOCK ? "LOCK" : "COND", tid,
					id.lock_id.addr, (u64) holder_ips_node->hash,
					n_waiters, clock_to_us(this_waiting_time),
					alloc_len, pos,adjust_len);
			} else {
				/* we need to adjust real waiting data size */
				if (lock_obj->waiters_data_len >= pos - adjust_len)
					lock_obj->waiters_data_len = pos - adjust_len;
				else {
					lock_obj->waiters_data_len = 0;
					kdks_pr_trace(LOG_ERR,
						"Waiter's data length calculation mismatch"
						"Mutex %s Holder tid %u, "
						"addr 0x%llx, ips_hash:0x%llx, n_waiters %d, "
						"alloc %luB, sent %luB"
						"adjust size %lu \n",
						lock_type == KDKS_MUTEXLOCK ? "LOCK" : "COND", tid,
						id.lock_id.addr, (u64) holder_ips_node->hash,
						n_waiters, alloc_len, pos, adjust_len);
				}
			}

			kdks_pr_trace(LOG_DEBUG, "Mutex %s Holder tid %u, "
				"addr 0x%llx, ips_hash:0x%llx, n_waiters %d, "
				"waiting %llu us, alloc %luB, sent %luB\n",
				lock_type == KDKS_MUTEXLOCK ? "LOCK" : "COND", tid,
				id.lock_id.addr, (u64) holder_ips_node->hash, n_waiters,
				clock_to_us(this_waiting_time), alloc_len, pos);
		}
	}

	/*finally free allocated buffer*/
out:
	if (data)
		kfree(data);
	spin_unlock(&lock_obj->lock);
}

void futex_do_work(struct work_struct *work)
{
	struct work_request *req = NULL;
	struct work_desc *desc = NULL;
	union object_id id;

	if (unlikely(!work))
		return;

	req = (struct work_request *)work;

	/*assign key data*/
	desc = &req->desc;
	id.idle_id.addr = desc->addr;
	id.idle_id.pid  = desc->pid;
	id.idle_id.tid  = desc->tid;
	id.idle_id.ips	= desc->ips;

	/*process request according to lock object and request type*/
	switch (desc->op) {
	case FUTEX_WAIT:	/*All waiting object*/
		process_futex_wait(id, desc->time);
		break;
	case FUTEX_WAKE:	/*pthread_mutex unlock*/
		process_futex_wake(KDKS_MUTEXLOCK, id, desc->time);
		break;
	case FUTEX_WAKE_OP:	/*pthread_cond_single lock*/
		process_futex_wake(KDKS_MUTEXCOND, id, desc->time);
		break;
	case FUTEX_CMP_REQUEUE:	/*pthread_cond_broadcast unlock*/
		process_futex_wake_all(KDKS_MUTEXCOND, id, desc->time);
		break;
	default:
		kdks_pr_trace(LOG_DEBUG,"kdks wrong work request [%u/%u] 0x%llx\n",
			desc->pid, desc->tid, desc->addr);
	}

	if (desc->ips)
		kfree((void *)desc->ips);
	kfree((void *)work);
}
