#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include <asm/debugreg.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include "kdks_i.h"

#ifndef UINT64_MAX
#define UINT64_MAX	(u64)(~((u64)0))
#endif

//#define DEBUG_NO_SET_HBP 1

struct workqueue_struct *hbp_wq = NULL;

/*get task_struct using target tid*/
struct task_struct *hbp_get_task_struct(pid_t nr)
{
	struct pid *pid = NULL;
	struct task_struct *task = NULL;

	pid = find_get_pid(nr);
	if (!pid)
		return NULL;

	// get_pid_task internally invokes get_task_struct().
	// Thus, we need to call put_task_struct() after use.
	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);

	return task;
}

/*unregister thread-wide breakpoint*/
void hbp_wide_unregister_bp(pid_t pid)
{
	struct task_struct *task;
	struct task_struct *group_leader;
	int i;

	group_leader = hbp_get_task_struct(pid);
	if (!group_leader) {
		kdks_pr_trace(LOG_ERR, "failed to get task for pid:%u failed \n", pid);
		return;
	}

	/*unregister hw_breakpoint for all task in the same group */
	for_each_thread(group_leader, task) {
		struct thread_struct *thread = &task->thread;

		/*unregister all bps*/
		for (i = 0; i < HBP_NUM; i++) {
			if (!thread->ptrace_bps[i])
				continue;
			unregister_hw_breakpoint(thread->ptrace_bps[i]);
			thread->ptrace_bps[i] = NULL;
		}

		thread->debugreg6 = 0;
		thread->ptrace_dr7 = 0;
	}
	put_task_struct(group_leader);
	kdks_pr_trace(LOG_INFO, "unregister HW Breakpoint done.\n");
}

/*unregister a hbp slot in the thread*/
__attribute__((unused))
static void hbp_unregister_slot(pid_t pid, int hbp_slot)
{
	struct task_struct *task;
	struct task_struct *group_leader;

	group_leader = hbp_get_task_struct(pid);
	if (!group_leader) {
		kdks_pr_trace(LOG_ERR, "failed to get task for pid:%u failed \n", pid);
		return;
	}

	for_each_thread(group_leader, task) {
		struct thread_struct *thread;

		get_task_struct(task);

		thread = &task->thread;
		unregister_hw_breakpoint(thread->ptrace_bps[hbp_slot]);

		thread->ptrace_bps[hbp_slot] = NULL;
		thread->debugreg6 = 0;
		thread->ptrace_dr7 = 0;

		put_task_struct(task);
	}
	put_task_struct(group_leader);
}

/*compensate loss time being evicted*/
static inline void compensate_acc_time(struct lock_obj *lock_obj, struct idle_obj *idle_obj)
{
	idle_obj->acc_waiting_time += lock_obj->avg_time_diff;
	idle_obj->tot_waiting_time += lock_obj->avg_time_diff;
}

static void process_lock_holder(struct lock_obj *lock_object, callchain_t *callchain,
	struct callchain_node *callchain_entry_node, union object_id *object_id_p, u64 ip)
{
	struct list_head *waiter, *tmp;
	struct kdks_sample_data *data;
	struct kdks_record *record;
	struct callchain_node *callchain_node_p;
	char *array = NULL;
	// Consider maximum callchain size. Otherwise, we should loop twice.
	size_t data_len, pos = 0;
	u64 this_waiting_time = 0;
	int waiter_count = 0;
	const pid_t pid = object_id_p->lock_id.pid;
	const pid_t tid = object_id_p->idle_id.tid;

	// Calculate data_len considering header and waiters.
	data_len = sizeof(kdks_sample_header_t) + sizeof__kdks_record(callchain->nr)
		+ lock_object->waiters_data_len;
	data = (struct kdks_sample_data *)kmalloc(data_len, GFP_ATOMIC);
	array = (char *)data;

	// Copy lock holder
	pos = sizeof(kdks_sample_header_t);
	record = (kdks_record_t *)(array + pos);
	pos += copy_kdks_record(record, pid, tid, lock_object->acc_waiting_time,
		&callchain_entry_node->ips, true);
	set_callchain_shipped(callchain_entry_node);

	// Copy locks & waiters
	list_for_each_safe(waiter, tmp, &lock_object->waiters) {
		struct idle_obj *waiter_obj = container_of(waiter, struct idle_obj, link_node);
		callchain_node_p = container_of(waiter_obj->id.ips, struct callchain_node, ips);

		// Record position is where to copy.
		record = (kdks_record_t *)(array + pos);

		if (data_len < pos) {
			kdks_pr_trace(LOG_ERR, "Spinlock copy datasize mismatch"
				"tid %u, addr 0x%llx, waiter_count %d"
				"original %lu, current %lu\n",
				tid, object_id_p->lock_id.addr, waiter_count, data_len, pos);
			break;
		}

		kdks_pr_trace(LOG_VERBOSE, "Spinlock Waiter tid %u - key %u, "
				"wait_time %llums, total %llums\n",
				waiter_obj->id.tid, waiter_obj->hash,
				clock_to_ms(waiter_obj->acc_waiting_time),
				clock_to_ms(waiter_obj->tot_waiting_time));

		this_waiting_time += waiter_obj->acc_waiting_time;

		// FIXME: Needs to know if this list contain the holder.
		// One hotfix we can apply is to skip it if waiter's tid is same.
		if (waiter_obj->id.tid != tid) {
			// check ips shipped status
			pos += copy_kdks_record(record, waiter_obj->id.pid,
				waiter_obj->id.tid, waiter_obj->acc_waiting_time,
				waiter_obj->id.ips, !is_callchain_shipped(callchain_node_p));

			set_callchain_shipped(callchain_node_p);
			lock_object->acc_waiting_time += waiter_obj->acc_waiting_time;
			++waiter_count;
		}

		// Clean up
		waiter_obj->acc_waiting_time = 0;
		waiter_obj->last_time = KDKS_INVALID_TIME_VAL;
		waiter_obj->lid = NULL;
		list_del_rcu(waiter);
	}

	// Where we have waiters, we send data only.
	if (waiter_count) {
		// Copy header and kdks sample header
		kdks_set_perf_header(&data->header.perf_header);
		data->header.lock_type = KDKS_SPINLOCK;
		data->header.addr = object_id_p->lock_id.addr;
		data->header.n_waiters = waiter_count;
		data->header.data_len = pos;	/*this is real size*/

		// Send sample data
		if (copy_kdks_data_to_prb(data)) {
			kdks_pr_trace(LOG_ERR, "Failed to copy sample data "
				"Spinlock Holder tid %u at ip 0x%llx, "
				"addr 0x%llx, waiter_count %d, waiting %llums, "
				"last_time %llums\n",
				tid, ip, object_id_p->lock_id.addr, lock_object->n_waiters,
				clock_to_ms(this_waiting_time),
				clock_to_ms(lock_object->last_time));
		} else {
			kdks_pr_trace(LOG_VERBOSE, "Spinlock Holder tid %u at ip 0x%llx, "
				"addr 0x%llx, waiter_count %d, waiting %llums, "
				"last_time %llums\n",
				tid, ip, object_id_p->lock_id.addr, lock_object->n_waiters,
				clock_to_ms(this_waiting_time),
				clock_to_ms(lock_object->last_time));
		}
	}

	// Reset current holder
	lock_object->n_waiters = 0;
	lock_object->waiters_data_len = 0;
	kfree(data);
}

static void process_lock_waiter(struct idle_obj *idle_object, struct lock_obj *lock_object,
	struct callchain_node *callchain_entry_node)
{
	if (!idle_object || !lock_object) {
		kdks_pr_trace(LOG_ERR, "Both idle object and lock object should be valid! "
			"idle_object = %p, lock_object = %p\n", idle_object, lock_object);
		return;
	}

	update_acc_time(lock_object, idle_object);

	// FIXME: Find a safe way to update lock object status.
	// Adding waiters does not work without a spin lock for now.
	if (!idle_object->lid) {
		idle_obj_add_to_waiters(lock_object, idle_object);

		// Keep track of data_len
		if (!is_callchain_shipped(callchain_entry_node))
			lock_object->waiters_data_len += sizeof__kdks_record(idle_object->id.ips->nr);
		else
			lock_object->waiters_data_len += sizeof(struct kdks_record);
	}

	if (lock_object->status == LOCKOBJ_MAY_WAIT)
		lock_object->status = LOCKOBJ_SURE_WAIT;
}

/*breakpoint handler,
  we will check current breakpoint's addr has been updated or not*/
static void hbp_breakpoint_triggered(struct perf_event *bp, struct perf_sample_data *data,
	struct pt_regs *regs)
{
	union object_id id;
	struct spin_node *spin_node_p;
	struct lock_obj *lock_object;
	struct callchain_node *callchain_entry_node;
	callchain_t *callchain;
	u64 ip = instruction_pointer(regs);

	// FIXME: Get user callchain and kernel callchain.
	callchain = perf_get_callchain(regs, 0, false, true, false, true);
	if (!callchain) {
		pr_warning("unable to get callchain \n");
		return;
	}

	id.lock_id.addr = bp->attr.bp_addr;
	id.lock_id.pid = current->tgid;
	id.idle_id.tid = current->pid;
	id.idle_id.ips = callchain;

	/*get lock obj and idle obj*/
	lock_object = lock_obj_ht_lookup(id.lock_id.pid, id.lock_id.addr);
	if (!lock_object) {
		BUG();
		return;
	}

	callchain_entry_node = callchain_ht_get_node(callchain);
	if (IS_ERR(callchain_entry_node)) {
		pr_warning("unable to allocate kdks callchain entry\n");
		BUG();
		return;
	}

	// We can access lock holder and wiaters via spin_node.
	spin_node_p = spintable_find(ip);

	// FIXME: Do we need spin_lock here?
	spin_lock(&lock_object->lock); {
		if (spin_node_p) {
			struct idle_obj *idle_object = idle_ht_get_obj(id.idle_id);
			process_lock_waiter(idle_object, lock_object, callchain_entry_node);
		} else
			process_lock_holder(lock_object, callchain, callchain_entry_node, &id, ip);
	} spin_unlock(&lock_object->lock);
}

static struct perf_event *hbp_register_user_hbp(struct task_struct *task,
	int len, int type, u64 hbp_addr)
{
	struct perf_event_attr attr;

	hw_breakpoint_init(&attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.exclude_kernel = 1;
	attr.bp_addr = hbp_addr;
	attr.bp_len = len;
	attr.bp_type = type;
	return register_user_hw_breakpoint(&attr, hbp_breakpoint_triggered, NULL, task);
}

/*set breakpoint address in breakpoint slot*/
#ifndef DEBUG_NO_SET_HBP
static struct perf_event *hbp_set_breakpoint_addr(struct task_struct *task,
	int hbp_slot, u64 hbp_addr)
{
	struct perf_event_attr attr;
	struct thread_struct *thread = &task->thread;
	struct perf_event *bp = thread->ptrace_bps[hbp_slot];
	int err = 0;

	if (!bp) {
		// FIXME: HW_BREAKPOINT_LEN_1 might not work for all the cases.
		// We just mimic ptrace_set_breakpoint_addr here.
		bp = hbp_register_user_hbp(task, HW_BREAKPOINT_LEN_1, HW_BREAKPOINT_RW, hbp_addr);
		if (!IS_ERR(bp)) {
			thread->ptrace_bps[hbp_slot] = bp;
			kdks_pr_trace(LOG_VERBOSE, "set new breakpoint addr tid %u for 0x%llx slot %d\n",
				task->pid, hbp_addr, hbp_slot);
		}
		return bp;
	}

	attr = bp->attr;
	if (attr.bp_addr == hbp_addr)
		return bp;

	kdks_pr_trace(LOG_VERBOSE, "modify breakpoint addr tid %u for 0x%llx slot %d \n",
		task->pid, hbp_addr, hbp_slot);

	attr.bp_addr = hbp_addr;
	err = modify_user_hw_breakpoint(bp, &attr);
	return err ? ERR_PTR(err) : bp;
}
#endif

/*check task has breakpoint in a certain slot*/
__attribute__((unused))
static inline struct perf_event *hbp_get_slot_from_task(struct task_struct *task, int slot)
{
	return task->thread.ptrace_bps[slot];
}

/*register or replace hbp address*/
static int hbp_register_bp_for_all_threads(pid_t pid, u64 hbp_addr, int hbp_slot)
{
	struct task_struct *group_leader;
	struct task_struct *task;
#ifndef DEBUG_NO_SET_HBP
	struct perf_event *bp_event;
#endif
	int ret = 0;

	kdks_pr_trace(LOG_VERBOSE, "register breakpoint enter pid %u for 0x%llx\n", pid, hbp_addr);

	group_leader = hbp_get_task_struct(pid);
	if (!group_leader) {
		kdks_pr_error("failed to get task for pid:%u failed \n", pid);
		return -EFAULT;
	}

	for_each_thread(group_leader, task) {
		get_task_struct(task);
#ifndef DEBUG_NO_SET_HBP
		bp_event = hbp_set_breakpoint_addr(task, hbp_slot, hbp_addr);
		if (IS_ERR(bp_event)) {
			ret = PTR_ERR(bp_event);
			// No such process. This happens when the target task has switched out.
			if (ret != -ESRCH)
				kdks_pr_error("failed to set breakpoint for 0x%llx, err %d\n", hbp_addr, ret);

			kdks_pr_trace(LOG_VERBOSE, "failed to set breakpoint for 0x%llx, err %d\n", hbp_addr, ret);
			put_task_struct(task);
			put_task_struct(group_leader);
			return ret;
		}
#endif
		put_task_struct(task);
	}

	put_task_struct(group_leader);
	kdks_pr_verbose("HW Breakpoint slot[%d] at 0x%llx for RW installed.\n", hbp_slot, hbp_addr);

	return ret;
}

static inline
struct lock_obj *bp_lookup_lock_obj(pid_t pid, struct perf_event *event)
{
	/*get lock object*/
	u64 addr = event->attr.bp_addr;
	return lock_obj_ht_lookup(pid, addr);
}

__attribute__((unused))
static void clear_waiting_list(struct lock_obj *lock_obj){
	struct list_head *waiter, *tmp;
	list_for_each_safe(waiter, tmp, &lock_obj->waiters){
		struct idle_obj *waiter_obj = container_of(waiter,
				struct idle_obj, link_node);

		waiter_obj->last_time = KDKS_INVALID_TIME_VAL;
		waiter_obj->lid = NULL;	/*cut link*/

		/*delete from list*/
		list_del(waiter);
	}

	/*reset */
	lock_obj->n_waiters = 0;
}

/*install hw-breakpoint at hbp addr,
  find free bp slot and then steal it.
  return hbp_slot index*/
static int get_watchpoint_slot(pid_t pid, u64 addr, int *hbp_slot)
{
	int slot;
	int victim = 0;
	u64 last_time = UINT64_MAX;
	struct task_struct *group_leader;
	struct thread_struct *thread;
	struct perf_event *event;
	struct lock_obj *victim_obj = NULL;
	struct lock_obj *target_obj = NULL;

	group_leader = hbp_get_task_struct(pid);
	if (!group_leader) {
		kdks_pr_error("failed to get task for pid:%u failed \n", pid);
		return -EFAULT;
	}

	thread = &group_leader->thread;

	// Search empty or the same address already installed in the hbp.
	for (slot = 0; slot < HBP_NUM; slot++) {
		event = thread->ptrace_bps[slot];
		if (!event) {
			put_task_struct(group_leader);
			*hbp_slot = slot;
			return HBP_SLOT_EMPTY;
		}

		if (event->attr.bp_addr == addr) {
			/*we found the same address slot*/
			put_task_struct(group_leader);
			*hbp_slot = slot;
			return HBP_SLOT_SAME;
		}

		/*get lock object*/
		target_obj = bp_lookup_lock_obj(pid, event);

		/*if target lock object is missing,
		  then use this slot*/
		if (!target_obj) {
			put_task_struct(group_leader);
			BUG();
			return -EFAULT;
		}

		if (target_obj->last_time < last_time) {
			last_time = target_obj->last_time;
			victim = slot;
			victim_obj = target_obj;
		}
	}
	put_task_struct(group_leader);

	slot = victim;
#if 0
	// Unregistering hbp is not necessary since modify_user_hw_breakpoint handles it.
	hbp_unregister_slot(pid, slot);

	// FIXME: Update lock status in a safe way.
	if (victim_obj) {
		victim_obj->status = LOCKOBJ_NEW_WAIT;
		clear_waiting_list(victim_obj);	// Cut link
	}
#endif
	*hbp_slot = slot;
	return HBP_SLOT_EVICTED;
}

/****************************************************************
 * Account waiting time and promotion to watchpoint *
 We will account for time distance between waiters.
 It is calculated per each lock objects.
 Whether register lock object to hardware breakpoint or not is
 decided by average inter-arrival time of waiters.
 However, we only maintain accumulated total waiting time for
 each idle_objects.
 By doing this, we can promote
 if a certain lock object's waiting time is too small.
 *****************************************************************/
static inline void update_lockobj_last_time(struct lock_obj *lock_obj, u64 pebs_ts)
{
	u64 time_diff, timestamp;

	//timestamp = kdks_get_current_time();
	timestamp = pebs_ts;

	// FIXME: It seems like pebs event is not ordered event.
	if (!lock_obj->last_time) {
		lock_obj->last_time = timestamp;
		return;
	}

	if (timestamp > lock_obj->last_time) {
		time_diff = timestamp - lock_obj->last_time;
		lock_obj->last_time = timestamp;
	} else
		time_diff = lock_obj->last_time - timestamp;

	/* calculate average of time difference */
	lock_obj->avg_time_diff = (lock_obj->avg_time_diff >> 1) + (time_diff >> 1);
}

static int process_lockobj_new(struct lock_obj *lock_obj, struct idle_obj *idle_obj, u64 timestamp)
{
	int result, hbp_slot;
	pid_t pid = lock_obj->id.pid;
	u64 addr = lock_obj->id.addr;

	result = get_watchpoint_slot(pid, addr, &hbp_slot);
	if (result < 0)
		return result;

	/*we can skip if the same address already set*/
	if (result != HBP_SLOT_SAME) {
		update_lockobj_last_time(lock_obj, timestamp);
		result = hbp_register_bp_for_all_threads(pid, addr, hbp_slot);
		if (result < 0) {
			kdks_pr_trace(LOG_VERBOSE, "Error: %d, hbp_slot: %d\n", result, hbp_slot);
			return -EFAULT;
		}
	}

	/*upate status*/
	lock_obj->status = LOCKOBJ_MAY_WAIT;
	return hbp_slot;
}

static int process_lockobj_old(struct lock_obj *lock_obj, struct idle_obj *idle_obj, u64 timestamp)
{
	int ret;
	int hbp_slot;
	pid_t pid = lock_obj->id.pid;
	u64 addr = lock_obj->id.addr;

	if (unlikely(lock_obj->hbp_slot < 0)) {
		kdks_pr_error("lock object status and slot mismatch\n");
		return -EINVAL;
	}

	hbp_slot = lock_obj->hbp_slot;
	// This means that hbp slot taken by others.
	ret = get_watchpoint_slot(pid, addr, &hbp_slot);
	if (ret < 0)
		return ret;

	if (ret != HBP_SLOT_SAME) {
		update_lockobj_last_time(lock_obj, timestamp);
		ret = hbp_register_bp_for_all_threads(pid, addr, hbp_slot);
		if (ret < 0)
			return ret;
		lock_obj->status = LOCKOBJ_MAY_WAIT;
	}
	return hbp_slot;
}

// Handle deferrable hw_breakpoint request
void hbp_handle_work_request(struct work_struct *work)
{
	struct work_request *req = NULL;
	struct lock_obj *lock_obj = NULL;
	struct idle_obj *idle_obj = NULL;
	struct work_desc *desc = NULL;
	union object_id id;
	int result;

	if (unlikely(!work))
		return;

	/* get work description */
	req = (struct work_request*)work;
	desc = &req->desc;

	/*assign key data*/
	id.idle_id.addr = desc->addr;
	id.idle_id.pid  = desc->pid;
	id.idle_id.tid  = desc->tid;

#ifdef KDKS_USE_SPINPROBE_IPS
	/*get idle object*/
	id.idle_id.ips	= desc->ips;
	idle_obj = idle_ht_get_obj(id.idle_id);
#endif
	/*get lock object and copy status*/
	lock_obj = lock_obj_ht_get_obj(id.lock_id);

	// Get existing hbp_slot or assign a hbp_slot with new address
	if (lock_obj->status == LOCKOBJ_NEW_WAIT)
		result = process_lockobj_new(lock_obj, idle_obj, desc->time);
	else
		result = process_lockobj_old(lock_obj, idle_obj, desc->time);

	// Update hbp_slot number.
	if (result >= 0)
		lock_obj->hbp_slot = result;

	if (desc->ips)
		kfree((void *)desc->ips);
	kfree((void *)work);
}

int init_kdks_hbp(void)
{
	hbp_wq = create_singlethread_workqueue("kdks_hbp_wq");
	return unlikely(!hbp_wq) ? -ENOMEM : 0;
}

void exit_kdks_hbp(void)
{
	kdks_flush_wq(hbp_wq);
}

