#include <asm/perf_regs.h>
#include <asm/ptrace.h>
#include <asm/stacktrace.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include "kdks_i.h"

#ifndef PERF_MAX_CONTEXTS_PER_STACK
#define PERF_MAX_CONTEXTS_PER_STACK       8
#endif

struct callchain_cpus_entries {
	struct rcu_head	rcu_head;
	callchain_t 	*cpu_entries[0];
};

int sysctl_perf_event_max_stack __read_mostly = PERF_MAX_STACK_DEPTH;
int sysctl_perf_event_max_contexts_per_stack __read_mostly = PERF_MAX_CONTEXTS_PER_STACK;

static inline size_t callchain_entry__sizeof(void)
{
	return (sizeof(struct kdks_perf_callchain_entry) +
			sizeof(__u64) * (sysctl_perf_event_max_stack +
				sysctl_perf_event_max_contexts_per_stack));
}

static DEFINE_PER_CPU(int, callchain_recursion[PERF_NR_CONTEXTS]);
static atomic_t nr_callchain_events;
static DEFINE_MUTEX(callchain_mutex);
static struct callchain_cpus_entries *callchain_cpus_entries=NULL;


static inline int
valid_user_frame(const void __user *fp, unsigned long size)
{
	return (__range_not_ok(fp, size, TASK_SIZE) == 0);
}

/*get/put_recursion_context from kernel/events/internal.h*/
static inline int get_recursion_context(int *recursion)
{
	int rctx;

	if (in_nmi())
		rctx = 3;
	else if (in_irq())
		rctx = 2;
	else if (in_softirq())
		rctx = 1;
	else
		rctx = 0;

	if (recursion[rctx])
		return -1;

	recursion[rctx]++;
	barrier();

	return rctx;
}

static inline void put_recursion_context(int *recursion, int rctx)
{
	barrier();
	recursion[rctx]--;
}

static inline int kdks_perf_callchain_store(callchain_t *entry, u64 ip)
{
	if (entry->nr < PERF_MAX_STACK_DEPTH) {
		entry->ip[entry->nr++] = ip;
		return 0;
	} else {
		return -1; /* no more room, stop walking the stack */
	}
}


static void release_callchain_buffers_rcu(struct rcu_head *head)
{
	struct callchain_cpus_entries *entries;
	int cpu;

	entries = container_of(head, struct callchain_cpus_entries, rcu_head);

	for_each_possible_cpu(cpu)
		kfree(entries->cpu_entries[cpu]);

	kfree(entries);
}

static void release_callchain_buffers(void)
{
	struct callchain_cpus_entries *entries;

	entries = callchain_cpus_entries;
	RCU_INIT_POINTER(callchain_cpus_entries, NULL);
	call_rcu(&entries->rcu_head, release_callchain_buffers_rcu);
}

static int alloc_callchain_buffers(void)
{
	int cpu;
	int size;
	struct callchain_cpus_entries *entries;

	/*
	 * We can't use the percpu allocation API for data that can be
	 * accessed from NMI. Use a temporary manual per cpu allocation
	 * until that gets sorted out.
	 */
	size = offsetof(struct callchain_cpus_entries, cpu_entries[nr_cpu_ids]);

	entries = kzalloc(size, GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	size = callchain_entry__sizeof() * PERF_NR_CONTEXTS;

	for_each_possible_cpu(cpu) {
		entries->cpu_entries[cpu] = kmalloc_node(size, GFP_KERNEL, cpu_to_node(cpu));
		if (!entries->cpu_entries[cpu])
			goto fail;
	}

	rcu_assign_pointer(callchain_cpus_entries, entries);

	return 0;

fail:
	for_each_possible_cpu(cpu)
		kfree(entries->cpu_entries[cpu]);
	kfree(entries);

	return -ENOMEM;
}

callchain_t *perf_get_callchain_entry(int *rctx)
{
	int cpu;
	struct callchain_cpus_entries *entries;

	*rctx = get_recursion_context(this_cpu_ptr(callchain_recursion));
	if (*rctx == -1)
		return NULL;

	entries = rcu_dereference(callchain_cpus_entries);
	if (!entries)
		return NULL;

	cpu = smp_processor_id();

	//return &entries->cpu_entries[cpu][*rctx];
	return (((void *)entries->cpu_entries[cpu]) +
			(*rctx * callchain_entry__sizeof()));
}

static void put_callchain_entry(int rctx)
{
	put_recursion_context(this_cpu_ptr(callchain_recursion), rctx);
}

int perf_get_callchain_buffers(void)
{
	int err = 0;
	int count;

	mutex_lock(&callchain_mutex);
	count = atomic_inc_return(&nr_callchain_events);
	if (WARN_ON_ONCE(count < 1)) {
		atomic_dec(&nr_callchain_events);
		mutex_unlock(&callchain_mutex);
		return -EINVAL;
	}

	if (count > 1) {
		/* If the allocation failed, give up */
		if (!callchain_cpus_entries)
			atomic_dec(&nr_callchain_events);
		mutex_unlock(&callchain_mutex);
		return -ENOMEM;
	}

	err = alloc_callchain_buffers();
	if (err)
		atomic_dec(&nr_callchain_events);
	mutex_unlock(&callchain_mutex);
	return err;
}

void perf_put_callchain_buffers(void)
{
	if (!atomic_dec_and_mutex_lock(&nr_callchain_events, &callchain_mutex))
		return;
	release_callchain_buffers();
	mutex_unlock(&callchain_mutex);
}

bool perf_has_callchain_buffers(void)
{
	return callchain_cpus_entries != NULL;
}

static void
kdks_perf_callchain_user(callchain_t *entry, struct pt_regs *regs)
{
	struct stack_frame frame;
	const void __user *fp;

	/*TODO:handle this*/
#if 0 /*there's no way to get this from kernel*/
	if (perf_guest_cbs && perf_guest_cbs->is_in_guest()) {
		/* TODO: We don't support guest os callchain now */
		return;
	}
#endif

	/*
	 * We don't know what to do with VM86 stacks.. ignore them for now.
	 */
	if (regs->flags & (X86_VM_MASK | PERF_EFLAGS_VM))
		return;

	fp = (void __user *)regs->bp;

	kdks_perf_callchain_store(entry, regs->ip);

	if (!current->mm)
		return;

	/*TODO:IA32 support?*/
#if 0 /*no ia32 support*/
	if (perf_callchain_user32(regs, entry))
		return;
#endif

	pagefault_disable();
	while (entry->nr < PERF_MAX_STACK_DEPTH) {
		unsigned long bytes;
		frame.next_frame             = NULL;
		frame.return_address = 0;

		if (!access_ok(VERIFY_READ, fp, 16))
			break;

		bytes = __copy_from_user_inatomic(&frame.next_frame, fp, 8);
		if (bytes != 0)
			break;
		bytes = __copy_from_user_inatomic(&frame.return_address, fp+8, 8);
		if (bytes != 0)
			break;

		if (!valid_user_frame(fp, sizeof(frame)))
			break;

		kdks_perf_callchain_store(entry, frame.return_address);
		fp = (void __user *)frame.next_frame;
	}
	pagefault_enable();
}

/*get perf callchain user - copied from get_perf_callchain from core.c*/
callchain_t *
perf_get_callchain(struct pt_regs *regs, u32 init_nr, bool kernel, bool user,
		bool crosstask, bool add_mark)
{
	callchain_t *entry;
	int rctx;

	entry = perf_get_callchain_entry(&rctx);
	if (rctx == -1)
		return NULL;

	if (!entry)
		goto exit_put;

	entry->nr = init_nr;

#if 0 /*At the first, just try to get user callchain*/
	if (kernel && !user_mode(regs)) {
		if (add_mark)
			perf_callchain_store(entry, PERF_CONTEXT_KERNEL);
		perf_callchain_kernel(entry, regs);
	}
#endif

	if (user) {
		if (!user_mode(regs)) {
			if  (current->mm)
				regs = task_pt_regs(current);
			else
				regs = NULL;
		}

		if (regs) {
			if (crosstask)
				goto exit_put;

			if (add_mark)
				kdks_perf_callchain_store(entry, PERF_CONTEXT_USER);
			kdks_perf_callchain_user(entry, regs);
		}
	}

exit_put:
	put_callchain_entry(rctx);

	return (callchain_t *)entry;
}
