#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
//#include <linux/spinlock.h>

#include <spintable.h>
#include "kdks_i.h"

#ifndef __KDKS_POISON
#define __KDKS_POISON 0xDEADBEEFBAD22222
#endif

/*find spinloop node and return it*/
static inline struct spin_node *spinprobe_get_spinnode(struct perf_sample_data *data)
{
	// Returning NULL means that the data is not a spin address.
	return data->type & PERF_SAMPLE_IP ? spintable_find(data->ip) : NULL;
}

/*get memory address of sync_variable from gas memory syntax*/
static u64 spinprobe_get_sync_addr(struct spin_entry *entry, struct sync_node *node,
	struct perf_sample_data *data)
{
	int sign_bit;
	u64 sync_addr;

	// Get required registers and calcuate hw-breakpoint addr from GAS syntax.
	// indirect memory addressing of x86
	// x86: *(base register + (offset register * multiplier) + displacement)
	// GAS: displacement(base register, offset register, multiplier)

	// Calculate sync address in memory.
	sync_addr = ut_decode_sync_var(data, entry, node->var, &sign_bit, 0);
	if (!IS_VALID_ADDR(sync_addr)) {
		kdks_pr_trace(LOG_ERR, "invalid sync variable mem addr\n");
		return KDKS_INVALID_ADDR;
	}

	if (sign_bit == -1) {
		kdks_pr_trace(LOG_ERR, "address can not be null\n");
		return KDKS_INVALID_ADDR;
	}

	kdks_pr_trace(LOG_VERBOSE, "sync variable mem addr 0x%llx\n", sync_addr);
	return sync_addr;
}

/*extract idle sync object information from spinnode and perf sample data,
  and fill idle object key(pid, tid, hbp_addr).*/
static int spinprobe_submit_requests(struct spin_node *spin_node_p, struct perf_sample_data *data)
{
	u64 time;
	u32 pid, tid;
	struct work_request *request;
	struct list_head *element, *next_element;
#ifdef KDKS_USE_SPINPROBE_IPS
	callchain_t *callchain;
#endif
	struct spin_entry *entry = spin_node_p->e;

	/*check how many sync vars in the current spinnode*/
	kdks_pr_trace(LOG_VERBOSE, "spinnode info-range:[0x%llx,0x%llx], n_vars:%d\n",
		entry->saddr, entry->eaddr, entry->n_vars);

	pid = perf_data_get_pid(data);
	if (pid == KDKS_INVALID_PID) {
		kdks_pr_trace(LOG_ERR, "Fail to get pid from perf sample\n");
		return -EFAULT;
	}

	tid = perf_data_get_tid(data);
	if (tid == KDKS_INVALID_TID) {
		kdks_pr_trace(LOG_ERR, "Fail to get tid from perf sample\n");
		return -EFAULT;
	}

	time = perf_data_get_time(data);
	if (time == KDKS_INVALID_TIME) {
		kdks_pr_trace(LOG_ERR, "Fail to get time from perf sample\n");
		return -EFAULT;
	}

#ifdef KDKS_USE_SPINPROBE_IPS
	/*get callchain*/
	callchain = (callchain_t *)perf_data_get_callchain(data);
	if (IS_ERR(callchain)) {
		int error = PTR_ERR(callchain);
		kdks_pr_trace(LOG_ERR, "perf sample doesn't have a callchain %d\n", error);
		return error;
	}

	if (!callchain->nr) {
		kdks_pr_trace(LOG_ERR, "callchain is empty \n");
		return -EFAULT;
	}
#endif

	/*loop over sync_address list*/
	list_for_each_safe(element, next_element, &entry->vars) {
		u64 hbp_addr;
#ifdef KDKS_USE_SPINPROBE_IPS
		u64 ips_size;
		callchain_t *callchain_clone;
#endif
		struct sync_node *sync_node_p = list_entry(element, struct sync_node, node);
		if (!sync_node_p)
			continue;

		/*Get the sync memory address*/
		hbp_addr = spinprobe_get_sync_addr(entry, sync_node_p, data);
		if (!IS_VALID_ADDR(hbp_addr)) {
			kdks_pr_trace(LOG_ERR, "Fail to get hbp_addr from perf sample\n");
			return -EFAULT;
		}

		/*TODO - this can incur too much memory overhead.
		  we can reuse allocated memory like a ring buffer*/
		request = (struct work_request*)kmalloc(sizeof(struct work_request), GFP_ATOMIC);
		if (!request) {
			kdks_pr_trace(LOG_ERR, "Can't allocate work queue memory\n");
			return -ENOMEM;
		}

		INIT_WORK(&request->work, hbp_handle_work_request);

		kdks_pr_trace(LOG_VERBOSE,
			"tid:%u, spin_range:[0x%llx,0x%llx], n_vars:%d, "
			"sync_mem:0x%llx, time %llu\n",
			tid, entry->saddr, entry->eaddr, entry->n_vars, hbp_addr, time);

		request->desc.addr = hbp_addr;
		request->desc.time = time;
		request->desc.pid = pid;
		request->desc.tid = tid;
#ifdef KDKS_USE_SPINPROBE_IPS
		// Copy callchain data to the description.
		// perf_callchain_entry might contain garbage at the end of the callchain.
		ips_size = sizeof(u64) * callchain->nr;
		callchain_clone = (callchain_t *)kmalloc(sizeof(*callchain) + ips_size, GFP_ATOMIC);
		if (!callchain_clone)
			return -ENOMEM;

		callchain_clone->nr = callchain->nr;
		memcpy((void *)&callchain_clone->ip[0], (void *)&callchain->ip[0], ips_size);
		request->desc.ips = callchain_clone;
#endif
		queue_work(hbp_wq, &request->work);
	}

	return 0;
}

/*
 * kdks probes perf_output_sample(), which is to copy a perf event
 * to userspace mmaped buffer. By solely turning on a PEBS event
 * for conditional branch instruction, kdks can sample the execution
 * of potentially spinning loops.
 */

/*
 * list of perf events, which may be useful
 * - PERF_SAMPLE_IP:           data->ip
 * - PERF_SAMPLE_REGS_USER:    data->regs_user.regs
 */
static int spin_perf_sample_handler(struct kprobe *kprobe_at_perf, struct pt_regs *regs)
{
	int ret = 0;
	struct perf_sample_data *data;
	struct spin_node *spin_node_p = NULL;

	/* get a perf_sample_data from perf_output_sample():
	 * void perf_output_sample(struct perf_output_handle *handle,
	 *			   struct perf_event_header *header,
	 * 			   struct perf_sample_data *data,
	 *			   struct perf_event *event)
	 */

	/*get header and data*/
	//header = (void *) PT_REGS_PARM2(regs);
	data = (struct perf_sample_data *)PT_REGS_PARM3(regs);
	//kdks_pr_trace(LOG_VERBOSE, "invoked from ip:0x%llx\n", data->ip);

	/* Check sampled application is running in spinloop region */
	spin_node_p = spinprobe_get_spinnode(data);
	if (!spin_node_p)
		return 0;

	kdks_pr_trace(LOG_VERBOSE, "found spin node 0x%p\n", (void *)spin_node_p);
	if (!spin_node_p->e) {
		kdks_pr_trace(LOG_ERR, "found orphan spin node 0x%p!\n", (void *)spin_node_p);
		return 0;
	}

	/*fill idle key object,
	  copy whole ips data for the deferrable task - work_queue*/
	ret = spinprobe_submit_requests(spin_node_p, data);
	if (ret)
		kdks_pr_trace(LOG_ERR, "kdks_perf_sample_handler return error %d\n", ret);
	return 0;
}

static struct kprobe g_kprobe_at_perf = {
	.symbol_name = "perf_output_sample",
	.pre_handler = spin_perf_sample_handler,
};

int init_spinprobe(struct kdks_attr kdks_attr)
{
	int ret;

	ret = init_kdks_hbp();
	if (unlikely(ret < 0)) {
		kdks_pr_error("Fail to create hw-breakpoint data structures : %d\n", ret);
		exit_kdks_hbp();
		exit_spintable();
		return ret;
	}

	ret = init_spintable();
	if (unlikely(ret < 0)) {
		kdks_pr_error("Fail to create spinloop table data structures : %d\n", ret);
		exit_kdks_hbp();
		exit_spintable();
		return ret;
	}

	ret = register_kprobe(&g_kprobe_at_perf);
	if (unlikely(ret < 0)) {
		kdks_pr_error("Fail to register kprobe for perf: %d\n", ret);
		exit_kdks_hbp();
		exit_spintable();
		return ret;
	}

	kdks_pr_info("Planted kprobe at : 0x%p for spinloop probing\n", g_kprobe_at_perf.addr);
	return 0;
}

void exit_spinprobe(void)
{
	if (g_kprobe_at_perf.addr) {
		unregister_kprobe(&g_kprobe_at_perf);
		kdks_pr_info("Unregister kprobe at : 0x%p\n", g_kprobe_at_perf.addr);
	}

	exit_kdks_hbp();
	exit_spintable();
}
