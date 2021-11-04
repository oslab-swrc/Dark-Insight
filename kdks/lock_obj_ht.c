#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <linux/perf_event.h>
#include <linux/hashtable.h>
#include "kdks_i.h"

/*lock object hash*/
#define KDKS_LOCKOBJ_HASHBITS (10)
static DEFINE_HASHTABLE(lock_obj_ht, KDKS_LOCKOBJ_HASHBITS);

/* hash table spin lock */
spinlock_t lock_hash_lock;
int init_lock_obj_ht(void)
{
	spin_lock_init(&lock_hash_lock);
	return 0;
}

void exit_lock_obj_ht(void)
{
	struct lock_obj *lock_obj;
	struct hlist_node *tmp;
	unsigned int bkt;

	hash_for_each_safe(lock_obj_ht, bkt, tmp, lock_obj, node) {
		/* need unregister hbp if it was registered */
		if (kdks_run_mode != KDKS_RUN_MODE_FTEX_ONLY
			&& hbp_get_task_struct(lock_obj->id.pid))
			hbp_wide_unregister_bp(lock_obj->id.pid);

		/* delete */
		hash_del(&lock_obj->node);
		kfree(lock_obj);
	}
}

struct lock_obj *lock_obj_ht_lookup(pid_t pid, u64 addr)
{
	struct lock_obj *lock_obj;
	hash_for_each_possible_rcu(lock_obj_ht, lock_obj, node, addr) {
		if (lock_obj->id.pid == pid && lock_obj->id.addr == addr)
			return lock_obj;
	}

	return NULL;
}

static void lock_obj_print(struct lock_obj *node)
{
	kdks_pr_trace(LOG_DEBUG, "Lock object info\n");
	kdks_pr_trace(LOG_DEBUG, "...pid/memaddr : %u/0x%llx\n", node->id.pid, node->id.addr);
}

/*
 * Find and add lock object,
 * return added lock object node or error pointer
 */
struct lock_obj *lock_obj_ht_get_obj(struct lock_id id)
{
	struct lock_obj *lock_obj = lock_obj_ht_lookup(id.pid, id.addr);
	if(lock_obj)
		return lock_obj;

	lock_obj = kzalloc(sizeof(*lock_obj), GFP_NOIO);
	if (IS_ERR(lock_obj))
		return ERR_PTR(-ENOMEM);

	/*init lock object*/
	// Init lock objects
	lock_obj->id.pid = id.pid;
	lock_obj->id.addr = id.addr;
	lock_obj->n_waiters = 0;
	lock_obj->waiters_data_len = 0;
	lock_obj->avg_time_diff = 0;
	lock_obj->last_time = 0;
	lock_obj->acc_waiting_time = 0;
	lock_obj->hbp_slot = KDKS_INVALID_HBP_SLOT;

	spin_lock_init(&lock_obj->lock);
	INIT_LIST_HEAD(&lock_obj->waiters);

	// Add lock obj to hashtable
	spin_lock(&lock_hash_lock);
	hash_add_rcu(lock_obj_ht, &lock_obj->node, id.addr);
	spin_unlock(&lock_hash_lock);

	// Debugging purpose only.
	if (kdks_debug_level >= LOG_DEBUG)
		lock_obj_print(lock_obj);

	return lock_obj;
}
