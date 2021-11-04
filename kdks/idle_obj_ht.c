#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <linux/perf_event.h>
#include <linux/hashtable.h>
#include "kdks_i.h"

/*idle thread hash*/
#define KDKS_IDLETABLE_HASHBITS 14
static DEFINE_HASHTABLE(idle_ht, KDKS_IDLETABLE_HASHBITS);

/* we might update rcu concurrently */
spinlock_t idle_hash_lock;

int init_idle_ht(void)
{
	spin_lock_init(&idle_hash_lock);
	return 0;
}

/*exit thread ht*/
void exit_idle_ht(void)
{
	struct idle_obj *idle_obj;
	struct hlist_node *tmp;
	unsigned int bkt;

	hash_for_each_safe(idle_ht, bkt, tmp, idle_obj, node) {
		hash_del(&idle_obj->node);
		kfree(idle_obj);
	}
}

static void idle_obj_print(struct idle_obj *idle_obj)
{
	struct callchain_node *ips_node = container_of(idle_obj->id.ips, struct callchain_node, ips);
	kdks_pr_trace(LOG_INFO, "... IDLETABLE ENTRY INFO \n");
	kdks_pr_trace(LOG_INFO, "..... addr           : 0x%llx\n", idle_obj->id.addr);
	kdks_pr_trace(LOG_INFO, "..... pid/tid/c_time :%u/%u/%llums\n",
		idle_obj->id.pid, idle_obj->id.tid, clock_to_ms(idle_obj->last_time));
	kdks_pr_trace(LOG_INFO, "..... key/ips        : %8u/%8u\n", idle_obj->hash, ips_node->hash);
}

static inline u32 idle_ht_get_hash_val(const void *key, u32 ips_hash)
{
	return jhash2((u32 *)key, offsetof(struct idle_id, ips) / sizeof(u32), ips_hash);
}

/*hash lookup,
  key is hash value created from callchain*/
static struct idle_obj *idle_ht_lookup(pid_t pid, pid_t tid, u64 addr, callchain_t *ips, u32 hash)
{
	struct idle_obj *idle_obj;

	/*to make hash id, we don't account ips pointer*/
	hash_for_each_possible_rcu(idle_ht, idle_obj, node, hash) {
		struct idle_id *id = &idle_obj->id;
		if(idle_obj->hash == hash
			&& cmp_perf_callchain(id->ips, ips)
			/*if hash id matches, following is mostly match*/
#if !KDKS_IDLEID_FAST_CMP
			&& id->addr == addr
			&& id->tid == tid
			&& id->pid == pid
#endif
		)
			return idle_obj;
	}

	return NULL;
}

/*find and add idle node to hashtable
skip: Because ips is already allocated dynamically, we use idle_id's callchain memory.
 */
struct idle_obj*
idle_ht_get_obj(struct idle_id id) {
	struct idle_obj *idle_obj= NULL;
	struct callchain_node *ips_node = NULL;
	u32 hash;

	ips_node = callchain_ht_get_node(id.ips);
	if(IS_ERR(ips_node))
		return (struct idle_obj *)ips_node;

	hash=idle_ht_get_hash_val((void *)&id, ips_node->hash);

	/*idle hash lookup*/
	idle_obj = idle_ht_lookup(id.pid, id.tid, id.addr, &ips_node->ips, hash);

	/*found idle node*/
	if(idle_obj){
		if(idle_obj->last_time == KDKS_INVALID_TIME_VAL) {
			idle_obj->last_time = kdks_get_current_time();
			goto print_out;
		}
		goto out;
	}

	/*this lock object is not in the map, add it*/
	idle_obj = kzalloc(sizeof(*idle_obj), GFP_ATOMIC);

	if(IS_ERR(idle_obj))
		return ERR_PTR(-ENOMEM);

	/*set id and callchain*/
	idle_obj->id.pid = id.pid;
	idle_obj->id.tid = id.tid;
	idle_obj->id.addr = id.addr;
	idle_obj->id.ips = &ips_node->ips;

	INIT_LIST_HEAD(&idle_obj->link_node);
	idle_obj->last_time = kdks_get_current_time();	/*update current time*/

	/* add idle_obj to hashtable */
	idle_obj->hash = hash;

	/* hashtable update guarded by spinlock */
	spin_lock(&idle_hash_lock);
	hash_add_rcu(idle_ht, &idle_obj->node, hash);
	spin_unlock(&idle_hash_lock);

print_out:
	/*debug print*/
	if(kdks_debug_level >= LOG_VERBOSE)
		idle_obj_print(idle_obj);

	if(idle_obj->id.ips->nr > PERF_MAX_STACK_DEPTH){
		kdks_pr_trace(LOG_INFO, "... Callchain stack depth too long : %lld "
				"addr 0x%llx "
				"pid/tid  %u/%u " 
				"key/ips  %8u/%8u\n", 
				idle_obj->id.ips->nr,
				idle_obj->id.addr,
				idle_obj->id.pid, idle_obj->id.tid,
				idle_obj->hash, ips_node->hash);
	}
out:
	return idle_obj;
}
