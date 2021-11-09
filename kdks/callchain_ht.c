// SPDX-License-Identifier: MIT
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <linux/perf_event.h>
#include <linux/hashtable.h>
#include "kdks_i.h"

/*callchain hash*/
#define KDKS_CALLCHAIN_HASHBITS 10

spinlock_t callchain_hash_lock;

/*callchain hashtable*/
static DEFINE_HASHTABLE(callchain_ht, KDKS_CALLCHAIN_HASHBITS);

int init_callchain_ht(void)
{
	spin_lock_init(&callchain_hash_lock);
	return 0;
}

void exit_callchain_ht(void)
{
	struct callchain_node *ips_node;
	struct hlist_node *tmp;
	unsigned int bkt;

	hash_for_each_safe(callchain_ht, bkt, tmp, ips_node, node) {
		hash_del(&ips_node->node);
		kfree(ips_node);
	}
}

static inline u32 callchain_ht_get_hash_val(callchain_t *ips)
{
	return jhash2((u32 *)&ips->ip, ips->nr * sizeof(u64) / sizeof(u32), 0);
}

static struct callchain_node *callchain_ht_lookup(callchain_t *ips, u32 hash)
{
	struct callchain_node *ips_node;
	hash_for_each_possible_rcu(callchain_ht, ips_node, node, hash) {
		/*callchain already in the map*/
		if (hash == ips_node->hash && cmp_perf_callchain(&ips_node->ips, ips))
			return ips_node;
	}

	return NULL;
}

/*
 * Find and add callchain to hashtable.
 * Return callchain entry pointer in hashtable,
 * ips : callchain_entries pointer
 */
struct callchain_node* callchain_ht_get_node(callchain_t *ips)
{
	struct callchain_node *ips_node;
	/*size of callchain node*/
	size_t length;
	size_t alloc_size;
	u32 hash;

	/* don't have a valid callchain */
	if (!ips || !ips->nr)
		return ERR_PTR(-EFAULT);

	if (ips->nr > PERF_MAX_STACK_DEPTH) {
		kdks_pr_trace(LOG_ERR, "callchain length too long %lld\n", ips->nr);
		return ERR_PTR(-E2BIG);
	}

	/*make hash value from callchain*/
	hash = callchain_ht_get_hash_val(ips);
	ips_node = callchain_ht_lookup(ips, hash);
	if (ips_node)
		return ips_node;

	length = ips->nr * sizeof(u64);
	alloc_size = sizeof(*ips_node) + length;

	/*this callchain is not in the map, add it*/
	ips_node = kzalloc(alloc_size, GFP_ATOMIC);
	if (IS_ERR(ips_node))
		return ERR_PTR(-ENOMEM);

	/*set values*/
	ips_node->hash = hash;
	ips_node->flags = 0;
	ips_node->ips.nr = ips->nr;
	memcpy(&ips_node->ips.ip[0], &ips->ip[0], length);

	spin_lock(&callchain_hash_lock);
	hash_add_rcu(callchain_ht, &ips_node->node, hash);
	spin_unlock(&callchain_hash_lock);

	// Debugging purpose only
	if (kdks_debug_level >= LOG_DEBUG)
		perf_print_callchain(&ips_node->ips);

	return ips_node;
}
