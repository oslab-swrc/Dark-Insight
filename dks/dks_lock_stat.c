#include <sys/types.h>
#include <linux/types.h>

#include <dks_common.h>

#include "include/dks_lock_stat.h"
#include "linux/hashtable.h"
#include "util/util.h"
#include "util/debug.h"

struct dks_ht *dks_ht__new(unsigned int bits, size_t entry_size)
{
	struct dks_ht *dks_ht;
	struct hlist_head *ht;
	size_t size;

	dks_ht = zalloc(sizeof(struct dks_ht));
	if (!dks_ht)
		return NULL;

	size = 1UL << bits;
	ht = calloc(size, sizeof(struct hlist_head));
	if (!ht) {
		free(dks_ht);
		return NULL;
	}

	/*init hashtable buckets*/
	__hash_init(ht, bits);

	dks_ht->ht = ht;
	dks_ht->entry_size = entry_size;
	dks_ht->sz = size;
	dks_ht->bits = bits;
	return dks_ht;
}

/*free all entries in the hashtable*/
static void dks_ht__drop(struct dks_ht *dks_ht, free_entry_fn free_entry)
{
	struct dks_hash_entry *entry;
	struct hlist_node *tmp;
	unsigned int bkt;

	if (!dks_ht)
		return;

	dks_hash_for_each_safe(dks_ht->ht, bkt, tmp, entry, node, dks_ht->sz) {
		hash_del(&entry->node);
		if (free_entry)
			free_entry(dks_ht, entry);
		else
			dks_ht__free_entry(dks_ht, entry);
	}

	dks_ht->cnt = 0;
}

void dks_ht__free(struct dks_ht *dks_ht, free_entry_fn fn)
{
	if (!dks_ht)
		return;

	dks_ht__drop(dks_ht, fn);
	free(dks_ht->ht);
	free(dks_ht);
}

void *dks_ht__alloc_entry(struct dks_ht *dks_ht)
{
	return malloc(dks_ht->entry_size);
}

void dks_ht__free_entry(struct dks_ht *dks_ht, void *entry)
{
	dks_ht->cnt--;
	free(entry);
}

int dks_ht__add(struct dks_ht *dks_ht, u64 key, struct dks_hash_entry *entry)
{
	entry->key = key;
	dks_hash_add(dks_ht->ht, &entry->node, key, dks_ht->bits);
	dks_ht->cnt++;

	return 0;
}

void *dks_ht__lookup(struct dks_ht *dks_ht, u64 key)
{
	struct dks_hash_entry *entry;

	dks_hash_for_each_possible((dks_ht->ht), entry, node, key, dks_ht->bits) {
		if (entry->key == key)
			return (void *)entry;
	}

	dks_debug("new hash key 0x%"PRIx64" hash_32 0x%lx # entries %zu \n",
		key, hash_long(key, dks_ht->bits), dks_ht->cnt);

	return NULL;
}

/*lock related hash APIs*/
void *dks_lock_table__lookup(struct dks_ht *dks_ht, u64 key, pid_t pid, u64 addr, u64 ips_id)
{
	struct dks_hash_entry *entry;

	dks_hash_for_each_possible(dks_ht->ht, entry, node, key, dks_ht->bits) {
		if (entry->key != key)
			continue;

		struct dks_lock_entry *lock_entry = (struct dks_lock_entry *)entry;
		if (lock_entry->pid == pid && lock_entry->addr == addr && lock_entry->ips_id == ips_id)
			return (void *)entry;
	}
	return NULL;
}

/* lock entry free function 
   we have clean-up waiters hashtable */
static void free_lock_entry_callback(struct dks_ht *dks_ht, void *entry)
{
	struct dks_lock_entry *lock_entry = (struct dks_lock_entry *)entry;

	dks_ht__free(lock_entry->waiters_ht, NULL);
	lock_entry->waiters_ht = NULL;
	dks_ht__free(lock_entry->cf_causality_ht, NULL);
	lock_entry->cf_causality_ht = NULL;

	dks_ht__free_entry(dks_ht, lock_entry);
}

static void free_lock_causality_entry_callback(struct dks_ht *dks_ht, void *entry)
{
	struct dks_lock_causality_entry *lock_causality_entry = (struct dks_lock_causality_entry *)entry;
	dks_ht__free(lock_causality_entry->next_lock_ht, NULL);
	lock_causality_entry->next_lock_ht = NULL;
	dks_ht__free_entry(dks_ht, lock_causality_entry);
}

/********************************
   statistics related functions
 ********************************/
int dks_lock_stat__build_stat_tables(struct dks_lock_stat *lock_stats)
{
	int ret = 0;
	struct dks_ht *lock_ht = NULL;
	struct dks_ht *ips_ht = NULL;
	struct dks_ht *last_lock_entry_ht = NULL;
	struct dks_ht *lock_causality_ht = NULL;

	lock_ht = dks_ht__new(DKS_LOCKOBJ_HASHBITS, sizeof(struct dks_lock_entry));
	if (!lock_ht) {
		pr_err("failed to create lock object hashtable\n");
		ret = -ENOMEM;
		goto err_out;
	}

	ips_ht = dks_ht__new(DKS_CALLCHAIN_HASHBITS, sizeof(struct dks_ips_entry));
	if (!ips_ht) {
		pr_err("failed to create ips hashtable\n");
		ret = -ENOMEM;
		goto err_out;
	}

	lock_causality_ht = dks_ht__new(DKS_LOCKOBJ_HASHBITS, sizeof(struct dks_count_entry));
	if (!lock_causality_ht) {
		pr_err("failed to create next lock object hashtable\n");
		ret = -ENOMEM;
		goto err_out;
	}

	last_lock_entry_ht = dks_ht__new(DKS_CALLCHAIN_HASHBITS, sizeof(struct dks_last_lock_entry));
	if (!last_lock_entry_ht) {
		pr_err("failed to create last ips hashtable\n");
		ret = -ENOMEM;
		goto err_out;
	}

	lock_stats->lock_ht = lock_ht;
	lock_stats->ips_ht = ips_ht;
	lock_stats->lock_causality_ht = lock_causality_ht;
	lock_stats->last_lock_entry_ht = last_lock_entry_ht;

err_out:
	if (ret) {
		dks_ht__free(lock_ht, free_lock_entry_callback);
		dks_ht__free(ips_ht, NULL);
		dks_ht__free(lock_causality_ht, free_lock_causality_entry_callback);
		dks_ht__free(last_lock_entry_ht, NULL);

		lock_stats->lock_ht = NULL;
		lock_stats->ips_ht = NULL;
		lock_stats->lock_causality_ht = NULL;
		lock_stats->last_lock_entry_ht = NULL;
	}

	return ret;
}

void dks_lock_stat__destroy_stat_tables(struct dks_lock_stat *lock_stats)
{
	dks_ht__free(lock_stats->lock_ht, free_lock_entry_callback);
	dks_ht__free(lock_stats->ips_ht, NULL);
	dks_ht__free(lock_stats->lock_causality_ht, free_lock_causality_entry_callback);
	dks_ht__free(lock_stats->last_lock_entry_ht, NULL);
}
