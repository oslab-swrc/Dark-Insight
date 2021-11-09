// SPDX-License-Identifier: MIT
#ifndef __DKS_LOCK_STAT_H__
#define __DKS_LOCK_STAT_H__

#include <linux/types.h>
#include <linux/hashtable.h>

#include <linux/jhash.h>

#include <dks_common.h>

#define DKS_LOCKOBJ_HASHBITS (14) /* lock object hash bucket bits */
#define DKS_WAITERS_HASHBITS (18) /* hashbits for waiters hash in lock obj */
#define DKS_CALLCHAIN_HASHBITS (18)	/* callchain hashtable bits */

#define dks_hash_for_each_safe(name, bkt, tmp, obj, member, sz)		\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < sz; (bkt)++)	\
		hlist_for_each_entry_safe(obj, tmp, &name[bkt], member)

#define dks_hash_add(hashtable, node, key, bits)                       \
	hlist_add_head(node, &hashtable[hash_min(key, bits)])

#define dks_hash_empty(hashtable, sz) __hash_empty(hashtable, sz)

#define dks_hash_for_each_possible(name, obj, member, key, bits)       \
	hlist_for_each_entry(obj, &name[hash_min(key, bits)], member)

/*dks hash table*/
struct dks_ht {
	struct hlist_head *ht;
	size_t entry_size;
	size_t sz;
	size_t cnt;
	unsigned int bits;
};

/* user defined hash entry free function */
typedef void (*free_entry_fn)(struct dks_ht *, void *entry);

struct dks_hash_entry {
	struct hlist_node node;	/*hash node*/
	u64 key;		/*hash key*/
};

struct dks_lock_stat {
	struct dks_ht *lock_ht;       /* for lock object */
	struct dks_ht *ips_ht;        /* for callchain hash */
	struct dks_ht *lock_causality_ht;  /* for causality among locks */
	struct dks_ht *last_lock_entry_ht;  /* for causality among callchains for a lock */
};

/* callchain info */
#define sizeof_ips_entry(ips) (sizeof(struct dks_ips_entry) + (ips->nr * sizeof(u64)))
struct dks_ips_entry {
	struct dks_hash_entry entry;
	callchain_t ips;
};

/* hash entry for callchain pointer */
struct dks_ips_ptr_entry {
	struct dks_hash_entry entry;
	callchain_t *ips_ptr;
};

struct dks_lock_causality_entry {
	struct dks_hash_entry entry;
	struct dks_ht *next_lock_ht;  /* for causality among locks */
};

struct dks_last_lock_entry {
	struct dks_hash_entry entry;
	struct dks_lock_entry *lock_entry;	// lock_addr
};

struct dks_count_entry {
	struct dks_hash_entry entry;
	unsigned long key;	// callchain ptr address
	unsigned long count;
};


/* lock entry it also manages all waiters for the lock entry */
struct dks_lock_entry {
	struct dks_hash_entry entry;
	u8 lock_type;
	pid_t pid;
	pid_t tid;
	u64 addr;
	u64 ips_id;

	/* for statistics */
	u64 n_events;           /* the number of events */
	u64 n_waiters;          /* the number of blocked waiters */
	u64 blocking_time;	/* total time for blocking waiters */

	callchain_t *ips_ptr;  /* callchain of the holder */

	struct dks_ht *waiters_ht;  /* callchain hash table ot the waiters */
	struct dks_ht *cf_causality_ht;  /* control flow causality */
};

/* hash key for lock object */
struct dks_lock_hash_key {
	u64 addr;
	pid_t pid;
};

/*hashtable APIs*/
struct dks_ht *dks_ht__new(unsigned int bits, size_t entry_size);
void dks_ht__free(struct dks_ht *ht, free_entry_fn fn);
void *dks_ht__alloc_entry(struct dks_ht *ht);
void dks_ht__free_entry(struct dks_ht *ht, void *entry);
int dks_ht__add(struct dks_ht *ht, u64 key, struct dks_hash_entry *e);
void *dks_ht__lookup(struct dks_ht *ht, u64 key);

void *dks_lock_table__lookup(struct dks_ht *ht, u64 hash_key, pid_t pid, u64 addr, u64 ips_id);

/********************************
  statistics related functions
 ********************************/
int dks_lock_stat__build_stat_tables(struct dks_lock_stat *lock_stats);
void dks_lock_stat__destroy_stat_tables(struct dks_lock_stat *lock_stats);

#endif /* __DKS_LOCK_STAT_H__ */
