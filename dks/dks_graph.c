#include <sys/types.h>
#include <linux/types.h>

#include <dks_common.h>

#include "include/dks_lock_stat.h"
#include "include/dks_graph.h"
#include "linux/hashtable.h"
#include "util/util.h"
#include "util/debug.h"

/* hashtable lookup for node_entry */
void *dks_node_table__lookup(struct dks_ht *dks_ht, u64 key, pid_t pid){
	struct dks_hash_entry *e;

	hash_for_each_possible(dks_ht->ht, e, node, key){
		struct dks_node_entry *node = (struct dks_node_entry *)e;
		if(e->key == key && node->pid == pid )
			return (void *)e;
	}

	return NULL;
}

