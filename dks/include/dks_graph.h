#ifndef __DKS_GRAPH_H__
#define __DKS_GRAPH_H__

#include <linux/types.h>
#include <dks_common.h>
#include <dks_lock_stat.h>

/* graph related data structures.
   node and edge */
struct dks_node_entry{
	struct hlist_node node;	/*hash node*/
	union{
		u64 key;
		u64 node_id;
	}entry;
	pid_t pid;
	pid_t tid;
};

struct dks_edges_key_t{
	u64 node1;
	u64 node2;
};

/* hashtable lookup for node entry */
void *dks_node_table__lookup(struct dks_ht *dks_ht, u64 key, pid_t pid);

#endif /* __DKS_GRAPH_H__ */
