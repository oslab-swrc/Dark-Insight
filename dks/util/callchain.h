#ifndef __PERF_CALLCHAIN_H
#define __PERF_CALLCHAIN_H

#include "../perf.h"
#include <linux/list.h>
#include <linux/rbtree.h>
#include "event.h"
#include "symbol.h"

#define HELP_PAD "\t\t\t\t"

#define CALLCHAIN_HELP "setup and enables call-graph (stack chain/backtrace):\n\n"

#ifdef HAVE_DWARF_UNWIND_SUPPORT
# define RECORD_MODE_HELP  HELP_PAD "record_mode:\tcall graph recording mode (fp|dwarf|lbr)\n"
#else
# define RECORD_MODE_HELP  HELP_PAD "record_mode:\tcall graph recording mode (fp|lbr)\n"
#endif

#define RECORD_SIZE_HELP						\
	HELP_PAD "record_size:\tif record_mode is 'dwarf', max size of stack recording (<bytes>)\n" \
	HELP_PAD "\t\tdefault: 8192 (bytes)\n"

#define CALLCHAIN_RECORD_HELP  CALLCHAIN_HELP RECORD_MODE_HELP RECORD_SIZE_HELP

#define CALLCHAIN_REPORT_HELP						\
	HELP_PAD "print_type:\tcall graph printing style (graph|flat|fractal|folded|none)\n" \
	HELP_PAD "threshold:\tminimum call graph inclusion threshold (<percent>)\n" \
	HELP_PAD "print_limit:\tmaximum number of call graph entry (<number>)\n" \
	HELP_PAD "order:\t\tcall graph order (caller|callee)\n" \
	HELP_PAD "sort_key:\tcall graph sort key (function|address)\n"	\
	HELP_PAD "branch:\t\tinclude last branch info to call graph (branch)\n" \
	HELP_PAD "value:\t\tcall graph value (percent|period|count)\n"

enum perf_call_graph_mode {
	CALLCHAIN_NONE,
	CALLCHAIN_FP,
	CALLCHAIN_DWARF,
	CALLCHAIN_LBR,
	CALLCHAIN_MAX
};

enum chain_mode {
	CHAIN_NONE,
	CHAIN_FLAT,
	CHAIN_GRAPH_ABS,
	CHAIN_GRAPH_REL,
	CHAIN_FOLDED,
};

enum chain_order {
	ORDER_CALLER,
	ORDER_CALLEE
};

struct callchain_node {
	struct callchain_node	*parent;
	struct list_head	val;
	struct list_head	parent_val;
	struct rb_node		rb_node_in; /* to insert nodes in an rbtree */
	struct rb_node		rb_node;    /* to sort nodes in an output tree */
	struct rb_root		rb_root_in; /* input tree of children */
	struct rb_root		rb_root;    /* sorted output tree of children */
	unsigned int		val_nr;
	unsigned int		count;
	unsigned int		children_count;
	u64			hit;
	u64			children_hit;
};

struct callchain_root {
	u64			max_depth;
	struct callchain_node	node;
};

struct callchain_param;

typedef void (*sort_chain_func_t)(struct rb_root *, struct callchain_root *,
				 u64, struct callchain_param *);

enum chain_key {
	CCKEY_FUNCTION,
	CCKEY_ADDRESS
};

enum chain_value {
	CCVAL_PERCENT,
	CCVAL_PERIOD,
	CCVAL_COUNT,
};

struct callchain_param {
	bool			enabled;
	enum perf_call_graph_mode record_mode;
	u32			dump_size;
	enum chain_mode 	mode;
	u32			print_limit;
	double			min_percent;
	sort_chain_func_t	sort;
	enum chain_order	order;
	bool			order_set;
	enum chain_key		key;
	bool			branch_callstack;
	enum chain_value	value;
};

extern struct callchain_param callchain_param;

struct callchain_list {
	u64			ip;
	struct map_symbol	ms;
	struct /* for TUI */ {
		bool		unfolded;
		bool		has_children;
	};
	char		       *srcline;
	struct list_head	list;
};

/*
 * A callchain cursor is a single linked list that
 * let one feed a callchain progressively.
 * It keeps persistent allocated entries to minimize
 * allocations.
 */
struct callchain_cursor_node {
	u64				ip;
	struct map			*map;
	struct symbol			*sym;
	struct callchain_cursor_node	*next;
};

struct callchain_cursor {
	u64				nr;
	struct callchain_cursor_node	*first;
	struct callchain_cursor_node	**last;
	u64				pos;
	struct callchain_cursor_node	*curr;
};

extern __thread struct callchain_cursor callchain_cursor;

static inline void callchain_init(struct callchain_root *root)
{
	INIT_LIST_HEAD(&root->node.val);
	INIT_LIST_HEAD(&root->node.parent_val);

	root->node.parent = NULL;
	root->node.hit = 0;
	root->node.children_hit = 0;
	root->node.rb_root_in = RB_ROOT;
	root->max_depth = 0;
}

static inline u64 callchain_cumul_hits(struct callchain_node *node)
{
	return node->hit + node->children_hit;
}

static inline unsigned callchain_cumul_counts(struct callchain_node *node)
{
	return node->count + node->children_count;
}

int callchain_register_param(struct callchain_param *param);
int callchain_append(struct callchain_root *root,
		     struct callchain_cursor *cursor,
		     u64 period);

int callchain_merge(struct callchain_cursor *cursor,
		    struct callchain_root *dst, struct callchain_root *src);

/*
 * Initialize a cursor before adding entries inside, but keep
 * the previously allocated entries as a cache.
 */
static inline void callchain_cursor_reset(struct callchain_cursor *cursor)
{
	cursor->nr = 0;
	cursor->last = &cursor->first;
}

int callchain_cursor_append(struct callchain_cursor *cursor, u64 ip,
			    struct map *map, struct symbol *sym);

/* Close a cursor writing session. Initialize for the reader */
static inline void callchain_cursor_commit(struct callchain_cursor *cursor)
{
	cursor->curr = cursor->first;
	cursor->pos = 0;
}

/* Cursor reading iteration helpers */
static inline struct callchain_cursor_node *
callchain_cursor_current(struct callchain_cursor *cursor)
{
	if (cursor->pos == cursor->nr)
		return NULL;

	return cursor->curr;
}

static inline void callchain_cursor_advance(struct callchain_cursor *cursor)
{
	cursor->curr = cursor->curr->next;
	cursor->pos++;
}

struct option;

int record_parse_callchain_opt(const struct option *opt, const char *arg, int unset);
int record_callchain_opt(const struct option *opt, const char *arg, int unset);

int sample__resolve_callchain(struct perf_sample *sample, struct symbol **parent,
			      struct perf_event_attr *attr, struct addr_location *al,
			      int max_stack);
int fill_callchain_info(struct addr_location *al, struct callchain_cursor_node *node,
			bool hide_unresolved);

extern const char record_callchain_help[];
int parse_callchain_record(const char *arg, struct callchain_param *param);
int parse_callchain_record_opt(const char *arg, struct callchain_param *param);
int parse_callchain_report_opt(const char *arg);
int parse_callchain_top_opt(const char *arg);
int perf_callchain_config(const char *var, const char *value);

static inline void callchain_cursor_snapshot(struct callchain_cursor *dest,
					     struct callchain_cursor *src)
{
	*dest = *src;

	dest->first = src->curr;
	dest->nr -= src->pos;
}

static inline int arch_skip_callchain_idx(struct thread *thread __maybe_unused,
			struct ip_callchain *chain __maybe_unused)
{
	return -1;
}

char *callchain_list__sym_name(struct callchain_list *cl,
			       char *bf, size_t bfsize, bool show_dso);
char *callchain_node__scnprintf_value(struct callchain_node *node,
				      char *bf, size_t bfsize, u64 total);
int callchain_node__fprintf_value(struct callchain_node *node,
				  FILE *fp, u64 total);

void free_callchain(struct callchain_root *root);
void decay_callchain(struct callchain_root *root);
int callchain_node__make_parent_list(struct callchain_node *node);

#endif	/* __PERF_CALLCHAIN_H */
