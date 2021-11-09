// SPDX-License-Identifier: MIT
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

#include <spintable.h>
#include <linux/string.h>
#include "kdks_i.h"

/*rb_tree of spin_table and nodes*/
static struct rb_root spintable = RB_ROOT;
//static struct spin_node *spin_nodes;

void ut_print_spinentry(struct spin_entry *entry)
{
	kdks_pr_trace(LOG_VERBOSE, "saddr %llx, eaddr %llx is_pic %s\n",
		entry->saddr, entry->eaddr, entry->is_pic ? "true" : "false" );
}

/*TODO - add asm_reg_id and pt_reg_offset correctly*/
void ut_print_sync_variable(struct sync_var *var)
{
	if (var->is_nested) {
		kdks_pr_trace(LOG_VERBOSE, "sync variable addr 0x%p is nested.\n", (void *)var);
		return;
	}

	if (var->expr.is_reg) {
		kdks_pr_trace(LOG_VERBOSE, "sync variable addr 0x%p is not nested,"
			"type register offset %u\n", (void *)var, var->expr.reg);
	} else {
		kdks_pr_trace(LOG_VERBOSE, "sync variable addr 0x%p is not nested,"
			"type addr %llx\n", (void *)var, var->expr.addr);
	}
}

// FIXME: We might need a lock for root.
static void rb_insert_spinnode(struct rb_root *root, struct spin_node *node)
{
	struct rb_node *parent_rb_node_p = NULL;
	struct rb_node **rb_node_pp = &root->rb_node;
	// We use saddr as a key.
	u64 spin_node_key = node->e->saddr;

	while (*rb_node_pp) {
		u64 rb_node_key;
		struct spin_node *spin_node_p;
		struct rb_node *current_rb_node_p;

		current_rb_node_p = *rb_node_pp;

		spin_node_p = rb_entry(current_rb_node_p, struct spin_node, rb_node);
		rb_node_key = spin_node_p->e->saddr;
		parent_rb_node_p = current_rb_node_p;
		rb_node_pp = spin_node_key < rb_node_key ? &current_rb_node_p->rb_left : &current_rb_node_p->rb_right;
	}

	rb_link_node(&node->rb_node, parent_rb_node_p, rb_node_pp);
	rb_insert_color(&node->rb_node, &spintable);
}

static void rb_erase_spinnode(struct rb_root *root, struct spin_node *node)
{
	struct rb_node *erase_node = &node->rb_node;

	BUG_ON(RB_EMPTY_NODE(erase_node));
	rb_erase(erase_node, root);
	RB_CLEAR_NODE(erase_node);
}

static void check_spintable(struct rb_root *root)
{
	struct rb_node *rb;
	int count = 0;
	u64 prev_key = 0;

	for (rb = rb_first(root); rb; rb = rb_next(rb)) {
		struct spin_node *node = rb_entry_safe(rb, struct spin_node, rb_node);
		WARN_ON_ONCE(node->e->saddr < prev_key);

		/*print entry info*/
		ut_print_spinentry(node->e);

		prev_key = node->e->saddr;
		count++;
	}
	kdks_pr_trace(LOG_VERBOSE, "# of nodes : %d\n", count);
}

static void free_sync_var(struct sync_var *sync_var_p)
{
	if (!sync_var_p)
		return;

	// Debug purpose.
	ut_print_sync_variable(sync_var_p);

	/*recurse spin_entry and make it free*/
	if (sync_var_p->is_nested) {
		free_sync_var(sync_var_p->nested.d);
		sync_var_p->nested.d = NULL;

		free_sync_var(sync_var_p->nested.b);
		sync_var_p->nested.b = NULL;

		free_sync_var(sync_var_p->nested.o);
		sync_var_p->nested.o = NULL;

		free_sync_var(sync_var_p->nested.m);
		sync_var_p->nested.m = NULL;
	}

	kfree(sync_var_p);
}

/*allocate new sync variable*/
struct sync_var* new_sync_var(void)
{
	struct sync_var *sync_var_p;

	sync_var_p = (struct sync_var *)kzalloc(sizeof(*sync_var_p), GFP_KERNEL);
	return sync_var_p ? sync_var_p : (struct sync_var *)ERR_PTR(-ENOMEM);
}

/*allocate new sync variable node*/
static struct sync_node* new_sync_node(void)
{
	struct sync_node *sync_node_p;

	sync_node_p = (struct sync_node *)kzalloc(sizeof(*sync_node_p), GFP_KERNEL);
	if (!sync_node_p)
		return (struct sync_node *)ERR_PTR(-ENOMEM);

	sync_node_p->var = new_sync_var();
	if (IS_ERR(sync_node_p->var)) {
		kfree(sync_node_p);
		return (struct sync_node *)ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&sync_node_p->node);
	return sync_node_p;
}

/*init spinentry variables*/
void spin_entry__init(struct spin_entry *spin_entry_p)
{
	spin_entry_p->saddr = KDKS_INVALID_ADDR;
	spin_entry_p->eaddr = KDKS_INVALID_ADDR;
	spin_entry_p->n_vars = 0;
	INIT_LIST_HEAD(&spin_entry_p->vars);
}

void spin_entry__free(struct spin_entry *spin_entry_p)
{
	struct list_head *elem, *tmp;
	list_for_each_safe(elem, tmp, &spin_entry_p->vars){
		struct sync_node *sync_node_p = list_entry(elem, struct sync_node, node);

		kdks_pr_trace(LOG_VERBOSE, "delete spinentry info:\n");
		ut_print_spinentry(spin_entry_p);

		/*remove sync variable*/
		list_del(elem);
		free_sync_var(sync_node_p->var);
	}

	kfree(spin_entry_p);
	kdks_pr_trace(LOG_VERBOSE, "spinentry deleted!\n");
}

struct spin_entry* spintable__decode_spinstr(char *str)
{
	struct spin_entry *spin_entry_p;
	struct sync_node *sync_node_p = NULL;

	spin_entry_p = (struct spin_entry *)kmalloc(sizeof(*spin_entry_p), GFP_KERNEL);
	if (!spin_entry_p)
		return ERR_PTR(-ENOMEM);

	spin_entry__init(spin_entry_p);
	/*convert outer entries*/
	while (str && *str != '\n' && *str != '\0' && *str != ' ') {
		char *token;
		char buf[BUFSIZ];
		size_t len;
		int result;
		parse_stack stack;
		kdks_pr_trace(LOG_VERBOSE, "current string :%s\n", str);

		/*TODO - remove buffer in stack*/
		/*split str into each sync variable*/
		token = ut_str_split_comma(&stack, str);

		/*token (str, token) */
		len = token - str;
		memcpy(buf, str, len);
		buf[len]='\0';
		kdks_pr_trace(LOG_VERBOSE, "Token: %s\n", buf);

		/*new entry*/
		if (!sync_node_p) {
			sync_node_p = new_sync_node();
			if(IS_ERR(sync_node_p))
				return (struct spin_entry *)sync_node_p;
		}

		/*decode token*/
		result = ut_decode_gas(sync_node_p->var, buf, 0);
		if (result) {
			kdks_pr_error("Failed to decode spininfo string err:%d, %s", result, buf);
			spin_entry__free(spin_entry_p);
			spin_entry_p = NULL;
			return ERR_PTR(-EFAULT);
		}

		list_add_tail_rcu(&sync_node_p->node, &spin_entry_p->vars);
		spin_entry_p->n_vars++;
		sync_node_p = NULL;

		str = token;

		/*remove trailing comma*/
		if (str && *str == ',')
			str++;
	}

	return spin_entry_p;
}

static int build_spintable_from_spininfo(struct spininfo *spin_info)
{
	struct spin_node *node = NULL;
	struct spin_entry *spin_entry_p = NULL;

	/* preallocate memory for spinnode */
	node = (struct spin_node *)kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	/* decode and assign */
	spin_entry_p = spintable__decode_spinstr(spin_info->spinstr);
	if (IS_ERR(spin_entry_p)) {
		kfree(node);
		return PTR_ERR(spin_entry_p);
	}

	/*set start and end address*/
	spin_entry_p->saddr = spin_info->saddr;
	spin_entry_p->eaddr = spin_info->eaddr;
	spin_entry_p->is_pic = spin_info->is_pic;
	spin_entry_p->map_type = spin_info->map_type;
	node->e = spin_entry_p;

	/*insert it*/
	rb_insert_spinnode(&spintable, node);

	/*debug purpose*/
	check_spintable(&spintable);
	return 0;
}

static void destroy_spintable(struct rb_root *root)
{
	int count = 0;
	struct rb_node *rb = rb_first(root);
	while (rb) {
		struct spin_node *node = rb_entry(rb, struct spin_node, rb_node);
		kdks_pr_trace(LOG_VERBOSE, "delete node :0x%p\n", (void *)node);

		rb = rb_next(rb);
		rb_erase_spinnode(root, node);

		// Debugging purpose
		spin_entry__free(node->e);
		node->e = NULL;
		kfree(node);
		++count;
		kdks_pr_trace(LOG_VERBOSE, "deleted node count %d\n", count);
	}

	kdks_pr_trace(LOG_VERBOSE, "Destroy spintable done, freed:%d\n", count);
}

static inline bool is_ip_in_spin_range(struct spin_node *node, u64 ip)
{
	//pr_info("%llu <= %llu (%llu) <= %llu, pic = %d\n", node->e->saddr, ip, KDKS_INVALID_ADDR, node->e->eaddr, node->e->is_pic);
	return node->e->saddr <= ip && ip <= node->e->eaddr;
}

/*find spin_node using ip*/
struct spin_node *spintable_find(u64 ip)
{
	struct rb_node *rb_node_p = spintable.rb_node;
	struct spin_node *spin_node_p = NULL;

	while (rb_node_p) {
		spin_node_p = rb_entry_safe(rb_node_p, struct spin_node, rb_node);
		if (is_ip_in_spin_range(spin_node_p, ip))
			return spin_node_p;

		rb_node_p = ip < spin_node_p->e->saddr ? rb_node_p->rb_left : rb_node_p->rb_right;
	}
	return NULL;
}

// Build spintable from spininfo.
int spintable__push_spininfo(unsigned long arg)
{
	size_t data_size = 0;
	struct spininfo *spin_info;

	/*if spin entries are passed from user*/
	if (arg) {
		int result;
		kdks_pr_trace(LOG_VERBOSE, "build spintable\n");

		// FIXME: Why should we realloc memory here?
		spin_info = (struct spininfo*)kmalloc(sizeof(*spin_info), GFP_KERNEL);
		if (copy_from_user(spin_info, (struct spininfo __user *)arg, sizeof(*spin_info)))
			return -EFAULT;

		// Calculate payload size and realloc
		data_size = sizeof(*spin_info) + (size_t)spin_info->len;
		spin_info = (struct spininfo *)krealloc(spin_info, data_size, GFP_KERNEL);
		if (copy_from_user(spin_info, (struct spininfo__user *)arg, data_size))
			return -EFAULT;

		kdks_pr_trace(LOG_VERBOSE, "spininfo size:%lu, str:%s\n",
			data_size, spin_info->spinstr);

		// Build spintable
		result = build_spintable_from_spininfo(spin_info);
		if (unlikely(result < 0)) {
			kdks_pr_error("Fail to add spintable : %d\n", result);
			return result;
		}
	}

	kdks_pr_trace(LOG_VERBOSE, "push spininfo done\n");
	return 0;
}

int init_spintable(void)
{
	int ret = 0;

	// Pre-allocate memory for spintable
	// spin_nodes = NULL;
	return ret;
}

void exit_spintable(void)
{
	// Destroy dynamically allocated spinnodes.
	destroy_spintable(&spintable);
#if 0
	// Free preallocated nodes.
	if (spin_nodes)
		kfree(spin_nodes);
#endif
}

