// SPDX-License-Identifier: MIT
#ifndef _SPIN_TABLE_H
#define _SPIN_TABLE_H
#include <linux/types.h>
#include "dks_perf_regs.h"
#include "parse_stack.h"

#ifndef KDKS_CONF_KERNEL
#include "linux/types.h"
#include "linux/err.h"
#endif

#define _kdks_spin_test_str0 "spin_ts_lock,0x400a16,0x400a24,(-0x8(%rbp))\n"
#define _kdks_spin_test_str1 "spin_tts_lock,0x400a30,0x400a49,(-0x8(%rbp))\n"
#define _kdks_spin_test_str2 "spin_tts_lock,0x400a4d,0x400a4d,(-0x8(%rbp))\n"

enum dks_map_type {
        DKS_MAP__UNKNOWN = 0,
        DKS_MAP__USER,
        DKS_MAP__KERNEL,
        DKS_MAP__KMOD,
};
#define DKS_MAP__NR_TYPES (DKS_MAP__KMOD + 1)

/* sync addr = d(b, o, m) = *(base + (offset * multiplier) + displacement); */

struct kdks_expr {
	bool is_reg;
	bool is_direct;		/*'<' '>' will interpret as direct value*/
	bool is_negative;	/*if target is address and negative */
	union {
		__u64   addr;	/*expr address */
		__u16	reg;	/*regname mapping table index*/
	};
};

/*GAS*/
struct sync_var {
	bool is_nested;
	bool is_direct;
	union {
		struct kdks_expr expr;
		struct {
			struct sync_var *d;
			struct sync_var *b;
			struct sync_var *o;
			struct sync_var *m;
		} nested;
	};
};

/*sync variable node*/
struct sync_node {
	struct list_head node;
	struct sync_var *var;
};

/*spinloop_entry*/
struct spin_entry {
	__u64 saddr;	/*start addr of spin loop entry*/
	__u64 eaddr;	/*end addr of spin loop entry*/
	bool is_pic;
	uint8_t map_type;
	unsigned n_vars;
	struct list_head vars;/*multiple sync vars*/
};

/*user to kernel spininfo string data*/
struct spininfo {
	__u64 saddr;	/*start addr of spin loop entry*/
	__u64 eaddr;	/*end addr of spin loop entry*/
	bool is_pic;
	__u8 map_type;
	__u16 len;	/*string length*/
	char spinstr[0];
};


void spin_entry__init(struct spin_entry *e);
void spin_entry__free(struct spin_entry *e);

struct spin_entry *spintable__decode_spinstr(char *str);

int ut_decode_gas(struct sync_var *v, char *str, int depth);
void ut_print_spinentry(struct spin_entry *e);
void ut_print_sync_var(struct sync_var *v, int depth);
char *ut_str_split_comma(parse_stack *s, char *str);
char *ut_str_split_disp(parse_stack *s, char *str);

#endif /* _SPIN_TABLE_H */
