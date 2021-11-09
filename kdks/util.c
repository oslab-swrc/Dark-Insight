// SPDX-License-Identifier: MIT
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/errno.h>
#include "kdks_i.h"
#include "dks_perf_regs.h"

void _kdks_debug(enum kdks_debug_flags level, const char *func,
		 const unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (kdks_debug_level < level)
		return;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;
	pr_notice("%s:%u (%d): %pV",
		  func, line, task_pid_nr(current), &vaf);
	va_end(args);
}
EXPORT_SYMBOL(_kdks_debug);

int get_arg_from_pt_regs(struct pt_regs *regs, int n, unsigned long *arg)
{
	/* TODO: Need to support archtiectures other than x86_64 */

	/* x86_64 calling convention:
	 * - http://wiki.osdev.org/Calling_Conventions */
	switch(n) {
	case 0:
		*arg = regs->di;
		return 0;
	case 1:
		*arg = regs->si;
		return 0;
	case 2:
		*arg = regs->dx;
		return 0;
	case 3:
		*arg = regs->cx;
		return 0;
	case 4:
		*arg = regs->r8;
		return 0;
	case 5:
		*arg = regs->r9;
		return 0;
	};

	return -EINVAL;
}

void perf_print_callchain(callchain_t *ips)
{
	u32 i;
	kdks_pr_trace(LOG_DEBUG, "FP chain: nr:%llx\n", ips->nr);

	for (i = 0; i < ips->nr; i++)
		kdks_pr_trace(LOG_DEBUG, "..... %2d: %016llx\n",
				i, ips->ip[i]);
}

/****************************************************************************
 *                           workqueue init/exit
 ***************************************************************************/
void kdks_flush_wq(struct workqueue_struct *wq)
{
	if (!wq)
		return;

	flush_workqueue(wq);
	destroy_workqueue(wq);
	wq = NULL;
}

/****************************************************************************
 *                           GAS syntax parsing 
 ***************************************************************************/
static char *parse_unit(char *buf, char *str){
	char *s_token = str;
	size_t len;

	while(*str != '(' && *str != '<' && *str != '\0'){
		str++;
	}

	len = str-s_token;
	if(len)
		memcpy(buf, s_token, len);

	buf[len] = '\0';
	return str;
}

/*parse address string and store it as unsigned long long
  we also set signed flag(if it is negative)
 */
static int
parse_address(char *str, u64 *addr, bool *is_negative){
	int err;

	if(str[0] == '-'){
		*is_negative = true;
		err = kstrtoll(&str[1], 16, (long long *)addr);
	}
	else{
		*is_negative = false;
		err = kstrtoull(str, 16, addr);
	}

	if(err == ERANGE ||
			err == EINVAL){
		pr_err("err %d string decode fails :%s\n", err, str);
		return err;
	}

	return 0;
}

/*split source string into comma,
  return end token*/
static char *
split_and_copy_str(char *dst, char *src){
	parse_stack s;
	size_t len;
	char *e_token;

	e_token = ut_str_split_comma(&s, src);
	len = e_token - src; 
	strncpy(dst, src, len);
	dst[len]='\0';
	if(*e_token == ',')
		e_token++;

	return e_token;
}

/* allocate and decode GAS */
static int
allocate_nested_gas(struct sync_var **v, char *src, int depth){
	*v = new_sync_var();
	if(IS_ERR(*v))
		return PTR_ERR(*v);
	depth++;
	return ut_decode_gas(*v, src, depth);
}

/* allocate and decode GAS */
static int
allocate_and_decode_disp(struct sync_var *v, char *str, int depth){
	int ret;

	/*trans temp to disp*/
	struct sync_var *d = v->nested.d = new_sync_var();

	if(!d)
		return -ENOMEM;

	d->is_nested = false;
	d->is_direct = false;
	d->expr.is_reg = false;

	/*set dummy case */
	if(*str == '\0'){
		d->expr.addr = 0x0;
		kdks_pr_trace(LOG_VERBOSE,
				"[%d] dummy disp 0x%llx\n", depth, d->expr.addr);
	}
	else{
		ret = parse_address(str, &(d->expr.addr), &(d->expr.is_negative));
		if(ret) {
			kdks_pr_trace(LOG_VERBOSE, "err %d string decode fails :%s\n", ret, str);
			return ret;
		}

		kdks_pr_trace(LOG_VERBOSE, "[%d]disp %s0x%llx\n", depth,
				d->expr.is_negative?"Negative addr -":"", d->expr.addr);
	}

	return 0;
}

/* Extend spinfinder parsing rule,
   displacement can be nested with '<' '>' */
char *ut_str_split_disp(parse_stack *s, char *str){
	parse_stack__init(s);
	while(str && *str != '\0' && *str != '\n')
	{
		if(*str == ' ')
			break;

		else if(*str == '>'){
			parse_stack__push(s, *str);
			str++;
			parse_stack__pop(s);

			if(s->n_brackets == 0 
					&& s->n_parentheses == 0)
				break;
		}
		else{
			parse_stack__push(s, *str);
			str++;
		}

		if(parse_stack__is_empty(s))
			break;
	}

	return str;
}

/* Test whether disp nested or not */
static char *peek_if_disp_nested(char *dst, char *src){
	char *e_token;
	size_t len;
	parse_stack s;
	e_token = ut_str_split_disp(&s, src);

	len = e_token - src;
	strncpy(dst, src, len);
	dst[len]='\0';

	return e_token;
}

/*decode disp(base, offset, multiplier) form*/
int ut_decode_gas(struct sync_var *v, char *str, int depth){
	char temp[BUFSIZ];
	char *e_token;
	int ret = 0;
	bool f_direct_base = false;

	if(!v)
		return -EFAULT;

	depth++;
	e_token = parse_unit(temp, str);
	kdks_pr_trace(LOG_VERBOSE, "input string:%s, e_token:%s, parsed unit:%s\n", 
			str, e_token, temp);

	if(*e_token == '\0'){
		kdks_pr_trace(LOG_VERBOSE, "final:%s\n", temp);
		v->is_nested = false;

		if(temp[0] == '%'){
			v->expr.is_reg = true;
			v->expr.reg = perf_regs__regname_to_offset((const char*)&temp[1]);
			if(v->expr.reg == USHRT_MAX){
				ret = -EFAULT;
				goto out;
			}
			kdks_pr_trace(LOG_VERBOSE, "str:%s, pt_reg:[%u]%s\n", temp, v->expr.reg,
					perf_regs__get_reg_name(v->expr.reg));
		}
		else{
			v->expr.is_reg = false;

			/*convert str to address*/
			ret = parse_address(temp, &(v->expr.addr), &(v->expr.is_negative));
			if(ret){
				kdks_pr_trace(LOG_VERBOSE, "address translation failed ret %d, input %s\n",
						ret,temp);
				goto out;
			}

			kdks_pr_trace(LOG_VERBOSE, "is address true, %s0x%llx\n",
					v->expr.is_negative?"-":"",
					v->expr.addr);

		}
		goto out;
	}

	/*set nested*/
	v->is_nested = true;
	v->is_direct = false;

	if(*e_token == '<' || *e_token == '(' ){
		char dst[BUFSIZ];
		char *peek_next_token;

		/* to check how to split disp token*/
		peek_next_token = peek_if_disp_nested(dst, str);
		kdks_pr_trace(LOG_VERBOSE, "peek next token %s\n",
				*peek_next_token=='\0'?"NULL":peek_next_token);

		/* nested case - addr<xxx><base>*/
		if(*peek_next_token == '<'){
			kdks_pr_trace(LOG_VERBOSE, "handle disp nested case\n");
			/*translate nested disp*/
			ret = allocate_nested_gas(&(v->nested.d), dst, depth);
			kdks_pr_trace(LOG_VERBOSE, "[%d]disp:%s, next_token:%s\n",
					depth, dst, *peek_next_token=='\0'?"NULL":peek_next_token);
			if(ret)
				goto out;

			/* update end token */
			e_token = peek_next_token;
		}
		else{
			kdks_pr_trace(LOG_VERBOSE, "disp direct case\n");
			ret = allocate_and_decode_disp(v, temp, depth);

			if(ret){
				kdks_pr_error("allocate or decode new disp failed\n");
				goto out;
			}

			/* set direct flag on this */
			if(*e_token == '<')
				v->is_direct = true;
			kdks_pr_trace(LOG_VERBOSE, "[%d]disp:%s, next_token:%s\n",
					depth,
					*temp =='\0'?"0x0":temp,
					*e_token=='\0'?"NULL":e_token);
		}
	}
	else{
		/* translate temp string to displacement */
		struct sync_var *d = v->nested.d = new_sync_var();

		if(!d)
			return -ENOMEM;

		d->is_nested = false;
		d->is_direct = false;
		d->expr.is_reg = false;

		ret = parse_address(temp, &(d->expr.addr), &(d->expr.is_negative));
		if(ret){
			kdks_pr_trace(LOG_VERBOSE, "[%d] displacement decode failed %s\n",
					depth, temp);
			goto out;
		}

		kdks_pr_trace(LOG_VERBOSE, "[%d]disp %s0x%llx\n",
				depth,
				d->expr.is_negative?"-":"",
				d->expr.addr);
	}

	/* move forward*/
	str = e_token;
	e_token = str + strlen(str)-1;

	/* remove parentheses */
	if(*str == '(' &&
		*e_token == ')'){
		*e_token = '\0';
		str++;
	}

	/* remove brackets */
	if(*str == '<' &&
		*e_token == '>'){
		*e_token = '\0';
		str++;
		/* next token(base register) should not
		   be interpreted as nested */
		f_direct_base = true;	
	}

	/*translate base register*/
	e_token = split_and_copy_str(temp, str);
	ret = allocate_nested_gas(&(v->nested.b), temp, depth);
	kdks_pr_trace(LOG_VERBOSE, "base string : %s, addr 0x%p\n", temp, (void *)v->nested.b);
	if(ret)
		goto out;

	/* check flag */
	if(f_direct_base)
		v->nested.b->is_direct = true;

	if(*e_token == '\0')
		goto out;

	/*offset */
	str = e_token;
	e_token = split_and_copy_str(temp, str);
	ret = allocate_nested_gas(&(v->nested.o), temp, depth);
	kdks_pr_trace(LOG_VERBOSE, "offset string : %s, addr 0x%p\n", temp, (void *)v->nested.o);
	if(ret)
		goto out;
	if(*e_token == '\0')
		goto out;

	/*multiplier*/
	str = e_token;
	e_token = split_and_copy_str(temp, str);
	ret = allocate_nested_gas(&(v->nested.m), temp, depth);
	kdks_pr_trace(LOG_VERBOSE, "multiplier string : %s\n, addr 0x%p", temp, (void *)v->nested.m);
out:
	return ret;
}

char *ut_str_split_comma(parse_stack *stack, char *str)
{
	parse_stack__init(stack);
	while (str && *str != '\0' && *str != '\n') {
		if (*str == ' ')
			break;

		if (*str == ',' && stack->n_parentheses == 0 && stack->n_brackets == 0)
			break;
		else if (*str == ')' || *str == '>') {
			parse_stack__push(stack, *str);
			++str;
			parse_stack__pop(stack);
		} else {
			parse_stack__push(stack, *str);
			str++;
		}

		if (parse_stack__is_empty(stack))
			break;
	}

	return str;
}


/****************************************************************************
 *                get values from GAS syntax data
 ***************************************************************************/
/*get required register from perf_sample_data*/
inline u64
ut_get_reg_value(struct perf_sample_data *data, u16 idx) {
	struct pt_regs *regs = data->regs_user.regs;
	u64 val=0;

	/*if current sample don't have user regs, then return 0*/
	if(!(data->type & PERF_SAMPLE_REGS_USER))
		return KDKS_INVALID_ADDR;

	if(!data->regs_user.abi)
		return KDKS_INVALID_ADDR;

	val = perf_regs__get_reg_value(regs, idx);

	kdks_pr_trace(LOG_VERBOSE,
			"get register[%u]=0x%llx\n", idx, val);
	return val;
}

// Addr = base register + (offset register * multiplier) + displacement
u64 ut_decode_sync_var(struct perf_sample_data *perf_sample_data_p,
	struct spin_entry *spin_entry_p, struct sync_var *sync_var_p, int *sign_bit, int depth)
{
	u64 disp, base, offset, multiplier;
	u64 addr = 0;

	// The sign_bit and disp could be negative.
	// We set a negative flag for a string that has a sign(-) character.
	// Except that, we parse the others as unsigned integer.
	int sign_disp = 1, sign_base = 1, sign_offset = 1, sign_mult = 1;

	if (!sync_var_p)
		return 0;

	if (sync_var_p->is_nested) {
		const int next_depth = depth + 1;
		disp = ut_decode_sync_var(perf_sample_data_p, spin_entry_p, sync_var_p->nested.d, &sign_disp, next_depth);
		if (sign_disp == -1)
			kdks_pr_trace(LOG_VERBOSE, "minus displacement\n");

		base = ut_decode_sync_var(perf_sample_data_p, spin_entry_p, sync_var_p->nested.b, &sign_base, next_depth);
		if (!IS_VALID_ADDR(base))
			return KDKS_INVALID_ADDR;

		offset = ut_decode_sync_var(perf_sample_data_p, spin_entry_p, sync_var_p->nested.o, &sign_offset, next_depth);
		if (!IS_VALID_ADDR(offset))
			return KDKS_INVALID_ADDR;

		multiplier = ut_decode_sync_var(perf_sample_data_p, spin_entry_p, sync_var_p->nested.m, &sign_mult, next_depth);
		if (!IS_VALID_ADDR(multiplier))
			return KDKS_INVALID_ADDR;

		if (multiplier)
			offset *= multiplier;

		kdks_pr_trace(LOG_DEBUG, "addr=0x%llx(d[%s0x%llx], b[%s0x%llx], o[%s0x%llx], m[%s0x%llx])\n",
			addr, sign_disp == -1 ? "-" : "", disp,
			sign_base == -1 ? "-" : "", base,
			sign_offset == -1 ? "-" : "", offset,
			sign_mult == -1 ? "-" : "", multiplier);

		// FIXME: Why not just assignment?
		addr += base + offset + sign_disp * disp;
		if (!addr || !IS_VALID_ADDR(addr)) {
			kdks_pr_trace(LOG_ERR, "Invalid sync variable decode: %llu\n", addr);
			return KDKS_INVALID_ADDR;
		}

#if 0
		/*nested means, need to reference memory*/
		if (depth && !sync_var_p->is_direct)
			addr = *(u64 *)((uintptr_t)addr);
#endif
		/* nested */
		if (depth) {
			if (!sync_var_p->is_direct) {
				if (spin_entry_p->map_type == DKS_MAP__USER) {
					u64 *user_addr = NULL;
					if (copy_from_user(&user_addr, (u64 __user *)addr, sizeof(u64)) ) {
						kdks_pr_trace(LOG_ERR, "failed to fetch user address at %p\n",
							(u64 *)((uintptr_t)addr));
						return KDKS_INVALID_ADDR;
					}
					kdks_pr_trace(LOG_DEBUG, "user memory address uintptr_t 0x%p (0x%p)\n",
						user_addr, (u64 *)((uintptr_t)addr));
				} else
					kdks_pr_trace(LOG_DEBUG, "kernel map address\n");

				kdks_pr_trace(LOG_DEBUG, "in-direct memory address uintptr_t 0x%p\n",
					(u64 *)((uintptr_t)addr));
			} else
				kdks_pr_trace(LOG_DEBUG, "direct address memory address\n");

			kdks_pr_trace(LOG_DEBUG, "depth [%d] addr=0x%llx(d,b,o,m=%llx, %llx, %llx, %llx)\n",
				depth, addr, disp, base, offset, multiplier);
		} else {
			kdks_pr_trace(LOG_DEBUG, "target sync variable "
				"addr=0x%llx(d,b,o,m=%llx, %llx, %llx, %llx)\n",
				addr, disp, base, offset, multiplier);
		}

		if (sign_base == -1 || sign_offset == -1 || sign_mult == -1) {
			kdks_pr_trace(LOG_ERR, "WRONG SIGNBIT FOUND "
				"(d,b,o,m's sign var =%d, %d, %d, %d)\n",
				sign_disp, sign_base, sign_offset, sign_mult);
			return KDKS_INVALID_ADDR;
		}
	} else {
		/*need to get register and reinterpret it as mem addr*/
		if (sync_var_p->expr.is_reg) {
			addr = ut_get_reg_value(perf_sample_data_p, sync_var_p->expr.reg);
			kdks_pr_trace(LOG_DEBUG, "register value : 0x%llx\n", addr);
			if (!IS_VALID_ADDR(addr))
				kdks_pr_trace(LOG_DEBUG, "get register is invalid\n");
		} else {
			addr = (u64)sync_var_p->expr.addr;
			kdks_pr_trace(LOG_DEBUG, "address value : 0x%llx\n", addr);
			if (!IS_VALID_ADDR(addr))
				kdks_pr_trace(LOG_ERR, "expression addr is invalid\n");

			if (sync_var_p->expr.is_negative) {
				kdks_pr_trace(LOG_DEBUG, "negative sign bit\n");
				*sign_bit = -1;
			}
		}
	}

	kdks_pr_trace(LOG_DEBUG, "depth[%d] return address 0x%llx\n", depth, addr);
	return addr;
}
