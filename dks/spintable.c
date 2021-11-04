#include "util/util.h"
#include "util/debug.h"
#include "dks_common.h"
#include "spintable.h"
#include "parse_stack.h"
#include "linux/err.h"

int depth=0;

void ut_print_sync_var(struct sync_var *var, int depth)
{
	if (!var)
		return;

	if (var->is_direct)
		pr_debug("[%d] direct flag is on \n", depth);

	if (var->is_nested) {
		depth++;

		ut_print_sync_var(var->nested.d, depth);
		ut_print_sync_var(var->nested.b, depth);
		ut_print_sync_var(var->nested.o, depth);
		ut_print_sync_var(var->nested.m, depth);
		return;
	}

	if (var->expr.is_reg)
		pr_debug("[%d] reg: %u\n", depth, var->expr.reg);
	else
		pr_debug("[%d] addr: %ld(0x%llx)\n", depth, (int64_t)var->expr.addr, var->expr.addr);
}

void ut_print_spinentry(struct spin_entry *entry)
{
	int i = 0;
	struct list_head *elem;

	pr_debug("saddr: %llx\n", entry->saddr);
	pr_debug("eaddr: %llx\n", entry->eaddr);
	pr_debug("n_var: %d\n", entry->n_vars);

	list_for_each(elem, &entry->vars) {
		struct sync_node *node = list_entry(elem, struct sync_node, node);
		pr_debug("var_id[%d]\n", i++);
		ut_print_sync_var(node->var, 0);
	}
}

static char *parse_unit(char *buf, char *str){
	char *s_token = str;
	size_t len;

	while(*str != '(' && *str != '<' &&*str != '\0'){
		str++;
	}

	len = str-s_token;
	if(len)
		memcpy(buf, s_token, len);

	buf[len] = '\0';
	return str;
}

/*allocate new sync variable*/
static struct sync_var*
new_sync_var(void){
	struct sync_var *v;
	v = (struct sync_var *) zalloc(sizeof(*v));

	if(!v)
		return (struct sync_var *)ERR_PTR(-ENOMEM);
	return v;
}

/*allocate new sync variable node*/
static struct sync_node*
new_sync_node(void){
	struct sync_node *n;
	n = (struct sync_node *) zalloc(sizeof(*n));

	if(!n)
		return (struct sync_node *)ERR_PTR(-ENOMEM);

	/*allocate sync_var*/
	n->var = new_sync_var();

	if(IS_ERR(n->var))
		return (struct sync_node *)ERR_PTR(-ENOMEM);

	/*init*/
	INIT_LIST_HEAD(&n->node);
	return n;
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

/*allocate and decode GAS */
static int
allocate_nested_gas(struct sync_var **v, char *src, int depth){
	*v = new_sync_var();
	if(IS_ERR(*v))
		return PTR_ERR(*v);
	return ut_decode_gas(*v, src, depth);
}

/*parse address string and store it as unsigned long long
  we also set signed flag(if it is negative)
*/
static int
parse_address(char *str, __u64 *addr, bool *is_negative){
	if(str[0] == '-'){
		*is_negative = true;
		*addr = strtoll(&str[1], NULL, 16);
	}
	else{
		*is_negative = false;
		*addr = strtoull(str, NULL, 16);
	}

	if(errno == ERANGE ||
			errno == EINVAL){
		pr_err("err %d string decode fails :%s\n", errno, str);
		return errno;
	}

	return 0;
}

/*allocate and decode GAS */
static int
allocate_and_decode_disp(struct sync_var *v, char *str, int depth){
	/*trans temp to disp*/
	struct sync_var *d = v->nested.d = new_sync_var();
	int err;

	if(!d)
		return -ENOMEM;

	d->is_nested = false;
	d->is_direct = false;
	d->expr.is_reg = false;

	/*set dummy case */
	if(*str == '\0'){
		d->expr.addr = 0x0;
		dks_debug("[%d] dummy disp 0x%llx\n", depth, d->expr.addr);
	}
	else{
		err = parse_address(str, &(d->expr.addr),&(d->expr.is_negative));
		if(err) {
			pr_err("err %d string decode fails :%s\n", err, str);
			return err;
		}

		dks_debug("[%d]disp %s0x%llx\n", depth,
				d->expr.is_negative?"-":"", d->expr.addr);
	}

	return 0;
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
	char *e_token = NULL;
	int ret = 0;
	bool f_direct_base = false;

	if(!v)
		return -EFAULT;

	depth++;
	e_token = parse_unit(temp, str);
	dks_debug("[%d]input string:%s, e_token:%s, parsed unit:%s\n",
			depth, str, *e_token == '\0'?"NULL":e_token, *temp == '\0'?"NULL":
			temp);

	if(*e_token == '\0'){
		dks_debug("final:%s\n", temp);
		v->is_nested = false;

		if(temp[0] == '%'){
			v->expr.is_reg = true;

			v->expr.reg = perf_regs__regname_to_offset((const char*)&temp[1]);
			if(v->expr.reg == USHRT_MAX){
				dks_debug("failed to decode regsiter name %s\n", temp);
				ret = -EFAULT;
				goto out;
			}
			dks_debug("ptrace regname:%s[%u]\n", temp, v->expr.reg);
		}
		else{
			v->expr.is_reg = false;

			/*convert str to address*/
			ret = parse_address(temp, &(v->expr.addr), &(v->expr.is_negative));

			if(ret){
				pr_err("err : %d, string decode fails :%s\n", ret, temp);
				goto out;
			}
			dks_debug("address %s0x%llx\n",
					v->expr.is_negative?"-":"",
					v->expr.addr);
		}
		goto out;
	}

	/* set flasgs */
	v->is_nested = true;
	v->is_direct = false;

	/* test disp nested case */
	if(*e_token == '<' || *e_token == '(' ){
		char dst[BUFSIZ];
		char *peek_next_token;
		//v->is_direct = true;

		/* to check how to split disp token*/
		peek_next_token = peek_if_disp_nested(dst, str);
		dks_debug("peek next token %s\n",
				*peek_next_token=='\0'?"NULL":peek_next_token);

		/* nested case - addr<xxx><base>*/
		if(*peek_next_token == '<'){
			dks_debug("handle disp nested case\n");
			/*translate nested disp*/
			ret = allocate_nested_gas(&(v->nested.d), dst, depth);
			dks_debug("[%d]disp:%s, next_token:%s\n",
					depth, dst, *peek_next_token=='\0'?"NULL":peek_next_token);
			if(ret)
				goto out;

			/* update end token */
			e_token = peek_next_token;
		}
		else{
			if(*e_token == '<')
				v->is_direct = true;
			dks_debug("disp direct case\n");
			ret = allocate_and_decode_disp(v, temp, depth); 
			if(ret){
				dks_debug("new disp allocate failed \n");
				goto out;
			}
			dks_debug("[%d]disp:%s, next_token:%s\n",
					depth,
					*temp =='\0'?"0x0":temp,
					*e_token=='\0'?"NULL":e_token);
		}
	}
	else{
		/*trans temp to disp*/
		struct sync_var *d = v->nested.d = new_sync_var();

		if(!d)
			return -ENOMEM;
		d->is_nested = false;
		d->is_direct = false;
		d->expr.is_reg = false;

		ret = parse_address(temp, &(d->expr.addr), &(d->expr.is_negative));
		if(ret) {
			pr_err("err %d, string decode fails :%s\n", ret, temp);
			goto out;
		}

		dks_debug("[%d]disp %s0x%llx\n",
				depth,
				d->expr.is_negative?"-":"",
				d->expr.addr);
	}

	/*move forward*/
	str = e_token;
	e_token = str + strlen(str)-1;

	/* remove parentheses*/
	if(*str == '(' &&
			*e_token == ')'){
		*e_token = '\0';
		str++;
		dks_debug("[%d] remove indirect bracket \n", depth);
	}

	/* remove brackets */
	if(*str == '<' &&
			*e_token == '>'){
		*e_token = '\0';
		str++;
		dks_debug("[%d] remove direct bracket \n", depth);
		/*set base is direct */
		f_direct_base = true;
	}

	/* translate base register */
	e_token = split_and_copy_str(temp, str);
	ret = allocate_nested_gas(&(v->nested.b), temp, depth);
	dks_debug("[%d]base :%s, next_token:%s\n", depth, temp, *e_token=='\0'?"NULL":e_token);

	/* error case */
	if(ret)
		goto out;

	/* set if direct flag is on */
	if(f_direct_base)
		v->nested.b->is_direct = true;

	if(*e_token == '\0')
		goto out;

	/*offset */
	str = e_token;
	e_token = split_and_copy_str(temp, str);
	ret = allocate_nested_gas(&(v->nested.o), temp, depth);
	dks_debug("[%d]offset :%s, next_token:%s\n",depth, temp,  *e_token=='\0'?"NULL":e_token);
	if(ret)
		goto out;
	if(*e_token == '\0')
		goto out;

	/*multiplier*/
	str = e_token;
	e_token = split_and_copy_str(temp, str);
	ret = allocate_nested_gas(&(v->nested.m), temp,depth);
	dks_debug("[%d]multiplier :%s, next_token:%s\n",
			depth, temp, *e_token=='\0'?"NULL": e_token);
out:
	return ret;
}

char *ut_str_split_comma(parse_stack *s, char *str){
	parse_stack__init(s);
	dks_debug("current str:%s\n", str);

	while(str && *str != '\0' && *str != '\n')
	{
		if(*str == ' ')
			break;

		if(*str == ',' && s->n_parentheses == 0
			&& s->n_brackets == 0) {
			break;
		}

		else if(*str == ')' || *str == '>'){
			parse_stack__push(s, *str);
			str++;
			parse_stack__pop(s);
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

/* Extend spinfinder parsing rule,
   displacement can be nested with '<' '>' */
char *ut_str_split_disp(parse_stack *s, char *str){
	parse_stack__init(s);
	dks_debug("current str:%s\n", str);

	while(str && *str != '\0' && *str != '\n')
	{
		if(*str == ' ')
			break;
		else if(*str == '>'){
			parse_stack__push(s, *str);
			str++;
			parse_stack__pop(s);

			/* break first complete brackets */
			if(s->n_brackets == 0 &&
					s->n_parentheses == 0)
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

void spin_entry__init(struct spin_entry *entry)
{
	entry->saddr = KDKS_INVALID_ADDR;
	entry->eaddr = KDKS_INVALID_ADDR;
	entry->n_vars = 0;
	INIT_LIST_HEAD(&entry->vars);
}

static void
free_sync_var(struct sync_var *v){
	if(v){
		/*recurse spin_entry and make it free*/
		if(v->is_nested){
			free_sync_var(v->nested.d);
			v->nested.d = NULL;

			free_sync_var(v->nested.b);
			v->nested.b = NULL;

			free_sync_var(v->nested.o);
			v->nested.o = NULL;

			free_sync_var(v->nested.m);
			v->nested.m = NULL;
		}

		free(v);
	}
}

void spin_entry__free(struct spin_entry *e){
	struct list_head *elem, *tmp;
	list_for_each_safe(elem, tmp, &e->vars){
		struct sync_node *n = list_entry(elem, struct sync_node, node);
		dks_debug("delete spinentry info:\n");
		ut_print_spinentry(e);

		/*remove sync variable*/
		list_del(elem);
		free_sync_var(n->var);
	}

	free(e);
	dks_debug("spinentry deleted!\n");
}

struct spin_entry* spintable__decode_spinstr(char *str)
{
	struct spin_entry *entry;
	struct sync_node *sync_node_p = NULL;

	entry = (struct spin_entry *)malloc(sizeof(*entry));
	if (!entry)
		return ERR_PTR(-ENOMEM);

	spin_entry__init(entry);
	// Convert outer entries
	while (str && *str != '\n' && *str != '\0' && *str != ' ') {
		char *token;
		char buf[BUFSIZ];
		size_t len;
		int result;
		parse_stack stack;

		dks_debug("current string :%s[%lu]\n", str, strlen(str));
		/* split str into each sync variable */
		token = ut_str_split_comma(&stack, str);

		/*token (str, token) */
		len = token - str;
		memcpy(buf, str, len);
		buf[len]='\0';
		dks_debug("Token :%s[%lu]\n", buf, strlen(buf));

		/* new entry */
		if (!sync_node_p) {
			sync_node_p = new_sync_node();
			if(IS_ERR(sync_node_p))
				return (struct spin_entry *)sync_node_p;
		}

		/* decode token */
		result = ut_decode_gas(sync_node_p->var, buf, 0);
		if (result) {
			pr_err("Failed to decode spininfo string err:%d, %s\n", result, buf);
			spin_entry__free(entry);
			entry = NULL;
			return ERR_PTR(-EFAULT);
		}

		list_add_tail(&sync_node_p->node, &entry->vars);
		entry->n_vars++;
		sync_node_p = NULL;

		str = token;

		/* Remove trailing comma */
		if (str && *str == ',')
			++str;
	}

	return entry;
}
