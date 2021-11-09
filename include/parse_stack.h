// SPDX-License-Identifier: MIT
#ifndef _PARSE_STACK_H
#define _PARSE_STACK_H

#ifndef KDKS_CONF_KERNEL
#include <stdio.h>
#include <stdbool.h>
#endif

/*TODO - need to find safe size for small stack limitation for kernel*/
#if defined(KDKS_CONF_KERNEL) && !defined(BUFSIZ)
#define BUFSIZ	(256)
#endif

typedef struct parse_stack {
	char buf[BUFSIZ];
	int top;
	int n_parentheses;
	int n_brackets;
} parse_stack;

/*parse_stack interfaces*/
static inline void parse_stack__init(parse_stack *s)
{
	s->top = 0;
	s->n_brackets = 0;
	s->n_parentheses = 0;
	//memset((void *)s->buf,0x00, BUFSIZ);;
	s->buf[0]='\0';
}

static inline bool parse_stack__is_full(parse_stack *s)
{
	return s-> top == BUFSIZ;
}

static inline bool parse_stack__is_empty(parse_stack *s)
{
	return s->top == 0;
}

static inline void parse_stack__push(parse_stack *s, const char c)
{
	if (parse_stack__is_full(s))
		return;

	if(c == '(')
		s->n_parentheses++;

	if(c == '<')
		s->n_brackets++;

	s->buf[s->top++] = c;
}

static inline void parse_stack__pop(parse_stack *s){
	while(!parse_stack__is_empty(s)){
		s->top--;
		/*will removed*/
		if(s->buf[s->top] == '(' || s->buf[s->top] == '<')
			break;
		/*pop*/
		if(s->buf[s->top] == ')') 
			s->n_parentheses--;

		if(s->buf[s->top] == '>')
			s->n_brackets--;
	}
}

#endif /* _PARSE_STACK_H */
