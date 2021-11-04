#ifndef _MTEST_H
#define _MTEST_H
/*
 * minimalist test and debug utilities
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define mtest(__cond, ...) ({					\
		int __bool = (__cond) ? 1 : 0;			\
		fprintf(stdout,					\
			"%s[MTEST:%s:%d] [%s] ",		\
			(__bool) ? "\033[92m" : "\033[91m",     \
			__func__, __LINE__,                     \
			(__bool) ? "PASS" : "FAIL");		\
		fprintf(stdout, __VA_ARGS__);			\
		fprintf(stdout, "\033[0m\n");			\
		(__bool);					\
	})

#define mstatic_assert(__c, __m) typedef			\
	int ___mstatic_assert___##__LINE__[(__c) ? 1 : -1]

static inline
void mprint_stack_trace(void) {
	/*
         * quick and dirty backtrace implementation
         * - http://stackoverflow.com/questions/4636456/how-to-get-a-stack-trace-for-c-using-gcc-with-line-number-information
	*/
	char pid_buf[30];
	char name_buf[512];
	int child_pid;

	sprintf(pid_buf, "%d", getpid());
	name_buf[readlink("/proc/self/exe", name_buf, 511)] = 0;
	child_pid = fork();

	if (!child_pid) {
		dup2(2, 1); /* redirect output to stderr */
		fprintf(stdout, "stack trace for %s pid=%s\n",
			name_buf, pid_buf);
		execlp("gdb", "gdb", "--batch", "-n", "-ex", "thread",
		       "-ex", "bt", name_buf, pid_buf, NULL);
		fprintf(stdout, "gdb is not installed. ");
		fprintf(stdout, "Please, install gdb to see stack trace.");
		abort(); /* If gdb failed to start */
	} else
		waitpid(child_pid, NULL, 0);
}

#define massert(__cond, ...) if (!(__cond)) {	\
		int *__p = NULL;		\
		fprintf(stderr, "\033[91m");	\
		fprintf(stderr,			\
			"[ASSERT:%s:%d] ",	\
			__func__, __LINE__);	\
		fprintf(stderr, __VA_ARGS__);	\
		fprintf(stderr"\033[92m\n");	\
		mprint_stack_trace();		\
		fprintf(stderr, "\033[0m");	\
		*__p = 0;			\
	}

#endif /* _MTEST_H */
