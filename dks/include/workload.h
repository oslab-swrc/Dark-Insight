// SPDX-License-Identifier: MIT
#ifndef __DKS_WORKLOAD_H__
#define __DKS_WORKLOAD_H__

#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif
#include <fcntl.h>
#include <signal.h>

#include "../util/util.h"

struct workload{
	int cork_fd;
	pid_t	pid;
};

/*prepare target command for profiling*/
int prepare_workload(struct workload *work, const char *argv[],
		void (*exec_error)(int signo, siginfo_t *info, void *ucontext));
int start_workload(struct workload *work);
#endif
