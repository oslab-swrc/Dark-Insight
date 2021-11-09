// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "workload.h"

#include "util/debug.h"

/*prepare target command for profiling*/
int prepare_workload(struct workload *work, const char *argv[],
	void (*exec_error)(int signo, siginfo_t *info, void *ucontext))
{
	int child_ready_pipe[2], go_pipe[2];
	char bf;

	if (pipe(child_ready_pipe) < 0) {
		perror("failed to create 'ready' pipe");
		return -1;
	}

	if (pipe(go_pipe) < 0) {
		perror("failed to create 'go' pipe");
		goto out_close_ready_pipe;
	}

	work->pid = fork();
	if(work->pid < 0) {
		perror("failed to fork");
		goto out_close_pipes;
	}

	if (!work->pid) {
		int ret;

		signal(SIGTERM, SIG_DFL);

		close(child_ready_pipe[0]);
		close(go_pipe[1]);
		fcntl(go_pipe[0], F_SETFD, FD_CLOEXEC);

		/*
		 * Tell the parent we're ready to go
		 */
		close(child_ready_pipe[1]);

		/*
		 * Wait until the parent tells us to go.
		 */
		ret = read(go_pipe[0], &bf, 1);
		/*
		 * The parent will ask for the execvp() to be performed by
		 * writing exactly one byte, in workload.cork_fd, usually via
		 * start_workload().
		 */
		if (ret == -1)
			perror("unable to read pipe");
		if (ret != 1)
			exit(ret);

		execvp(argv[0], (char **)argv);

		/*check error and prepare signal*/
		if (exec_error) {
			union sigval val;
			val.sival_int = errno;
			if (sigqueue(getppid(), SIGUSR1, val))
				perror(argv[0]);
		} else
			perror(argv[0]);
		exit(-1);
	}

	if (exec_error) {
		struct sigaction act = {
			.sa_flags     = SA_SIGINFO,
			.sa_sigaction = exec_error,
		};
		sigaction(SIGUSR1, &act, NULL);
	}

	close(child_ready_pipe[1]);
	close(go_pipe[0]);
	// Wait for child to settle
	if (read(child_ready_pipe[0], &bf, 1) == -1) {
		perror("unable to read pipe");
		goto out_close_pipes;
	}

	fcntl(go_pipe[1], F_SETFD, FD_CLOEXEC);
	work->cork_fd = go_pipe[1];
	close(child_ready_pipe[0]);

	return 0;

out_close_pipes:
	close(go_pipe[0]);
	close(go_pipe[1]);
out_close_ready_pipe:
	close(child_ready_pipe[0]);
	close(child_ready_pipe[1]);
	return -1;
}

int start_workload(struct workload *work)
{
	int ret;
	char bf = 0;

	if (!work || work->cork_fd <= 0) {
		dks_debug("leave\n");
		return 0;
	}

	ret = write(work->cork_fd, &bf, 1);
	if (ret < 0)
		perror("enable to write to pipe");

	close(work->cork_fd);
	return ret;

}
