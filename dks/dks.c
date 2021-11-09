// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <inttypes.h>
#include <signal.h>

/*perf util headers*/
#include "perf.h"
#include "util/debug.h"
#include "util/util.h"
#include "util/cache.h"

/*dks specific headers*/
#include "dks.h"

bool exports_json = false;
const char *input_file_name;
int limit_ranks = 20;

struct cmd_struct {
	const char *cmd;
	int (*run)(int, const char **);
	int option;
};

static struct cmd_struct commands[] = {
	{"profile", dks_cmd_profile, 0},
	{"analyze", dks_cmd_analyze, 0},
	{"deadlock", dks_cmd_deadlock, 0},
};

const char dks_usage_string[] =
	"dks [OPTIONS] {--spnf spin-finder path} {--cmd profile|analyze|deadlock} {target exec command} \n"
	"     OPTIONS) \n"
	"              --help        : show this usage \n"
	"              --dump_trace  : dump raw perf event\n"
	"              --debug       : enable debug output\n"
	"     --spnf : set spin-finder python3 script \n"
	"     --cmd  : set running mode, profile, analyze or deadlock(detector)";

static void show_usage(void) {
	printf("\n%s\n\n", dks_usage_string);
}

static int run_dks(struct cmd_struct *p, int argc, const char **argv)
{
	return p->run(argc, argv);
}

static int find_cmd(const char *cmd_str)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); ++i) {
		struct cmd_struct *p = commands + i;
		if (strcmp(p->cmd, cmd_str))
			continue;
		return i;
	}

	return -1;
}

static int set_spnf_path(const char *str){
	char *fname = strdup(str);

	if( access( fname, F_OK ) == -1 ) {
		fprintf(stderr, "spin-finder script:%s is not exists\n", fname); 
		return -ENOENT;
	}

	g_spnf_path = fname;
	fprintf(stdout, "spin-finder script:%s is selected\n", fname); 

	return 0;
}

/*parse options for dks command,
  subcmd's option will be handled by their own*/
static int handle_options(int *argc, char ***argv, int *cmd_idx)
{
	int arg_cnt = 0;

	while (*argc > 0) {
		const char *cmd = (*argv)[0];

		/*if it is not start with option string,
		  then stop handle*/
		if (cmd[0] != '-')
			break;

		if (!strcmp(cmd, "--help"))
			return -EINVAL;

		if (!strcmp(cmd, "--debug") || !strcmp(cmd, "-d")) {
			/*move forward*/
			(*argc)--;
			(*argv)++;
			perf_debug_option("verbose");
		} else if (!strcmp(cmd, "--spnf")) {
			// One moving forward due to spin-finder path
			(*argc)--;
			(*argv)++;

			if (set_spnf_path((const char *)(*argv)[0]))
				return -EINVAL;

			(*argc)--;
			(*argv)++;
		} else if (!strcmp(cmd, "--dump_trace") || !strcmp(cmd, "-D")) {
			dump_trace = true;
			(*argc)--;
			(*argv)++;
		} else if (!strcmp(cmd, "--cmd") || !strcmp(cmd, "-c")) {
			(*argc)--;
			(*argv)++;

			if (!(*argc))
				return -EINVAL;

			*cmd_idx = find_cmd((const char*)(*argv)[0]);
			arg_cnt++;
		} else {
			fprintf(stderr, "Unknown options : %s\n", cmd);
			return -EINVAL;
		}
	}

	return arg_cnt;
}

/* Main function,
 - Handle input arguments,
 - exec dks_cmd_profile or dks_cmd_analyze */
int main(int argc, char **argv)
{
	int cmd_idx = -1;
	struct cmd_struct* command = NULL;

	// The utility module uses page and cacheline size.
	// Normally, page_size = 4096, cacheline_size = 64
	page_size = sysconf(_SC_PAGE_SIZE);
	cacheline_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);

	srandom(time(NULL));

	perf_config(perf_default_config, NULL);
	perf_debug_setup();

	// Remove program name from argument list
	argc--;
	argv++;

	if (handle_options(&argc, &argv, &cmd_idx) < 1)
		goto out;

	if (cmd_idx == -1) {
		fprintf(stderr, "dks error : missing command!\n"
			"            Please specify 'profile' or 'analyze'\n");
		goto out;
	}

	/*set subcmd function*/
	command = &commands[cmd_idx];
	exit(run_dks(command, argc, (const char **)argv));
out:
	show_usage();
	return 1;
}
