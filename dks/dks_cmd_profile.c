#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/*dks header*/
#include "dks.h"
#include "spinloop_maps.h"

/*perf headers*/
#include "perf.h"

/*perf util headers*/
#include "asm/bug.h"
#include "util/util.h"
#include "util/debug.h"
#include "util/machine.h"
#include "util/session.h"
#include "util/symbol.h"
#include "util/target.h"
#include "util/build-id.h"

#include <subcmd/parse-options.h>

#define PROF_DO_PERF_EVENT 1
/* turn off kernel map synthsize */
#define PROF_DO_SYNTHESIZE_KERNEL 0

/*static variables for signal and workload handling*/
static volatile int done;
static volatile int signr = -1;
static volatile int child_finished;
static volatile int workload_exec_errno;

static void sig_handler(int sig)
{
	if (sig == SIGCHLD)
		child_finished = 1;
	else
		signr = sig;

	done = 1;
}

static void sig_exit(void)
{
	if (signr == -1)
		return;
	signal(signr, SIG_DFL);
	raise(signr);
}

/*
 * prepare_workload will send a SIGUSR1
 * if the fork fails, since we asked by setting its
 * want_signal to true.
 */
static void workload_exec_failed_signal(int signo, siginfo_t *info, void *ucontext)
{
	workload_exec_errno = info->si_value.sival_int;
	done = 1;
	child_finished = 1;
}

/*dummy event for finished round*/
static struct perf_event_header finished_round_event = {
	.size = sizeof(struct perf_event_header),
	.type = PERF_RECORD_FINISHED_ROUND,
};


static int dks_process_sample(struct perf_tool *tool, union perf_event *event,
	struct perf_sample *sample, struct machine *machine)
{
	struct dks_ctrl *ctrl = container_of(tool, struct dks_ctrl, tool);
	ctrl->samples++;

	return build_id__mark_dso_hit(tool, event, sample, machine);
}

static int dks_process_synthesized(struct perf_tool *tool, union perf_event *event,
	struct perf_sample *sample __maybe_unused, struct machine *machine __maybe_unused)
{
	struct dks_ctrl *ctrl = container_of(tool, struct dks_ctrl, tool);

	/* push spinloop maps */
	if (event->header.type == PERF_RECORD_MMAP2) {
		if (spinloop_maps__process_mmap2_event(tool, event, sample, machine)) {
			pr_err("failed to process synthesized mmap2 event for spinloop map\n");
			return -EFAULT;
		}
	}
#if PROF_DO_SYNTHESIZE_KERNEL
	else if (event->header.type == PERF_RECORD_MMAP) {
		if (spinloop_maps__process_mmap_event(tool, event, sample, machine)) {
			pr_err("failed to process synthesized mmap2 event for spinloop map\n");
			return -EFAULT;
		}
	}
#endif

	return dks_ctrl__event_write(ctrl, event, event->header.size);
}

/*process mmap event.
  build dso maps and push relocate address to kernel*/
int dks_process_mmap(struct perf_tool *tool, union perf_event *event,
	struct perf_sample *sample, struct machine *machine)
{
	// Skip if any problem happens.
	if (machine__process_mmap_event(machine, event, sample))
		return 0;

	char *filename = event->mmap.filename;
	u64 start = event->mmap.start;
	/*push spinloop information for current event*/
	pr_info("%d/%d-dso:%s, start addr:0x%llx\n",
		event->mmap.pid, event->mmap.tid, filename, (long long unsigned)start);
	return 0;
}

/*process mmap2 event.
  build dso maps and push relocate address to kernel*/
int dks_process_mmap2(struct perf_tool *tool, union perf_event *event,
	struct perf_sample *sample, struct machine *machine)
{
	/*if it has some problem, skip it*/
	if (machine__process_mmap2_event(machine, event, sample))
		return 0;

	/*push spinloop information for current mmap event*/
	return spinloop_maps__process_mmap2_event(tool, event, sample, machine);
}

static int dks_ctrl__mmap_read_all(struct dks_ctrl *ctrl)
{
	int i;
	u64 bytes_written = ctrl->bytes_written;
	// We allocated mmaps as many as the number of cpu.
	for (i = 0; i < ctrl->nr_cpus; ++i) {
		struct perf_mmap *mmap = ctrl->mmap[i];
		if (!mmap || !mmap->base)
			continue;
		if (perf__event_read(ctrl, i))
			return -1;
	}

	// Mark the round finished. In this case, we wrote one event at least.
	return bytes_written == ctrl->bytes_written ? 0
		: dks_ctrl__event_write(ctrl, &finished_round_event, sizeof(finished_round_event));
}

static struct dks_ctrl dks_control_data = {
	.tool = {
		.sample = dks_process_sample,
		.mmap   = dks_process_mmap,
		.mmap2  = dks_process_mmap2,
		.fork   = perf_event__process_fork,
		.exit   = perf_event__process_exit,
		.comm   = perf_event__process_comm,
		.ordered_events = false,
	},
	.opts = {
		.mmap_pages = UINT_MAX,
		.target.pid_d = -1,
		.target.tid_d = -1,
		.target.uid = UINT_MAX,

	},
	.work = {
		.pid = -1,
	},
	.file = {
		.mode = PERF_DATA_MODE_WRITE,
	},
	.bytes_written = 0,
	.samples = 0,
	.kdks_thread = NULL,
	.init = false,
};

static int dks_ctrl__synthesize(struct dks_ctrl *ctrl)
{
	struct perf_session *session = ctrl->session;
	struct machine *machine = &session->machines.host;
	struct perf_tool *tool = &ctrl->tool;
	int err = 0;

	if (!ctrl->init) {
		pr_err("dks control block is not initialized!\n");
		return -EFAULT;
	}

	// Synthesize kernel map
	err = perf_event__synthesize_kernel_mmap(tool, dks_process_synthesized, machine);
	WARN_ONCE(err < 0, "Couldn't record kernel reference relocation symbol\n"
			"Symbol resolution may be skewed if relocation was used (e.g. kexec).\n"
			"Check /proc/kallsyms permission or run as root.\n");

	// Synthesize kernel modules
	err = perf_event__synthesize_modules(tool, dks_process_synthesized, machine);
	WARN_ONCE(err < 0, "Couldn't record kernel module information.\n"
			"Symbol resolution may be skewed if relocation was used (e.g. kexec).\n"
			"Check /proc/modules permission or run as root.\n");

	/*all thread synthesize need to be done,
	  set data_mmap true since we sample data_address,
	  set default timeout same value of perf record  */
	err = __machine__synthesize_threads(machine, tool, &ctrl->opts.target,
		ctrl->threads, dks_process_synthesized, true, 500);
	return err;
}

static int process_buildids(struct dks_ctrl *ctrl){
	struct perf_data_file *file  = &ctrl->file;
	struct perf_session *session = ctrl->session;

	if (file->size == 0)
		return 0;

	/*
	 * During this process, it'll load kernel map and replace the
	 * dso->long_name to a real pathname it found.  In this case
	 * we prefer the vmlinux path like
	 *   /lib/modules/3.16.4/build/vmlinux
	 *
	 * rather than build-id path (in debug directory).
	 *   $HOME/.debug/.build-id/f0/6e17aa50adf4d00b88925e03775de107611551
	 */
	symbol_conf.ignore_vmlinux_buildid = true;

	/*
	 * If --buildid-all is given, it marks all DSO regardless of hits,
	 * so no need to process samples.
	 */
	if (ctrl->buildid_all)
		ctrl->tool.sample = NULL;

	return perf_session__process_events(session);
}

static int finish_output(struct dks_ctrl *ctrl)
{
	struct perf_data_file *file;

	if(!ctrl->init)
		return -EFAULT;

	ctrl->tool.mmap = perf_event__process_mmap;
	ctrl->tool.mmap2 = perf_event__process_mmap2;

	dks_debug("enter \n");
	ctrl->session->header.data_size += ctrl->bytes_written;
	file = &ctrl->file;
	file->size = lseek(perf_data_file__fd(file), 0, SEEK_CUR);

	if (!ctrl->no_buildid) {
		process_buildids(ctrl);
		if (ctrl->buildid_all)
			dsos__hit_all(ctrl->session);
	}

	/*final*/
	perf_session__write_header(ctrl->session, perf_data_file__fd(file), true);
	return 0;
}

static const char *profile_usage[] = {
	"dks --cmd profile [<options>] [<execute-command>]",
	"dks --cmd profile [<options>] -- <command> [<options>]",
	NULL
};

/*write sample data to file*/
static void write_kdks_sample_data(struct dks_ctrl *ctrl, int cpu, struct kdks_sample_data *data)
{
	if (dks_ctrl__event_write(ctrl, (void *)data, (size_t)data->header.data_len))
		pr_err("failed to write kdks event sample\n");
	/*for debug*/
	pr_kdks_sample_data(cpu, data);
}

static void *kdks_event_poll(void *arg)
{
	struct dks_ctrl *ctrl = (struct dks_ctrl *)arg;
	int nr_cpus = ctrl->nr_cpus;
	int err, i;
	u64 bytes_written;

	while (!done) {
		bytes_written = ctrl->bytes_written;
		kdks__event_poll(nr_cpus);

		for (i = 0; i < nr_cpus; ++i) {
			if (!(kdks__get_poll_revent(i) & POLLIN))
				continue;

			struct ring_buffer_req_t ev_req;
			struct kdks_sample_data *ev_data;

			/*consume until we have sample data*/
			while (!(err = kdks__evbuf_get(i, &ev_req))) {
				ev_data = (struct kdks_sample_data*)ev_req.data;
				write_kdks_sample_data(ctrl, i, ev_data);
				kdks__evbuf_get_done(i, &ev_req);
			}

			if (err != -EAGAIN)
				pr_err("CPU-%d: kdks_event buffer consume error\n", i);
			else
				dks_debug("CPU-%d: kdks_event buffer is empty\n", i);

			kdks__set_poll_revent(i, 0);
		}

		/*write finish round event*/
		if (bytes_written != ctrl->bytes_written) {
			err = dks_ctrl__event_write(ctrl, &finished_round_event,
				sizeof(finished_round_event));
			if (err)
				pr_err("Failed to write out kdks event to disk\n");
		}
	}

	bytes_written = ctrl->bytes_written;

	/*process remain data*/
	for (i = 0; i < nr_cpus; ++i) {
		struct ring_buffer_req_t ev_req;
		struct kdks_sample_data *ev_data;

		/*consume until we have sample data*/
		while (!kdks__evbuf_get(i, &ev_req)) {
			ev_data = (struct kdks_sample_data*)ev_req.data;
			write_kdks_sample_data(ctrl, i, ev_data);
			kdks__evbuf_get_done(i, &ev_req);
		}
	}

	/*write finish round event*/
	if (bytes_written != ctrl->bytes_written) {
		err = dks_ctrl__event_write(ctrl, &finished_round_event,
			sizeof(finished_round_event));
		if (err)
			pr_err("Failed to write out kdks event to disk\n");
	}

	return NULL;
}

static inline void set_time(struct timeval *t)
{
	gettimeofday(t, NULL);
}

static struct timeval get_elapsed_time(struct timeval *s, struct timeval *e)
{
	struct timeval res;
	timersub(e, s, &res);
	return res;
}

int dks_cmd_profile(int argc, const char **argv)
{
	int err;
	bool fork;
	pthread_t poll_thread;
	/*dks control block */
	struct dks_ctrl *ctrl = &dks_control_data;
	struct workload *work = &(ctrl->work);
	struct kdks_attr kdks_attr;

	/* target app string */
	char target_path[PATH_MAX];
	const char *target_app_name = NULL;
	const char *output_file_name = NULL;

	// To measure elapsed time.
	struct timeval t_start, t_end, t_res;

	struct option options[] = {
		OPT_BOOLEAN('a', "all-cpus", &(ctrl->opts.target.system_wide),
			"system-wide collection from all CPUs"),
		OPT_STRING('o', "output", &output_file_name, "file", "output file name"),
		OPT_STRING('p', "pid", &(ctrl->opts.target.pid), "pid",
			"record events on existing process id"),
		OPT_STRING('t', "tid", &(ctrl->opts.target.tid), "tid",
			"record events on existing thread id"),
		OPT_STRING(0, "vmlinux", &symbol_conf.vmlinux_name, "file", "vmlinux pathname"),
		OPT_END()
	};

	// Parse profile specific options
	argc = parse_options(argc, argv, options, NULL, profile_usage,
		PARSE_OPT_STOP_AT_NON_OPTION);

	if (!argc && target__none(&ctrl->opts.target)) {
		pr_info("System wide profiling enabled\n");
		ctrl->opts.target.system_wide = true;
	}
	//usage_with_options(profile_usage, profile_options);

	if (output_file_name && strlen(output_file_name)) {
		ctrl->file.path = output_file_name;
		pr_info("Output file name: %s\n", ctrl->file.path);
	}

	symbol__init(NULL);
	if (symbol_conf.kptr_restrict) {
		pr_warning(
		"WARNING: Kernel address maps (/proc/{kallsyms,modules}) are restricted,\n"
		"check /proc/sys/kernel/kptr_restrict.\n\n"
		"Samples in kernel functions may not be resolved if a suitable vmlinux\n"
		"file is not found in the buildid cache or in the vmlinux path.\n\n"
		"Samples in kernel modules won't be resolved at all.\n\n"
		"If some relocation was applied (e.g. kexec) symbols may be misresolved\n"
		"even with a suitable vmlinux or kallsyms file.\n\n");
	}

	err = target__validate(&ctrl->opts.target);
	if (err) {
		char errbuf[BUFSIZ] = {0, };
		target__strerror(&ctrl->opts.target, err, errbuf, BUFSIZ);
		pr_warning("%s", errbuf);
	}

	err = dks_ctrl__init(ctrl);
	if (err < 0) {
		pr_err("dks control block init fails\n");
		goto out_dks_ctrl_exit;
	}

	// FIXME: fork might be replaced with target.
	fork = argc > 0;
	if (fork) {
		err = prepare_workload(work, (const char**)argv, workload_exec_failed_signal);
		if (err < 0) {
			pr_err("Couldn't run the workload!\n");
			goto out_dks_ctrl_exit;
		}

		ctrl->opts.target.pid_d = work->pid;
		target_app_name = argv[0];
		pr_info("Target workload pid: %d, target_name = %s\n", work->pid, target_app_name);
	} else if (target__has_task(&ctrl->opts.target)) {
		/* get target binary path for spinloop map build */
		char path[PATH_MAX];

		/* get target app name from pid */
		pid_t pid = (int)strtol(ctrl->opts.target.pid, NULL, 10);
		ctrl->opts.target.pid_d = pid;

		sprintf(path, "/proc/%d/exe", pid);
		if (readlink(path, target_path, PATH_MAX - 1) < 0) {
			pr_err("couldn't get target pid info\n");
			goto out_dks_ctrl_exit;
		}

		target_app_name = target_path;
		pr_info("dks target app path :%s\n", target_app_name);
	} else {
		target_app_name = NULL;
		pr_info("System Wide - Kernel Profile enabled\n");
	}

	/*********************************************************
	 * Run spin-finder to build spinloop maps.
	 * if it is system wide mode,
	 * then we will build all kernel maps during synthesizing
	 *********************************************************/

	// FIXME: Exclude kernel profile if possible.
	set_time(&t_start);
	err = spinloop_maps__build_kernel_maps(&ctrl->spin_maps);
	if (err) {
		pr_err("build spinloop infomation tree fails\n");
		goto out_err_exit;
	}
	set_time(&t_end);

	t_res = get_elapsed_time(&t_start, &t_end);
	pr_info("spinfinder running & build map time for kernel : %ld.%06ld sec\n",
		t_res.tv_sec, t_res.tv_usec);

	if (target_app_name) {
		set_time(&t_start);
		err = spinloop_maps__build_maps(&ctrl->spin_maps, target_app_name);
		if (err) {
			pr_err("build spinloop infomation tree fails\n");
			goto out_err_exit;
		}
		set_time(&t_end);

		t_res = get_elapsed_time(&t_start, &t_end);
		pr_info("spinfinder running & build map time : %ld.%06ld sec\n",
			t_res.tv_sec, t_res.tv_usec);
	}

	/******************************************
	 * open dark insight kernel event handler *
	 ******************************************/
	// this function initialize and allocate data structures for kdks event.
	// This is done by seperate kdks threads
	err = kdks__event_open_allcpus(ctrl);
	if (err < 0) {
		pr_err("kdks event perf open fails, err:%d\n", err);
		goto out_err_exit;
	}

	// Start kdks polling thread.
	err = pthread_create(&poll_thread, NULL, kdks_event_poll, (void *)ctrl);
	if (err < 0)
		goto out_err_exit;
	ctrl->kdks_thread = &poll_thread;

	/*****************************************
	 * synthesize inital thread maps
	 *****************************************/
	err = dks_ctrl__create_maps(ctrl, &ctrl->opts.target);
	if (err < 0)
		goto out_dks_ctrl_exit;

	/* Synthesize initial state:
	   - synthesize kernel and modules : for kernel symbol mapping
	   - synthesize threads.
	 */
	err = dks_ctrl__synthesize(ctrl);
	if (err < 0) {
		pr_err("dks kernel maps synthesize fails\n");
		goto out_dks_ctrl_exit;
	}
	pr_info("dks initial shared maps synthesize done.\n");

	/*****************************************
	 * start kdks after all synthesized
	 *****************************************/
	// Set target pid
	kdks_attr.pid = ctrl->opts.target.pid_d;
	err = kdks__start_profile_all(&kdks_attr);
	if (err < 0)
		goto out_err_exit;
	pr_info("dks kernel module started.\n");

#if PROF_DO_PERF_EVENT
	/********************************
	 * open perf event for all cpus *
	 ********************************/
	// This function initializes and allocates data structures for perf event.
	// Then, it opens perf event for all cpus.
	err = perf__event_open_allcpus(ctrl);
	if (err < 0) {
		pr_err("dks event perf open fails\n");
		goto out_err_exit;
	}
	pr_info("dks event perf open done.\n");
#endif

	set_time(&t_start);

	/*prepare signals and atexist*/
	atexit(sig_exit);
	signal(SIGCHLD, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGUSR2, SIG_IGN);

	/*******************
	 * start workload  *
	 *******************/
	// FIXME: Append following if statement to support pid attachment.
	// It should generate spinloop info from its process name.
	if (fork && !start_workload(work)) {
		pr_err("failed to start workload\n");
		goto out_err_exit;
	}

	// Child process sets done to true via signals.
	while (!done) {
#if PROF_DO_PERF_EVENT
		unsigned long long hits = ctrl->samples;
		if (dks_ctrl__mmap_read_all(ctrl) < 0) {
			err = -1;
			goto out_err_exit;
		}

		if (hits == ctrl->samples) {
			err = perf__event_poll(ctrl->nr_cpus);
			// We don't need to handle in errors related to interrupt.
			if (err > 0 || (err < 0 && errno == EINTR))
				err = 0;

			// When attaching a process, we need to check
			// if poll events are POLLERR or POLLHUP.
			if (!dks_ctrl__filter_poll_events(ctrl->nr_cpus, POLLERR | POLLHUP))
				done = 1;
		}
#else
		usleep(1000000);
#endif
	}
	err = 0;

out_err_exit:
	pr_info("dks profile status done!\n");
	// If we have forked the process, kill the child process.
	if (fork && err < 0) {
		int exit_status;
		if (!child_finished)
			kill(work->pid, SIGTERM);
		wait(&exit_status);
	}

	if (!err) {
		set_time(&t_end);
		t_res = get_elapsed_time(&t_start, &t_end);
		pr_info("dks profiling Elapsed Time : %ld.%06ld sec\n",
			t_res.tv_sec, t_res.tv_usec);
	}

	if (ctrl->kdks_thread)
		pthread_join(*ctrl->kdks_thread, NULL);

	kdks__exit(ctrl);
	perf__event_exit(ctrl);

out_dks_ctrl_exit:
	finish_output(ctrl);
	dks_ctrl__exit(ctrl);
	symbol__exit();

	return err;
}
