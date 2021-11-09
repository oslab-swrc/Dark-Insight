// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/*perf headers*/
#include "perf.h"

/*dks support headers*/
#include "dks.h"
#include "spinloop_maps.h"

#include "util/debug.h"
#include "util/util.h"
#include "util/session.h"
#include "util/target.h"
#include "util/thread_map.h"

const char *g_spnf_path;

int dks_ctrl__init(struct dks_ctrl *ctrl)
{
	int err;
	struct perf_data_file *perf_data_file_p = &ctrl->file;
	struct perf_session *perf_session_p;
	struct perf_tool *perf_tool_p = &(ctrl->tool);
	int fd;

	err = spinloop_maps__init(&ctrl->spin_maps);
	if (err < 0) {
		pr_err("spinloop_maps init fail \n");
		return -1;
	}

	// During init session, we will create spinloop maps for kernel.
	perf_session_p = perf_session__new(perf_data_file_p, perf_tool_p);
	if (!perf_session_p) {
		pr_err("perf session creation failed.\n");
		return -1;
	}

	/*set session id_hdr_size*/
	perf_session__set_id_hdr_size(perf_session_p);

	/*now we open session and profile output file.
	  session create machine data which has kernel maps*/
	fd = perf_data_file__fd(perf_data_file_p);
	ctrl->session = perf_session_p;

	/*write initial perf file header */
	err = perf_session__write_header(perf_session_p, fd, false);
	if (err < 0) {
		pr_err("perf write header fail \n");
		goto out_delete_session;
	}

	/*prepare perf attribute for opening*/
	err = perf__init_event_attr(&(ctrl->attr));
	/*XXX test version for tracepoint event*/
	//err = perf__init_probe_event_attr(&(ctrl->attr));
	if (err < 0) {
		pr_err("perf event attribute init fail \n");
		goto out_delete_session;
	}

	/* get nr_cpus */
	ctrl->nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ctrl->nr_cpus < 1) {
		pr_err("# of cpus should be larger than 1\n");
		goto out_delete_session;
	}

	ctrl->init = true;
	return 0;

out_delete_session:
	perf_session__delete(perf_session_p);
	dks_debug("leave with error\n");
	return err;
}

void dks_ctrl__exit(struct dks_ctrl *ctrl)
{
	if (!ctrl->init)
		return;

	if (ctrl->session)
		perf_session__delete(ctrl->session);
	if (ctrl->threads)
		thread_map__put(ctrl->threads);
}

int dks_ctrl__create_maps(struct dks_ctrl *ctrl, struct target *target)
{
	struct thread_map *threads = NULL;
	assert(ctrl);

	if (target->pid_d != -1 || target->tid_d != -1) {
		threads = thread_map__new(target->pid_d, target->tid_d, target->uid);
		if (threads) {
			ctrl->threads = threads;
			return 0;
		}
	}

	/*let's try to create thrad_map from string*/
	threads = thread_map__new_str(target->pid, target->tid, target->uid);
	if (!threads)
		return -1;

	ctrl->threads = threads;
	return 0;
}

int dks_ctrl__event_write(struct dks_ctrl *ctrl, void *bf, size_t size)
{
	if (perf_data_file__write(&ctrl->file, bf, size) < 0) {
		pr_err("failed to write perf data, error: %m\n");
		return -1;
	}

	ctrl->bytes_written += size;
	return 0;
}

size_t dks_ctrl__mmap_size(unsigned long pages)
{
	if (pages == UINT_MAX) {
		int max;

		if (sysctl__read_int("kernel/perf_event_mlock_kb", &max) < 0) {
			/*
			 * Pick a once upon a time good value, i.e. things look
			 * strange since we can't read a sysctl value, but lets not
			 * die yet...
			 */
			max = 512;
		} else {
			max -= (page_size / 1024);
		}

		pages = (max * 1024) / page_size;
		if (!is_power_of_2(pages))
			pages = rounddown_pow_of_two(pages);
	} else if (!is_power_of_2(pages))
		return 0;

	return (pages + 1) * page_size;
}

int dks_ctrl__filter_poll_events(int nr_cpus, short revents_mask){
	int i = 0, nr = 0;

	/*check all revents has target event*/
	for(; i < nr_cpus; i++) {
		if(perf__get_poll_revent(i)& revents_mask){
			continue;
		}

		nr++;
	}

	return nr;
}

