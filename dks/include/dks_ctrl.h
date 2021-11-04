#ifndef __DKS_CTRL_H__
#define __DKS_CTRL_H__

#include <pthread.h>
#include <linux/perf_event.h>
#include <linux/bitops.h>
#include <linux/log2.h>
#include <api/fs/fs.h>

#include "../perf.h"
#include "../util/target.h"
#include "../util/machine.h"
#include "../util/data.h"
#include "../util/util.h"
#include "../util/tool.h"
#include "workload.h"
#include "spinloop_maps.h"
#include "dks_util.h"

/* dks ctrol block */
struct dks_ctrl {
	struct  perf_event_attr attr;
	struct  perf_tool	tool;
	struct  record_opts	opts;
	struct  workload        work;
	//struct	target		target;
	struct	perf_session	*session;
	size_t			mmap_size;
	struct  perf_mmap	**mmap;
	struct  perf_data_file  file;
	struct	thread_map	*threads;
	struct  spinloop_maps	spin_maps; /*rb_tree for dso search*/
	pthread_t		*kdks_thread;
	int			nr_cpus;
	u64			bytes_written;
	unsigned long long      samples;
	bool			buildid_all;
	bool			no_buildid;
	bool			init;
};

/* init dks control block */
int  dks_ctrl__init(struct dks_ctrl *ctrl);
void dks_ctrl__exit(struct dks_ctrl *ctrl);

/* create maps(thread/cpu) for dks_ctrl,
   currently don't create cpumap*/
int dks_ctrl__create_maps(struct dks_ctrl *ctrl, struct target *target); 
int dks_ctrl__event_write(struct dks_ctrl *ctrl, void *bf, size_t size);

/*calculate proper mmap size*/
size_t dks_ctrl__mmap_size(unsigned long pages);

/*filter poll events*/
int dks_ctrl__filter_poll_events(int nr_cpus, short revents_mask);

/*spin-finder path*/
extern const char *g_spnf_path;

#endif /* __DKS_CTRL_H__ */
