// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/*dks header*/
#include "dks.h"
#include "dks_lock_stat.h"
#include "dks_graph.h"

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

#include <linux/types.h>
#include <subcmd/parse-options.h>

static const char *deadlock_usage[] = {
	"dks --cmd deadlock [<options>]",
	NULL
};

struct deadlock_detector {
	struct perf_tool 	tool;
	struct perf_session 	*session;
	bool 			max_stack;
	u64			nr_entries;
};

static void sig_handler(int sig __maybe_unused){
	session_done = 1;
}

/*********************************************************
   		extracting nodes and edges	
*********************************************************/

/* extract node entry from sample data */
static struct dks_node_entry *dks_extract_node(struct dks_lock_stat *stats,
		struct kdks_sample_data *data){
	struct dks_ht *lock_ht = NULL; 
	struct dks_node_entry *e = NULL;
	u64 hash_val = 0;
	pid_t pid;

	/************************************************************* 
	   INIT phase
	 *************************************************************/
	/* init required data structures.
	   get lock hash table from session */
	lock_ht = stats->lock_ht;
	kdks_sample_header_t *header = &data->header;	/*fixed size header*/
	kdks_record_t *r = &data->holder;		/*point to first record*/

	/* we use mutex's memory address as a key */
	hash_val = header->addr;
	pid = r->pid;

	/* consult existence */
	e = (struct dks_node_entry *)dks_node_table__lookup(
			lock_ht, hash_val, pid);
	if(e){
		dks_debug("found node entry hash_val 0x%"PRIx64"\n", e->entry.key);
		return e;
	}

	/*allocate new entry and then add it to hashtable*/
	e = (struct dks_node_entry *) malloc(sizeof(*e));
	if(!e)
		goto out;

	/* set new lock entry info */
	e->pid = r->pid;
	e->tid = r->tid;

	dks_ht__add(lock_ht, hash_val, (struct dks_hash_entry *) e);
	dks_debug("add new lock_entry hash_val 0x%"PRIx64"\n", e->entry.key);

out:
	return e;
}

static inline struct dks_ips_entry * lookup_ips_entry(struct dks_lock_stat *stats,
		u64 hash_val){
	return 	(struct dks_ips_entry *) dks_ht__lookup(stats->ips_ht, hash_val);
}

/* extract possible edges from sample data */
static void dks_extract_possible_edges(struct dks_lock_stat *stats,
		struct kdks_sample_data *data){
	int i;
	size_t pos = 0;
	kdks_record_t *record;
	kdks_sample_header_t *header = &data->header;
	char *array = (char *)data;

	dks_debug("type %u waiters %u, size %u\n",
			header->lock_type,
			header->n_waiters,
			header->data_len);

	/* proceed amount of header */
	pos += sizeof(kdks_sample_header_t);

	/* set first record,
	   process holder data first */
	record = &data->holder;

	dks_debug("============================ \n");
	dks_debug("current holder's waiter list \n");
	dks_debug("============================ \n");

	/* update waiting time and waiter list */
	for(i=0; i < header->n_waiters; i++){
		pos +=  sizeof__kdks_record(record->ips.nr);
		record = (kdks_record_t *) (array+pos);
		pr_kdks_record(i, record);
	}
	dks_debug("============================ \n");
}

/*Process kdks sample data,
  return value: processed size of sample data*/
static int process_kdks_sample(struct perf_tool *tool,
		struct kdks_sample_data *data, struct perf_session *session){
	int data_size = 0;
	struct deadlock_detector *p = container_of(tool, struct deadlock_detector, tool);
	struct dks_lock_stat *stats = &session->lock_stats;
	kdks_sample_header_t *header = &data->header;
	struct dks_node_entry *entry = NULL;

	/* get data size */
	data_size = header->data_len - sizeof(struct perf_event_header);

	/* if the size of processed sample data,
	   then return 0*/
	if(data_size <= sizeof(struct perf_event_header)){
		pr_err("failed to process kdks sample, "
				"wrong sample data header header.data_len %u\n",
				data->header.data_len);
		return 0;
	}

	/*if holder doesn't have any waiters,
	  then skip it*/
	if(header->n_waiters == 0){
		pr_warning("holder info at 0x%"PRIx64"doesn't have any waiters\n",
				header->addr);
		goto out;
	}

	/* extract node info from sample data */
	entry = dks_extract_node(stats, data);

	/*failed entry - skip it*/
	if(!entry){
		pr_err("failed to process kdks sample, "
				"failed to allocate node entry\n"); 
		goto out;
	}

	/* extract node and edges to generate graph */
	dks_extract_possible_edges(stats, data);

	p->nr_entries++;
out:
	return data_size ;
}

static int __cmd_deadlock(struct deadlock_detector *d){
	int ret;
	struct perf_session *session = d->session;

	signal(SIGINT, sig_handler);

	ret = perf_session__process_events(session);
	if (ret) {
		pr_err("failed to process sample\n");
		return ret;
	}

	if (session_done())
		return 0;

	return 0;
}

/*run dks cmd analyze - it is similar to perf report*/
int dks_cmd_deadlock(int argc, const char **argv)
{
	int err = 0;
	struct perf_session *session;
	struct stat st;

	struct deadlock_detector d = {
		.tool = {
			.kdks_sample	= process_kdks_sample,
			.mmap           = perf_event__process_mmap,
			.mmap2          = perf_event__process_mmap2,
			.comm           = perf_event__process_comm,
			.exit           = perf_event__process_exit,
			.fork           = perf_event__process_fork,
			.ordered_events = true,
			.ordering_requires_timestamps = true,
		},
		.max_stack               = PERF_MAX_STACK_DEPTH,
	};

	struct option options[] = {
		OPT_BOOLEAN('e', "export", &exports_json, "export profile in json format"),
		OPT_STRING('i', "input", &input_file_name, "file",
				"input file name"),
		OPT_INCR('v', "verbose", &verbose,
				"be more verbose (show symbol address, etc)"),
		OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
				"dump raw trace in ASCII"),
		OPT_END()
	};

	struct perf_data_file file = {
		.mode  = PERF_DATA_MODE_READ,
	};

	pr_info("dks deadlock detector \n");
	/**************************************
	 *  Parse options
	 **************************************/
	argc = parse_options(argc, argv, options, NULL, deadlock_usage,
			PARSE_OPT_STOP_AT_NON_OPTION);

	if(argc > 1)
		usage_with_options(deadlock_usage, options);

	/*input file name*/
	if (!input_file_name || !strlen(input_file_name)) {
		if (!fstat(STDIN_FILENO, &st) && S_ISFIFO(st.st_mode))
			input_file_name = "-";
		else
			input_file_name = "dks_profile.data";
	}

	file.path  = input_file_name;
	pr_info("target filename %s\n", input_file_name);

	session = perf_session__new(&file, &d.tool);
	if (session == NULL)
		return -1;

	err = dks_lock_stat__build_stat_tables(&session->lock_stats);
	if(err)
		goto err_out;

	d.session = session;
	pr_info("setup deadlock detector env. done \n");

	err = __cmd_deadlock(&d);

	if(err){
		pr_err("failed to analyze kdks sample data\n");
		goto err_out;
	}
	pr_info("process samples done, # of processed samples:%"PRIu64"\n",
			d.nr_entries);

err_out:
	dks_lock_stat__destroy_stat_tables(&session->lock_stats);
	perf_session__delete(session);

	pr_info("dks analyze done!\n");
	return err;
}
