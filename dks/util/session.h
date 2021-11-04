#ifndef __PERF_SESSION_H
#define __PERF_SESSION_H

#include "event.h"
#include "header.h"
#include "machine.h"
#include "symbol.h"
#include "thread.h"
#include "data.h"
#include "ordered-events.h"
#include <linux/rbtree.h>
#include <linux/perf_event.h>

#include "../include/dks_lock_stat.h"

struct ip_callchain;
struct thread;

struct perf_session {
	struct perf_header	header;
	struct machines		machines;
	bool			one_mmap;
	void			*one_mmap_addr;
	u64			one_mmap_offset;
	struct ordered_events	ordered_events;
	struct perf_data_file	*file;
	struct perf_tool	*tool;

	struct dks_lock_stat	lock_stats;	/*consist of hash tables for lock stat*/
};

#define PRINT_IP_OPT_IP		(1<<0)
#define PRINT_IP_OPT_SYM		(1<<1)
#define PRINT_IP_OPT_DSO		(1<<2)
#define PRINT_IP_OPT_SYMOFFSET	(1<<3)
#define PRINT_IP_OPT_ONELINE	(1<<4)
#define PRINT_IP_OPT_SRCLINE	(1<<5)

struct perf_tool;

struct perf_session *perf_session__new(struct perf_data_file *file,
		struct perf_tool *tool);
void perf_session__delete(struct perf_session *session);

void perf_event_header__bswap(struct perf_event_header *hdr);

int perf_session__peek_event(struct perf_session *session, off_t file_offset,
			     void *buf, size_t buf_sz,
			     union perf_event **event_ptr,
			     struct perf_sample *sample);

int perf_session__process_events(struct perf_session *session);

int perf_session__queue_event(struct perf_session *s, union perf_event *event,
			      struct perf_sample *sample, u64 file_offset);

void perf_tool__fill_defaults(struct perf_tool *tool);

size_t perf_session__fprintf(struct perf_session *session, FILE *fp);
size_t perf_session__fprintf_dsos(struct perf_session *session, FILE *fp);
size_t perf_session__fprintf_dsos_buildid(struct perf_session *session, FILE *fp,
		bool (fn)(struct dso *dso, int parm), int parm);

int perf_session__resolve_callchain(struct perf_session *session,
				    struct perf_evsel *evsel,
				    struct thread *thread,
				    struct ip_callchain *chain,
				    struct symbol **parent);

void perf_event__attr_swap(struct perf_event_attr *attr);

int perf_session__create_kernel_maps(struct perf_session *session);

void perf_session__set_id_hdr_size(struct perf_session *session);

static inline
struct machine *perf_session__find_machine(struct perf_session *session, pid_t pid)
{
	return machines__find(&session->machines, pid);
}

static inline
struct machine *perf_session__findnew_machine(struct perf_session *session, pid_t pid)
{
	return machines__findnew(&session->machines, pid);
}

struct thread *perf_session__findnew(struct perf_session *session, pid_t pid);
int perf_session__register_idle_thread(struct perf_session *session);
struct perf_evsel_str_handler;

extern volatile int session_done;

#define session_done()	ACCESS_ONCE(session_done)

int perf_session__deliver_synth_event(struct perf_session *session,
				      union perf_event *event,
				      struct perf_sample *sample);
int perf_session__deliver_event(struct perf_session *session,
		union perf_event *event,
		struct perf_sample *sample,
		struct perf_tool *tool,
		u64 file_offset);

void dump_sample(union perf_event *event, struct perf_sample *sample);

#endif /* __PERF_SESSION_H */
