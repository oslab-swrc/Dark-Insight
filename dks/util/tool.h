#ifndef __PERF_TOOL_H
#define __PERF_TOOL_H

#include <stdbool.h>
#include <linux/types.h>
#include <dks_common.h>

union perf_event;
struct perf_sample;
struct perf_tool;
struct machine;
struct perf_session;
struct ordered_events;

typedef int (*event_kdks_sample)(struct perf_tool *tool,
		struct kdks_sample_data *event,
		struct perf_session *session);

typedef int (*event_sample)(struct perf_tool *tool, union perf_event *event,
		struct perf_sample *sample,
		struct machine *machine);

typedef int (*event_op)(struct perf_tool *tool, union perf_event *event,
		struct perf_sample *sample, struct machine *machine);

typedef int (*event_op2)(struct perf_tool *tool, union perf_event *event,
		struct perf_session *session);

typedef int (*event_oe)(struct perf_tool *tool, union perf_event *event,
		struct ordered_events *oe);


struct perf_tool {
	event_sample	sample;
	event_kdks_sample	kdks_sample;
	event_op	mmap,
			mmap2,
			comm,
			fork,
			exit,
			throttle,
			unthrottle;
	event_oe        finished_round;
	event_op2	build_id,
			thread_map;
	bool            ordered_events;
	bool            ordering_requires_timestamps;
};

#endif /* __PERF_TOOL_H */
