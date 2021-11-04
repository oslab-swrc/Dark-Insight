#ifndef __DKS_PERF_EVL_H__
#define __DKS_PERF_EVL_H__

#include "../perf.h"
#include "../util/event.h"

/*forward decl*/
struct thread_map;

union u64_swap {     
	u64 val64;
	u32 val32[2];
};
/*parse sample,
  but we don't use evsel*/
int perf_evsel__parse_sample(union perf_event *event,
		struct perf_sample *data);
/*dummy definition*/
#define perf_evlist__parse_sample(x,y)  perf_evsel__parse_sample(x,y)

/*get id_hdr_size*/
u16 perf_evlist__id_hdr_size(void);                                  

/*we always use branch call stack*/
static inline bool has_branch_callstack(void)             
{                                                                             
	return true;
}                                                                             
#endif /* END PERF_EVL_H__ */
