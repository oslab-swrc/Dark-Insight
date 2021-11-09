// SPDX-License-Identifier: MIT
#ifndef _DKS_COMMON_H
#define _DKS_COMMON_H
#include <linux/types.h>
#include <linux/perf_event.h>

#ifndef KDKS_CONF_KERNEL
#include <string.h>
#endif

#ifndef KDKS_CONF_KERNEL
# ifndef L1D_CACHELINE_SIZE
# define L1D_CACHELINE_SIZE   64
# endif
# ifndef ____cacheline_aligned
# define ____cacheline_aligned  __attribute__ ( \
		(aligned (L1D_CACHELINE_SIZE)))
# endif
#else
# ifndef L1D_CACHELINE_SIZE
# define L1D_CACHELINE_SIZE L1_CACHE_BYTES
# endif
#endif

#define CMD_BUFSIZE (256)
#define KDKS_INVALID_ADDR ((unsigned long long)(-1))
#define IS_VALID_ADDR(x) (x != KDKS_INVALID_ADDR)

#define PERF_RECORD_KDKS_SAMPLE 63	/*KDKS sample event number*/
#define DKS_CALLCHAIN_FAST_CMP 0

#define sizeof__callchain_t(ips) (sizeof(callchain_t)+(ips)->nr*sizeof(u64))

enum kdks_lock_type {
	KDKS_LOCK_NONE = 0,
	KDKS_SPINLOCK = 1,
	KDKS_MUTEXLOCK = 2,
	KDKS_MUTEXCOND = 3,
};

typedef struct kdks_perf_callchain_entry {
	u64 nr;	/*size of callchain*/
	u64 ip[0];
} callchain_t;

typedef struct kdks_record {
	pid_t pid, tid;
	u64 waiting_time;	/*acc block/wait time*/
	u64 ips_id;	/*unique id of callchain*/
	callchain_t ips;/*variable size callchain data*/
} kdks_record_t;

/*kdks_sample_header,
  we can't use perf_event_header because of size limit.
  perf_event_header.size is u16, so max size is limited to 64K*/
typedef struct kdks_sample_header {
	struct perf_event_header perf_header;/*for compatible with perf*/
	u64 addr;	/*lock variable address*/
	u16 lock_type;
	u16 n_waiters;  /*# of waiters*/
	u32 data_len ; 	/*size of sample data include header*/
} kdks_sample_header_t;

/*sample data output structure*/
struct __attribute__((packed)) kdks_sample_data {
	kdks_sample_header_t header;
	kdks_record_t holder;		/*holder*/
	kdks_record_t waiter[0];	/*waiters*/
} ____cacheline_aligned;

/*perf_callchain_entry comparison function,
  if fast cmp mode, we compare # of ips between two entries.
  at this point two entries hash value already checked*/
static inline bool cmp_perf_callchain(callchain_t *e1, callchain_t *e2) {
#if DKS_CALLCHAIN_FAST_CMP
	return e1->nr == e2->nr;
#else
	return e1->nr == e2->nr
		&& memcmp(e1, e2, e1->nr*sizeof(u64)) == 0;
#endif
}

static inline size_t sizeof__kdks_record(u64 nr)
{
	return nr * sizeof(u64) + sizeof(kdks_record_t);
}

#endif /* _DKS_COMMON_H */
