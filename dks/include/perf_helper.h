// SPDX-License-Identifier: MIT
#ifndef __DKS_PERF_HELPER_H__
#define __DKS_PERF_HELPER_H__

#include <stdio.h>
#include <stdint.h>

#include "../perf.h"
#include "../util/event.h"
#include "workload.h"

/*perf sample handling */
/*
 * struct {
 *      struct perf_event_header        header;
 *
 *      #
 *      # Note that PERF_SAMPLE_IDENTIFIER duplicates PERF_SAMPLE_ID.
 *      # The advantage of PERF_SAMPLE_IDENTIFIER is that its position
 *      # is fixed relative to header.
 *      #
 *
 *      { u64                   id;       } && PERF_SAMPLE_IDENTIFIER
 *      { u64                   ip;       } && PERF_SAMPLE_IP
 *      { u32                   pid, tid; } && PERF_SAMPLE_TID
 *      { u64                   time;     } && PERF_SAMPLE_TIME
 *      { u64                   addr;     } && PERF_SAMPLE_ADDR
 *      { u64                   id;       } && PERF_SAMPLE_ID
 *      { u64                   stream_id;} && PERF_SAMPLE_STREAM_ID
 *      { u32                   cpu, res; } && PERF_SAMPLE_CPU
 *      { u64                   period;   } && PERF_SAMPLE_PERIOD
 *
 *      { struct read_format    values;   } && PERF_SAMPLE_READ
 *
 *      { u64                   nr,
 *        u64                   ips[nr];  } && PERF_SAMPLE_CALLCHAIN
 *
 *      #
 *      # The RAW record below is opaque data wrt the ABI
 *      #
 *      # That is, the ABI doesn't make any promises wrt to
 *      # the stability of its content, it may vary depending
 *      # on event, hardware, kernel version and phase of
 *      # the moon.
 *      #
 *      # In other words, PERF_SAMPLE_RAW contents are not an ABI.
 *      #
 *
 *      { u32                   size;
 *        char                  data[size];}&& PERF_SAMPLE_RAW
 *
 *      { u64                   nr;
 *        { u64 from, to, flags } lbr[nr];} && PERF_SAMPLE_BRANCH_STACK
 *
 *      { u64                   abi; # enum perf_sample_regs_abi
 *        u64                   regs[weight(mask)]; } && PERF_SAMPLE_REGS_USER
 *
 *      { u64                   size;
 *        char                  data[size];
 *        u64                   dyn_size; } && PERF_SAMPLE_STACK_USER
 *
 *      { u64                   weight;   } && PERF_SAMPLE_WEIGHT
 *      { u64                   data_src; } && PERF_SAMPLE_DATA_SRC
 *      { u64                   transaction; } && PERF_SAMPLE_TRANSACTION
 *      { u64                   abi; # enum perf_sample_regs_abi
 *        u64                   regs[weight(mask)]; } && PERF_SAMPLE_REGS_INTR
 * };
 */

/*forward decl*/
struct dks_ctrl;

/* perf sample has 16 bits size limit */
#define PERF_SAMPLE_MAX_SIZE (1 << 16)  

struct perf_mmap {
	void	*base;
	u64	prev;
	int	mask;
	char    event_copy[PERF_SAMPLE_MAX_SIZE] __attribute__((aligned(8)));
};

typedef int (*handle_sample_fn)(union perf_event *event,
		struct perf_sample *data);

static inline u64 perf_mmap__read_head(struct perf_mmap *mm)
{
	struct perf_event_mmap_page *pc = mm->base;
	u64 head = ACCESS_ONCE(pc->data_head);
	rmb();
	return head;
}

static inline void perf_mmap__write_tail(struct perf_mmap *md, u64 tail)
{
	struct perf_event_mmap_page *pc = md->base;

	/*
	 * ensure all reads are done before we write the tail out.
	 */
	mb();
	pc->data_tail = tail;
}

void	perf__mmap_consume(struct dks_ctrl *ctrl, int idx);

/*Init perf attribute*/
int	perf__init_event_attr(struct perf_event_attr *attr);
int	perf__init_probe_event_attr(struct perf_event_attr *attr);

/*Open perf event as many as # of cpus with specified attribute*/
int	perf__event_open_allcpus(struct dks_ctrl *ctrl);
int	perf__event_drain(struct dks_ctrl *ctrl, int idx);
int     perf__event_read(struct dks_ctrl *ctrl, int idx);

/*cleanup functions*/
void	perf__event_exit(struct dks_ctrl *ctrl);


#endif
