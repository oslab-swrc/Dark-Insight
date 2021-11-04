#include <linux/kernel.h>

#include <byteswap.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <math.h>

#include "session.h"
#include "tool.h"
#include "util.h"
#include "asm/bug.h"
#include "perf_evl.h"
#include "debug.h"
#include "event.h"

static int perf_session__open(struct perf_session *session)
{
	if (perf_session__read_header(session) < 0) {
		pr_err("incompatible file format (rerun with -v to learn more)\n");
		return -1;
	}

	return 0;
}

void perf_session__set_id_hdr_size(struct perf_session *session)
{
	u16 id_hdr_size = perf_evlist__id_hdr_size();

	machines__set_id_hdr_size(&session->machines, id_hdr_size);
}

int perf_session__create_kernel_maps(struct perf_session *session)
{
	return machine__create_kernel_maps(&session->machines.host);
}

static void perf_session__destroy_kernel_maps(struct perf_session *session)
{
	machines__destroy_kernel_maps(&session->machines);
}

/*TODO:
  currently do not enable comm_exec*/
static bool perf_session__has_comm_exec(struct perf_session *session)
{
	return false;
}

static void perf_session__set_comm_exec(struct perf_session *session)
{
	bool comm_exec = perf_session__has_comm_exec(session);

	machines__set_comm_exec(&session->machines, comm_exec);
}

static int ordered_events__deliver_event(struct ordered_events *oe,
		struct ordered_event *event)
{
	struct perf_sample sample;
	struct perf_session *session = container_of(oe, struct perf_session,
			ordered_events);
	int ret = perf_evlist__parse_sample(event->event, &sample);

	if (ret) {
		pr_err("Can't parse sample, err = %d\n", ret);
		return ret;
	}

	return perf_session__deliver_event(session, event->event, &sample,
		session->tool, event->file_offset);
}


struct perf_session *perf_session__new(struct perf_data_file *file, struct perf_tool *tool)
{
	struct perf_session *session = zalloc(sizeof(*session));
	if (!session)
		return NULL;

	session->tool = tool;
	machines__init(&session->machines);
	ordered_events__init(&session->ordered_events, ordered_events__deliver_event);

	if (file) {
		if (perf_data_file__open(file)) {
			perf_session__delete(session);
			return NULL;
		}

		session->file = file;

		// FIXME: perf_data_file__is_read is not handled yet.
		if (perf_data_file__is_read(file)) {
			if (perf_session__open(session) < 0) {
				perf_data_file__close(file);
				perf_session__delete(session);
				return NULL;
			}

			perf_session__set_id_hdr_size(session);
			perf_session__set_comm_exec(session);
		}
	}

	if (!file || perf_data_file__is_write(file)) {
		/*
		 * In O_RDONLY mode this will be performed when reading the
		 * kernel MMAP event, in perf_event__process_mmap().
		 */
		if (perf_session__create_kernel_maps(session) < 0)
			pr_warning("Cannot read kernel map\n");
	}

	return session;
}

static void perf_session__delete_threads(struct perf_session *session)
{
	machine__delete_threads(&session->machines.host);
}

void perf_session__delete(struct perf_session *session)
{
	perf_session__destroy_kernel_maps(session);
	perf_session__delete_threads(session);
	machines__exit(&session->machines);
	if (session->file)
		perf_data_file__close(session->file);
	free(session);
}

static int process_event_sample_stub(struct perf_tool *tool __maybe_unused,
	union perf_event *event __maybe_unused, struct perf_sample *sample __maybe_unused,
	struct machine *machine __maybe_unused)
{
	dump_printf(": unhandled!\n");
	return 0;
}

static int process_event_stub(struct perf_tool *tool __maybe_unused,
	union perf_event *event __maybe_unused, struct perf_sample *sample __maybe_unused,
	struct machine *machine __maybe_unused)
{
	dump_printf(": unhandled!\n");
	return 0;
}

static int process_event_op2_stub(struct perf_tool *tool __maybe_unused,      
		union perf_event *event __maybe_unused,
		struct perf_session *session __maybe_unused)
{
	dump_printf(": unhandled!\n");
	return 0;
}

	static
int process_event_thread_map_stub(struct perf_tool *tool __maybe_unused,
		union perf_event *event __maybe_unused,
		struct perf_session *session __maybe_unused)
{
	if (dump_trace)
		perf_event__fprintf_thread_map(event, stdout);

	dump_printf(": unhandled!\n");
	return 0;
}

static int process_finished_round_stub(struct perf_tool *tool __maybe_unused,
		union perf_event *event __maybe_unused,
		struct ordered_events *oe __maybe_unused)
{
	dump_printf(": unhandled!\n");
	return 0;
}

static int process_finished_round(struct perf_tool *tool,
		union perf_event *event,
		struct ordered_events *oe);


void perf_tool__fill_defaults(struct perf_tool *tool)
{
	if (tool->sample == NULL)
		tool->sample = process_event_sample_stub;
	if (tool->mmap == NULL)
		tool->mmap = process_event_stub;
	if (tool->mmap2 == NULL)
		tool->mmap2 = process_event_stub;
	if (tool->comm == NULL)
		tool->comm = process_event_stub;
	if (tool->fork == NULL)
		tool->fork = process_event_stub;
	if (tool->exit == NULL)
		tool->exit = process_event_stub;
	if (tool->throttle == NULL)
		tool->throttle = process_event_stub;
	if (tool->unthrottle == NULL)
		tool->unthrottle = process_event_stub;
	if (tool->build_id == NULL)                     
		tool->build_id = process_event_op2_stub;
	if (tool->thread_map == NULL)
		tool->thread_map = process_event_thread_map_stub;
	if (tool->finished_round == NULL){
		if(tool->ordered_events)
			tool->finished_round = process_finished_round;
		else /*dks use only dummy finished round*/
			tool->finished_round = process_finished_round_stub;
	}
}

/*
 * When perf record finishes a pass on every buffers, it records this pseudo
 * event.
 * We record the max timestamp t found in the pass n.
 * Assuming these timestamps are monotonic across cpus, we know that if
 * a buffer still has events with timestamps below t, they will be all
 * available and then read in the pass n + 1.
 * Hence when we start to read the pass n + 2, we can safely flush every
 * events with timestamps below t.
 *
 *    ============ PASS n =================
 *       CPU 0         |   CPU 1
 *                     |
 *    cnt1 timestamps  |   cnt2 timestamps
 *          1          |         2
 *          2          |         3
 *          -          |         4  <--- max recorded
 *
 *    ============ PASS n + 1 ==============
 *       CPU 0         |   CPU 1
 *                     |
 *    cnt1 timestamps  |   cnt2 timestamps
 *          3          |         5
 *          4          |         6
 *          5          |         7 <---- max recorded
 *
 *      Flush every events below timestamp 4
 *
 *    ============ PASS n + 2 ==============
 *       CPU 0         |   CPU 1
 *                     |
 *    cnt1 timestamps  |   cnt2 timestamps
 *          6          |         8
 *          7          |         9
 *          -          |         10
 *
 *      Flush every events below timestamp 7
 *      etc...
 */
static int process_finished_round(struct perf_tool *tool __maybe_unused,
		union perf_event *event __maybe_unused,
		struct ordered_events *oe)
{
	if (dump_trace)
		fprintf(stdout, "\n");
	return ordered_events__flush(oe, OE_FLUSH__ROUND);
}

int perf_session__queue_event(struct perf_session *s, union perf_event *event,
		struct perf_sample *sample, u64 file_offset)
{
	return ordered_events__queue(&s->ordered_events, event, sample, file_offset);
}

static void callchain__printf(struct perf_sample *sample)
{
	unsigned int i;
	struct ip_callchain *callchain = sample->callchain;

	printf("... FP chain: nr:%" PRIu64 "\n", callchain->nr);

	for (i = 0; i < callchain->nr; i++)
		printf("..... %2d: %016" PRIx64 "\n",
				i, callchain->ips[i]);
}

static void branch_stack__printf(struct perf_sample *sample)
{
	uint64_t i;

	printf("... branch stack: nr:%" PRIu64 "\n", sample->branch_stack->nr);

	for (i = 0; i < sample->branch_stack->nr; i++) {
		struct branch_entry *e = &sample->branch_stack->entries[i];

		printf("..... %2"PRIu64": %016" PRIx64 " -> %016" PRIx64 " %hu cycles %s%s%s%s %x\n"
				,
				i, e->from, e->to,
				e->flags.cycles,
				e->flags.mispred ? "M" : " ",
				e->flags.predicted ? "P" : " ",
				e->flags.abort ? "A" : " ",
				e->flags.in_tx ? "T" : " ",
				(unsigned)e->flags.reserved);
	}
}

static void regs_dump__printf(u64 mask, u64 *regs)
{
	unsigned rid, i = 0;

	for_each_set_bit(rid, (unsigned long *) &mask, sizeof(mask) * 8) {
		u64 val = regs[i++];

		printf(".... %-5s 0x%" PRIx64 "\n",
				perf_reg_name(rid), val);
	}
}

static const char *regs_abi[] = {
	[PERF_SAMPLE_REGS_ABI_NONE] = "none",
	[PERF_SAMPLE_REGS_ABI_32] = "32-bit",
	[PERF_SAMPLE_REGS_ABI_64] = "64-bit",
};

static inline const char *regs_dump_abi(struct regs_dump *d)
{
	if (d->abi > PERF_SAMPLE_REGS_ABI_64)
		return "unknown";

	return regs_abi[d->abi];
}

static void regs__printf(const char *type, struct regs_dump *regs)
{
	u64 mask = regs->mask;

	printf("... %s regs: mask 0x%" PRIx64 " ABI %s\n",
			type,
			mask,
			regs_dump_abi(regs));

	regs_dump__printf(mask, regs->regs);
}

static void regs_user__printf(struct perf_sample *sample)
{
	struct regs_dump *user_regs = &sample->user_regs;

	if (user_regs->regs)
		regs__printf("user", user_regs);
}

static void stack_user__printf(struct stack_dump *dump)
{
	printf("... ustack: size %" PRIu64 ", offset 0x%x\n",
			dump->size, dump->offset);
}

static void perf_evlist__print_tstamp(union perf_event *event,
		struct perf_sample *sample)
{
	/*TODO:
	  we already know we have sample_cpu and time,
	  but keep this form for the later usage*/
	u64 sample_type = PERF_SAMPLE_MASK;

	if ((sample_type & PERF_SAMPLE_CPU))
		printf("%u ", sample->cpu);

	if (sample_type & PERF_SAMPLE_TIME)
		printf("%" PRIu64 " ", sample->time);
}

static void dump_event(union perf_event *event,
		u64 file_offset, struct perf_sample *sample)
{
	if (!dump_trace)
		return;

	printf("\n%#" PRIx64 " [%#x]: event: %d\n",
			file_offset, event->header.size, event->header.type);

	/*        trace_event(event);*/

	if (sample)
		perf_evlist__print_tstamp(event, sample);

	printf("%#" PRIx64 " [%#x]: PERF_RECORD_%s", file_offset,
			event->header.size, perf_event__name(event->header.type));
}

void dump_sample(union perf_event *event,
		struct perf_sample *sample)
{
	u64 sample_type = DKS_SAMPLE_MASK;

	if (!dump_trace)
		return;

	dks_debug("enter \n");

	printf("(IP, 0x%x): ID[%ld] %d/%d: %#" PRIx64 " period: %" 
			PRIu64 " addr: %#" PRIx64 "\n",
			event->header.misc, (int64_t)sample->id, sample->pid, sample->tid, sample->ip,
			sample->period, sample->addr);

	if (sample_type & PERF_SAMPLE_CALLCHAIN)
		callchain__printf(sample);

	if ((sample_type & PERF_SAMPLE_BRANCH_STACK) && !has_branch_callstack())
		branch_stack__printf(sample);

	if (sample_type & PERF_SAMPLE_REGS_USER)
		regs_user__printf(sample);

	if (sample_type & PERF_SAMPLE_STACK_USER)
		stack_user__printf(&sample->user_stack);

}

static struct machine *machines__find_for_cpumode(struct machines *machines,
		union perf_event *event,
		struct perf_sample *sample)
{
	struct machine *machine;

	if (perf_guest &&
			((sample->cpumode == PERF_RECORD_MISC_GUEST_KERNEL) ||
			 (sample->cpumode == PERF_RECORD_MISC_GUEST_USER))) {
		u32 pid;

		if (event->header.type == PERF_RECORD_MMAP
				|| event->header.type == PERF_RECORD_MMAP2)
			pid = event->mmap.pid;
		else
			pid = sample->pid;

		machine = machines__find(machines, pid);
		if (!machine)
			machine = machines__findnew(machines, DEFAULT_GUEST_KERNEL_ID);
		return machine;
	}

	return &machines->host;
}

	static int
perf_evlist__deliver_sample(struct perf_tool *tool,
		union  perf_event *event,
		struct perf_sample *sample,
		struct machine *machine)
{
	/* Standard sample delievery. */
	return tool->sample(tool, event, sample, machine);
}

static int machines__deliver_event(struct machines *machines,
		union perf_event *event,
		struct perf_sample *sample,
		struct perf_tool *tool, u64 file_offset)
{
	struct machine *machine;

	dump_event(event, file_offset, sample);

	machine = machines__find_for_cpumode(machines, event, sample);

	switch (event->header.type) {
		case PERF_RECORD_SAMPLE:
			dump_sample(event, sample);

			if (machine == NULL) {
				return 0;
			}
			return perf_evlist__deliver_sample(tool, event, sample, machine);
		case PERF_RECORD_MMAP:
			return tool->mmap(tool, event, sample, machine);
		case PERF_RECORD_MMAP2:
			return tool->mmap2(tool, event, sample, machine);
		case PERF_RECORD_COMM:
			return tool->comm(tool, event, sample, machine);
		case PERF_RECORD_FORK:
			return tool->fork(tool, event, sample, machine);
		case PERF_RECORD_EXIT:
			return tool->exit(tool, event, sample, machine);
		case PERF_RECORD_THROTTLE:
			return tool->throttle(tool, event, sample, machine);
		case PERF_RECORD_UNTHROTTLE:
			return tool->unthrottle(tool, event, sample, machine);
		default:
			return -1;
	}
}

int perf_session__deliver_event(struct perf_session *session,
		union perf_event *event,
		struct perf_sample *sample,
		struct perf_tool *tool,
		u64 file_offset)
{
	return machines__deliver_event(&session->machines,
			event, sample, tool, file_offset);
}

static s64 perf_session__process_user_event(struct perf_session *session,
		union perf_event *event,
		u64 file_offset)
{
	struct ordered_events *oe = &session->ordered_events;
	struct perf_tool *tool = session->tool;
	struct kdks_sample_data *kdks_sample_data_p;

	dump_event(event, file_offset, NULL);

	/* These events are processed right away */
	switch (event->header.type) {
	case PERF_RECORD_KDKS_SAMPLE:
		kdks_sample_data_p = (struct kdks_sample_data *)event;
		if (tool->kdks_sample)
			return tool->kdks_sample(tool, (struct kdks_sample_data *)event, session);
		// Size to skip
		return (s64)(kdks_sample_data_p->header.data_len - sizeof(struct perf_event_header));
	case PERF_RECORD_HEADER_BUILD_ID:
		return tool->build_id(tool, event, session);
	case PERF_RECORD_THREAD_MAP:
		return tool->thread_map(tool, event, session);
	case PERF_RECORD_FINISHED_ROUND:
		return tool->finished_round(tool, event, oe);
	default:
		break;
	}
	return -EINVAL;
}

int perf_session__deliver_synth_event(struct perf_session *session,
		union perf_event *event,
		struct perf_sample *sample)
{
	struct perf_tool *tool = session->tool;

	if (event->header.type >= PERF_RECORD_USER_TYPE_START)
		return perf_session__process_user_event(session, event, 0);

	return machines__deliver_event(&session->machines, event, sample, tool, 0);
}

int perf_session__peek_event(struct perf_session *session, 
		off_t file_offset,
		void *buf, size_t buf_sz,
		union perf_event **event_ptr,
		struct perf_sample *sample)
{
	union perf_event *event;
	size_t hdr_sz, rest;
	int fd;

	if (session->one_mmap) {
		event = file_offset - session->one_mmap_offset +
			session->one_mmap_addr;
		goto out_parse_sample;
	}

	if (perf_data_file__is_pipe(session->file))
		return -1;

	fd = perf_data_file__fd(session->file);
	hdr_sz = sizeof(struct perf_event_header);

	if (buf_sz < hdr_sz)
		return -1;

	if (lseek(fd, file_offset, SEEK_SET) == (off_t)-1 ||
			readn(fd, buf, hdr_sz) != (ssize_t)hdr_sz)
		return -1;

	event = (union perf_event *)buf;

	if (event->header.size < hdr_sz || event->header.size > buf_sz)
		return -1;

	rest = event->header.size - hdr_sz;

	if (readn(fd, buf, rest) != (ssize_t)rest)
		return -1;

out_parse_sample:

	if (sample && event->header.type < PERF_RECORD_USER_TYPE_START &&
			perf_evlist__parse_sample(event, sample))
		return -1;

	*event_ptr = event;

	return 0;
}

static s64 perf_session__process_event(struct perf_session *session,
		union perf_event *event, u64 file_offset)
{
	struct perf_tool *tool = session->tool;
	struct perf_sample sample;
	int ret;

	if(event->header.type >= PERF_RECORD_HEADER_MAX)
		return -EINVAL;

	/*special record type for kdks sample*/
	if (event->header.type >= PERF_RECORD_KDKS_SAMPLE){
#if 0
		u64 	s;
		long	us; 
		struct timespec spec;

		clock_gettime(CLOCK_REALTIME, &spec);

		s  = spec.tv_sec;
		us = round(spec.tv_nsec / 1.0e3);
		pr_info("process event time and offset : %llu.%06ld %llu\n",
				(u64)s,us,file_offset);
#endif
		return perf_session__process_user_event(session, event, file_offset);
	}

	/*
	 * For all kernel events we get the sample data
	 */
	ret = perf_evlist__parse_sample(event, &sample);
	if (ret)
		return ret;

	return perf_session__deliver_event(session, event, &sample, tool,
			file_offset);
}

void perf_event_header__bswap(struct perf_event_header *hdr)
{
	hdr->type = bswap_32(hdr->type);
	hdr->misc = bswap_16(hdr->misc);
	hdr->size = bswap_16(hdr->size);
}

struct thread *perf_session__findnew(struct perf_session *session, pid_t pid)
{
	return machine__findnew_thread(&session->machines.host, -1, pid);
}

int perf_session__register_idle_thread(struct perf_session *session)
{
	struct thread *thread;
	int err = 0;

	thread = machine__findnew_thread(&session->machines.host, 0, 0);
	if (!thread || thread__set_comm(thread, "swapper", 0)) {
		pr_err("problem inserting idle task.\n");
		err = -1;
	}

	/* machine__findnew_thread() got the thread, so put it */
	thread__put(thread);
	return err;
}

volatile int session_done;

static union perf_event *
fetch_mmaped_event(struct perf_session *session,
		u64 head, size_t mmap_size, char *buf)
{
	union perf_event *event;

	/*
	 * Ensure we have enough space remaining to read
	 * the size of the event in the headers.
	 */
	if (head + sizeof(event->header) > mmap_size)
		return NULL;

	event = (union perf_event *)(buf + head);

	return event;
}

/*
 * On 64bit we can mmap the data file in one go. No need for tiny mmap
 * slices. On 32bit we use 32MB.
 */
#if BITS_PER_LONG == 64
#define MMAP_SIZE ULLONG_MAX
#define NUM_MMAPS 1
#else
#define MMAP_SIZE (32 * 1024 * 1024ULL)
#define NUM_MMAPS 128
#endif

static int __perf_session__process_events(struct perf_session *session,
	u64 data_offset, u64 data_size, u64 file_size)
{
	struct perf_tool *tool = session->tool;
	int fd = perf_data_file__fd(session->file);
	u64 head, page_offset, file_offset, file_pos, size;
	int err=0, mmap_prot, mmap_flags, map_idx = 0;
	size_t	mmap_size;
	char *buf, *mmaps[NUM_MMAPS];
	union perf_event *event;
	s64 skip;

	perf_tool__fill_defaults(tool);

	page_offset = page_size * (data_offset / page_size);
	file_offset = page_offset;
	head = data_offset - page_offset;

	if (!data_size)
		goto out;

	if (data_offset + data_size < file_size)
		file_size = data_offset + data_size;

	mmap_size = MMAP_SIZE;
	if (mmap_size > file_size) {
		mmap_size = file_size;
		session->one_mmap = true;
	}

	memset(mmaps, 0, sizeof(mmaps));

	mmap_prot  = PROT_READ;
	mmap_flags = MAP_SHARED;

remap:
	buf = mmap(NULL, mmap_size, mmap_prot, mmap_flags, fd,
			file_offset);
	if (buf == MAP_FAILED) {
		pr_err("failed to mmap file\n");
		err = -errno;
		goto out_err;
	}
	mmaps[map_idx] = buf;
	map_idx = (map_idx + 1) & (ARRAY_SIZE(mmaps) - 1);
	file_pos = file_offset + head;
	if (session->one_mmap) {
		session->one_mmap_addr = buf;
		session->one_mmap_offset = file_offset;
	}

more:
	event = fetch_mmaped_event(session, head, mmap_size, buf);
	if (!event) {
		if (mmaps[map_idx]) {
			munmap(mmaps[map_idx], mmap_size);
			mmaps[map_idx] = NULL;
		}

		page_offset = page_size * (head / page_size);
		file_offset += page_offset;
		head -= page_offset;
		goto remap;
	}

	size = event->header.size;

	if (size < sizeof(struct perf_event_header) ||
		(skip = perf_session__process_event(session, event, file_pos)) < 0) {
		pr_err("%#" PRIx64 " [%#x]: failed to process type: %d\n",
			file_offset + head, event->header.size, event->header.type);
		err = -EINVAL;
		goto out_err;
	}

	if (skip)
		size += skip;

	head += size;
	file_pos += size;

	if (session_done())
		goto out;

	if (file_pos < file_size)
		goto more;

out:
	//	err = perf_session__flush_thread_stacks(session);
out_err:
	session->one_mmap = false;
	return err;
}

int perf_session__process_events(struct perf_session *session)
{
	u64 size = perf_data_file__size(session->file);
	int err = 0;

	if (perf_session__register_idle_thread(session) < 0)
		return -ENOMEM;

	if (!perf_data_file__is_pipe(session->file)) {
		err = __perf_session__process_events(session, session->header.data_offset,
			session->header.data_size, size);
	}
	return err;
}

size_t perf_session__fprintf_dsos(struct perf_session *session, FILE *fp)
{
	return machines__fprintf_dsos(&session->machines, fp);
}

int maps__set_kallsyms_ref_reloc_sym(struct map **maps, const char *symbol_name, u64 addr)
{
	char *bracket;
	enum map_type i;
	struct ref_reloc_sym *symbol;

	dks_debug("enter symbol name: %s\n", symbol_name);

	symbol = zalloc(sizeof(struct ref_reloc_sym));
	if (!symbol)
		return -ENOMEM;

	symbol->name = strdup(symbol_name);
	if (!symbol->name) {
		free(symbol);
		return -ENOMEM;
	}

	bracket = strchr(symbol->name, ']');
	if (bracket)
		*bracket = '\0';

	symbol->addr = addr;
	for (i = 0; i < MAP__NR_TYPES; ++i) {
		struct kmap *kmap = map__kmap(maps[i]);
		if (kmap)
			kmap->ref_reloc_sym = symbol;
	}

	return 0;
}

size_t perf_session__fprintf(struct perf_session *session, FILE *fp)
{
	/*
	 * FIXME: Here we have to actually print all the machines in this
	 * session, not just the host...
	 */
	return machine__fprintf(&session->machines.host, fp);
}

size_t perf_session__fprintf_dsos_buildid(struct perf_session *session, FILE *fp,
		bool (skip)(struct dso *dso, int parm), int parm)
{
	return machines__fprintf_dsos_buildid(&session->machines, fp, skip, parm);
}

