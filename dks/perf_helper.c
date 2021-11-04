#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <assert.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>
#include <linux/bitops.h>
#include <linux/log2.h>
/*include from external-lib ringbuffer arch.h*/
#include <arch.h>	

#include "dks.h"

/*perf header*/
#include "perf.h"
#include "util/debug.h"
#include "util/util.h"
#include "util/session.h"
#include "util/machine.h"

static int *perf_fds = NULL;		/* perf file desc.*/

static int perf__init_event_files(int nr)
{
	if (nr < 0)
		return -EINVAL;

	perf_fds = (int *)malloc(nr * sizeof(int));
	if (!perf_fds)
		return -ENOMEM;

	while (nr--)
		perf_fds[nr] = -1;

	return 0;
}

static void perf__free_event_files(int nr)
{
	if (nr < 0)
		return;

	if (!perf_fds)
		return;

	while (nr--) {
		if (perf_fds[nr] == -1)
			continue;
		close(perf_fds[nr]);
	}

	free(perf_fds);
	perf_fds = NULL;
}

static void perf__event_disable(int nr)
{
	if (!perf_fds)
		return;

	while (nr--)
		ioctl(perf_fds[nr], PERF_EVENT_IOC_DISABLE, 0);
}

/*set map header entries*/
static int perf__init_mmap_headers(struct dks_ctrl *ctrl)
{
	int nr = ctrl->nr_cpus;
	if (nr < 0)
		return -EINVAL;

	/*set mmap_size*/
	ctrl->mmap_size = dks_ctrl__mmap_size(ctrl->opts.mmap_pages);
	if(!ctrl->mmap_size)
		return -EINVAL;

	/* init mmap for sample output */
	ctrl->mmap = (struct perf_mmap **)zalloc(sizeof(struct perf_mmap *) * nr);
	if (!ctrl->mmap)
		return -ENOMEM;

	dks_debug("Map address\n");
	while (nr--) {
		ctrl->mmap[nr] = (struct perf_mmap *)zalloc(sizeof(struct perf_mmap));
		if(ctrl->mmap[nr]->base)
			dks_debug("cpu %d, addr: 0x%p\n", nr, ctrl->mmap[nr]->base);
	}

	return 0;
}

/*free map header entries*/
static void perf__free_mmap_headers(struct dks_ctrl *ctrl)
{
	if (!ctrl->mmap)
		return;

	int cpus = ctrl->nr_cpus;
	while (cpus--) {
		if (!ctrl->mmap[cpus])
			continue;
		free(ctrl->mmap[cpus]);
	}

	free(ctrl->mmap);
	ctrl->mmap = NULL;
}

/*perf event mmap to read perf event output*/
static int perf__event_mmap(struct perf_mmap *perf_map, size_t mmap_size, int fd)
{
	void *base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		pr_err("mmap failed\n");
		return -1;
	}

	/*assign mmap headers*/
	perf_map->base = base;
	perf_map->prev = 0;
	perf_map->mask = mmap_size - page_size - 1 ;
	return 0;
}

/*perf event unmap*/
static void perf__event_munmap(struct dks_ctrl *ctrl)
{
	int i;
	if (!ctrl->mmap)
		return;

	for (i = 0; i < ctrl->nr_cpus; ++i) {
		void *base = ctrl->mmap[i]->base;
		if (!base)
			continue;

		munmap(base, ctrl->mmap_size);
		ctrl->mmap[i]->base = NULL;
	}
}

/*clear perf event attr, set sample type and event id*/
int perf__init_event_attr(struct perf_event_attr *attr)
{
	/*set perf attributes*/
	memset(attr, 0, sizeof(struct perf_event_attr));
	attr->type = PERF_TYPE_RAW;
	attr->config = 0x0c4; /*retired branches inst*/
	attr->size = sizeof(struct perf_event_attr);
	// We use a default sample type. Check out util/event.h for the detail.
	attr->sample_type = DKS_SAMPLE_MASK;

	attr->sample_period = 1000; /*sample every 1000th event*/
	attr->disabled = 1;
#if 0
	// Using an user callchain, we can distinguish each idle_entry.
	attr->exclude_callchain_kernel = 1;
#endif
	// FIXME: Callchain mode (lbr) is not working for goldbug.
//	attr->branch_sample_type = PERF_SAMPLE_BRANCH_USER
//		| PERF_SAMPLE_BRANCH_CALL_STACK
//		| PERF_SAMPLE_BRANCH_NO_CYCLES
//		| PERF_SAMPLE_BRANCH_NO_FLAGS;

	// Register options
	attr->sample_regs_user = PERF_REGS_MASK;

	// Enable PEBS
	attr->precise_ip = 3;
	while (attr->precise_ip--) {
		int fd = sys_perf_event_open(attr, 0, -1, -1, 0);
		if (fd == -1)
			continue;
		close(fd);
		break;
	}

	// precise_ip should be equal or greater than 1 in order to enable PEBS.
	if (attr->precise_ip < 1) {
		pr_err("fail to set perf precise_ip\n");
		return -EFAULT;
	}

	attr->task = 1;
	attr->comm = 1;
	/*add mmap event for shared library mapping*/
	attr->mmap = 1;
	attr->mmap2 = 1;
	attr->inherit = 1;

	return 0;
}

/*clear perf event attr, set sample type and event id*/
int perf__init_probe_event_attr(struct perf_event_attr *attr) {
	dks_debug("enter\n");

	/*set perf attributes*/
	memset(attr, 0, sizeof(struct perf_event_attr));

	/*init */
	attr->type = PERF_TYPE_TRACEPOINT;
	/*tracepoint number,
	  This is user installed kprobe event*/
	attr->config = 1305;
	attr->size = sizeof(struct perf_event_attr);

	/*set default sample type.
	  see util/event.h for detail */ 
	attr->sample_type = DKS_SAMPLE_MASK ;

	/*set sample period*/
	attr->sample_period = 1; /*tracepoint*/
	attr->disabled = 1;

	/*we can distinguish each idle_entry 
	  using only user callchain */
	attr->exclude_callchain_kernel = 1;

	/*set regs options*/
	attr->sample_regs_user = PERF_REGS_MASK;

	/*set precise_ip to enable PEBS*/
	attr->precise_ip = 3;

	while (attr->precise_ip != 0) {
		int fd = sys_perf_event_open(attr, 0, -1, -1, 0);
		if (fd != -1) {
			close(fd);
			break;
		}
		--attr->precise_ip;
	}

	/*to enable PEBS, this should be larger than 1*/
	if(attr->precise_ip < 1){
		pr_err("fail to set perf precise_ip\n");
		return -EFAULT;
	}

	dks_debug("leave \n");
	return 0;
}

int perf__event_open_allcpus(struct dks_ctrl *ctrl)
{
	pid_t pid;
	int nr_cpus;
	int err, i;
	struct perf_event_attr *attr;

	dks_debug("enter \n");

	if (!ctrl->init)
		return -EINVAL;

	attr = &ctrl->attr;
	pid = ctrl->opts.target.pid_d;
	nr_cpus = ctrl->nr_cpus;

	err = perf__init_event_files(nr_cpus);
	if (err < 0) {
		pr_err("perf init event files fail\n");
		return err;
	}

	/*init mmap headers*/
	err = perf__init_mmap_headers(ctrl);
	if (err < 0) {
		pr_err("perf init mmap fail\n");
		goto exit_free_perf_files;
	}

	/*init poll events*/
	err = perf__init_pollfds(nr_cpus);
	if (err) {
		pr_err("perf init pollfds fail\n");
		goto exit_free_map_headers;
	}

	/*open perf event, set mmap addr and poll event*/
	for (i = 0; i < nr_cpus; ++i) {
		int fd = sys_perf_event_open(attr, pid, i, -1, 0);
		if (fd == -1) {
			pr_err("CPU-%i, Error opening perf", i);
			pr_err("        attr->type:%u\n", attr->type);
			pr_err("        attr->config:%llx\n", attr->config);
			err = -1;
			goto exit_perf_open;
		}
		perf_fds[i] = fd;

		if (perf__event_mmap(ctrl->mmap[i], ctrl->mmap_size, fd)) {
			pr_err("CPU-%i, Error allocate perf event mmap",i);
			err = -1;
			goto exit_perf_open;
		}

		perf__assign_pollfd(i, fd);
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	}

	dks_debug("leave \n");
	return 0;

exit_perf_open:
	perf__event_munmap(ctrl);
	perf__free_pollfds();
exit_free_map_headers:
	perf__free_mmap_headers(ctrl);
exit_free_perf_files:
	perf__free_event_files(nr_cpus);

	dks_debug("leave with error\n");
	return err;
}

/*cleanup*/
void perf__event_exit(struct dks_ctrl *ctrl)
{
	int nr_cpus;

	assert(ctrl->init);
	nr_cpus = ctrl->nr_cpus;

	perf__event_disable(nr_cpus);
	perf__event_munmap(ctrl);
	perf__free_pollfds();
	perf__free_mmap_headers(ctrl);
	perf__free_event_files(nr_cpus);
}

/*write drained event data to file*/
#define DO_WRITE_EVENT (1)

int perf__event_drain(struct dks_ctrl *ctrl, int idx) {
	int err = 0;
	struct perf_mmap *md = ctrl->mmap[idx];
	u64 head = perf_mmap__read_head(md);
	u64 old = md->prev;
	unsigned char *data = md->base + page_size;
	union perf_event *event;
#if DO_WRITE_EVENT
	void *buf;
	unsigned long size;
#endif
	if (head == old )
		return 0;
#if DO_WRITE_EVENT
	size = head - old;

	event = (union perf_event *)&data[old & md->mask];
	pr_info("Event header type:%s\n", perf_event__name(event->header.type));

	/* over case*/
	if ((old & md->mask) + size != (head & md->mask)){
		buf = &data[old & md->mask];
		size = md->mask + 1 - (old & md->mask);
		old += size;

		if(dks_ctrl__event_write(ctrl, buf, size) < 0) {
			err = -1;
			goto out;
		}
	}

	/*write remains*/
	buf = &data[old & md->mask];
	size = head - old;
	old += size;

	if (dks_ctrl__event_write(ctrl, buf, size) < 0) {
		err = -1;
		goto out;
	}
#endif
	md->prev = old;
	perf__mmap_consume(ctrl, idx);

#if DO_WRITE_EVENT
out:
#endif
	return err;
}

void perf__mmap_consume(struct dks_ctrl *ctrl, int idx)
{
	struct perf_mmap *md = ctrl->mmap[idx];
	u64 old = md->prev;
	perf_mmap__write_tail(md, old);
}

/*perf event read mmaped perf event pages*/
int perf__event_read(struct dks_ctrl *ctrl, int idx)
{
	union perf_event *event = NULL;
	struct perf_mmap *md = ctrl->mmap[idx];
	unsigned char *data = md->base + page_size;
	u64 head = perf_mmap__read_head(md);
	u64 old = md->prev;
	int err = 0;
	size_t size;

	if (head == old)
		return 0;

	ctrl->samples++;

	/*consume events*/
	while (head != old) {
		event = (union perf_event *)&data[old & md->mask];
		size = event->header.size;

		/*
		 * Event straddles the mmap boundary -- header should always
		 * be inside due to u64 alignment of output.
		 */
		if ((old & md->mask) + size != ((old + size) & md->mask)) {
			unsigned int offset = old;
			unsigned int len = min(sizeof(*event), size), cpy;
			void *dst = md->event_copy;

			do {
				cpy = min(md->mask + 1 - (offset & md->mask), len);
				memcpy(dst, &data[offset & md->mask], cpy);
				offset += cpy;
				dst += cpy;
				len -= cpy;
			} while (len);

			event = (union perf_event *)md->event_copy;
		}
		old += size;

		//dks_debug("Event header type:%s\n", perf_event__name(event->header.type));
		/*process mmap events because we have to push it down to kernel
		  for relocating address mapping of the DSOs*/
		if(event->header.type == PERF_RECORD_MMAP2) {
			/*process mmap event first - we might not need this*/
			err = perf_session__deliver_event(ctrl->session, event, NULL, &ctrl->tool, 0);
			if (err)
				return err;

			/*write mmap event to file.
			  We need this data to map instruction pointer with
			  corresponding user address*/
			if (dks_ctrl__event_write(ctrl, (void *)event, size) < 0)
				return -1;
		}
	}

	md->prev = old;
	perf__mmap_consume(ctrl, idx);
	return err;
}
