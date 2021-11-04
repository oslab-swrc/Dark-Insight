#include "util.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <sys/utsname.h>

#include "header.h"
#include "../perf.h"
#include "session.h"
#include "symbol.h"
#include "debug.h"
#include "vdso.h"
#include "strbuf.h"
#include "data.h"
#include <api/fs/fs.h>
#include "asm/bug.h"

/*
 * magic2 = "PERFILE2"
 * must be a numerical value to let the endianness
 * determine the memory layout. That way we are able
 * to detect endianness when reading the perf.data file
 * back.
 *
 * we check for legacy (PERFFILE) format.
 */
static const char *__perf_magic1 = "PERFFILE";
static const u64 __perf_magic2    = 0x32454c4946524550ULL;
static const u64 __perf_magic2_sw = 0x50455246494c4532ULL;

#define PERF_MAGIC	__perf_magic2

static int do_write(int fd, const void *buf, size_t size)
{
	while (size) {
		int ret = write(fd, buf, size);

		if (ret < 0)
			return -errno;

		size -= ret;
		buf += ret;
	}

	return 0;
}

int write_padded(int fd, const void *bf, size_t count, size_t count_aligned)
{
	static const char zero_buf[NAME_ALIGN];
	int err = do_write(fd, bf, count);

	if (!err)
		err = do_write(fd, zero_buf, count_aligned - count);

	return err;
}

#define string_size(str)						\
	(PERF_ALIGN((strlen(str) + 1), NAME_ALIGN) + sizeof(u32))

bool is_perf_magic(u64 magic)
{
	if (!memcmp(&magic, __perf_magic1, sizeof(magic))
		|| magic == __perf_magic2
		|| magic == __perf_magic2_sw)
		return true;

	return false;
}

static int check_magic_endian(u64 magic, uint64_t hdr_sz,
			      bool is_pipe, struct perf_header *ph)
{
	/*
	 * the new magic number serves two purposes:
	 * - unique number to identify actual perf.data files
	 * - encode endianness of file
	 */
	ph->version = PERF_HEADER_VERSION_2;

	/* check magic number with one endianness */
	if (magic == __perf_magic2)
		return 0;

	return -1;
}

int perf_file_header__read(struct perf_file_header *header,
			   struct perf_header *ph, int fd)
{
	ssize_t ret;

	lseek(fd, 0, SEEK_SET);

	ret = readn(fd, header, sizeof(*header));
	if (ret <= 0)
		return -1;

	if (check_magic_endian(header->magic,
			       0, false, ph) < 0) {
		pr_debug("magic/endian check failed\n");
		return -1;
	}

	if (header->size != sizeof(*header)) {
		return -1;
	}

	ph->data_offset  = header->data.offset;
	ph->data_size	 = header->data.size;
	return 0;
}

int perf_session__read_header(struct perf_session *session)
{
	struct perf_data_file *file = session->file;
	struct perf_header *header = &session->header;
	struct perf_file_header	f_header;
	int fd = perf_data_file__fd(file);

	if (perf_file_header__read(&f_header, header, fd) < 0)
		return -EINVAL;

	/*
	 * Sanity check that perf.data was written cleanly; data size is
	 * initialized to 0 and updated only if the on_exit function is run.
	 * If data size is still 0 then the file contains only partial
	 * information.  Just warn user and process it as much as it can.
	 */
	if (f_header.data.size == 0) {
		pr_warning("WARNING: The %s file's data size field is 0 which is unexpected.\n"
			   "Was the 'dks profile' command properly terminated?\n",
			   file->path);
	}

	symbol_conf.nr_events = DKS_NR_ATTRS;

	return 0;
}

/*Simplified write header,
  because we fixed event type,
  our job is to write updated data offset and size*/
int perf_session__write_header(struct perf_session *session, int fd, bool at_exit)
{
	int err;
	struct perf_file_header f_header;
	struct perf_header *header = &session->header;

	lseek(fd, sizeof(f_header), SEEK_SET);

	if (!header->data_offset)
		header->data_offset = lseek(fd, 0, SEEK_CUR);

	f_header = (struct perf_file_header){
		.magic = PERF_MAGIC,
		.size = sizeof(f_header),
		.data = {
			.offset = header->data_offset,
			.size   = header->data_size,
		},
		/* event_types is ignored, store zeros */
	};

	/*Update Header */
	lseek(fd, 0, SEEK_SET);
	err = do_write(fd, &f_header, sizeof(f_header));
	if (err < 0) {
		pr_debug("failed to write perf header\n");
		return err;
	}

	/*Set data offset */
	lseek(fd, header->data_offset + header->data_size, SEEK_SET);
	return 0;
}

static int __event_process_build_id(struct build_id_event *bev,
		char *filename,
		struct perf_session *session)
{
	int err = -1;
	struct machine *machine;
	u16 cpumode;
	struct dso *dso;
	enum dso_kernel_type dso_type;

	machine = perf_session__findnew_machine(session, bev->pid);
	if (!machine)
		goto out;

	cpumode = bev->header.misc & PERF_RECORD_MISC_CPUMODE_MASK;

	switch (cpumode) {
		case PERF_RECORD_MISC_KERNEL:
			dso_type = DSO_TYPE_KERNEL;
			break;
		case PERF_RECORD_MISC_GUEST_KERNEL:
			dso_type = DSO_TYPE_GUEST_KERNEL;
			break;
		case PERF_RECORD_MISC_USER:
		case PERF_RECORD_MISC_GUEST_USER:
			dso_type = DSO_TYPE_USER;
			break;
		default:
			goto out;
	}

	dso = machine__findnew_dso(machine, filename);
	if (dso != NULL) {
		char sbuild_id[BUILD_ID_SIZE * 2 + 1];

		dso__set_build_id(dso, &bev->build_id);

		if (!is_kernel_module(filename, cpumode))
			dso->kernel = dso_type;

		build_id__sprintf(dso->build_id, sizeof(dso->build_id),
				sbuild_id);
		pr_debug("build id event received for %s: %s\n",
				dso->long_name, sbuild_id);
		dso__put(dso);
	}

	err = 0;
out:
	return err;
}



int perf_event__process_build_id(struct perf_tool *tool __maybe_unused,
		union perf_event *event,
		struct perf_session *session)
{
	__event_process_build_id(&event->build_id,
			event->build_id.filename,
			session);
	return 0;
}

