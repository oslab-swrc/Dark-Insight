#ifndef __PERF_HEADER_H
#define __PERF_HEADER_H

#include <linux/perf_event.h>
#include <sys/types.h>
#include <stdbool.h>
#include <linux/bitmap.h>
#include <linux/types.h>
#include "event.h"

enum perf_header_version {
	PERF_HEADER_VERSION_1,
	PERF_HEADER_VERSION_2,
};

struct perf_file_section {
	u64 offset;
	u64 size;
};

struct perf_file_header {
	u64				magic;
	u64				size;
	struct perf_file_section	data;
};

/*TODO: we might not need perf_header */
struct perf_header;

int perf_file_header__read(struct perf_file_header *header,
			   struct perf_header *ph, int fd);

struct perf_header {
	enum perf_header_version	version;
	u64				data_offset;
	u64				data_size;
};

struct perf_session;

int perf_session__read_header(struct perf_session *session);
int perf_session__write_header(struct perf_session *session,
			       int fd, bool at_exit);
int perf_header__process_sections(struct perf_header *header, int fd,
				  void *data,
				  int (*process)(struct perf_file_section *section,
				  struct perf_header *ph,
				  int fd, void *data));
int perf_event__process_build_id(struct perf_tool *tool,
		union perf_event *event,
		struct perf_session *session);

bool is_perf_magic(u64 magic);

#define NAME_ALIGN 64

int write_padded(int fd, const void *bf, size_t count, size_t count_aligned);

/*
 * arch specific callback
 */
int get_cpuid(char *buffer, size_t sz);

#endif /* __PERF_HEADER_H */
