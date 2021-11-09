// SPDX-License-Identifier: MIT
#include <errno.h>
#include <json-c/json.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/*perf headers*/
#include "perf.h"

/*dks support headers*/
#include "dks_common.h"
#include "include/dks_util.h"

#include "util/debug.h"
#include "util/thread.h"
#include "util/util.h"
#include "util/symbol.h"

#define SYMBOL_NAME_MAX 1024
struct callchain_info {
	const char *bin_name;
	char func_name[SYMBOL_NAME_MAX];
	char src_file_name[SYMBOL_NAME_MAX];
	char inlined_in[SYMBOL_NAME_MAX];
	char inlined_at[SYMBOL_NAME_MAX];
	long long src_file_line;
	long long inlined_at_line;
	bool inlined;
};

static const char *kdks_lock_type_names[] = {
	[0]		= "EMPTY",
	[KDKS_SPINLOCK] = "Spin Lock",
	[KDKS_MUTEXLOCK] = "Mutex Lock",
	[KDKS_MUTEXCOND] = "Cond Var",
};

static struct map *map_from_thread_addr(struct thread *thread, u64 addr)
{
	struct map *map;

	if (!thread)
		return NULL;
	map = map_groups__find(thread->mg, MAP__FUNCTION, addr);
	return map ?: map_groups__find(thread->mg, MAP__VARIABLE, addr);
}

static char *create_string_from_callchain_info(struct callchain_info *callchain_info)
{
	if (!callchain_info)
		return NULL;

	size_t length = strlen(" [:] ") + strlen(callchain_info->func_name)
		+ strlen(callchain_info->src_file_name) + digit_count(callchain_info->src_file_line)
		+ strlen(callchain_info->bin_name) + 1;

	if (callchain_info->inlined) {
		length += (strlen(" inlined at [:] in ") + strlen(callchain_info->inlined_at)
			+ digit_count(callchain_info->inlined_at_line) + strlen(callchain_info->inlined_in));
		char *buffer = (char *)malloc(length);
		snprintf(buffer, length, "%s [%s:%lld] inlined at [%s:%llu] in %s %s",
			callchain_info->func_name, callchain_info->src_file_name,
			callchain_info->src_file_line, callchain_info->inlined_at,
			callchain_info->inlined_at_line, callchain_info->inlined_in,
			callchain_info->bin_name);
		return buffer;
	}
	char *buffer = (char *)malloc(length);
	snprintf(buffer, length, "%s [%s:%lld] %s",
		callchain_info->func_name, callchain_info->src_file_name,
		callchain_info->src_file_line, callchain_info->bin_name);
	return buffer;
}

/* read elf_hdr_bin_type */
int read_elf_hdr_bin_type(const char *filename, u16 *type){
	int fd;

	/* open file read only*/
	fd = open(filename, O_CLOEXEC | O_RDONLY);
	if (fd < 0)
		goto out;

	// https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
	if(pread(fd, type, sizeof(u16), 0x10) <= 0){
		close(fd);
		goto out;
	}

	return 0;
out:
	return errno;
}

/* check whether binary is pic */
static inline bool is_pic(u16 type)
{
	return type != ET_EXEC;
}

/* Alternative way to get the ELF type. */
//static bool is_pic(const char *filename)
//{
//	FILE *file = fopen(filename, "rb");
//	if (!file)
//		return false;
//
//	u8 format;
//	if (fseek(file, 0x04, SEEK_SET)) {
//		fclose(file);
//		return false;
//	}
//	fread(&format, sizeof(u8), 1, file);
//
//	if (fseek(file, 0x0, SEEK_SET)) {
//		fclose(file);
//		return false;
//	}
//
//	u16 type;
//	if (format == ELFCLASS32) {
//		Elf32_Ehdr elf_header;
//		fread(&elf_header, sizeof(Elf32_Ehdr), 1, file);
//		type = elf_header.e_type;
//	} else {
//		Elf64_Ehdr elf_header;
//		fread(&elf_header, sizeof(Elf64_Ehdr), 1, file);
//		type = elf_header.e_type;
//	}
//
//	fclose(file);
//	return type != ET_EXEC;
//}

static char *demangle(char *func_name)
{
	FILE *fd;
	char *command;
	char *line = NULL;
	ssize_t read_length;
	size_t size = 0, length = 0;

	length = strlen("c++filt \"\"") + strlen(func_name) + 1;
	command = (char *)malloc(length);
	if (!command)
		return NULL;
	snprintf(command, length, "c++filt \"%s\"", func_name);
	fd = popen(command, "r");
	free(command);
	if (!fd)
		return NULL;

	read_length = getline(&line, &size, fd);
	if (!size || !line) {
		pclose(fd);
		return NULL;
	}

	length = min((int)(read_length - 1), (SYMBOL_NAME_MAX - 1));
	memcpy(func_name, line, length);
	func_name[length] = '\0';
	free(line);
	pclose(fd);
	return func_name;
}

static struct callchain_info *callchain_info_new(struct thread *thread, u64 addr)
{
	int err;
	FILE *fd;
	struct map *map;
	struct callchain_info *callchain_info;
	const char *bin_name;
	char *command;
	char *line = NULL, *delimiter;
	int read_length;
	size_t size = 0, length = 0;
	u16 elf_type;

	assert(thread);

	/* KERNEL/USER separation mark */
	if (addr == PERF_CONTEXT_USER)
		return NULL;

	map = map_from_thread_addr(thread, addr);
	if (!map) {
		pr_err("failed to find map for thread %d/%d at %"PRIx64"\n",
			thread->pid_, thread->tid, addr);
		return NULL;
	}

	if (map__load(map, NULL) < 0) {
		pr_err("failed to load map for thread %d/%d at %"PRIx64"\n",
			thread->pid_, thread->tid, addr);
		return NULL;
	}

	bin_name = map && map->dso ? map->dso->long_name : "";
	if (!strcmp(bin_name, "")) {
		pr_err("Empty binary name\n");
		return NULL;
	}

	if (map->dso) {
		elf_type = map->dso->elf_type;
		dks_debug("elftype %s\n", is_pic(elf_type) ? "fixed" : "dyn or rel");
	} else {
		/* read elf_hdr */
		err = read_elf_hdr_bin_type(bin_name, &elf_type);
		if (err) {
			pr_err("callchain target file %s read error. %s\n",
				bin_name, strerror(errno));
			return NULL;
		}
	}

	// FIXME: Performance matters later, we can adopt addr2line code from binutil.
	// See translate_addresses() in binutils/addr2line.c
	length = strlen("eu-addr2line -f -e  0x") + strlen(bin_name) + 16 + 1; // 16 is the address length
	command = (char *)malloc(length);
	if (!command)
		return NULL;

	snprintf(command, length, "eu-addr2line -f -e %s 0x%016"PRIx64"",
		bin_name, is_pic(elf_type) ? addr - map->start : addr);

	// Due to overcommit memory restriction implemented in fork() of glibc,
	// popen() can fail because of huge memory usage of the parents.
	// Check the README.md
	fd = popen(command, "r");
	if (!fd) {
		pr_err("Fail to open fd for %s because of an error: %s\n", command, strerror(errno));
		free(command);
		return NULL;
	}
	free(command);

	read_length = getline(&line, &size, fd);
	if (!size || !line) {
		pclose(fd);
		return NULL;
	}

	callchain_info = (struct callchain_info *)malloc(sizeof(*callchain_info));
	if (!callchain_info) {
		pclose(fd);
		free(line);
		return NULL;
	}

	callchain_info->bin_name = bin_name;

	char *indicator = strstr(line, "inlined at ");
	callchain_info->inlined = !!indicator;
	if (read_length > 0 && callchain_info->inlined) {
		length = min((int)(indicator - line - 1), (SYMBOL_NAME_MAX - 1));
		memcpy(callchain_info->func_name, line, length);
		callchain_info->func_name[length] = '\0';
		demangle(callchain_info->func_name);

		indicator += strlen("inlined at "); // "inlined at "
		delimiter = strchr(indicator, ':');
		length = min((int)(delimiter - indicator), (SYMBOL_NAME_MAX - 1));
		memcpy(callchain_info->inlined_at, indicator, length);
		callchain_info->inlined_at[length] = '\0';
		callchain_info->inlined_at_line = atoll(delimiter + 1);

		indicator = strstr(indicator, " in ") + strlen(" in ");
		length = min((int)(read_length - (indicator - line) - 1), (SYMBOL_NAME_MAX - 1));
		memcpy(callchain_info->inlined_in, indicator, length);
		callchain_info->inlined_in[length] = '\0';
		demangle(callchain_info->inlined_in);
	} else if (read_length > 0) {
		length = min((int)(read_length - 1), (SYMBOL_NAME_MAX - 1));
		memcpy(callchain_info->func_name, line, length);
		callchain_info->func_name[length] = '\0';
		demangle(callchain_info->func_name);
	} else {
		const char unknown[] = "unknown";
		length = min((int)sizeof(unknown), (SYMBOL_NAME_MAX - 1));
		memcpy(callchain_info->func_name, unknown, length);
		callchain_info->func_name[length] = '\0';
	}

	// Output format example : source.c:123
	read_length = getline(&line, &size, fd);
	delimiter = strchr(line, ':');
	if (delimiter) {
		length = min((int)(delimiter - line), (SYMBOL_NAME_MAX - 1));
		memcpy(callchain_info->src_file_name, line, length);
		callchain_info->src_file_name[length] = '\0';
		callchain_info->src_file_line = atoll(delimiter + 1);
	} else {
		const char unknown[] = "unknown";
		length = min((int)sizeof(unknown), (SYMBOL_NAME_MAX - 1));
		memcpy(callchain_info->src_file_name, unknown, length);
		callchain_info->src_file_name[length] = '\0';
		callchain_info->src_file_line = -1;
	}

	pclose(fd);
	free(line);
	return callchain_info;
}

/*
   print callchain,
   <- force: force print out
 */
void pr_callchain(callchain_t *ips, struct thread *thread, bool force)
{
	u64 i;
	struct callchain_info *callchain_info = NULL;
	char *symbol_info_string = NULL;

	dks_debug("... FP chain: nr:%"PRIu64"\n", ips->nr);
	for (i = 0; i < ips->nr && i < PERF_MAX_STACK_DEPTH; i++) {
		u64 addr = ips->ip[i];

		if (thread) {
			callchain_info = callchain_info_new(thread, addr);
			symbol_info_string = create_string_from_callchain_info(callchain_info);
		}

		if (force)
			pr_info("..... %2lu: %016"PRIx64" %s\n", i, addr, symbol_info_string ?: "");
		else
			dks_debug("..... %2lu: %016"PRIx64" %s\n", i, addr, symbol_info_string ?: "");

		if (symbol_info_string)
			free(symbol_info_string);
		if (callchain_info)
			free(callchain_info);
	}
}

json_object *callchain_to_json_object(callchain_t *ips, struct thread *thread)
{
	json_object *callchain_array;
	u64 i;

	callchain_array = json_object_new_array();
	assert(callchain_array);

	for (i = 0; i < ips->nr && i < PERF_MAX_STACK_DEPTH; i++) {
		u64 addr = ips->ip[i];

		// Filter out meaningless nodes here.
		if (addr == PERF_CONTEXT_USER)
			continue;

		json_object *callchain_object = json_object_new_object();
		struct callchain_info *callchain_info = callchain_info_new(thread, addr);

		json_object_object_add(callchain_object, "Address", json_object_new_int64(addr));
		if (!callchain_info) {
			json_object_object_add(callchain_object, "BinaryName", NULL);
			json_object_object_add(callchain_object, "FunctionName", NULL);
			json_object_object_add(callchain_object, "SourceFileName", NULL);
			json_object_object_add(callchain_object, "SourceFileLine", NULL);
		} else {
			json_object_object_add(callchain_object, "BinaryName",
				json_object_new_string(callchain_info->bin_name));
			json_object_object_add(callchain_object, "FunctionName",
				json_object_new_string(callchain_info->func_name));
			json_object_object_add(callchain_object, "SourceFileName",
				json_object_new_string(callchain_info->src_file_name));
			json_object_object_add(callchain_object, "SourceFileLine",
				json_object_new_int64(callchain_info->src_file_line));

			if (callchain_info->inlined) {
				json_object_object_add(callchain_object, "InlinedIn",
					json_object_new_string(callchain_info->inlined_in));
				json_object_object_add(callchain_object, "InlinedAt",
					json_object_new_string(callchain_info->inlined_at));
				json_object_object_add(callchain_object, "InlinedAtLine",
					json_object_new_int64(callchain_info->inlined_at_line));
			}
		}

		json_object_array_add(callchain_array, callchain_object);

		free(callchain_info);
	}

	return callchain_array;
}

/* print kdks sample record */
void pr_kdks_record(int num, kdks_record_t *record)
{
	dks_debug("record %d: [%u/%u] ips_id:%"PRIx64", ips->nr:%"PRIu64", waiting_time:%"PRIu64"\n",
		num, record->pid, record->tid, record->ips_id, record->ips.nr, record->waiting_time);

	if (record->ips.nr)
		pr_callchain(&record->ips, NULL, false);
}

/* print kdks sample data */
void pr_kdks_sample_data(int cpu, struct kdks_sample_data *data)
{
	int i;
	size_t pos = 0;
	kdks_record_t *record;

	dks_debug("CPU-%d type %s waiters %u, size %u\n", cpu,
		kdks_lock_type_names[data->header.lock_type],
		data->header.n_waiters, data->header.data_len);

	pos += sizeof(kdks_sample_header_t);
	record = (kdks_record_t *)((char *)data + pos);
	pr_kdks_record(0, record);
	pos += sizeof__kdks_record(record->ips.nr);

	/*print all waiter records*/
	for (i = 0; i < data->header.n_waiters; ++i) {
		/*update pos*/
		record = (kdks_record_t *)((char *)data + pos);
		pr_kdks_record(i + 1, record);
		pos += sizeof__kdks_record(record->ips.nr);
	}
}

bool exists(const char *path) {
	struct stat s;
	return stat(path, &s) == 0;
}

char *json_export_path_alloc()
{
	ssize_t length;
	char buffer[PATH_MAX];
	char filename[] = "/vis/dks_profile.json";
	char *c, *filep, *dirp;

	length = readlink("/proc/self/exe", buffer, PATH_MAX - 1);
	if (length == -1)
		return NULL;
	buffer[length] = '\0';

	if (!(c = strrchr(buffer, '/')))
		return NULL;
	*c = '\0';
	if (!(c = strrchr(buffer, '/')))
		return NULL;
	*c = '\0';

	length = strlen(buffer) + strlen(filename) + 1;
	filep = (char *)malloc(length); // '\0' + '/'
	if (!filep)
		return NULL;
	snprintf(filep, length, "%s%s", buffer, filename);

	dirp = dirname(filep);
	if (!exists(dirp) && mkdir(dirp, 0755) == -1) {
		pr_err("failed to create a dir: %s\n", dirp);
		free(filep);
		return NULL;
	}

	/* restore filep from dirname */
	snprintf(filep, length, "%s%s", buffer, filename);
	return filep;
}

/*
 * convert locktype to name
 */
const struct dks_locktype_str locktype_id_str[] = {
	LOCKTYPE_NAME_MAPPING(none, KDKS_LOCK_NONE),
	LOCKTYPE_NAME_MAPPING(spinlock, KDKS_SPINLOCK),
	LOCKTYPE_NAME_MAPPING(mutex_lock, KDKS_MUTEXLOCK),
	LOCKTYPE_NAME_MAPPING(mutex_cond, KDKS_MUTEXCOND),
	LOCKTYPE_NAME_MAPPING_END
};

const char *locktype2name(enum kdks_lock_type id){
	return locktype_id_str[id].name;
}

/* timer spec diff */
struct timespec timespec_diff(struct timespec start, struct timespec end) {
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

unsigned digit_count(s64 value) {
	return value ? floor(log10(abs(value))) + 1 : 1;
}

/* find out valid vmlinux_path */
const char *get_vmlinux_path(void) {
	int i;
	const char *vmlinux_name = symbol_conf.vmlinux_name;

	/* provide vmlinux_path exists */
	if (vmlinux_name && access(vmlinux_name, F_OK) != -1)
		return vmlinux_name;

	/* return first possible vmlinux_name */
	for (i = 0; i < vmlinux_path__nr_entries; ++i) {
		vmlinux_name = vmlinux_path[i];
		if (access(vmlinux_name, F_OK) != -1)
			return vmlinux_name;
	}

	/* can't found valid vmlinux path*/
	pr_err("can't find valid vmlinux path\n");
	return NULL;
}
