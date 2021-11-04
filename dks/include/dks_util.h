#ifndef __DKS_UTIL_H__
#define __DKS_UTIL_H__

#include "dks_common.h"
#include <json-c/json.h>

#define LOCKTYPE_NAME_MAPPING(n, i) { .name = #n, .id = (i) }
#define LOCKTYPE_NAME_MAPPING_END {.name = NULL }

struct dks_locktype_str{
	const char *name;
	u8 id;
};

struct thread;

void pr_callchain(callchain_t *ips, struct thread *thread, bool force);
void pr_kdks_record(int num, kdks_record_t *record);
void pr_kdks_sample_data(int cpu, struct kdks_sample_data *data);

char *json_export_path_alloc(void);
json_object *callchain_to_json_object(callchain_t *ips, struct thread *thread);

extern const struct dks_locktype_str locktype_id_str[];
const char *locktype2name(enum kdks_lock_type id);

struct timespec timespec_diff(struct timespec start, struct timespec end);
unsigned digit_count(s64 value);
const char *get_vmlinux_path(void);
#endif /* __DKS_UTIL_H__ */
