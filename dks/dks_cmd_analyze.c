// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

/*dks header*/
#include "dks.h"
#include "dks_lock_stat.h"

/*perf headers*/
#include "perf.h"

/*perf util headers*/
#include "asm/bug.h"
#include "util/util.h"
#include "util/debug.h"
#include "util/machine.h"
#include "util/session.h"
#include "util/symbol.h"
#include "util/target.h"
#include "util/build-id.h"

#include <linux/types.h>
#include <subcmd/parse-options.h>

#include <sqlite3.h>	/*for reporting results*/

//#define PROF_DKS_ANALYZE
#define DISPLAY_FULL_CAUSALITY 0
#if !DISPLAY_FULL_CAUSALITY
#define CAUSALITY_MAX_COUNT 3
#endif

static const char *analyze_usage[] = {
	"dks --cmd analyze [<options>]",
	NULL
};

// https://en.wikipedia.org/wiki/Web_colors
static const char *html_color_names[] = {
	"gray", "blue", "red", "green", "maroon",
	"black", "yellow", "olive", "lime", "purple",
	"aqua", "teal", "navy", "fuchsia", "silver"
};

enum html_color {
	HTML_COLOR_GRAY = 0, HTML_COLOR_BLUE, HTML_COLOR_RED, HTML_COLOR_GREEN, HTML_COLOR_MAROON,
	HTML_COLOR_BLACK, HTML_COLOR_YELLOW, HTML_COLOR_OLIVE, HTML_COLOR_LIME, HTML_COLOR_PURPLE,
	HTML_COLOR_AQUA, HTML_COLOR_TEAL, HTML_COLOR_NAVY, HTML_COLOR_FUCHSIA, HTML_COLOR_SILVER,
	HTML_COLOR_MAX,
};

struct analyze {
	struct perf_tool 	tool;
	struct perf_session 	*session;
	bool 			max_stack;
	u64			nr_entries;
};

struct dks_json_object {
	struct dks_hash_entry entry;
	json_object *jobject;
	u32 count;
	enum html_color color;
};

// TODO : prepare query for reporting
// SELECT SQL - remove items of which total wait_time is less than 100ms
// const char *select_all_sql = "SELECT * from lock_stat;";
const char *select_sql =
"SELECT id, type, pid, tid, addr, ips_id, \
		n_events, n_waiters, wait_time/1000, \
		(wait_time/n_waiters)/1000 \
		FROM lock_stat \
		WHERE wait_time\
		ORDER BY wait_time desc limit ?;";

const char *group_sql =
"SELECT type, pid, tid, ips_id, sum(n_events), sum(n_waiters), \
		sum(wait_time), (sum(wait_time)/sum(n_waiters))/1000 \
		FROM lock_stat \
		GROUP BY pid, ips_id \
		ORDER BY sum(wait_time) desc limit ?;";

const char *to_html_color_name(enum html_color color)
{
	return html_color_names[color];
}

// http://www.cse.yorku.ca/~oz/hash.html
static unsigned long hash(char *string)
{
	int c;
	unsigned long hash = 5381;

	while ((c = *string++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	return hash;
}

static void sig_handler(int sig __maybe_unused)
{
	session_done = 1;
}

//static char *utf8_string_alloc(const char *cstring)
//{
//	char *utf8_char;
//	char *utf8_string = calloc(strlen(cstring) * 2, sizeof(char));
//	if (!utf8_string)
//		return NULL;
//
//	utf8_char = utf8_string;
//	while (*cstring) {
//		if (*cstring < 128)
//			*utf8_char++ = *cstring++;
//		else {
//			*utf8_char++ = 0xc2 + (*cstring > 0xbf);
//			*utf8_char++ = (*cstring++ & 0x3f) + 0x80;
//		}
//	}
//	return utf8_string;
//}

/*********************************************************
   			hash lookups
  TODO - change lookup more compact(using function pointer)
*********************************************************/
/*get ips hash entry,
  used data for hash key :
	- merged value of callchain entries
 */
static struct dks_ips_entry *get_ips_entry(struct dks_lock_stat *stats,
	callchain_t *ips, u64 ips_id)
{
	struct dks_ht *ips_ht = stats->ips_ht;
	struct dks_ips_entry *ips_entry = NULL;
	u64 hash_val;

	/* Currently this would not happen */
	if (!ips_id) {
		if (!ips->nr) {
			dks_debug("ips callchain is empty\n");
			return NULL;
		}

		/*gen ips entry hash_key*/
		hash_val = jhash2((u32 *)&ips->ip, ips->nr * sizeof(u64) / sizeof(u32), 0);
	} else {
		/* use kernel side callchain address as a unique callchain id */
		hash_val = ips_id;
		dks_debug("current ips uniqueue id 0x%"PRIx64"\n", hash_val);
	}

	/*check it current hashtable*/
	ips_entry = (struct dks_ips_entry *)dks_ht__lookup(ips_ht, hash_val);
	if (ips_entry) {
		dks_debug("found ips_entry hash_val 0x%"PRIx64" #%zu\n", ips_entry->entry.key, ips_ht->cnt);
		if (ips_entry->ips.nr)
			return ips_entry;
		dks_debug("update existing ips entry 0x%"PRIx64"\n", ips_entry->entry.key);
		free(ips_entry);
	}

	// Although we found an entry, we still need to update real callchain info.
	ips_entry = (struct dks_ips_entry *)malloc(sizeof_ips_entry(ips));
	if (!ips_entry) {
		pr_err("failed to allocate memory for callchain entry\n");
		return NULL;
	}

	if (ips->nr)
		memcpy(&ips_entry->ips, ips, sizeof__callchain_t(ips));
	dks_ht__add(ips_ht, hash_val, (struct dks_hash_entry *)ips_entry);

	pr_callchain(ips, NULL, false);
	return ips_entry;
}

/*get lock hash entry,
  used data for hash key :
	- pid/tid,
	- memory address of lock variable,
	- hash value for callchain
 */
static struct dks_lock_entry *get_lock_entry(struct dks_lock_stat *lock_stats,
	struct kdks_sample_data *sample_data)
{
	struct dks_ht *lock_ht = lock_stats->lock_ht;
	struct dks_ht *waiter_ht = NULL;
	struct dks_ht *cf_causality_ht = NULL;
	struct dks_lock_entry *lock_entry = NULL;
	struct dks_ips_entry *ips_entry = NULL;
	kdks_sample_header_t *header = &sample_data->header;
	kdks_record_t *holder_record = &sample_data->holder;
	callchain_t *ips = NULL;
	struct dks_lock_hash_key lock_key;
	u32 hash_val;

	ips = (callchain_t *)(&holder_record->ips);
	ips_entry = get_ips_entry(lock_stats, ips, holder_record->ips_id);
	if (!ips_entry) {
		pr_err("failed to get ips callchain entry\n");
		return NULL;
	}

	/* generate hash key
	   TODO find better way to hash value gen.
	   this kind of hash value generation looks ugly.
	 */
	memset(&lock_key, 0, sizeof(struct dks_lock_hash_key));
	lock_key.pid = holder_record->pid;
	lock_key.addr = header->addr;
	hash_val = jhash2((u32 *)&lock_key, sizeof(lock_key) / sizeof(u32), ips_entry->entry.key);

	/* consult existence */
	lock_entry = (struct dks_lock_entry *)dks_lock_table__lookup(lock_ht, hash_val,
		lock_key.pid, lock_key.addr, ips_entry->entry.key);
	if (lock_entry) {
		dks_debug("found lock entry hash_val 0x%"PRIx64"\n", lock_entry->entry.key);
		return lock_entry;
	}

	/*allocate new entry and then add it to hashtable*/
	lock_entry = (struct dks_lock_entry *)malloc(sizeof(*lock_entry));
	if (!lock_entry)
		return lock_entry;

	/* set new lock entry info */
	lock_entry->lock_type = header->lock_type;
	lock_entry->pid = holder_record->pid;
	lock_entry->tid = holder_record->tid;
	lock_entry->addr = header->addr;
	lock_entry->ips_id = ips_entry->entry.key;
	lock_entry->ips_ptr = &ips_entry->ips;

	/* init statistics */
	lock_entry->n_events = 0;
	lock_entry->n_waiters = 0;
	lock_entry->blocking_time = 0;

	/* create waiters hash table for current lock object */
	waiter_ht = dks_ht__new(DKS_WAITERS_HASHBITS, sizeof(struct dks_ips_ptr_entry));
	if (!waiter_ht) {
		pr_err("Failed to create new waiter's hashtable for current "
			"lock entry hash_val 0x%"PRIx64"\n", lock_entry->entry.key);
		free(lock_entry);
		lock_entry = NULL;
		return lock_entry;
	}
	lock_entry->waiters_ht = waiter_ht;

	cf_causality_ht = dks_ht__new(DKS_LOCKOBJ_HASHBITS, sizeof(struct dks_count_entry));
	if (!cf_causality_ht) {
		pr_err("Failed to create new hashtable for containing next lock holder info."
			"Current lock entry hash_va 0x%"PRIx64"\n", lock_entry->entry.key);
		dks_ht__free(lock_entry->waiters_ht, NULL);
		free(lock_entry);
		lock_entry = NULL;
		return lock_entry;
	}
	lock_entry->cf_causality_ht = cf_causality_ht;

	dks_ht__add(lock_ht, hash_val, (struct dks_hash_entry *)lock_entry);
	dks_debug("add new lock_entry #%zu\n", lock_ht->cnt);
	return lock_entry;
}

static inline struct dks_ips_entry *lookup_ips_entry(struct dks_lock_stat *stats, u64 hash_val)
{
	return (struct dks_ips_entry *)dks_ht__lookup(stats->ips_ht, hash_val);
}

static void update_lock_info(struct dks_lock_entry *lock_entry, struct dks_lock_stat *lock_stats,
	struct kdks_sample_data *sample_data)
{
	int i;
	size_t pos = 0;
	kdks_record_t *kdks_record;
	struct dks_ips_entry *ips_entry = NULL;
	kdks_sample_header_t *header = &sample_data->header;

	dks_debug("type %s waiters %u, size %u\n", locktype2name(header->lock_type),
		header->n_waiters, header->data_len);

	/* proceed amount of header */
	pos += sizeof(kdks_sample_header_t);

	// Process holder data first.
	kdks_record = &sample_data->holder;

	dks_debug("============================ \n");
	dks_debug("current holder's waiter list \n");
	dks_debug("============================ \n");

	// Update waiters' info such as waiting time and their list.
	for (i = 0; i < header->n_waiters; ++i) {
		pos += sizeof__kdks_record(kdks_record->ips.nr);
		kdks_record = (kdks_record_t *)((char *)sample_data + pos);
		ips_entry = NULL;

		pr_kdks_record(i, kdks_record);

		// We need to update callchain hash table here since waiters can
		// be shipped with real callchain.
		if (kdks_record->ips.nr)
			ips_entry = get_ips_entry(lock_stats, &kdks_record->ips, kdks_record->ips_id);

		// FIXME: ips_id is not set, create new one and set it on-the-fly.
		if (likely(kdks_record->ips_id)) {
			struct dks_ips_ptr_entry *ips_ptr_entry;
			u64 hash_val = kdks_record->ips_id;

			/* let's lookup first */
			ips_ptr_entry = (struct dks_ips_ptr_entry *)dks_ht__lookup(lock_entry->waiters_ht, hash_val);
			if (likely(ips_ptr_entry)) {
				dks_debug("found lock entry hash_val 0x%"PRIx64", "
					"ips entry hash_val 0x%"PRIx64" #%zu\n",
					lock_entry->entry.key, hash_val, lock_entry->waiters_ht->cnt);
				dks_debug("lock entry blocking time %"PRId64"\n", lock_entry->blocking_time);
				lock_entry->blocking_time += kdks_record->waiting_time;
				continue;
			}

			/* allocate new entry and then add it to hashtable*/
			ips_ptr_entry = (struct dks_ips_ptr_entry *)malloc(sizeof(*ips_ptr_entry));
			if (!ips_ptr_entry) {
				pr_err("failed to allocate ips_entry for allocate "
					"lock hash_val 0x%"PRIx64", ips hash_val 0x%"PRIx64" #%zu\n",
					lock_entry->entry.key, hash_val, lock_entry->waiters_ht->cnt);
				continue;
			}

			dks_debug("add new waiter entry for lock entry hash_val 0x%"PRIx64", "
				"ips entry hash_val 0x%"PRIx64" #ips entries %zu\n",
				lock_entry->entry.key, hash_val, lock_stats->ips_ht->cnt);

			/* set ips entry ptr data */
			ips_ptr_entry->entry.key = hash_val;

			/* lookup ips entry from ips_ht */
			if (likely(!ips_entry))
				ips_entry = lookup_ips_entry(lock_stats, hash_val);

			/* can't find callchain info - not added yet */
			ips_ptr_entry->ips_ptr = likely(!ips_entry) ? NULL : &ips_entry->ips;

			assert(lock_entry->waiters_ht);

			dks_ht__add(lock_entry->waiters_ht, ips_ptr_entry->entry.key,
				(struct dks_hash_entry *)ips_ptr_entry);
		}

		dks_debug("lock entry blocking time %"PRId64"\n", lock_entry->blocking_time);
		lock_entry->blocking_time += kdks_record->waiting_time;
	}
	dks_debug("============================ \n");

	lock_entry->n_events++;
	lock_entry->n_waiters += header->n_waiters;
}

// Return value: size of processed sample data
static int process_kdks_sample(struct perf_tool *perf_tool_p, struct kdks_sample_data *sample_data,
	struct perf_session *session)
{
	static struct dks_lock_entry *prev_lock_entry = NULL;
	struct dks_lock_entry *lock_entry;
	struct dks_last_lock_entry *last_lock_entry;
	struct analyze *analyze_p = container_of(perf_tool_p, struct analyze, tool);
	struct dks_lock_stat *lock_stats = &session->lock_stats;
	kdks_sample_header_t *header = &sample_data->header;
	int sample_data_size = 0;

#ifdef PROF_DKS_ANALYZE
	u64 s;
	long us;
	struct timespec start, end, elapsed_time;
#endif
	// kdks data size
	sample_data_size = header->data_len - sizeof(struct perf_event_header);
	if (sample_data_size <= sizeof(struct perf_event_header)) {
		pr_err("failed to process kdks sample, wrong sample data header header.data_len %u\n",
			sample_data->header.data_len);
		return 0;
	}

	if (!header->n_waiters) {
		pr_warning("holder info at 0x%"PRIx64"doesn't have any waiters\n", header->addr);
		return sample_data_size;
	}

	/*get stat entry : generate new lock stat entry or fetch existing one*/
	lock_entry = get_lock_entry(lock_stats, sample_data);
	if (!lock_entry) {
		pr_err("failed to process kdks sample, failed to allocate lock entry\n");
		return sample_data_size;
	}

	const u64 lock_addr = lock_entry->addr;
	if (prev_lock_entry) {
		const u64 prev_lock_addr = prev_lock_entry->addr;
		struct dks_lock_causality_entry *lock_causality_entry = (struct dks_lock_causality_entry *)dks_ht__lookup(lock_stats->lock_causality_ht, prev_lock_addr);
		if (!lock_causality_entry) {
			lock_causality_entry = (struct dks_lock_causality_entry *)malloc(sizeof(*lock_causality_entry));
			lock_causality_entry->next_lock_ht = dks_ht__new(DKS_LOCKOBJ_HASHBITS, sizeof(struct dks_count_entry));
			dks_ht__add(lock_stats->lock_causality_ht, prev_lock_addr,
				(struct dks_hash_entry *)lock_causality_entry);
		}

		struct dks_count_entry *count_entry = (struct dks_count_entry *)dks_ht__lookup(lock_causality_entry->next_lock_ht, lock_addr);
		if (!count_entry) {
			count_entry = (struct dks_count_entry *)malloc(sizeof(*count_entry));
			count_entry->key = lock_addr;
			count_entry->count = 0;
			dks_ht__add(lock_causality_entry->next_lock_ht, (u64)lock_entry->addr,
				(struct dks_hash_entry *)count_entry);
		}
		count_entry->count++;
	}
	prev_lock_entry = lock_entry;

	last_lock_entry = (struct dks_last_lock_entry *)dks_ht__lookup(lock_stats->last_lock_entry_ht, lock_addr);
	if (!last_lock_entry) {
		last_lock_entry = (struct dks_last_lock_entry *)malloc(sizeof(*last_lock_entry));
		last_lock_entry->lock_entry = lock_entry;
		dks_ht__add(lock_stats->last_lock_entry_ht, lock_addr,
			(struct dks_hash_entry *)last_lock_entry);
	} else {
		struct dks_count_entry *count_entry;
		struct dks_ht *cf_causality_ht = last_lock_entry->lock_entry->cf_causality_ht;

		count_entry = (struct dks_count_entry *)dks_ht__lookup(cf_causality_ht, (u64)lock_entry->ips_id);
		if (!count_entry) {
			count_entry = (struct dks_count_entry *)malloc(sizeof(*count_entry));
			count_entry->key = (u64)lock_entry->ips_id;
			count_entry->count = 0;
			dks_ht__add(cf_causality_ht, (u64)lock_entry->ips_id,
				(struct dks_hash_entry *)count_entry);
		}
		count_entry->count++;

		last_lock_entry->lock_entry = lock_entry;
	}

#ifdef PROF_DKS_ANALYZE
	clock_gettime(CLOCK_REALTIME, &start);
#endif
	update_lock_info(lock_entry, lock_stats, sample_data);
#ifdef PROF_DKS_ANALYZE
	clock_gettime(CLOCK_REALTIME, &end);

	elapsed_time = timespec_diff(start, end);
	s  = elapsed_time.tv_sec;
	us = round(elapsed_time.tv_nsec / 1.0e3);
	pr_info("lock stat process time : %"PRIu64".%06ld \n",(u64)s, us);
#endif
	dks_debug(" - lock_info [%u/%u] type %s at 0x%"PRIx64"\n",
		lock_entry->pid, lock_entry->tid, locktype2name(lock_entry->lock_type), lock_entry->addr);
	dks_debug(" - # events %"PRIu64", # waiters %"PRIu64"\n",
		lock_entry->n_events, lock_entry->n_waiters);
	dks_debug(" - total block time(avg/waiters) %"PRIu64" (%llu)(us)\n",
		lock_entry->blocking_time, (lock_entry->blocking_time / lock_entry->n_waiters) / 1000ULL);
	dks_debug("process kdks sample #%"PRIu64" done\n\n", analyze_p->nr_entries);

	analyze_p->nr_entries++;
	return sample_data_size;
}

static int __cmd_analyze(struct analyze *analyze)
{
	int ret;
	struct perf_session *session = analyze->session;

	signal(SIGINT, sig_handler);

	ret = perf_session__process_events(session);
	if (ret) {
		pr_err("Failed to process sample\n");
		return ret;
	}

	session_done();
	return 0;
}

static struct thread *thread_for_mapping(struct perf_session *session, pid_t pid, pid_t tid)
{
	// FIXME: ID for host and guest?
	struct machine *machine = &session->machines.host;
	return machine ? machine__findnew_thread(machine, pid, tid) : NULL;
}

static void show_results(struct perf_session *session, sqlite3 *db,
	struct dks_hash_entry **hash_entry_array, size_t array_size)
{
	struct dks_ht *ips_ht;
	sqlite3_stmt *select_stmt;
	size_t i;
	int rc;	// sqlite3 return value

	dks_debug("enter\n");

	pr_info("********************************************************\n");
	pr_info("              DKS Lock blame shift                      \n");
	pr_info("********************************************************\n");
	pr_info(" # of hash_entries : %ld\n", array_size);
	pr_info(" [id] lock_type, pid/tid, mem_addr, ips_id, "
		"# of events, # of waiters, wait(us), wait/waiters(us)\n");

	/* prepare statement */
	rc = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL);
	if (rc != SQLITE_OK) {
		pr_err("Can't prepare select statment %s (%i): %s\n",
			select_sql, rc, sqlite3_errmsg(db));
		return;
	}

	/* bind limit ranks */
	if (sqlite3_bind_int(select_stmt, 1, limit_ranks) != SQLITE_OK) {
		pr_err("Can't bind variable select statment %s (%i): %s\n",
			select_sql, rc, sqlite3_errmsg(db));
		return;
	}

	pr_info("********************************************************\n");
	for (i = 0; sqlite3_step(select_stmt) == SQLITE_ROW && i < array_size; i++) {
		int id = sqlite3_column_int(select_stmt, 0);
		struct dks_lock_entry *lock_entry = (struct dks_lock_entry *)hash_entry_array[id];
		u64 addr, ips_id;
		memcpy(&addr, sqlite3_column_blob(select_stmt, 4), sizeof(u64));
		memcpy(&ips_id, sqlite3_column_blob(select_stmt, 5), sizeof(u64));

		pr_info("[%ld] %s, %d/%d, %016"PRIx64", %016"PRIx64", %llu, %llu, %llu, %llu\n",
			i, locktype2name(sqlite3_column_int(select_stmt, 1)),
			sqlite3_column_int(select_stmt, 2), sqlite3_column_int(select_stmt, 3),
			addr, ips_id, sqlite3_column_int64(select_stmt, 6),
			sqlite3_column_int64(select_stmt, 7), sqlite3_column_int64(select_stmt, 8),
			sqlite3_column_int64(select_stmt, 9));

		pr_callchain(lock_entry->ips_ptr,
			thread_for_mapping(session, lock_entry->pid, lock_entry->tid), true);
	}
	pr_info("********************************************************\n");
	sqlite3_finalize(select_stmt);

	pr_info("********************************************************\n");
	pr_info("        DKS Lock blame shift (merged callchain)          \n");
	pr_info("********************************************************\n");
	pr_info(" [id] lock_type, pid/tid, ips_id, # of events, # of waiters, wait(us), wait/waiters(us)\n");

	/* prepare statement */
	rc = sqlite3_prepare_v2(db, group_sql, -1, &select_stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Can't prepare select statment %s (%i): %s\n",
			group_sql, rc, sqlite3_errmsg(db));
		return;
	}

	/* bind limit ranks */
	if (sqlite3_bind_int(select_stmt, 1, limit_ranks) != SQLITE_OK) {
		pr_err("Can't bind variable select statment %s (%i): %s\n",
			group_sql, rc, sqlite3_errmsg(db));
		return;
	}

	ips_ht = session->lock_stats.ips_ht;
	pr_info("********************************************************\n");
	for (i = 0; sqlite3_step(select_stmt) == SQLITE_ROW && i < array_size; i++) {
		struct dks_ips_entry *ips_entry;
		s32 pid = sqlite3_column_int(select_stmt, 1);
		s32 tid = sqlite3_column_int(select_stmt, 2);
		u64 ips_id;

		memcpy(&ips_id, sqlite3_column_blob(select_stmt, 3), sizeof(u64));

		pr_info("[%ld] %s, %d/%d, %016"PRIx64", %llu, %llu, %llu, %llu\n",
			i, locktype2name(sqlite3_column_int(select_stmt, 0)),
			pid, tid, ips_id, sqlite3_column_int64(select_stmt, 4),
			sqlite3_column_int64(select_stmt, 5), sqlite3_column_int64(select_stmt, 6),
			sqlite3_column_int64(select_stmt, 7));

		/* check it current hashtable */
		ips_entry = (struct dks_ips_entry *)dks_ht__lookup(ips_ht, ips_id);
		if (!ips_entry) {
			pr_err("can't find callchain for current entry\n");
			continue;
		}

		pr_callchain(&ips_entry->ips, thread_for_mapping(session, pid, tid), true);
	}
	pr_info("********************************************************\n");
	sqlite3_finalize(select_stmt);
}

int debug_callback(void *__dumy __maybe_unused, int argc, char **argv, char **azColName)
{
	char ret_text[PATH_MAX] = "\0";
	int i, len=0;

	for (i = 0; i < argc; i++) {
		sprintf((char *)(ret_text+len), "%s ", argv[i] ? argv[i] : "NULL");
		len += strlen(ret_text);
		ret_text[len]='\0';
	}

	dks_debug("%s\n",ret_text);
	return 0;
}

static struct json_object *lock_node_alloc(u64 lock_addr,
	int lock_type, int pid, long event_count, long waiter_count,
	long blocking_time, long blocking_time_per_waiter, u64 lock_node_index)
{
	json_object *node, *font_object, *color_object;
	char *buffer;
	static const char label_template[] = \
		"[Lock %lu]\n" \
		"LockAddr: 0x%016"PRIx64"\n" \
		"LockType: %s\n" \
		"PID: %d\n" \
		"EventCount: %ld\n" \
		"WaiterCount: %ld\n" \
		"BlockingTime: %ld μs\n" \
		"BlockingTimePerWaiter: %ld μs";
	static const unsigned label_template_length = sizeof(label_template) + 16 + 16 + 1;

	unsigned lock_type_length;
	char lock_type_string[16] = {0, };
	if (lock_type == 1) {
		lock_type_length = strlen("spinlock");
		strncpy(lock_type_string, "spinlock", lock_type_length);
	} else if (lock_type == 2) {
		lock_type_length = strlen("mutex");
		strncpy(lock_type_string, "mutex", lock_type_length);
	} else {
		lock_type_length = strlen("unknown");
		strncpy(lock_type_string, "unknown", lock_type_length);
	}
	lock_type_string[lock_type_length] = '\0';

	const unsigned max_label_length = label_template_length
		+ digit_count(lock_node_index)
		+ lock_type_length
		+ digit_count(pid)
		+ digit_count(event_count) + digit_count(waiter_count)
		+ digit_count(blocking_time) + digit_count(blocking_time_per_waiter);
	const unsigned buffer_length = max_label_length;

	buffer = (char *)malloc(buffer_length);
	assert(buffer);

	node = json_object_new_object();
	snprintf(buffer, buffer_length, "%016"PRIx64"", lock_addr);
	json_object_object_add(node, "id", json_object_new_string(buffer));
	json_object_object_add(node, "shape", json_object_new_string("box"));
	json_object_object_add(node, "color", json_object_new_string("white"));

	color_object = json_object_new_object();
	json_object_object_add(color_object, "background", json_object_new_string("white"));
	json_object_object_add(color_object, "border", json_object_new_string("black"));
	json_object_object_add(node, "color", color_object);

	font_object = json_object_new_object();
	json_object_object_add(font_object, "face", json_object_new_string("monospace"));
	json_object_object_add(font_object, "align", json_object_new_string("left"));
	json_object_object_add(node, "font", font_object);

	snprintf(buffer, buffer_length, label_template, lock_node_index, lock_addr,
		lock_type_string, pid, event_count, waiter_count, blocking_time,
		blocking_time_per_waiter);
	json_object_object_add(node, "label", json_object_new_string(buffer));

	// Unofficial properties
	json_object_object_add(node, "event_count", json_object_new_int64(event_count));
	json_object_object_add(node, "lock_node_index", json_object_new_int64(lock_node_index));
	json_object_object_add(node, "waiter_count", json_object_new_int64(waiter_count));
	json_object_object_add(node, "blocking_time", json_object_new_int64(blocking_time));
	json_object_object_add(node, "blocking_time_per_waiter", json_object_new_int64(blocking_time_per_waiter));

	free(buffer);
	return node;
}

static void lock_node_update(json_object *lock_node, u64 lock_addr,
	int lock_type, int pid, long event_count, long waiter_count,
	long blocking_time, long blocking_time_per_waiter)
{
	json_object *jsobject;
	u64 lock_node_index;
	long new_event_count, new_waiter_count, new_blocking_time, new_blocking_time_per_waiter;
	char *buffer;
	static const char label_template[] = \
		"[Lock %lu]\n" \
		"LockAddr: 0x%016"PRIx64"\n" \
		"LockType: %s\n" \
		"PID: %d\n" \
		"EventCount: %ld\n" \
		"WaiterCount: %ld\n" \
		"BlockingTime: %ld μs\n" \
		"BlockingTimePerWaiter: %ld μs";

	unsigned lock_type_length;
	char lock_type_string[16] = {0, };
	if (lock_type == 1) {
		lock_type_length = strlen("spinlock");
		strncpy(lock_type_string, "spinlock", lock_type_length);
	} else if (lock_type == 2) {
		lock_type_length = strlen("mutex");
		strncpy(lock_type_string, "mutex", lock_type_length);
	} else {
		lock_type_length = strlen("unknown");
		strncpy(lock_type_string, "unknown", lock_type_length);
	}
	lock_type_string[lock_type_length] = '\0';

	json_object_object_get_ex(lock_node, "lock_node_index", &jsobject);
	lock_node_index = json_object_get_int64(jsobject);

	json_object_object_get_ex(lock_node, "event_count", &jsobject);
	new_event_count = json_object_get_int64(jsobject) + event_count;
	json_object_object_add(lock_node, "event_count", json_object_new_int64(new_event_count));

	json_object_object_get_ex(lock_node, "waiter_count", &jsobject);
	new_waiter_count = json_object_get_int64(jsobject) + waiter_count;
	json_object_object_add(lock_node, "waiter_count", json_object_new_int64(new_waiter_count));

	json_object_object_get_ex(lock_node, "blocking_time", &jsobject);
	new_blocking_time = json_object_get_int64(jsobject) + blocking_time;
	json_object_object_add(lock_node, "blocking_time", json_object_new_int64(new_blocking_time));

	new_blocking_time_per_waiter = (long)(new_blocking_time / new_waiter_count);
	static const unsigned label_template_length = sizeof(label_template) + 16 + 16 + 1;
	const unsigned max_label_length = label_template_length
		+ digit_count(lock_node_index)
		+ lock_type_length
		+ digit_count(pid)
		+ digit_count(new_event_count) + digit_count(new_waiter_count)
		+ digit_count(new_blocking_time) + digit_count(new_blocking_time_per_waiter);
	const unsigned buffer_length = max_label_length;

	buffer = (char *)malloc(buffer_length);
	assert(buffer);

	snprintf(buffer, buffer_length, label_template, lock_node_index, lock_addr,
		lock_type_string, pid, new_event_count, new_waiter_count,
		new_blocking_time, new_blocking_time_per_waiter);
	json_object_object_add(lock_node, "label", json_object_new_string(buffer));

	free(buffer);
}

static struct json_object *callchain_node_alloc(json_object *node_info,
	u64 node_addr, u64 lock_addr, u64 index, enum html_color node_color,
	const char *cid_string)
{
	u64 line;
	u64 inlined_at_line;
	unsigned short_func_name_length;
	char *buffer;
	char *short_func_name;
	json_object *node, *jsobject, *font_object;
	const char *file_name, *func_name, *bin_name, *inlined_at, *inlined_in;
	static const char title_template[] = \
		"[Callchain %lu (cid: %s)]<br>" \
		"Addr: 0x%016"PRIx64"<br>" \
		"BinaryName: %s<br>" \
		"SourceFile: %s:%ld<br>" \
		"Function: %s";
	static const char title_inline_template[] = \
		"[Callchain %lu (cid: %s)]<br>" \
		"Addr : 0x%016"PRIx64"<br>" \
		"BinaryName: %s<br>" \
		"SourceFile: %s:%ld<br>" \
		"InlinedAt: %s:%ld<br>" \
		"InlinedIn: %s<br>" \
		"Function: %s";
	static const unsigned title_template_length = sizeof(title_template) + 16 + 1;

	node = json_object_new_object();
	assert(node);
	json_object_object_add(node, "color", json_object_new_string(to_html_color_name(node_color)));
//	json_object_object_add(node, "size", json_object_new_int64(15));
	json_object_object_add(node, "level", json_object_new_int64(index));

	font_object = json_object_new_object();
	json_object_object_add(font_object, "face", json_object_new_string("monospace"));
	json_object_object_add(font_object, "align", json_object_new_string("center"));
	json_object_object_add(font_object, "size", json_object_new_int64(25));
	json_object_object_add(node, "font", font_object);

	json_object_object_get_ex(node_info, "BinaryName", &jsobject);
	bin_name = json_object_get_string(jsobject);
	json_object_object_get_ex(node_info, "FunctionName", &jsobject);
	func_name = json_object_get_string(jsobject);

       if (func_name) {
               char *left_parenthesis = strchr(func_name, '(');
	       if (left_parenthesis)
		       short_func_name_length = (unsigned)(left_parenthesis - func_name);
	       else
		       short_func_name_length = strlen(func_name);
               short_func_name = (char *)malloc(short_func_name_length + 1);
               assert(short_func_name);
               strncpy(short_func_name, func_name, short_func_name_length);
               short_func_name[short_func_name_length] = '\0';
       } else {
               short_func_name_length = 0;
               short_func_name = (char *)malloc(short_func_name_length + 1);
               short_func_name[short_func_name_length] = '\0';
       }
	json_object_object_add(node, "label", json_object_new_string(short_func_name));

	json_object_object_get_ex(node_info, "SourceFileName", &jsobject);
	file_name = json_object_get_string(jsobject);
	json_object_object_get_ex(node_info, "SourceFileLine", &jsobject);
	line = json_object_get_int64(jsobject);

	json_object_object_get_ex(node_info, "InlinedIn", &jsobject);
	inlined_in = json_object_get_string(jsobject);
	json_object_object_get_ex(node_info, "InlinedAt", &jsobject);
	inlined_at = json_object_get_string(jsobject);
	json_object_object_get_ex(node_info, "InlinedAtLine", &jsobject);
	inlined_at_line = json_object_get_int64(jsobject);

	const unsigned cid_length = cid_string ? strlen(cid_string) : 0;
	const unsigned bin_name_length = bin_name ? strlen(bin_name) : 0;
	const unsigned file_name_length = file_name ? strlen(file_name) : 0;
	const unsigned func_name_length = func_name ? strlen(func_name) : 0;

	const unsigned inlined_in_length = inlined_in ? strlen(inlined_in) : 0;
	const unsigned inlined_at_length = inlined_at ? strlen(inlined_at) : 0;

	const unsigned max_title_length = title_template_length + cid_length
		+ digit_count(index) + bin_name_length + file_name_length
		+ digit_count(line) + inlined_at_length + digit_count(inlined_at_line)
		+ inlined_in_length + func_name_length;
	// 49 = (64 / 4) * 3 + 1
	// Each 64 bit value is represented by 4bits characters, 0-F. Below node id is
	// composed of 3 addresses. So the buffer should be at least 49 bytes including '\0'
	const unsigned buffer_length = max(max_title_length, (unsigned)49);

	buffer = (char *)malloc(buffer_length);
	assert(buffer);

	snprintf(buffer, buffer_length, "%016"PRIx64"-%016"PRIx64"", lock_addr, node_addr);
	json_object_object_add(node, "id", json_object_new_string(buffer));
	json_object_object_add(node, "cid", json_object_new_string(cid_string));

	if (inlined_in_length > 0) {
		snprintf(buffer, buffer_length, title_inline_template, index, cid_string,
			node_addr, bin_name, file_name, line, inlined_at, inlined_at_line,
			inlined_in, func_name);
	} else {
		snprintf(buffer, buffer_length, title_template, index, cid_string,
			node_addr, bin_name, file_name, line, func_name);
	}
	json_object_object_add(node, "title", json_object_new_string(buffer));

	free(short_func_name);
	free(buffer);
	return node;
}

static struct json_object *callchain_edge_alloc(json_object *from_node, json_object *to_node,
	json_object *callchain_info, u64 count, s64 total_blocking_time, enum html_color edge_color)
{
	json_object *edge, *smooth_object, *object;
	const char *from_node_id, *to_node_id;
	const char *smooth_type;
	char *buffer;
	double roundness;
	u64 blocking_time, blocking_time_per_waiter, waiter_count;
//	u64 scale;
	unsigned buffer_length;
	static const char title_template[] = \
		"WaiterCount: %ld<br>" \
		"BlockingTime: %ld us<br>" \
		"BlockingTimePerWaiter: %ld us";
	static const unsigned title_template_length = sizeof(title_template) + 1;

	edge = json_object_new_object();
	assert(edge);

	json_object_object_get_ex(from_node, "id", &object);
	from_node_id = json_object_get_string(object);
	json_object_object_get_ex(to_node, "id", &object);
	to_node_id = json_object_get_string(object);

	json_object_object_add(edge, "from", json_object_new_string(from_node_id));
	json_object_object_add(edge, "to", json_object_new_string(to_node_id));

	json_object_object_add(edge, "arrows", json_object_new_string("to"));
	json_object_object_add(edge, "color", json_object_new_string(to_html_color_name(edge_color)));

	smooth_object = json_object_new_object();
	assert(smooth_object);

	if (count == 1)
		smooth_type = "continuous";
	else
		smooth_type = count % 2 ? "curvedCW" : "curvedCCW";
	json_object_object_add(smooth_object, "type", json_object_new_string(smooth_type));
	roundness = 1.0f / max((float)count, 1.0f);
	json_object_object_add(smooth_object, "roundness", json_object_new_double(roundness));
	json_object_object_add(edge, "smooth", smooth_object);

	json_object_object_get_ex(callchain_info, "blocking_time", &object);
	blocking_time = json_object_get_int64(object);

	json_object_object_get_ex(callchain_info, "waiter_count", &object);
	waiter_count = json_object_get_int64(object);
	blocking_time_per_waiter = blocking_time / waiter_count;

	buffer_length = title_template_length + digit_count(waiter_count)
		+ digit_count(blocking_time) + digit_count(blocking_time_per_waiter);
	buffer = (char *)malloc(buffer_length);
	assert(buffer);

	snprintf(buffer, buffer_length, title_template, waiter_count,
		blocking_time, blocking_time_per_waiter);
	json_object_object_add(edge, "title", json_object_new_string(buffer));

	memset(buffer, 0, buffer_length);
	snprintf(buffer, 9, "%.2f %%", (blocking_time / (float)total_blocking_time) * 100);
	json_object_object_add(edge, "label", json_object_new_string(buffer));

	free(buffer);
	return edge;
}

static struct json_object *callchain_node_and_edge_alloc(json_object *node_info_array,
	struct dks_ht *json_object_node_htable, struct dks_ht *json_object_edge_htable,
	json_object *nodes, json_object *edges, json_object *info, json_object *lock_node,
	enum html_color node_color, enum html_color edge_color, const char *cid_string)
{
	size_t length, i;
	s64 lock_level, total_blocking_time;
	json_object *first_node = NULL, *jsobject;

	json_object_object_get_ex(lock_node, "blocking_time", &jsobject);
	total_blocking_time = json_object_get_int64(jsobject);

	json_object_object_get_ex(lock_node, "level", &jsobject);
	lock_level = json_object_get_int64(jsobject);

	length = json_object_array_length(node_info_array);
	if (length > lock_level)
		json_object_object_add(lock_node, "level", json_object_new_int64(length));

	for (i = 0; i < length; ++i) {
		static json_object *prev_node = NULL;
		struct dks_json_object *dks_jobject;
		json_object *node_info, *node, *edge, *object, *parent_node, *callchain_info;
		u64 node_addr, hash_value;
		char id_string[34]; // 16 + 16 + 1 ('-') + 1 ('\0')

		node_info = json_object_array_get_idx(node_info_array, i);
		assert(node_info);

		json_object_object_get_ex(node_info, "Address", &object);
		node_addr = json_object_get_int64(object);

		snprintf(id_string, sizeof(id_string), "%016"PRIx64"-%016"PRIx64"",
			(u64)lock_node, node_addr);
		hash_value = hash(id_string);

		dks_jobject = (struct dks_json_object *)dks_ht__lookup(json_object_node_htable, hash_value);
		if (!dks_jobject) {
			dks_jobject = (struct dks_json_object *)malloc(sizeof(*dks_jobject));
			node = callchain_node_alloc(node_info, node_addr, (u64)lock_node, length - 1 - i, node_color, cid_string);
			assert(node);
			dks_jobject->jobject = node;
			dks_ht__add(json_object_node_htable, hash_value, (struct dks_hash_entry *)dks_jobject);
			json_object_array_add(nodes, node);
		} else
			node = dks_jobject->jobject;

		if (!i)
			first_node = node;

		parent_node = i ? prev_node : lock_node;
		snprintf(id_string, sizeof(id_string), "%016"PRIx64"-%016"PRIx64"",
			(u64)node, (u64)parent_node);
		hash_value = hash(id_string);

		dks_jobject = (struct dks_json_object *)dks_ht__lookup(json_object_edge_htable, hash_value);
		if (!dks_jobject) {
			dks_jobject = (struct dks_json_object *)malloc(sizeof(*dks_jobject));
			dks_jobject->count = 0;
			dks_ht__add(json_object_edge_htable, hash_value, (struct dks_hash_entry *)dks_jobject);
		}

		json_object_object_get_ex(info, "callchains", &object);
		json_object_object_get_ex(object, cid_string, &callchain_info);

		edge = callchain_edge_alloc(node, parent_node, callchain_info,
			++dks_jobject->count, total_blocking_time, edge_color);
		assert(edge);
		json_object_array_add(edges, edge);

		prev_node = node;
	}

	return first_node;
}

static void append_callchain_node_and_edge(struct dks_ht *callchain_entry_htable,
	struct dks_ht *json_object_node_htable, struct dks_ht *json_object_edge_htable,
	struct dks_lock_entry *lock_entry, u64 callchain_id, struct thread *thread,
	json_object *lock_node,	json_object *nodes, json_object *edges, json_object *info,
	long event_count, long waiter_count, long blocking_time,
	enum html_color node_color, enum html_color edge_color)
{
	callchain_t *callchain;
	struct dks_json_object *callchain_entry;
	char id_string[34]; // 16 + 16 + 1 ('-') + 1 ('\0')
	char cid_string[34] = {0, };
	s64 total_blocking_time;
	u64 callchain_hash_value;
	static u32 callchain_count = 0;

	callchain = lock_entry->ips_ptr;
	snprintf(cid_string, sizeof(cid_string), "%016"PRIx64"-%016"PRIx64"",
		(u64)lock_entry->addr, (u64)callchain_id);

	snprintf(id_string, sizeof(id_string), "%016"PRIx64"-%016"PRIx64"",
		(u64)lock_node, callchain_id);
	callchain_hash_value = hash(id_string);

	// Lock holder's callchain nodes and edges
	callchain_entry = (struct dks_json_object *)dks_ht__lookup(callchain_entry_htable, callchain_hash_value);
	if (!callchain_entry) {
		struct hlist_node *tmp;
		struct dks_hash_entry *hash_entry;
		struct dks_ht *cf_causality_ht;
		json_object *callchain_array, *callchain_info;
		json_object *callchains, *next_callchains;
		unsigned bkt;
		unsigned long total_next_callchains = 0;

		callchain_info = json_object_new_object();
		json_object_object_add(callchain_info, "color", json_object_new_string(to_html_color_name(edge_color)));
		json_object_object_add(callchain_info, "event_count", json_object_new_int64(event_count));
		json_object_object_add(callchain_info, "waiter_count", json_object_new_int64(waiter_count));
		json_object_object_add(callchain_info, "blocking_time", json_object_new_int64(blocking_time));

		next_callchains = json_object_new_object();
		cf_causality_ht = lock_entry->cf_causality_ht;
#if DISPLAY_FULL_CAUSALITY
		dks_hash_for_each_safe(cf_causality_ht->ht, bkt, tmp, hash_entry, node, cf_causality_ht->sz) {
			struct dks_count_entry *count_entry = (struct dks_count_entry *)hash_entry;
			unsigned long next_holder_entry_count = count_entry->count;
			total_next_callchains += next_holder_entry_count;

			char next_cid_string[34];
			snprintf(next_cid_string, sizeof(next_cid_string),
				"%016"PRIx64"-%016"PRIx64"", (u64)lock_entry->addr, count_entry->key);
			json_object_object_add(next_callchains, next_cid_string,
				json_object_new_int64(count_entry->count));
		}
#else
		struct dks_count_entry *top_ranked_count_entries[CAUSALITY_MAX_COUNT] = {NULL, };
		dks_hash_for_each_safe(cf_causality_ht->ht, bkt, tmp, hash_entry, node, cf_causality_ht->sz) {
			struct dks_count_entry *count_entry = (struct dks_count_entry *)hash_entry;
			unsigned long next_holder_entry_count = count_entry->count;
			total_next_callchains += next_holder_entry_count;

			if (top_ranked_count_entries[0]
				&& top_ranked_count_entries[0]->count >= next_holder_entry_count)
				continue;

			int i;
			for (i = 1; i < CAUSALITY_MAX_COUNT; ++i) {
				if (!top_ranked_count_entries[i]
					|| top_ranked_count_entries[i]->count <= next_holder_entry_count)
					continue;

				int j;
				for (j = 0; j < i - 1; ++j)
					top_ranked_count_entries[j] = top_ranked_count_entries[j + 1];
				top_ranked_count_entries[i - 1] = count_entry;
				break;
			}

			if (i == CAUSALITY_MAX_COUNT) {
				int j;
				for (j = 0; j < CAUSALITY_MAX_COUNT - 1; ++j)
					top_ranked_count_entries[j] = top_ranked_count_entries[j + 1];
				top_ranked_count_entries[CAUSALITY_MAX_COUNT - 1] = count_entry;
			}
		}

		int i;
		for (i = 0; i < CAUSALITY_MAX_COUNT; ++i) {
			char next_cid_string[34];
			if (!top_ranked_count_entries[i])
				continue;

			snprintf(next_cid_string, sizeof(next_cid_string),
				"%016"PRIx64"-%016"PRIx64"",
				(u64)lock_entry->addr, top_ranked_count_entries[i]->key);
			json_object_object_add(next_callchains, next_cid_string,
				json_object_new_int64(top_ranked_count_entries[i]->count));
		}
#endif // end of DISPLAY_FULL_CAUSALITY

		json_object_object_add(callchain_info, "total_next_callchains",
			json_object_new_int64(total_next_callchains));

		json_object_object_add(callchain_info, "next_callchains", next_callchains);

		json_object_object_get_ex(info, "callchains", &callchains);
		json_object_object_add(callchains, cid_string, callchain_info);

		callchain_entry = (struct dks_json_object *)malloc(sizeof(*callchain_entry));
		assert(callchain_entry);

		callchain_array = callchain_to_json_object(callchain, thread);
		callchain_entry->jobject = callchain_node_and_edge_alloc(callchain_array,
			json_object_node_htable, json_object_edge_htable,
			nodes, edges, info, lock_node, node_color, edge_color, cid_string);
		dks_ht__add(callchain_entry_htable, callchain_hash_value, (struct dks_hash_entry *)callchain_entry);
		json_object_object_add(info, "callchain_count", json_object_new_int64(++callchain_count));

		json_object_put(callchain_array);
		return;
	}

	u64 edge_hash_value;
	json_object *jsobject, *callchain_info;
	struct dks_json_object *dks_jobject = NULL;

	snprintf(id_string, sizeof(id_string), "%016"PRIx64"-%016"PRIx64"",
		(u64)callchain_entry->jobject, (u64)lock_node);
	edge_hash_value = hash(id_string);
	dks_jobject = (struct dks_json_object *)dks_ht__lookup(json_object_edge_htable, edge_hash_value);
	assert(dks_jobject);

	json_object_object_get_ex(lock_node, "blocking_time", &jsobject);
	total_blocking_time = json_object_get_int64(jsobject);

	json_object_object_get_ex(info, "callchains", &jsobject);
	json_object_object_get_ex(jsobject, cid_string, &callchain_info);

	// Callchain nodes exist so it is enough to add an edge
	// between lock node and the first node of the callchain
	json_object *edge = callchain_edge_alloc(callchain_entry->jobject, lock_node,
		callchain_info, ++dks_jobject->count, total_blocking_time, edge_color);
	assert(edge);
	json_object_array_add(edges, edge);
}

// FIXME: We may want to move this into dks_util.c or a new file.
static void export_results(struct perf_session *session, sqlite3 *db,
	struct dks_hash_entry **hash_entry_array, size_t array_size)
{
	struct dks_lock_stat *lock_stats;
	json_object *root, *edges, *nodes, *info;
	sqlite3_stmt *select_stmt;
	struct dks_ht *callchain_entry_htable;
	struct dks_ht *json_object_node_htable;
	struct dks_ht *json_object_edge_htable;
	char *export_file_name;
	size_t i;
	int rc;
	size_t lock_node_count = 0;

	pr_info("export results to json\n");

	rc = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Can't prepare select statment %s (%i): %s\n",
			select_sql, rc, sqlite3_errmsg(db));
		return;
	}

	/* bind limit */
	if (sqlite3_bind_int(select_stmt, 1, limit_ranks) != SQLITE_OK) {
		pr_err("Can't bind variable select statment %s (%i): %s\n",
			select_sql, rc, sqlite3_errmsg(db));
		return;
	}

	callchain_entry_htable = dks_ht__new(DKS_CALLCHAIN_HASHBITS, sizeof(struct dks_json_object));
	if (!callchain_entry_htable) {
		pr_err("Failed to create a hash table to keep callchains.\n");
		return;
	}

	json_object_node_htable = dks_ht__new(DKS_CALLCHAIN_HASHBITS, sizeof(struct dks_json_object));
	if (!json_object_node_htable) {
		pr_err("Failed to create a hash table to keep node json objects.\n");
		dks_ht__free(callchain_entry_htable, NULL);
		return;
	}

	json_object_edge_htable = dks_ht__new(DKS_CALLCHAIN_HASHBITS, sizeof(struct dks_json_object));
	if (!json_object_edge_htable) {
		pr_err("Failed to create a hash table to keep edge json objects.\n");
		dks_ht__free(json_object_node_htable, NULL);
		dks_ht__free(callchain_entry_htable, NULL);
		return;
	}

	nodes = json_object_new_array();
	edges = json_object_new_array();
	info = json_object_new_object();
	if (!nodes || !edges || !info) {
		pr_err("Failed to create essential json objects, edges or nodes or info.\n");
		dks_ht__free(json_object_edge_htable, NULL);
		dks_ht__free(json_object_node_htable, NULL);
		dks_ht__free(callchain_entry_htable, NULL);
		return;
	}
	json_object_object_add(info, "locks", json_object_new_object());
	json_object_object_add(info, "callchains", json_object_new_object());

	lock_stats = &session->lock_stats;
	// Create lock nodes
	for (i = 0; sqlite3_step(select_stmt) == SQLITE_ROW && i < array_size; ++i) {
		struct dks_json_object *dks_jobject_lock;
		json_object *lock_node;
		u64 lock_addr, holder_callchain_id;
		u64 hash_value;
		enum html_color node_color;
		char lock_id_string[34] = {0, }; // 16 + 16 + 1 ('-') + 1 ('\0')

		const int lock_type = sqlite3_column_int(select_stmt, 1);
		const int pid = sqlite3_column_int(select_stmt, 2);
		const long event_count = sqlite3_column_int64(select_stmt, 6);
		const long waiter_count = sqlite3_column_int64(select_stmt, 7);
		const long blocking_time = sqlite3_column_int64(select_stmt, 8);
		const long blocking_time_per_waiter = sqlite3_column_int64(select_stmt, 9);

		memcpy(&lock_addr, sqlite3_column_blob(select_stmt, 4), sizeof(u64));
		memcpy(&holder_callchain_id, sqlite3_column_blob(select_stmt, 5), sizeof(u64));

		snprintf(lock_id_string, sizeof(lock_id_string), "%016"PRIx64"", lock_addr);
		hash_value = hash(lock_id_string);

		// Lock holder node
		dks_jobject_lock = (struct dks_json_object *)dks_ht__lookup(json_object_node_htable, hash_value);
		if (!dks_jobject_lock) {
			struct hlist_node *tmp;
			struct dks_ht *next_lock_ht;
			struct dks_hash_entry *hash_entry;
			struct dks_lock_causality_entry *lock_causality_entry;
			json_object *next_locks, *lock_info, *locks;
			unsigned bkt;
			unsigned long total_next_lock_count = 0;
			char lock_id_string[17];

			dks_jobject_lock = (struct dks_json_object *)malloc(sizeof(*dks_jobject_lock));
			lock_node = lock_node_alloc(lock_addr, lock_type, pid,
				event_count, waiter_count, blocking_time,
				blocking_time_per_waiter, lock_node_count);
			assert(lock_node);

			node_color = max((int)(HTML_COLOR_MAX - 1 - lock_node_count), 0);

			dks_jobject_lock->jobject = lock_node;
			dks_jobject_lock->count = 0;
			dks_jobject_lock->color = node_color;
			dks_ht__add(json_object_node_htable, hash_value,
				(struct dks_hash_entry *)dks_jobject_lock);
			json_object_array_add(nodes, lock_node);
			++lock_node_count;

			lock_info = json_object_new_object();
			next_locks = json_object_new_object();
			lock_causality_entry = (struct dks_lock_causality_entry *)dks_ht__lookup(lock_stats->lock_causality_ht, lock_addr);
			assert(lock_causality_entry);

			next_lock_ht = lock_causality_entry->next_lock_ht;
#if DISPLAY_FULL_CAUSALITY
			dks_hash_for_each_safe(next_lock_ht->ht, bkt, tmp, hash_entry, node, next_lock_ht->sz) {
				struct dks_count_entry *count_entry = (struct dks_count_entry *)hash_entry;
				total_next_lock_count += count_entry->count;

				snprintf(lock_id_string, sizeof(lock_id_string),
					"%016"PRIx64"", count_entry->key);
				json_object_object_add(next_locks, lock_id_string,
					json_object_new_int64(count_entry->count));
			}
#else
			struct dks_count_entry *top_ranked_count_entries[CAUSALITY_MAX_COUNT] = {NULL, };
			dks_hash_for_each_safe(next_lock_ht->ht, bkt, tmp, hash_entry, node, next_lock_ht->sz) {
				struct dks_count_entry *count_entry = (struct dks_count_entry *)hash_entry;
				unsigned long next_lock_count = count_entry->count;
				total_next_lock_count += next_lock_count;

				if (top_ranked_count_entries[0]
					&& top_ranked_count_entries[0]->count >= next_lock_count)
					continue;

				int i;
				for (i = 1; i < CAUSALITY_MAX_COUNT; ++i) {
					if (!top_ranked_count_entries[i]
						|| top_ranked_count_entries[i]->count <= next_lock_count)
						continue;

					int j;
					for (j = 0; j < i - 1; ++j)
						top_ranked_count_entries[j] = top_ranked_count_entries[j + 1];
					top_ranked_count_entries[i - 1] = count_entry;
					break;
				}

				if (i == CAUSALITY_MAX_COUNT) {
					int j;
					for (j = 0; j < CAUSALITY_MAX_COUNT - 1; ++j)
						top_ranked_count_entries[j] = top_ranked_count_entries[j + 1];
					top_ranked_count_entries[CAUSALITY_MAX_COUNT - 1] = count_entry;
				}
			}

			int i;
			for (i = 0; i < CAUSALITY_MAX_COUNT; ++i) {
				if (!top_ranked_count_entries[i])
					continue;

				snprintf(lock_id_string, sizeof(lock_id_string),
					"%016"PRIx64"", top_ranked_count_entries[i]->key);
				json_object_object_add(next_locks, lock_id_string,
					json_object_new_int64(top_ranked_count_entries[i]->count));
			}
#endif // DISPLAY_FULL_CAUSALITY

			json_object_object_add(lock_info, "total_next_locks",
				json_object_new_int64(total_next_lock_count));
			json_object_object_add(lock_info, "next_locks", next_locks);

			json_object_object_get_ex(info, "locks", &locks);
			snprintf(lock_id_string, sizeof(lock_id_string), "%016"PRIx64"", lock_addr);
			json_object_object_add(locks, lock_id_string, lock_info);
		} else {
			lock_node = dks_jobject_lock->jobject;
			lock_node_update(lock_node, lock_addr, lock_type, pid,
				event_count, waiter_count, blocking_time,
				blocking_time_per_waiter);
		}
		dks_jobject_lock->count++;
	}

	// Create callchain nodes and edges.
	for (i = 0; sqlite3_step(select_stmt) == SQLITE_ROW && i < array_size; ++i) {
		struct dks_lock_entry *lock_entry;
		struct dks_json_object *dks_jobject_lock;
		json_object *lock_node;
		struct thread *thread;
		u64 lock_addr, holder_callchain_id;
		u64 hash_value;
		enum html_color node_color, edge_color;
		char lock_id_string[34] = {0, }; // 16 + 16 + 1 ('-') + 1 ('\0')

		const int index = sqlite3_column_int(select_stmt, 0);
		const long event_count = sqlite3_column_int64(select_stmt, 6);
		const long waiter_count = sqlite3_column_int64(select_stmt, 7);
		const long blocking_time = sqlite3_column_int64(select_stmt, 8);

		memcpy(&lock_addr, sqlite3_column_blob(select_stmt, 4), sizeof(u64));
		memcpy(&holder_callchain_id, sqlite3_column_blob(select_stmt, 5), sizeof(u64));

		snprintf(lock_id_string, sizeof(lock_id_string), "%016"PRIx64"", lock_addr);
		hash_value = hash(lock_id_string);

		// Lock holder node
		dks_jobject_lock = (struct dks_json_object *)dks_ht__lookup(json_object_node_htable, hash_value);
		assert(dks_jobject_lock);

		lock_node = dks_jobject_lock->jobject;
		node_color = dks_jobject_lock->color;

		lock_entry = (struct dks_lock_entry *)hash_entry_array[index];
		thread = thread_for_mapping(session, lock_entry->pid, lock_entry->tid);
		assert(thread);

		edge_color = max(min((int)(dks_jobject_lock->count - 1), HTML_COLOR_MAX - 1), 0);
		dks_jobject_lock->count--;

		// Lock holder's callchain nodes and edges
		append_callchain_node_and_edge(callchain_entry_htable,
			json_object_node_htable, json_object_edge_htable, lock_entry,
			holder_callchain_id, thread, lock_node, nodes, edges, info,
			event_count, waiter_count, blocking_time, node_color, edge_color);
	}

	root = json_object_new_object();
	assert(root);
	json_object_object_add(root, "nodes", nodes);
	json_object_object_add(root, "edges", edges);
	json_object_object_add(root, "info", info);

	export_file_name = json_export_path_alloc();
	if (!export_file_name) {
		pr_err("No export file path specified.\n");
		dks_ht__free(json_object_edge_htable, NULL);
		dks_ht__free(json_object_node_htable, NULL);
		dks_ht__free(callchain_entry_htable, NULL);
		json_object_put(root);
		return;
	}

	// For more compact size, use json_object_to_file(export_file_name, root)
	if (json_object_to_file_ext(export_file_name, root, JSON_C_TO_STRING_PRETTY))
		pr_info("dks failed in reporting analyzed data in json.\n");
	else
		pr_info("dks succeeded in reporting analyzed data in json.\n");

	free(export_file_name);

	// All json_objects are owned by root. All objects will be freed by the line below.
	dks_ht__free(json_object_edge_htable, NULL);
	dks_ht__free(json_object_node_htable, NULL);
	dks_ht__free(callchain_entry_htable, NULL);
	json_object_put(root);
}

// We sort all lock objects in descending order based on its waiting time.
static void dks_report_results(struct perf_session *session)
{
	struct dks_ht *lock_ht;
	struct dks_hash_entry *hash_entry;
	struct dks_hash_entry **hash_entry_array;
	struct hlist_node *tmp;
	int column_index = 0;
	unsigned int bkt;
	size_t entry_count, i = 0;
	sqlite3 *db;
	char *zErrMsg;
	char temp[PATH_MAX];
	sqlite3_stmt *pStmt;
	/* change data type BUG!! uint64_t couldn't express correctly in SQLite */
	const char *create_sql =
		"CREATE TABLE lock_stat	\
		(id INT PRIMARY KEY, \
		type INT, \
		pid INT, \
		tid INT, \
		addr BLOB, \
		ips_id BLOB, \
		n_events INT, \
		n_waiters INT, \
		wait_time INT);";
	const char *insert_sql= "INSERT INTO lock_stat VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)";

	assert(session);
	lock_ht = session->lock_stats.lock_ht;
	if (!lock_ht)
		return;

	/* get total # of entries */
	entry_count = lock_ht->cnt;
	if (!entry_count) {
		pr_info("Lock stat hash table is empty\n");
		return;
	}

	hash_entry_array = (struct dks_hash_entry **)malloc(sizeof(struct dks_lock_entry *) * entry_count);
	if (!hash_entry_array) {
		pr_err("Failed to allocate report entry buffer\n");
		return;
	}

	/* create sqlite3 in-memory db */
	if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
		pr_err("Failed to open reporting database :%s\n", sqlite3_errmsg(db));
		goto out;
	}

	/* create table */
	if (sqlite3_exec(db, create_sql, NULL, NULL, &zErrMsg) != SQLITE_OK) {
		pr_err("failed to create table errmsg:%s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		goto out;
	}

	/* loop over all hash entries */
	dks_hash_for_each_safe(lock_ht->ht, bkt, tmp, hash_entry, node, lock_ht->sz) {
		struct dks_lock_entry *lock_entry = (struct dks_lock_entry *)hash_entry;

		/* reset column no */
		column_index = 0;

		/* prepare statement - compile */
		if (sqlite3_prepare(db, insert_sql, -1, &pStmt, 0) != SQLITE_OK) {
			pr_err("failed to prepare insert sql stmt errmsg:%s\n", zErrMsg);
			goto out;
		}

		sprintf(temp, "insert into lock_stat values(%ld, %u, %u, %u, %"PRIu64", "
			"%"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64");",
			i, lock_entry->lock_type, lock_entry->pid, lock_entry->tid,
			lock_entry->addr, lock_entry->ips_id, lock_entry->n_events,
			lock_entry->n_waiters, lock_entry->blocking_time);

		/* bind each variables */
		if (sqlite3_bind_int(pStmt, 1, i) != SQLITE_OK) {
			column_index = 1;
			goto out;
		}

		if (sqlite3_bind_int(pStmt, 2, lock_entry->lock_type) != SQLITE_OK) {
			column_index = 2;
			goto out;
		}

		if (sqlite3_bind_int(pStmt, 3, lock_entry->pid) != SQLITE_OK) {
			column_index = 3;
			goto out;
		}

		if (sqlite3_bind_int(pStmt, 4, lock_entry->tid) != SQLITE_OK) {
			column_index = 4;
			goto out;
		}

		if (sqlite3_bind_blob(pStmt, 5, (void *)&(lock_entry->addr),
			sizeof(lock_entry->addr), SQLITE_TRANSIENT) != SQLITE_OK) {
			column_index = 5;
			goto out;
		}

		if (sqlite3_bind_blob(pStmt, 6, (void *)&(lock_entry->ips_id),
			sizeof(lock_entry->ips_id), SQLITE_TRANSIENT) != SQLITE_OK) {
			column_index = 6;
			goto out;
		}

		if (sqlite3_bind_int64(pStmt, 7, lock_entry->n_events) != SQLITE_OK) {
			column_index = 7;
			goto out;
		}

		if (sqlite3_bind_int64(pStmt, 8, lock_entry->n_waiters) != SQLITE_OK) {
			column_index = 8;
			goto out;
		}

		if (sqlite3_bind_int64(pStmt, 9, lock_entry->blocking_time) != SQLITE_OK) {
			column_index = 9;
			goto out;
		}

		/* insert statement */
		if (sqlite3_step(pStmt) != SQLITE_DONE) {
			pr_err("failed to insert row %s\n err msg: %s\n", temp, sqlite3_errmsg(db));
			goto out;
		}
		sqlite3_finalize(pStmt);

		hash_entry_array[i++] = hash_entry;
		dks_debug("INSERTED STATEMENT : %s\n", temp);
	}

	if (!exports_json)
		show_results(session, db, hash_entry_array, entry_count);
	else
		export_results(session, db, hash_entry_array, entry_count);
out:
	if (column_index)
		pr_err("failed to bind column index: %d argument\n", column_index);

	sqlite3_close(db);
	free(hash_entry_array);
};

/*run dks cmd analyze - it is similar to perf report*/
int dks_cmd_analyze(int argc, const char **argv)
{
	int err = 0;
	struct perf_session *session;
	struct stat st;

	struct analyze analyze= {
		.tool = {
			.kdks_sample	= process_kdks_sample,
			.mmap           = perf_event__process_mmap,
			.mmap2          = perf_event__process_mmap2,
			.comm           = perf_event__process_comm,
			.exit           = perf_event__process_exit,
			.fork           = perf_event__process_fork,
			.ordered_events = true,
			.ordering_requires_timestamps = true,
		},
		.max_stack              = PERF_MAX_STACK_DEPTH,
	};

	struct option options[] = {
		OPT_BOOLEAN('e', "export", &exports_json, "export profile in json format"),
		OPT_STRING('i', "input", &input_file_name, "file", "input file name"),
		OPT_INTEGER('l', "limit", &limit_ranks, "# of output for the lock holders"),
		OPT_INCR('v', "verbose", &verbose, "be more verbose (show symbol address, etc)"),
		OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace, "dump raw trace in ASCII"),
		OPT_END()
	};

	struct perf_data_file file = {
		.mode  = PERF_DATA_MODE_READ,
	};

	pr_info("dks analyze start \n");
	symbol__init(NULL);

	/**************************************
	 *  Parse analyze specific options
	 **************************************/
	argc = parse_options(argc, argv, options, NULL, analyze_usage,
		PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc > 1)
		usage_with_options(analyze_usage, options);

	/*input file name*/
	if (!input_file_name || !strlen(input_file_name)) {
		if (!fstat(STDIN_FILENO, &st) && S_ISFIFO(st.st_mode))
			input_file_name = "-";
		else
			input_file_name = "dks_profile.data";
	}

	file.path = input_file_name;
	pr_info("target filename %s\n", input_file_name);

	session = perf_session__new(&file, &analyze.tool);
	if (!session)
		return -1;

	err = dks_lock_stat__build_stat_tables(&session->lock_stats);
	if (err)
		goto err_out;

	analyze.session = session;
	pr_info("setup analyze env. done\n");

	err = __cmd_analyze(&analyze);
	if (err) {
		pr_err("failed to analyze kdks sample data\n");
		goto err_out;
	}
	pr_info("process samples done, # of processed samples:%"PRIu64"\n", analyze.nr_entries);

	pr_info("dks prepare report analyze data\n");
	// FIXME: Add report policy and address location where debug info is available.
	dks_report_results(session);
err_out:
	dks_lock_stat__destroy_stat_tables(&session->lock_stats);
	perf_session__delete(session);

	pr_info("dks analyze done!\n");
	return err;
}
