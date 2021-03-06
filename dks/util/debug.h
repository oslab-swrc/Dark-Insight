/* For debugging general purposes */
#ifndef __PERF_DEBUG_H
#define __PERF_DEBUG_H

#include <stdbool.h>
#include <string.h>
#include "event.h"

extern int verbose;
extern bool quiet, dump_trace;
extern int debug_ordered_events;
extern int debug_data_convert;

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#define pr_err(fmt, ...) \
	eprintf(0, verbose, pr_fmt("[DKS ERR ]:" fmt), ##__VA_ARGS__)
#define pr_warning(fmt, ...) \
	eprintf(0, verbose, pr_fmt("[DKS WARN]:" fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	eprintf(0, verbose, pr_fmt("[DKS INFO]:" fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
	eprintf(1, verbose, pr_fmt("[DKS DBG ]:" fmt), ##__VA_ARGS__)
#define pr_debugN(n, fmt, ...) \
	eprintf(n, verbose, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug2(fmt, ...) pr_debugN(2, pr_fmt("[DKS DBG2]:"fmt), ##__VA_ARGS__)
#define pr_debug3(fmt, ...) pr_debugN(3, pr_fmt("[DKS DBG3]:"fmt), ##__VA_ARGS__)
#define pr_debug4(fmt, ...) pr_debugN(4, pr_fmt("[DKS DBG4]:"fmt), ##__VA_ARGS__)

#define pr_time_N(n, var, t, fmt, ...) \
	eprintf_time(n, var, t, fmt, ##__VA_ARGS__)

#define pr_oe_time(t, fmt, ...)  pr_time_N(1, debug_ordered_events, t, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_oe_time2(t, fmt, ...) pr_time_N(2, debug_ordered_events, t, pr_fmt(fmt), ##__VA_ARGS__)

#define STRERR_BUFSIZE	128	/* For the buffer size of strerror_r */

#define dks_debug(fmt, ...) \
	eprintf(1, verbose, pr_fmt("[DKS DBG at %s:%d]:" fmt), __func__, __LINE__, ##__VA_ARGS__)

int dump_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void trace_event(union perf_event *event);

int ui__error(const char *format, ...) __attribute__((format(printf, 1, 2)));
int ui__warning(const char *format, ...) __attribute__((format(printf, 1, 2)));

int eprintf(int level, int var, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
int eprintf_time(int level, int var, u64 t, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
int veprintf(int level, int var, const char *fmt, va_list args);

int perf_debug_option(const char *str);
void perf_debug_setup(void);

bool is_verbose(void);

#endif	/* __PERF_DEBUG_H */
