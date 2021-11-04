#ifndef __DKS_H__
#define __DKS_H__

#include <linux/perf_event.h>

/*dks control & helper headers*/
#include "dks_ctrl.h"
#include "perf_helper.h"
#include "poll_helper.h"

/*kernel dks event headers*/
#include <kdks.h>
#include <mtest.h>
#include <kdks_event.h>
#include "kdks_event_helper.h"
#include <dks_common.h>

#define DEFAULT_DUMP_STACK_SIZE	(8192)

/* dks commands */
int dks_cmd_profile(int argc, const char **argv);
int dks_cmd_analyze(int argc, const char **argv);
int dks_cmd_deadlock(int argc, const char **argv);

/* for dks analyze output control */
extern bool exports_json;
extern int limit_ranks;

#endif /* __DKS_H__ */

