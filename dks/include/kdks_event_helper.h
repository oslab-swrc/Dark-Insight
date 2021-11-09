// SPDX-License-Identifier: MIT
#ifndef __KDKS_EVENT_HELPER_H__
#define __KDKS_EVENT_HELPER_H__

#include "kdks_event.h"

/*forward decl*/
struct dsk_ctrl;

/*close all open files and free fds*/
int  kdks__event_open_allcpus(struct dks_ctrl *ctrl);
void kdks__exit(struct dks_ctrl *ctrl);
void kdks__run_test(int nr_cpus);
int  kdks__start_profile_all(struct kdks_attr *attr);
int  kdks__stop_profile_all(void);
int  kdks__push_spininfo(struct spininfo *spininfo);
int  kdks__evbuf_get(int idx, struct ring_buffer_req_t *ev_req);
void kdks__evbuf_get_done(int idx, struct ring_buffer_req_t *ev_req);

#endif /* end of __KDKS_EVENT_HELPER_H__ */
