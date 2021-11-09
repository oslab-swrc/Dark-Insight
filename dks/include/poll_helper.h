// SPDX-License-Identifier: MIT
#ifndef __DKS_POLL_HELPER_H__
#define __DKS_POLL_HELPER_H__

/*perf wrappers*/
int	perf__init_pollfds(int nr);
void	perf__assign_pollfd(int idx, int fd);
int 	perf__event_poll(int nr);
void	perf__free_pollfds(void);
short   perf__get_poll_revent(int idx);
void 	perf__set_poll_revent(int idx, short val);

/*kdks wrappers*/
int	kdks__init_pollfds(int nr);
void	kdks__assign_pollfd(int idx, int fd);
int 	kdks__event_poll(int nr);
void	kdks__free_pollfds(void);
short   kdks__get_poll_revent(int idx);
void 	kdks__set_poll_revent(int idx, short val);
#endif
