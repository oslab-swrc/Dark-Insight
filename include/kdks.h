#ifndef _KDKS_H
#define _KDKS_H
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/perf_event.h>

struct spininfo;

struct kdks_attr {
	pid_t pid;      /* user pid to be profiled */
};

#define KDKS_IOC_BIND_CPU    		_IOR('K', 0, unsigned int)
#define KDKS_IOC_START_ALL    		_IOR('K', 1, struct kdks_attr *)
#define KDKS_IOC_STOP_ALL     		_IO ('K', 2)
#define KDKS_IOC_PUSH_SPININFO		_IOR('K', 3, struct spininfo *)
#define KDKS_IOC_PUSH_SPINSTR		_IOR('K', 4, char *)

#define __KDKS_IOC_EVBUF_PUT_3        _IO ('K', 5) /* test scaffold */
#define __KDKS_IOC_EVBUF_PUT_ENOUGH   _IO ('K', 6) /* test scaffold */
#define __KDKS_POISON                 0xDEADBEEFBAD22222

#endif /* _KDKS_H */
