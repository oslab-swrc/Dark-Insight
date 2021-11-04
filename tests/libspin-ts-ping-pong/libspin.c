#include "arch.h"

#define atomic_inc(x) __sync_fetch_and_add(&x, 1)
#define atomic_dec(x) __sync_fetch_and_sub(&x, 1)

volatile int libspin_lock = 0;	/* unlocked*/

void libspin_ts_lock(volatile int *lock, volatile unsigned *waiter_count)
{
	atomic_inc(*waiter_count);
	while(smp_swap(&libspin_lock, 1)) {
	};
	atomic_dec(*waiter_count);
}

void libspin_unlock(volatile int *lock)
{
	smp_rmb();
	libspin_lock = 0;
}
