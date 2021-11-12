void libspin_ts_lock(volatile int *lock, volatile unsigned *waiter_count);
void libspin_unlock(volatile int *lock);
