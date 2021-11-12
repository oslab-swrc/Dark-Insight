#include <stdio.h>
#include <stdlib.h>

volatile int thread_stop;

void spin_two_cond_and(volatile int *lock)
{
	while(*lock == 0 && !thread_stop) ;
	if (!thread_stop)
		*lock = 1;
}

void spin_two_cond_or(volatile int *lock)
{
	while(*lock == 0 && !thread_stop) ;
	if (!thread_stop)
		*lock = 1;
}

int main(int argc, char *argv[])
{
	volatile int lock = 0;

	if (argc%2) {
		spin_two_cond_and(&lock);
	}
	else {
		spin_two_cond_or(&lock);
	}
	return 0;
}
