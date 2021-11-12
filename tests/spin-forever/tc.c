#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

int main(int argc, char *argv[])
{
	pthread_spinlock_t lock;
	
	pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);

	pthread_spin_lock(&lock);
	printf(">>> spinlock is acquired\n");

	printf("<<< acquiring the spinlock - forever spinning\n"); 
	pthread_spin_lock(&lock);
	return 0;
}
