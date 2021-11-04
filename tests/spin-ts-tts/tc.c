#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arch.h>


void spin_ts_lock(volatile int *lock)
{
	while(smp_swap(lock, 1)) ;
}

void spin_tts_lock(volatile int *lock)
{
	while(1) {
		if (*lock == 0 && smp_swap(lock, 1) == 0)
			return;
	}
}

void usage(FILE *out)
{
	extern const char *__progname;
	fprintf(out, "Usage: %s {ts | tts}\n", __progname);
}

const char *parse_option(int argc, char *argv[])
{
	const char *types[] = {"ts", "tts"};
	int ntypes = sizeof(types) / sizeof(*types);
	int i;

	if (argc != 2)
		return NULL;
	for (i = 0; i < ntypes; ++i) {
		if (!strcmp(argv[1], types[i]))
			return types[i];
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	volatile int lock = 1; /* locked */
	const char *type = NULL;

	type = parse_option(argc, argv);
	if (!type) {
		usage(stderr);
		return 1;
	}

	if (!strcmp(type, "ts")) {
		spin_ts_lock(&lock);
	}
	else if (!strcmp(type, "tts")) {
		spin_tts_lock(&lock);
	}

	return 0;
}
