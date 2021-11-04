#if defined(__i386__) || defined(__x86_64__)
#include "../arch/x86/include/asm/barrier.h"
#else
#include <asm-generic/barrier.h>
#endif
