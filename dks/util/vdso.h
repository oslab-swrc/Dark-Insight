#ifndef __DKS_VDSO_H__
#define __DKS_VDSO_H__

#include <linux/types.h>
#include <string.h>
#include <stdbool.h>

#define VDSO__MAP_NAME "[vdso]"

#define DSO__NAME_VDSO    "[vdso]"
#define DSO__NAME_VDSO32  "[vdso32]"
#define DSO__NAME_VDSOX32 "[vdsox32]"

struct dso;
struct machine;
struct thread;

static inline bool is_vdso_map(const char *filename)
{
	return !strcmp(filename, VDSO__MAP_NAME);
}

bool dso__is_vdso(struct dso *dso);
struct dso *machine__findnew_vdso(struct machine *machine, struct thread *thread);
void machine__exit_vdso(struct machine *machine);

#endif /* __DKS_VDSO_H__ */
