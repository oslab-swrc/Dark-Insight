#ifndef __DKS_SPINLOOP_MAPS_H__
#define __DKS_SPINLOOP_MAPS_H__

/*TODO - build-id might helpful to cache dso spinloop*/
//#include "../util/build-id.h" 

#include "../util/dso.h"
#include "../util/event.h"
#include "spintable.h"

#define CMD_BUFSIZE	(256)

extern const char *dks_map_type__names[DKS_MAP__NR_TYPES];

struct dks_ctrl;

/*shared library spinloop info string.*/
struct spinloop_maps{
	struct rb_root	root;
	const char 	*bin_name;
};

struct spinloop_map{
	struct rb_node 	 rb_node;	/*long name search*/
	struct list_head node;		/*list head for spininfo entries*/
	u8		 map_type;	/*kernel, kmod, user */
	const char 	 *filename;	/*absolute file path of dso, searh key*/
	//u16		 name_len;	/*length of filename*/
	u64		 start;		/*map start address for relocation*/
	u64		 pgoff;		/*page offset*/
	bool		 is_pic;	/*how to map ip to spininfo?*/
};

struct spininfo_node{
	struct list_head node;		/*list head for spininfo entries*/
	struct spininfo  spininfo;	/*spininfo, start/end/ASM string*/
};

int spinloop_maps__init(struct spinloop_maps *maps);
int spinloop_maps__build_maps(struct spinloop_maps *maps, const char *exec_name);
int spinloop_maps__build_kernel_maps(struct spinloop_maps *maps);
int __spinloop_maps__build_maps(struct spinloop_maps *maps,
		const char *exec_name, const char *script_path, u8 map_type);

/*find spinloop map object using filename*/
struct spinloop_map *spinloop_maps__find(struct spinloop_maps *maps, char *filename);
int spinloop_maps__process_mmap2_event(struct perf_tool *tool, union perf_event *event,
		struct perf_sample *sample, struct machine *machine);
int spinloop_maps__process_mmap_event(struct perf_tool *tool, union perf_event *event,
		struct perf_sample *sample, struct machine *machine);

#endif /* __DKS_SPINLOOP_MAPS_H__ */
