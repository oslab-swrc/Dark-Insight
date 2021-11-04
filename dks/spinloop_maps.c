#include <stdlib.h>
#include <string.h>

#include "util/event.h"
#include "util/machine.h"
#include "util/util.h"
#include "util/debug.h"

#include <spintable.h>
#include <dks_ctrl.h>
#include <kdks_event_helper.h>
#include <spinloop_maps.h>

/*run command python script 'spnfind'*/
//#define SPINFIND_CMD_FMT "python3 %s -r -q --binfile %s\n"

const char *dks_map_type__names[DKS_MAP__NR_TYPES]={
	[DKS_MAP__UNKNOWN] = "unknown",
	[DKS_MAP__USER] = "user",
	[DKS_MAP__KERNEL] = "kernel",
	[DKS_MAP__KMOD] = "kernel_module",
};

/* debug - push target binary info only */
#define SPINFIND_CMD_FMT "python3 %s -q --binfile %s\n"
#define	BIN_PREFIX "# bin-"
#define	BIN_PREFIX_LEN	(6)

#define SPINLOOP_BUILD_LIMIT INT_MAX
//#define SPINLOOP_BUILD_LIMIT 2

/*create a spinloop map object*/
static struct spinloop_map *spinloop_map__new(char *filename)
{
	struct spinloop_map *map = malloc(sizeof(struct spinloop_map));
	if (!map)
		return NULL;

	/*int rb and list node*/
	RB_CLEAR_NODE(&map->rb_node);
	INIT_LIST_HEAD(&map->node);

	map->filename = (const char*)strdup((const char*)filename);
	//map->name_len = strlen(filename);
	map->start = 0;
	map->is_pic = false;
	map->map_type = DKS_MAP__UNKNOWN;
	return map;
}

/*create a spinloop map object*/
static struct spininfo_node *spininfo__new(u64 saddr, u64 eaddr, const char *str)
{
	size_t node_size = sizeof(struct spininfo_node) + strlen(str) + 1;
	struct spininfo_node *spin_info_node = malloc(node_size);
	if (!spin_info_node)
		return NULL;

	INIT_LIST_HEAD(&spin_info_node->node);

	struct spininfo *spin_info = &spin_info_node->spininfo;
	spin_info->saddr = saddr;
	spin_info->eaddr = eaddr;
	spin_info->len = strlen(str) + 1;

	/* copy spinstring */
	strncpy((char *)spin_info->spinstr, str, (size_t)spin_info->len);
	return spin_info_node;
}

/*add spinloop string to spinloop map object*/
static int add_spinloop_string(struct spinloop_map *map, char *spinstr)
{
	char *token;
	struct spininfo_node *spin_info;
	u64 saddr;
	u64 eaddr;

	/*parse start addr, eaddr*/
	token = strsep(&spinstr, ",");
	if (!token)
		return -EINVAL;
	saddr = strtoull(token, NULL, 16);

	token = strsep(&spinstr, ",");
	if (!token)
		return -EINVAL;
	eaddr = strtoull(token, NULL, 16);

	if (!spinstr) {
		dks_debug("skip spininfo: syncvar is empty \n");
		return 0;
	}

	dks_debug("spininfo str, saddr:0x%"PRIx64", eaddr:0x%"PRIx64", gas:%s\n",
		saddr, eaddr, spinstr);

	spin_info = spininfo__new(saddr, eaddr, (const char *)spinstr);
	if (!spin_info)
		return -ENOMEM;

	list_add_tail(&spin_info->node, &map->node);
	return 0;
}

/*insert a spinloop map object to spinloop_maps tree*/
static int spinloop_map__insert(struct spinloop_maps *maps, struct spinloop_map *map)
{
	struct rb_node **node = &maps->root.rb_node;
	struct rb_node *parent_node = NULL;
	const char *filename = map->filename;

	// Traverse tree
	while (*node) {
		struct spinloop_map *this = rb_entry(*node, struct spinloop_map, rb_node);
		dks_debug("map filename: %s, this->filename: %s\n", filename, this->filename);

		parent_node = *node;
		/* Duplication shouldn't happen, just pass current spinloop_map*/
		int rc = strcmp(filename, this->filename);
		if (!rc) {
			pr_warning("spinloop map duplicated :%s\n", filename);
			return 0;
		}

		node = rc < 0 ? &(*node)->rb_left : &(*node)->rb_right;
	}

	// Add spinloop map and rebalance
	rb_link_node(&map->rb_node, parent_node, node);
	rb_insert_color(&map->rb_node, &maps->root);
	return 0;
}

/*trim function name and comment*/
static char *trim_spininfo_str(char *str)
{
	/*kernel only can handle strlen(buf) < CMD_BUFSIZ*/
	if (strlen(str) > CMD_BUFSIZE) {
		pr_warning("spinloop string too long for kdks %lu, skip\n", strlen(str));
		return NULL;
	}

	char *token = strsep(&str, ",");
	if(!token)
		return NULL;

	/*copy rest of token until end of line*/
	token = strsep(&str, "#\n");
	return token;
}

/*parse filename and create dso map entry*/
static struct spinloop_map *gen_spinloop_map(char *str, u8 map_type) {
	struct spinloop_map *map = NULL;
	char *filename;

	/* The main difference between map_user and map_kernel
	   is a filename of the map.
	   Kernel map is handled by synthesized kernel_mmap,
	   so we have to replace the name with synthesized ones
	 */
	if (map_type == DKS_MAP__USER) {
		const bool is_fix = !strncmp(str, "fix", 3);
		str += is_fix ? 7 : 5;
		filename = strsep(&str, "\n");
		map = spinloop_map__new(filename);
		map->map_type = map_type;
		if (!is_fix)
			map->is_pic = true;
	} else if (map_type == DKS_MAP__KERNEL) {
		filename = "[kernel.kallsyms]";
		map = spinloop_map__new(filename);
		map->map_type = map_type;
	} else
		pr_err("map_type kmod is not processed yet\n");

	return map;
}

/*init spinloop maps*/
int spinloop_maps__init(struct spinloop_maps *maps){
	maps->root = RB_ROOT;
	return 0;
}

/*build spinloop information rbtree*/
/*run spinfinder and generate spininfo string.
  assume that a single line doesn't exceed glibc IO_BUFSIZ
  in: target binary name */
int __spinloop_maps__build_maps(struct spinloop_maps *maps, const char *exec_name,
	const char *script_path, u8 map_type)
{
	char cmd[CMD_BUFSIZE];
	char *buf = NULL;
	FILE *fp = NULL;
	int ret = 0;
	int debug_count=0;

	/*generate command line*/
	sprintf(cmd, SPINFIND_CMD_FMT, script_path, exec_name);
	fp = popen(cmd, "r");
	if (!fp) {
		pr_err("exec spinfinder fails - can't open pipe\n");
		return -EFAULT;
	}

	maps->bin_name = exec_name;
	buf = (char *)malloc(sizeof(char)*BUFSIZ);

	/*first iteration only process target binary,
	  directly push spinstring because it doesn't need to relocation*/
	struct spinloop_map *map = NULL;

	pr_info("Running spinfind target binary %s\n", exec_name);
	while (fgets(buf, BUFSIZ, fp)) {
		char *str;
		dks_debug("input str: %s", buf);
		if (SPINLOOP_BUILD_LIMIT != 0 && debug_count == SPINLOOP_BUILD_LIMIT)
			break;

		if (!strlen(buf))
			continue;

		/*binary name sting*/
		if (!strncmp(buf, BIN_PREFIX, BIN_PREFIX_LEN)) {
			/*parse binary string*/
			map = gen_spinloop_map(buf + BIN_PREFIX_LEN, map_type);
			if (!map) {
				pr_err("failed to allocate memory for spinloop map\n");
				ret = -ENOMEM;
				goto out;
			}

			ret = spinloop_map__insert(maps, map);
			if (ret)
				goto out;
			continue;
		}

		/*skip comment str*/
		if(buf[0] == '#' || buf[0] == '\n')
			continue;

		str = trim_spininfo_str(buf);
		if (!str)
			continue;

		dks_debug("spininfo str: %s\n", str);

		if (!map) {
			pr_err("spinloop map is allocated\n");
			continue;
		}
		/*add spinloop string to current map*/
		ret = add_spinloop_string(map, str);
		if (ret == -ENOMEM) {
			pr_err("failed to allocate spininfo\n");
			goto out;
		} else if (ret == -EINVAL) {
			pr_err("failed to decode spininfo string\n");
			goto out;
		}

		debug_count++;
	}
out:
	if (buf) {
		free(buf);
		buf = NULL;
	}

	ret = pclose(fp);
	if (ret == -1) {
		pr_err("run spin-finder exit with error: %s\n", strerror(errno));
		return -errno;
	}
	pr_info("Done binary analysis\n");
	return 0;
}

int spinloop_maps__build_maps(struct spinloop_maps *maps, const char *exec_name) {
	assert(exec_name);
	return __spinloop_maps__build_maps(maps, exec_name, g_spnf_path, DKS_MAP__USER);
}

/* build spinloop maps for kernel */
int spinloop_maps__build_kernel_maps(struct spinloop_maps *maps)
{
	const char *vmlinux_path = get_vmlinux_path();
	dks_debug("vmlinux path: %s\n", vmlinux_path);
	if (!vmlinux_path)
		return -1;
	return __spinloop_maps__build_maps(maps, vmlinux_path, g_spnf_path, DKS_MAP__KERNEL);
}

struct spinloop_map *spinloop_maps__find(struct spinloop_maps *maps, char *filename)
{
	struct rb_node **node = &maps->root.rb_node;

	/* XXX. fix spurious/non-interesting debugging msgs */
	dks_debug("target filename: %s\n", filename);

	while (*node) {
		int result;
		struct spinloop_map *this = rb_entry(*node, struct spinloop_map, rb_node);

		// FIXME: To identify kernel map, We might need to compare
		// the first char of the filename with '['. Because the file name
		// for kernel is [kernel.kallsyms].
		if (this->map_type == DKS_MAP__KERNEL)
			result = strncmp(filename, this->filename, 17);
		else {
			// FIXME: 1. Check kernel module name decoding.
			// 2. If necessary, separate out DKS_MAP__USER from DKS_MAP__KMOD.
			result = strcmp(filename, this->filename);
		}

		if (!result) {
			dks_debug("found target\n");
			return this;
		}

		dks_debug("strcmp result: %d, this->filename: %s\n", result, this->filename);

		node = result < 0 ? &(*node)->rb_left : &(*node)->rb_right;
	}

	dks_debug("No spinloop map for %s\n", filename);
	return NULL;
}

static int spinloop_maps__push_spininfo(struct spinloop_map *map)
{
	struct spininfo_node *node;

	dks_debug("map_event->filename: %s, start:0x%"PRIx64", pgoff:0x%"PRIx64", is_pic: %s\n",
		map->filename, map->start, map->pgoff, map->is_pic ? "true":"false");

	/*loop over spinloop info strings to push it into kernel */
	list_for_each_entry(node, &map->node, node) {
		int error = 0;
		struct spininfo *spin_info = &node->spininfo;

		dks_debug("spininfo map_type %s, 0x%llx[0x%llx], 0x%llx[0x%llx], %s\n",
			dks_map_type__names[map->map_type],
			spin_info->saddr, spin_info->saddr + map->start,
			spin_info->eaddr, spin_info->eaddr + map->start,
			spin_info->spinstr);

		// need to relocate address
		if (map->is_pic) {
			spin_info->saddr += map->start;
			spin_info->eaddr += map->start;
			spin_info->is_pic = true;
		} else
			spin_info->is_pic = false;

		spin_info->map_type = map->map_type;

		// error handling
		error = kdks__push_spininfo(spin_info);
		if (error) {
			pr_err("failed to add spininfo err %d, at 0x%llx[0x%llx], 0x%llx[0x%llx], %s\n",
				error, spin_info->saddr, spin_info->saddr + map->start,
				spin_info->eaddr, spin_info->eaddr + map->start,
				spin_info->spinstr);
			return error;
		}
	}
	return 0;
}

// build dso maps and push relocate address to kernel
int spinloop_maps__process_mmap2_event(struct perf_tool *tool, union perf_event *event,
	struct perf_sample *sample, struct machine *machine)
{
	char *filename = event->mmap2.filename;
	struct dks_ctrl *ctrl = container_of(tool, struct dks_ctrl, tool);
	struct spinloop_maps *maps = &ctrl->spin_maps;
	struct spinloop_map *map = NULL;
	u64 start = event->mmap2.start;
	u64 pgoff= event->mmap2.pgoff;

	u8 cpumode = event->header.misc & PERF_RECORD_MISC_CPUMODE_MASK;
	if (cpumode == PERF_RECORD_MISC_GUEST_KERNEL || cpumode == PERF_RECORD_MISC_KERNEL)
		pr_err("Need to Create spinloop maps for kernel\n");

	map = spinloop_maps__find(maps, filename);
	if (!map)
		return 0;

	// Set relocation info.
	// FIXME: pic code needs to be relocated.
	if(map->is_pic)
		map->start = start;
	map->pgoff = pgoff;

	return spinloop_maps__push_spininfo(map);
}

/*process mmap event.
  build dso maps and push relocate address to kernel*/
int spinloop_maps__process_mmap_event(struct perf_tool *tool, union perf_event *event,
	struct perf_sample *sample, struct machine *machine)
{
	char *filename = event->mmap.filename;
	struct dks_ctrl *ctrl = container_of(tool, struct dks_ctrl, tool);
	struct spinloop_maps *maps = &ctrl->spin_maps;
	struct spinloop_map *map = NULL;
	u64 start = event->mmap.start;
	u64 pgoff= event->mmap.pgoff;

	u8 cpumode = event->header.misc & PERF_RECORD_MISC_CPUMODE_MASK;
	if (cpumode == PERF_RECORD_MISC_GUEST_KERNEL || cpumode == PERF_RECORD_MISC_KERNEL) {
		dks_debug("kernel mapping event\n");
		perf_event__fprintf_mmap(event, stdout);
	}

	/*find map*/
	map = spinloop_maps__find(maps, filename);
	if (!map)
		return 0;

	// Set relocation info.
	// FIXME: pic code needs to be relocated.
	if (map->is_pic)
		map->start = start;
	map->pgoff = pgoff;

	return spinloop_maps__push_spininfo(map);
}

