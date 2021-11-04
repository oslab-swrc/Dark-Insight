#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/types.h>
#include <mtest.h>
#include <getopt.h>

#include <dks_common.h>
#include <spintable.h>
#include <util/debug.h>
#include <include/spinloop_maps.h>

struct cmd_opt{
	char *target;
	u8 map_type;
};

struct cmd_opt opt;

struct option options[] = {
	{"target", required_argument, 0, 't'},
	{"map_type", required_argument, 0, 'm'},
};

static int parse_option(int argc,
		char *argv[],
		struct cmd_opt *opt){
	int arg_cnt;
	int c, idx;

	for (arg_cnt = 0; 1; ++arg_cnt) {
		c = getopt_long(argc, argv,
				"t:m:", options, &idx);
		if (c == -1)
			break;

		switch(c){
			case 't':
				opt->target = optarg;
				break;
			case 'm':
				if(strcmp("user", optarg))
					opt->map_type = DKS_MAP__USER;
				else if(strcmp("kernel", optarg))
					opt->map_type = DKS_MAP__KERNEL;
				else if(strcmp("kmod", optarg))
					opt->map_type = DKS_MAP__KMOD;
				else {
					pr_err("%s is wrong map_type \n", optarg);
					return -1;
				}
				break;
			default:
				return -1;
				break;
		}
	}

	return arg_cnt;
}

static int show_usage(void){
	printf("usage: ./tc --target binary_name --map_type {kernel|user|kmod}\n"
	       "e.g) : ./tc --target /lib/x86_64-linux-gnu/libc-2.19.so --map_type user\n");

	return 0;
}

static int
build_spintable_from_spininfo(struct spininfo *s){
	struct spin_entry *e;
	mtest(true, "spininfo str:%s", s->spinstr);
	e = spintable__decode_spinstr(s->spinstr);

	if(IS_ERR(e)){
		return PTR_ERR(e);
	}
	ut_print_spinentry(e);

	return 0;
}

static void iterate_spinloop_map(struct spinloop_map *map){
	struct spininfo_node *node;
	/*loop over spinloop info strings to push it into kernel */
	list_for_each_entry(node, &map->node, node){
		struct spininfo *i = &node->spininfo;
		if(build_spintable_from_spininfo(i)){
			mtest(false, "failed to parse map->file:%s "
			       "string %s",
			       map->filename,
			       (char *)i->spinstr);
			break;
		}
	}
}

static void traverse_spinloop_maps(struct spinloop_maps *maps){
	struct rb_root *root = &maps->root;
	struct rb_node *rb;

	for (rb = rb_first(root); rb; rb = rb_next(rb)) {
		struct spinloop_map *map = rb_entry_safe(rb, struct spinloop_map, rb_node);
		pr_info("map_event->filename:%s, start:0x%"PRIx64
			", pgoff:0x%"PRIx64", is_pic:%s\n",
			map->filename, map->start, map->pgoff,
			map->is_pic ? "true":"false");

		iterate_spinloop_map(map);
	}
}

int main(int argc, char *argv[])
{
	int err;
	struct spinloop_maps maps;

	if(parse_option(argc, argv, &opt) < 2)
		return show_usage();

	/*set debug output*/
	perf_debug_option("verbose");

	spinloop_maps__init(&maps);

	pr_info("target : %s\n", opt.target);

	/*build spinloop maps*/
	err = __spinloop_maps__build_maps(&maps, opt.target, "../../../spin-finder/spnfind",
			opt.map_type);
	mtest(!err, "Spinloop map build done");
	if(err)
		return err;

	/*iterate over spinloop maps for test parsing*/
	traverse_spinloop_maps(&maps);

	return 0;
}
