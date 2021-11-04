/*
 * KDKS (Kernel module of Dark-Insight) entry point
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <kdks.h>
#include "kdks_i.h"

static bool g_is_running = false;

static long ioctl_kdks(struct file *file, unsigned int cmd,
		       unsigned long arg);

static const struct file_operations kdks_fops = {
	.owner          = THIS_MODULE,
	.open           = evbuf_open,
	.release        = evbuf_release,
	.mmap           = evbuf_mmap,
	.poll           = evbuf_poll,
	.unlocked_ioctl = ioctl_kdks,
	.llseek         = noop_llseek,
};

static struct miscdevice kdks_miscdev = {
	MISC_DYNAMIC_MINOR,
	"kdks",
	&kdks_fops
};

int init_common(void)
{
	int result = perf_get_callchain_buffers();
	if (result) {
		pr_err("failed to get callchain buffers\n");
		exit_callchain_ht();
		exit_idle_ht();
		exit_lock_obj_ht();
		perf_put_callchain_buffers();
		return result;
	}

	init_lock_obj_ht();
	init_idle_ht();
	init_callchain_ht();
	return result;
}

void exit_common(void)
{
	exit_callchain_ht();
	exit_idle_ht();
	exit_lock_obj_ht();

	if (!perf_has_callchain_buffers())
		return;
	perf_put_callchain_buffers();
}

static int init_probes(void __user *arg)
{
	int ret;
	struct kdks_attr kdks_attr;

	if (arg) {
		if (copy_from_user(&kdks_attr, arg, sizeof(struct kdks_attr)))
			return -EFAULT;
		pr_info("target pid %d\n", kdks_attr.pid);
	} else
		kdks_attr.pid = -1; /*set invalid number*/

	ret = init_common();
	if (unlikely(ret)) {
		pr_err("Fail to init common err %d\n", ret);
		return ret;
	}

	kdks_pr_info("Running mode for Dark Insight : %d\n", kdks_run_mode);

	switch(kdks_run_mode) {
	case KDKS_RUN_MODE_SPIN_ONLY:
		ret = init_spinprobe(kdks_attr);
		if (unlikely(ret)) {
			pr_err("Fail to init spinprobes err %d\n", ret);
			exit_common();
			return ret;
		}
		break;
	case KDKS_RUN_MODE_FTEX_ONLY:
		ret = init_futexprobe(kdks_attr);
		if (unlikely(ret)) {
			pr_err("Fail to init futexprobes err %d\n", ret);
			exit_common();
			return ret;
		}
		break;
	case KDKS_RUN_MODE_ALL:
		ret = init_spinprobe(kdks_attr);
		if (unlikely(ret)) {
			pr_err("Fail to init spinprobes err %d\n", ret);
			exit_common();
			return ret;
		}

		ret = init_futexprobe(kdks_attr);
		if (unlikely(ret)) {
			pr_err("Fail to init futexprobes err %d\n", ret);
			exit_spinprobe();
			exit_common();
			return ret;
		}
		break;
	default:
		pr_err("Wrong kdks_run_mode  = %d\n"
			"SPINLOOP ONLY kdks_run_mode = %d\n"
			"FUTEX ONLY kdks_run_mode = %d\n"
			"BOTH (Default) kdks_run_mode = %d\n",
			kdks_run_mode,
			KDKS_RUN_MODE_SPIN_ONLY,
			KDKS_RUN_MODE_FTEX_ONLY,
			KDKS_RUN_MODE_ALL);
		exit_common();
		return ret;
	}

	g_is_running = true;
	return 0;
}

static void exit_probes(void)
{
	if (!g_is_running)
		return;

	exit_spinprobe();
	exit_futexprobe();
	exit_common();

	g_is_running = false;
}

static long ioctl_kdks(struct file *filp, unsigned int cmd,
		       unsigned long arg)
{
	int ret;
	switch (cmd) {
	case KDKS_IOC_BIND_CPU:
		return evbuf_bind_cpu(filp, arg);
	case KDKS_IOC_START_ALL:
		pr_info("Start Profile.\n");
		ret = init_probes((void __user *)arg);
		return ret;
	case KDKS_IOC_STOP_ALL:
		exit_probes();
		pr_info("Stop Profile.\n");
		return 0;
	case KDKS_IOC_PUSH_SPININFO:
		return spintable__push_spininfo(arg);
	case __KDKS_IOC_EVBUF_PUT_3:
		return __evbuf_put_3(filp);
	case __KDKS_IOC_EVBUF_PUT_ENOUGH:
		return __evbuf_put_enough(filp);
	}
	return -ENOTTY;
}

static int __init init_kdks(void)
{
	int result = 0;

	init_evbuf();
	/* register its device file */
	result = misc_register(&kdks_miscdev);
	if (result < 0) {
		pr_err("Cannot register /dev/kdks device\n");
		return result;
	}

	pr_info("Install the kernel module of DarkInsight\n");
	return 0;
}

static void __exit exit_kdks(void)
{
	/* deregister device file */
	misc_deregister(&kdks_miscdev);

	/* deinit spinprobe if it running*/
	if (g_is_running)
		exit_probes();

	/* deinit event buffer */
	deinit_evbuf();

	pr_info("DarkInsight unloaded\n");
}

/*
 * module declaration
 */
unsigned int kdks_debug_level = 1;
EXPORT_SYMBOL(kdks_debug_level);

module_param_named(debug, kdks_debug_level, uint, 0);
MODULE_PARM_DESC(debug, "debug message level");

unsigned int kdks_run_mode = KDKS_RUN_MODE_ALL;
EXPORT_SYMBOL(kdks_run_mode);

module_param_named(run_mode, kdks_run_mode, uint, 0);
MODULE_PARM_DESC(run_mode, "kdks running mode, spinlock = 1, futex = 2, all = 3 (default)");

module_init(init_kdks)
module_exit(exit_kdks)

MODULE_AUTHOR("Changwoo Min <changwoo.min@gatech.edu>");
MODULE_AUTHOR("Woonhak Kang <woonhak.kang@gatech.edu>");
MODULE_LICENSE("GPL");

