// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/current.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/printk.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/**
 * struct brute_stats - Fork brute force attack statistics.
 * @lock: Lock to protect the brute_stats structure.
 * @refc: Reference counter.
 * @faults: Number of crashes.
 * @jiffies: Last crash timestamp.
 * @period: Crash period's moving average.
 *
 * This structure holds the statistical data shared by all the fork hierarchy
 * processes.
 */
struct brute_stats {
	spinlock_t lock;
	refcount_t refc;
	unsigned char faults;
	u64 jiffies;
	u64 period;
};

/*
 * brute_blob_sizes - LSM blob sizes.
 *
 * To share statistical data among all the fork hierarchy processes, define a
 * pointer to the brute_stats structure as a part of the task_struct's security
 * blob.
 */
static struct lsm_blob_sizes brute_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct brute_stats *),
};

/**
 * brute_stats_ptr() - Get the pointer to the brute_stats structure.
 * @task: Task that holds the statistical data.
 *
 * Return: A pointer to a pointer to the brute_stats structure.
 */
static inline struct brute_stats **brute_stats_ptr(struct task_struct *task)
{
	return task->security + brute_blob_sizes.lbs_task;
}

/**
 * brute_new_stats() - Allocate a new statistics structure.
 *
 * If the allocation is successful the reference counter is set to one to
 * indicate that there will be one task that points to this structure. Also, the
 * last crash timestamp is set to now. This way, it is possible to compute the
 * application crash period at the first fault.
 *
 * Return: NULL if the allocation fails. A pointer to the new allocated
 *         statistics structure if it success.
 */
static struct brute_stats *brute_new_stats(void)
{
	struct brute_stats *stats;

	stats = kmalloc(sizeof(struct brute_stats), GFP_KERNEL);
	if (!stats)
		return NULL;

	spin_lock_init(&stats->lock);
	refcount_set(&stats->refc, 1);
	stats->faults = 0;
	stats->jiffies = get_jiffies_64();
	stats->period = 0;

	return stats;
}

/**
 * brute_share_stats() - Share the statistical data between processes.
 * @src: Source of statistics to be shared.
 * @dst: Destination of statistics to be shared.
 *
 * Copy the src's pointer to the statistical data structure to the dst's pointer
 * to the same structure. Since there is a new process that shares the same
 * data, increase the reference counter. The src's pointer cannot be NULL.
 *
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the task_alloc hook.
 */
static void brute_share_stats(struct brute_stats *src,
			      struct brute_stats **dst)
{
	unsigned long flags;

	spin_lock_irqsave(&src->lock, flags);
	refcount_inc(&src->refc);
	*dst = src;
	spin_unlock_irqrestore(&src->lock, flags);
}

/**
 * brute_task_alloc() - Target for the task_alloc hook.
 * @task: Task being allocated.
 * @clone_flags: Contains the flags indicating what should be shared.
 *
 * For a correct management of a fork brute force attack it is necessary that
 * all the tasks hold statistical data. The same statistical data needs to be
 * shared between all the tasks that hold the same memory contents or in other
 * words, between all the tasks that have been forked without any execve call.
 *
 * To ensure this, if the current task doesn't have statistical data when forks,
 * it is mandatory to allocate a new statistics structure and share it between
 * this task and the new one being allocated. Otherwise, share the statistics
 * that the current task already has.
 *
 * Return: -ENOMEM if the allocation of the new statistics structure fails. Zero
 *         otherwise.
 */
static int brute_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	struct brute_stats **stats, **p_stats;

	stats = brute_stats_ptr(task);
	p_stats = brute_stats_ptr(current);

	if (likely(*p_stats)) {
		brute_share_stats(*p_stats, stats);
		return 0;
	}

	*stats = brute_new_stats();
	if (!*stats)
		return -ENOMEM;

	brute_share_stats(*stats, p_stats);
	return 0;
}

/**
 * brute_task_execve() - Target for the bprm_committing_creds hook.
 * @bprm: Points to the linux_binprm structure.
 *
 * When a forked task calls the execve system call, the memory contents are set
 * with new values. So, in this scenario the parent's statistical data no need
 * to be shared. Instead, a new statistical data structure must be allocated to
 * start a new hierarchy. This condition is detected when the statistics
 * reference counter holds a value greater than or equal to two (a fork always
 * sets the statistics reference counter to a minimum of two since the parent
 * and the child task are sharing the same data).
 *
 * However, if the execve function is called immediately after another execve
 * call, althought the memory contents are reset, there is no need to allocate
 * a new statistical data structure. This is possible because at this moment
 * only one task (the task that calls the execve function) points to the data.
 * In this case, the previous allocation is used but the statistics are reset.
 *
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the bprm_committing_creds hook.
 */
static void brute_task_execve(struct linux_binprm *bprm)
{
	struct brute_stats **stats;
	unsigned long flags;

	stats = brute_stats_ptr(current);
	if (WARN(!*stats, "No statistical data\n"))
		return;

	spin_lock_irqsave(&(*stats)->lock, flags);

	if (!refcount_dec_not_one(&(*stats)->refc)) {
		/* execve call after an execve call */
		(*stats)->faults = 0;
		(*stats)->jiffies = get_jiffies_64();
		(*stats)->period = 0;
		spin_unlock_irqrestore(&(*stats)->lock, flags);
		return;
	}

	/* execve call after a fork call */
	spin_unlock_irqrestore(&(*stats)->lock, flags);
	*stats = brute_new_stats();
	WARN(!*stats, "Cannot allocate statistical data\n");
}

/**
 * brute_task_free() - Target for the task_free hook.
 * @task: Task about to be freed.
 *
 * The statistical data that is shared between all the fork hierarchy processes
 * needs to be freed when this hierarchy disappears.
 */
static void brute_task_free(struct task_struct *task)
{
	struct brute_stats **stats;
	bool refc_is_zero;

	stats = brute_stats_ptr(task);
	if (WARN(!*stats, "No statistical data\n"))
		return;

	spin_lock(&(*stats)->lock);
	refc_is_zero = refcount_dec_and_test(&(*stats)->refc);
	spin_unlock(&(*stats)->lock);

	if (refc_is_zero) {
		kfree(*stats);
		*stats = NULL;
	}
}

/*
 * brute_hooks - Targets for the LSM's hooks.
 */
static struct security_hook_list brute_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_alloc, brute_task_alloc),
	LSM_HOOK_INIT(bprm_committing_creds, brute_task_execve),
	LSM_HOOK_INIT(task_free, brute_task_free),
};

/**
 * brute_init() - Initialize the brute LSM.
 *
 * Return: Always returns zero.
 */
static int __init brute_init(void)
{
	pr_info("Brute initialized\n");
	security_add_hooks(brute_hooks, ARRAY_SIZE(brute_hooks),
			   KBUILD_MODNAME);
	return 0;
}

DEFINE_LSM(brute) = {
	.name = KBUILD_MODNAME,
	.init = brute_init,
	.blobs = &brute_blob_sizes,
};
