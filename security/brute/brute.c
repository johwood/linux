// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/lsm_hooks.h>

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
	unsigned int faults;
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
 * brute_get_stats() - Increase the statistics usage.
 * @stats: Statistical data shared by all the fork hierarchy processes. Cannot
 *         be NULL.
 */
static inline void brute_get_stats(struct brute_stats *stats)
{
	refcount_inc(&stats->refc);
}

/**
 * brute_print_no_stats_attack_running() - Warn about a no stats attack.
 * @task: Task that does not have statistical data.
 */
static inline void brute_print_no_stats_attack_running(struct task_struct *task)
{
	pr_warn_ratelimited("No stats attack detected [pid %d, %s]\n",
			    task->pid, task->comm);
}

/**
 * brute_manage_no_stats_attack() - Manage a no stats attack.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 * @task: Task that does not have statistical data.
 *
 * To be defensive, it's mandatory to kill the process if it has no statistics.
 * We must treat this as an attack. Moreover, set to ERR the stats pointer to
 * indicate that this has been done by the brute LSM.
 */
static void brute_manage_no_stats_attack(struct brute_stats **stats,
					 struct task_struct *task)
{
	WRITE_ONCE(*stats, ERR_PTR(-ESRCH));
	brute_print_no_stats_attack_running(task);
	do_send_sig_info(SIGKILL, SEND_SIG_PRIV, task, PIDTYPE_PID);
}

/**
 * brute_init_stats() - Initialize the statistical data.
 * @stats: Statistics to be initialized. Cannot be NULL.
 */
static inline void brute_init_stats(struct brute_stats *stats)
{
	spin_lock_init(&stats->lock);
	refcount_set(&stats->refc, 1);
	stats->jiffies = get_jiffies_64();
}

/*
 * brute_cache - Memory cache for the statistics structures.
 *
 * Since the allocation of brute_stats structures is tied to process creation,
 * it makes sense to have a dedicated cache.
 */
static struct kmem_cache *brute_cache __ro_after_init;

/**
 * brute_create_stats() - Allocate a new statistics structure.
 *
 * If the allocation is successful the reference counter is set to one to
 * indicate that there will be one task that points to this structure. Also, the
 * last crash timestamp is set to now. This way, it is possible to compute the
 * application crash period at the first fault.
 *
 * Return: -ENOMEM if the allocation fails. A pointer to the new allocated
 *         statistics structure if it success.
 */
static struct brute_stats *brute_create_stats(void)
{
	struct brute_stats *stats;

	stats = kmem_cache_zalloc(brute_cache, GFP_KERNEL);
	if (!stats)
		return ERR_PTR(-ENOMEM);

	brute_init_stats(stats);
	return stats;
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
 * To ensure this, allocate a new statistics structure for the init task (pid
 * equal to zero) when it doesn't have statistical data, since in this case it
 * is not possible to share the parent's statistics. Otherwise, share the
 * statistics that the current task (task that calls the fork system call)
 * already has.
 *
 * To be defensive, kill the current process if it has no statistics. Treat this
 * as an attack.
 *
 * Return: -ESRCH if there are no statistics. -ENOMEM if the allocation of the
 *         new statistics structure fails. Zero otherwise.
 */
static int brute_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	struct brute_stats **stats, **p_stats;

	stats = brute_stats_ptr(task);
	p_stats = brute_stats_ptr(current);

	if (likely(!IS_ERR_OR_NULL(*p_stats))) {
		brute_get_stats(*p_stats);
		WRITE_ONCE(*stats, *p_stats);
		return 0;
	}

	if (WARN_ON_ONCE(current->pid)) {
		brute_manage_no_stats_attack(p_stats, current);
		return -ESRCH;
	}

	WRITE_ONCE(*stats, brute_create_stats());
	if (WARN_ON_ONCE(IS_ERR(*stats)))
		return PTR_ERR(*stats);

	WRITE_ONCE(*p_stats, *stats);
	return 0;
}

/**
 * brute_reset_stats() - Reset the statistical data.
 * @stats: Statistics to be reset. Cannot be NULL.
 *
 * Reset the faults and period and set the last crash timestamp to now. This
 * way, it is possible to compute the application crash period at the next
 * fault.
 */
static void brute_reset_stats(struct brute_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	brute_init_stats(stats);
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
 * To be defensive, kill the current process if it has no statistics. Treat this
 * as an attack.
 */
static void brute_task_execve(struct linux_binprm *bprm)
{
	struct brute_stats **stats;

	stats = brute_stats_ptr(current);
	if (WARN_ON_ONCE(IS_ERR_OR_NULL(*stats))) {
		brute_manage_no_stats_attack(stats, current);
		return;
	}

	if (!refcount_dec_not_one(&(*stats)->refc)) {
		/* execve call after an execve call */
		brute_reset_stats(*stats);
		return;
	}

	/* execve call after a fork call */
	WRITE_ONCE(*stats, brute_create_stats());
	WARN_ON_ONCE(IS_ERR(*stats));
}

/**
 * brute_put_stats() - Decrease the statistics usage.
 * @stats: Statistical data shared by all the fork hierarchy processes. Cannot
 *         be NULL.
 */
static inline void brute_put_stats(struct brute_stats **stats)
{
	if (refcount_dec_and_test(&(*stats)->refc)) {
		kmem_cache_free(brute_cache, *stats);
		WRITE_ONCE(*stats, NULL);
	}
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

	stats = brute_stats_ptr(task);
	if (WARN_ON_ONCE(IS_ERR_OR_NULL(*stats)))
		return;

	brute_put_stats(stats);
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
 * brute_init_cache() - Initialize the cache for the statistics structures.
 */
static inline void __init brute_init_cache(void)
{
	brute_cache = kmem_cache_create("brute_cache",
					sizeof(struct brute_stats), 0,
					SLAB_PANIC, NULL);
}

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
	brute_init_cache();
	return 0;
}

DEFINE_LSM(brute) = {
	.name = KBUILD_MODNAME,
	.init = brute_init,
	.blobs = &brute_blob_sizes,
};
