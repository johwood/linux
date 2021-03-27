// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/lsm_hooks.h>
//#include <linux/math64.h>
//#include <linux/printk.h>
//#include <linux/refcount.h>
//#include <linux/rwlock.h>
//#include <linux/rwlock_types.h>
//#include <linux/sched.h>
//#include <linux/sched/signal.h>
//#include <linux/sched/task.h>
//#include <linux/slab.h>
//#include <linux/spinlock.h>
//#include <linux/types.h>

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
 * BRUTE_EMA_WEIGHT_NUMERATOR - Weight's numerator of EMA.
 */
static const u64 BRUTE_EMA_WEIGHT_NUMERATOR = 7;

/*
 * BRUTE_EMA_WEIGHT_DENOMINATOR - Weight's denominator of EMA.
 */
static const u64 BRUTE_EMA_WEIGHT_DENOMINATOR = 10;

/**
 * brute_mul_by_ema_weight() - Multiply by EMA weight.
 * @value: Value to multiply by EMA weight.
 *
 * Return: The result of the multiplication operation.
 */
static inline u64 brute_mul_by_ema_weight(u64 value)
{
	return mul_u64_u64_div_u64(value, BRUTE_EMA_WEIGHT_NUMERATOR,
				   BRUTE_EMA_WEIGHT_DENOMINATOR);
}

/*
 * BRUTE_MAX_FAULTS - Maximum number of faults.
 *
 * If a brute force attack is running slowly for a long time, the application
 * crash period's EMA is not suitable for the detection. This type of attack
 * must be detected using a maximum number of faults.
 */
static const unsigned int BRUTE_MAX_FAULTS = 200;

/**
 * brute_update_crash_period() - Update the application crash period.
 * @stats: Statistics that hold the application crash period to update. Cannot
 *         be NULL.
 * @now: The current timestamp in jiffies.
 *
 * The application crash period must be a value that is not prone to change due
 * to spurious data and follows the real crash period. So, to compute it, the
 * exponential moving average (EMA) is used.
 *
 * This kind of average defines a weight (between 0 and 1) for the new value to
 * add and applies the remainder of the weight to the current average value.
 * This way, some spurious data will not excessively modify the average and only
 * if the new values are persistent, the moving average will tend towards them.
 *
 * Mathematically the application crash period's EMA can be expressed as
 * follows:
 *
 * period_ema = period * weight + period_ema * (1 - weight)
 *
 * If the operations are applied:
 *
 * period_ema = period * weight + period_ema - period_ema * weight
 *
 * And finally, if the operands are ordered:
 *
 * period_ema = period_ema - period_ema * weight + period * weight
 */
static void brute_update_crash_period(struct brute_stats *stats, u64 now)
{
	u64 current_period;

	spin_lock(&stats->lock);
	current_period = now - stats->jiffies;

	WRITE_ONCE(stats->period,
		   stats->period - brute_mul_by_ema_weight(stats->period) +
		   brute_mul_by_ema_weight(current_period));

	if (stats->faults < BRUTE_MAX_FAULTS)
		WRITE_ONCE(stats->faults, stats->faults + 1);

	WRITE_ONCE(stats->jiffies, now);
	spin_unlock(&stats->lock);
}

/*
 * BRUTE_MIN_FAULTS - Minimum number of faults.
 *
 * The application crash period's EMA cannot be used until a minimum number of
 * data has been applied to it. This constraint allows getting a trend when this
 * moving average is used. Moreover, it avoids the scenario where an application
 * fails quickly from execve system call due to reasons unrelated to a real
 * attack.
 */
static const unsigned char BRUTE_MIN_FAULTS = 5;

/*
 * BRUTE_CRASH_PERIOD_THRESHOLD - Application crash period threshold.
 *
 * The units are expressed in milliseconds.
 *
 * A fast brute force attack is detected when the application crash period falls
 * below this threshold.
 */
static const u64 BRUTE_CRASH_PERIOD_THRESHOLD = 30000;

/**
 * brute_attack_running() - Test if a brute force attack is happening.
 * @stats: Statistical data shared by all the fork hierarchy processes. Cannot
 *         be NULL.
 *
 * The decision if a brute force attack is running is based on the statistical
 * data shared by all the fork hierarchy processes.
 *
 * There are two types of brute force attacks that can be detected using the
 * statistical data. The first one is a slow brute force attack that is detected
 * if the maximum number of faults per fork hierarchy is reached. The second
 * type is a fast brute force attack that is detected if the application crash
 * period falls below a certain threshold.
 *
 * Moreover, it is important to note that no attacks will be detected until a
 * minimum number of faults have occurred. This allows to have a trend in the
 * crash period when the EMA is used and also avoids the scenario where an
 * application fails quickly from execve system call due to reasons unrelated to
 * a real attack.
 *
 * Return: True if a brute force attack is happening. False otherwise.
 */
static bool brute_attack_running(const struct brute_stats *stats)
{
	u64 faults;
	u64 crash_period;

	faults = READ_ONCE(stats->faults);
	if (faults < BRUTE_MIN_FAULTS)
		return false;
	if (faults >= BRUTE_MAX_FAULTS)
		return true;

	crash_period = jiffies64_to_msecs(READ_ONCE(stats->period));
	return crash_period < BRUTE_CRASH_PERIOD_THRESHOLD;
}

/**
 * brute_print_fork_attack_running() - Warn about a fork brute force attack.
 */
static inline void brute_print_fork_attack_running(void)
{
	pr_warn("Fork brute force attack detected [pid %d, %s]\n", current->pid,
		current->comm);
}

/**
 * brute_manage_fork_attack() - Manage a fork brute force attack.
 * @stats: Statistical data shared by all the fork hierarchy processes. Cannot
 *         be NULL.
 * @now: The current timestamp in jiffies.
 *
 * For a correct management of a fork brute force attack it is only necessary to
 * update the statistics and test if an attack is happening based on these data.
 */
static void brute_manage_fork_attack(struct brute_stats *stats, u64 now)
{
	brute_update_crash_period(stats, now);
	if (brute_attack_running(stats))
		brute_print_fork_attack_running();
}

/**
 * brute_task_fatal_signal() - Target for the task_fatal_signal hook.
 * @siginfo: Contains the signal information.
 *
 * To detect a fork brute force attack it is necessary to update the fork
 * statistics in every fatal crash and act based on these data.
 *
 * To be defensive, the scenario where the current task has no statistics is
 * treated as an attack. Since in this case the current task is in the path to
 * be killed, only it is necessary to set to ERR the stats pointer.
 */
static void brute_task_fatal_signal(const kernel_siginfo_t *siginfo)
{
	struct brute_stats **stats;
	u64 now = get_jiffies_64();

	stats = brute_stats_ptr(current);
	if (WARN_ON_ONCE(IS_ERR_OR_NULL(*stats))) {
		WRITE_ONCE(*stats, ERR_PTR(-ESRCH));
		return;
	}

	brute_manage_fork_attack(*stats, now);
}

/*
 * brute_hooks - Targets for the LSM's hooks.
 */
static struct security_hook_list brute_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_alloc, brute_task_alloc),
	LSM_HOOK_INIT(bprm_committing_creds, brute_task_execve),
	LSM_HOOK_INIT(task_free, brute_task_free),
	LSM_HOOK_INIT(task_fatal_signal, brute_task_fatal_signal),
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
