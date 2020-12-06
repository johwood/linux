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
#include <linux/math64.h>
#include <linux/printk.h>
#include <linux/refcount.h>
#include <linux/rwlock.h>
#include <linux/rwlock_types.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
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
 * brute_stats_ptr_lock - Lock to protect the brute_stats structure pointer.
 */
static DEFINE_RWLOCK(brute_stats_ptr_lock);

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

	stats = kmalloc(sizeof(struct brute_stats), GFP_ATOMIC);
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
 *
 * Context: Must be called with interrupts disabled and brute_stats_ptr_lock
 *          held.
 */
static void brute_share_stats(struct brute_stats *src,
			      struct brute_stats **dst)
{
	spin_lock(&src->lock);
	refcount_inc(&src->refc);
	*dst = src;
	spin_unlock(&src->lock);
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
 * It's mandatory to disable interrupts before acquiring brute_stats_ptr_lock
 * and brute_stats::lock since the task_free hook can be called from an IRQ
 * context during the execution of the task_alloc hook.
 *
 * Return: -ENOMEM if the allocation of the new statistics structure fails. Zero
 *         otherwise.
 */
static int brute_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	struct brute_stats **stats, **p_stats;
	unsigned long flags;

	stats = brute_stats_ptr(task);
	p_stats = brute_stats_ptr(current);
	write_lock_irqsave(&brute_stats_ptr_lock, flags);

	if (likely(*p_stats)) {
		brute_share_stats(*p_stats, stats);
		write_unlock_irqrestore(&brute_stats_ptr_lock, flags);
		return 0;
	}

	*stats = brute_new_stats();
	if (!*stats) {
		write_unlock_irqrestore(&brute_stats_ptr_lock, flags);
		return -ENOMEM;
	}

	brute_share_stats(*stats, p_stats);
	write_unlock_irqrestore(&brute_stats_ptr_lock, flags);
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
 * It's mandatory to disable interrupts before acquiring brute_stats_ptr_lock
 * and brute_stats::lock since the task_free hook can be called from an IRQ
 * context during the execution of the bprm_committing_creds hook.
 */
static void brute_task_execve(struct linux_binprm *bprm)
{
	struct brute_stats **stats;
	unsigned long flags;

	stats = brute_stats_ptr(current);
	read_lock_irqsave(&brute_stats_ptr_lock, flags);

	if (WARN(!*stats, "No statistical data\n")) {
		read_unlock_irqrestore(&brute_stats_ptr_lock, flags);
		return;
	}

	spin_lock(&(*stats)->lock);

	if (!refcount_dec_not_one(&(*stats)->refc)) {
		/* execve call after an execve call */
		(*stats)->faults = 0;
		(*stats)->jiffies = get_jiffies_64();
		(*stats)->period = 0;
		spin_unlock(&(*stats)->lock);
		read_unlock_irqrestore(&brute_stats_ptr_lock, flags);
		return;
	}

	/* execve call after a fork call */
	spin_unlock(&(*stats)->lock);
	read_unlock_irqrestore(&brute_stats_ptr_lock, flags);

	write_lock_irqsave(&brute_stats_ptr_lock, flags);
	*stats = brute_new_stats();
	WARN(!*stats, "Cannot allocate statistical data\n");
	write_unlock_irqrestore(&brute_stats_ptr_lock, flags);
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
	read_lock(&brute_stats_ptr_lock);

	if (WARN(!*stats, "No statistical data\n")) {
		read_unlock(&brute_stats_ptr_lock);
		return;
	}

	spin_lock(&(*stats)->lock);
	refc_is_zero = refcount_dec_and_test(&(*stats)->refc);
	spin_unlock(&(*stats)->lock);
	read_unlock(&brute_stats_ptr_lock);

	if (refc_is_zero) {
		write_lock(&brute_stats_ptr_lock);
		kfree(*stats);
		*stats = NULL;
		write_unlock(&brute_stats_ptr_lock);
	}
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
static const unsigned char BRUTE_MAX_FAULTS = 200;

/**
 * brute_update_crash_period() - Update the application crash period.
 * @stats: Statistics that hold the application crash period to update.
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
 * If the operands are ordered:
 *
 * period_ema = period_ema - period_ema * weight + period * weight
 *
 * Finally, this formula can be written as follows:
 *
 * period_ema -= period_ema * weight;
 * period_ema += period * weight;
 *
 * The statistics that hold the application crash period to update cannot be
 * NULL.
 *
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the task_fatal_signal hook.
 *
 * Context: Must be called with interrupts disabled and brute_stats_ptr_lock
 *          held.
 * Return: The last crash timestamp before updating it.
 */
static u64 brute_update_crash_period(struct brute_stats *stats, u64 now)
{
	u64 current_period;
	u64 last_crash_timestamp;

	spin_lock(&stats->lock);
	current_period = now - stats->jiffies;
	last_crash_timestamp = stats->jiffies;
	stats->jiffies = now;

	stats->period -= brute_mul_by_ema_weight(stats->period);
	stats->period += brute_mul_by_ema_weight(current_period);

	if (stats->faults < BRUTE_MAX_FAULTS)
		stats->faults += 1;

	spin_unlock(&stats->lock);
	return last_crash_timestamp;
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
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * The decision if a brute force attack is running is based on the statistical
 * data shared by all the fork hierarchy processes. This statistics cannot be
 * NULL.
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
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the task_fatal_signal hook.
 *
 * Context: Must be called with interrupts disabled and brute_stats_ptr_lock
 *          held.
 * Return: True if a brute force attack is happening. False otherwise.
 */
static bool brute_attack_running(struct brute_stats *stats)
{
	u64 crash_period;

	spin_lock(&stats->lock);
	if (stats->faults < BRUTE_MIN_FAULTS) {
		spin_unlock(&stats->lock);
		return false;
	}

	if (stats->faults >= BRUTE_MAX_FAULTS) {
		spin_unlock(&stats->lock);
		return true;
	}

	crash_period = jiffies64_to_msecs(stats->period);
	spin_unlock(&stats->lock);

	return crash_period < BRUTE_CRASH_PERIOD_THRESHOLD;
}

/**
 * print_fork_attack_running() - Warn about a fork brute force attack.
 */
static inline void print_fork_attack_running(void)
{
	pr_warn("Fork brute force attack detected [%s]\n", current->comm);
}

/**
 * brute_manage_fork_attack() - Manage a fork brute force attack.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 * @now: The current timestamp in jiffies.
 *
 * For a correct management of a fork brute force attack it is only necessary to
 * update the statistics and test if an attack is happening based on these data.
 *
 * The statistical data shared by all the fork hierarchy processes cannot be
 * NULL.
 *
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the task_fatal_signal hook.
 *
 * Context: Must be called with interrupts disabled and brute_stats_ptr_lock
 *          held.
 * Return: The last crash timestamp before updating it.
 */
static u64 brute_manage_fork_attack(struct brute_stats *stats, u64 now)
{
	u64 last_fork_crash;

	last_fork_crash = brute_update_crash_period(stats, now);
	if (brute_attack_running(stats))
		print_fork_attack_running();

	return last_fork_crash;
}

/**
 * brute_get_exec_stats() - Get the exec statistics.
 * @stats: When this function is called, this parameter must point to the
 *         current process' statistical data. When this function returns, this
 *         parameter points to the parent process' statistics of the fork
 *         hierarchy that hold the current process' statistics.
 *
 * To manage a brute force attack that happens through the execve system call it
 * is not possible to use the statistical data hold by this process due to these
 * statistics dissapear when this task is finished. In this scenario this data
 * should be tracked by the statistics of a higher fork hierarchy (the hierarchy
 * that contains the process that forks before the execve system call).
 *
 * To find these statistics the current fork hierarchy must be traversed up
 * until new statistics are found.
 *
 * Context: Must be called with tasklist_lock and brute_stats_ptr_lock held.
 */
static void brute_get_exec_stats(struct brute_stats **stats)
{
	const struct task_struct *task = current;
	struct brute_stats **p_stats;

	do {
		if (!task->real_parent) {
			*stats = NULL;
			return;
		}

		p_stats = brute_stats_ptr(task->real_parent);
		task = task->real_parent;
	} while (*stats == *p_stats);

	*stats = *p_stats;
}

/**
 * brute_update_exec_crash_period() - Update the exec crash period.
 * @stats: When this function is called, this parameter must point to the
 *         current process' statistical data. When this function returns, this
 *         parameter points to the updated statistics (statistics that track the
 *         info to manage a brute force attack that happens through the execve
 *         system call).
 * @now: The current timestamp in jiffies.
 * @last_fork_crash: The last fork crash timestamp before updating it.
 *
 * If this is the first update of the statistics used to manage a brute force
 * attack that happens through the execve system call, its last crash timestamp
 * (the timestamp that shows when the execve was called) cannot be used to
 * compute the crash period's EMA. Instead, the last fork crash timestamp should
 * be used (the last crash timestamp of the child fork hierarchy before updating
 * the crash period). This allows that in a brute force attack that happens
 * through the fork system call, the exec and fork statistics are the same. In
 * this situation, the mitigation method will act only in the processes that are
 * sharing the fork statistics. This way, the process that forked before the
 * execve system call will not be involved in the mitigation method. In this
 * scenario, the parent is not responsible of the child's behaviour.
 *
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the task_fatal_signal hook.
 *
 * Context: Must be called with interrupts disabled and tasklist_lock and
 *          brute_stats_ptr_lock held.
 * Return: -EFAULT if there are no exec statistics. Zero otherwise.
 */
static int brute_update_exec_crash_period(struct brute_stats **stats,
					  u64 now, u64 last_fork_crash)
{
	brute_get_exec_stats(stats);
	if (!*stats)
		return -EFAULT;

	spin_lock(&(*stats)->lock);
	if (!(*stats)->faults)
		(*stats)->jiffies = last_fork_crash;
	spin_unlock(&(*stats)->lock);

	brute_update_crash_period(*stats, now);
	return 0;
}

/**
 * brute_get_crash_period() - Get the application crash period.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * The statistical data shared by all the fork hierarchy processes cannot be
 * NULL.
 *
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the task_fatal_signal hook.
 *
 * Context: Must be called with interrupts disabled and brute_stats_ptr_lock
 *          held.
 * Return: The application crash period.
 */
static u64 brute_get_crash_period(struct brute_stats *stats)
{
	u64 crash_period;

	spin_lock(&stats->lock);
	crash_period = stats->period;
	spin_unlock(&stats->lock);

	return crash_period;
}

/**
 * print_exec_attack_running() - Warn about an exec brute force attack.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * The statistical data shared by all the fork hierarchy processes cannot be
 * NULL.
 *
 * Before showing the process name it is mandatory to find a process that holds
 * a pointer to the exec statistics.
 *
 * Context: Must be called with tasklist_lock and brute_stats_ptr_lock held.
 */
static void print_exec_attack_running(const struct brute_stats *stats)
{
	struct task_struct *p;
	struct brute_stats **p_stats;
	bool found = false;

	for_each_process(p) {
		p_stats = brute_stats_ptr(p);
		if (*p_stats == stats) {
			found = true;
			break;
		}
	}

	if (WARN(!found, "No exec process\n"))
		return;

	pr_warn("Exec brute force attack detected [%s]\n", p->comm);
}

/**
 * brute_manage_exec_attack() - Manage an exec brute force attack.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 * @now: The current timestamp in jiffies.
 * @last_fork_crash: The last fork crash timestamp before updating it.
 *
 * For a correct management of an exec brute force attack it is only necessary
 * to update the exec statistics and test if an attack is happening based on
 * these data.
 *
 * It is important to note that if the fork and exec crash periods are the same,
 * the attack test is avoided. This allows that in a brute force attack that
 * happens through the fork system call, the mitigation method does not act on
 * the parent process of the fork hierarchy.
 *
 * The statistical data shared by all the fork hierarchy processes cannot be
 * NULL.
 *
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the task_fatal_signal hook.
 *
 * Context: Must be called with interrupts disabled and tasklist_lock and
 *          brute_stats_ptr_lock held.
 */
static void brute_manage_exec_attack(struct brute_stats *stats, u64 now,
				     u64 last_fork_crash)
{
	int ret;
	struct brute_stats *exec_stats = stats;
	u64 fork_period;
	u64 exec_period;

	ret = brute_update_exec_crash_period(&exec_stats, now, last_fork_crash);
	if (WARN(ret, "No exec statistical data\n"))
		return;

	fork_period = brute_get_crash_period(stats);
	exec_period = brute_get_crash_period(exec_stats);
	if (fork_period == exec_period)
		return;

	if (brute_attack_running(exec_stats))
		print_exec_attack_running(exec_stats);
}

/**
 * brute_task_fatal_signal() - Target for the task_fatal_signal hook.
 * @siginfo: Contains the signal information.
 *
 * To detect a brute force attack is necessary to update the fork and exec
 * statistics in every fatal crash and act based on these data.
 *
 * It's mandatory to disable interrupts before acquiring brute_stats_ptr_lock
 * and brute_stats::lock since the task_free hook can be called from an IRQ
 * context during the execution of the task_fatal_signal hook.
 */
static void brute_task_fatal_signal(const kernel_siginfo_t *siginfo)
{
	struct brute_stats **stats;
	unsigned long flags;
	u64 last_fork_crash;
	u64 now = get_jiffies_64();

	stats = brute_stats_ptr(current);
	read_lock(&tasklist_lock);
	read_lock_irqsave(&brute_stats_ptr_lock, flags);

	if (WARN(!*stats, "No statistical data\n")) {
		read_unlock_irqrestore(&brute_stats_ptr_lock, flags);
		read_unlock(&tasklist_lock);
		return;
	}

	last_fork_crash = brute_manage_fork_attack(*stats, now);
	brute_manage_exec_attack(*stats, now, last_fork_crash);
	read_unlock_irqrestore(&brute_stats_ptr_lock, flags);
	read_unlock(&tasklist_lock);
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
