// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/current.h>
#include <asm/rwonce.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/lsm_hooks.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/refcount.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>

/**
 * brute_timestamps_list_size - Last crashes timestamps list size.
 *
 * The application crash period is the time between the execve system call and
 * the first fault or the time between two consecutives faults, but this has a
 * drawback. If an application crashes once quickly from the execve system call
 * or crashes twice in a short period of time for some reason, a false positive
 * attack will be triggered. To avoid this scenario use a list of the i last
 * crashes timestamps and compute the application crash period as follows:
 *
 * crash_period = (n_last_timestamp - n_minus_i_timestamp) / i;
 *
 * The brute_timestamps_list_size variable sets the size of this list.
 */
static unsigned int brute_timestamps_list_size __read_mostly = 5;

/**
 * brute_crash_period_threshold - Application crash period threshold.
 *
 * The units are expressed in milliseconds.
 *
 * A fork brute force attack will be detected if the application crash period
 * falls under this threshold. So, the higher this value, the more sensitive the
 * detection will be.
 */
static unsigned int brute_crash_period_threshold __read_mostly = 30000;

/**
 * struct brute_stats - Fork brute force attack statistics.
 * @lock: Lock to protect the brute_stats structure.
 * @refc: Reference counter.
 * @timestamps: Last crashes timestamps list.
 * @timestamps_size: Last crashes timestamps list size.
 *
 * This structure holds the statistical data shared by all the fork hierarchy
 * processes.
 */
struct brute_stats {
	spinlock_t lock;
	refcount_t refc;
	struct list_head timestamps;
	unsigned char timestamps_size;
};

/**
 * struct brute_timestamp - Last crashes timestamps list entry.
 * @jiffies: Crash timestamp.
 * @node: Entry list head.
 *
 * This structure holds a crash timestamp.
 */
struct brute_timestamp {
	u64 jiffies;
	struct list_head node;
};

/**
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
 * brute_new_timestamp() - Allocate a new timestamp structure.
 *
 * If the allocation is successful the timestamp is set to now.
 *
 * Return: NULL if the allocation fails. A pointer to the new allocated
 *         timestamp structure if it success.
 */
static struct brute_timestamp *brute_new_timestamp(void)
{
	struct brute_timestamp *timestamp;

	timestamp = kmalloc(sizeof(struct brute_timestamp), GFP_KERNEL);
	if (timestamp)
		timestamp->jiffies = get_jiffies_64();

	return timestamp;
}

/**
 * brute_new_stats() - Allocate a new statistics structure.
 *
 * If the allocation is successful the reference counter is set to one to
 * indicate that there will be one task that points to this structure. The last
 * crashes timestamps list is initialized with one entry set to now. This way,
 * its possible to compute the application crash period at the first fault.
 *
 * Return: NULL if the allocation fails. A pointer to the new allocated
 *         statistics structure if it success.
 */
static struct brute_stats *brute_new_stats(void)
{
	struct brute_stats *stats;
	struct brute_timestamp *timestamp;

	stats = kmalloc(sizeof(struct brute_stats), GFP_KERNEL);
	if (!stats)
		return NULL;

	timestamp = brute_new_timestamp();
	if (!timestamp) {
		kfree(stats);
		return NULL;
	}

	spin_lock_init(&stats->lock);
	refcount_set(&stats->refc, 1);
	INIT_LIST_HEAD(&stats->timestamps);
	list_add_tail(&timestamp->node, &stats->timestamps);
	stats->timestamps_size = 1;

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
 * It's mandatory to disable interrupts before acquiring the lock since the
 * task_free hook can be called from an IRQ context during the execution of the
 * task_alloc hook.
 */
static void brute_share_stats(struct brute_stats **src,
			      struct brute_stats **dst)
{
	unsigned long flags;

	spin_lock_irqsave(&(*src)->lock, flags);
	refcount_inc(&(*src)->refc);
	*dst = *src;
	spin_unlock_irqrestore(&(*src)->lock, flags);
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
		brute_share_stats(p_stats, stats);
		return 0;
	}

	*stats = brute_new_stats();
	if (!*stats)
		return -ENOMEM;

	brute_share_stats(stats, p_stats);
	return 0;
}

/**
 * brute_reset_stats() - Reset the statistical data.
 * @stats: Statistics to be reset.
 *
 * Ensure that the last crashes timestamps list holds only one entry and set
 * this timestamp to now. This way, its possible to compute the application
 * crash period at the next fault. The statistics to be reset cannot be NULL.
 *
 * Context: Must be called with stats->lock held.
 */
static void brute_reset_stats(struct brute_stats *stats)
{
	unsigned char entries_to_delete;
	struct brute_timestamp *timestamp, *next;

	if (WARN(!stats->timestamps_size, "No last timestamps\n"))
		return;

	entries_to_delete = stats->timestamps_size - 1;
	stats->timestamps_size = 1;

	list_for_each_entry_safe(timestamp, next, &stats->timestamps, node) {
		if (unlikely(!entries_to_delete)) {
			timestamp->jiffies = get_jiffies_64();
			break;
		}

		list_del(&timestamp->node);
		kfree(timestamp);
		entries_to_delete -= 1;
	}
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
 * It's mandatory to disable interrupts before acquiring the lock since the
 * task_free hook can be called from an IRQ context during the execution of the
 * bprm_committing_creds hook.
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
		brute_reset_stats(*stats);
		spin_unlock_irqrestore(&(*stats)->lock, flags);
		return;
	}

	/* execve call after a fork call */
	spin_unlock_irqrestore(&(*stats)->lock, flags);
	*stats = brute_new_stats();
	WARN(!*stats, "Cannot allocate statistical data\n");
}

/**
 * brute_timestamps_free() - Empty a last crashes timestamp list.
 * @timestamps: Last crashes timestamps list to be emptied.
 *
 * Empty the last crashes timestamps list and deallocate all the entries. This
 * list cannot be NULL.
 *
 * Context: Must be called with stats->lock held.
 */
static void brute_timestamps_free(struct list_head *timestamps)
{
	struct brute_timestamp *timestamp, *next;

	if (list_empty(timestamps))
		return;

	list_for_each_entry_safe(timestamp, next, timestamps, node) {
		list_del(&timestamp->node);
		kfree(timestamp);
	}
}

/**
 * brute_stats_free() - Deallocate a statistics structure.
 * @stats: Statistics to be freed.
 *
 * Deallocate all the last crashes timestamps list entries and then the
 * statistics structure. The statistics to be freed cannot be NULL.
 *
 * Context: Must be called with stats->lock held and this function releases it.
 */
static void brute_stats_free(struct brute_stats *stats)
{
	brute_timestamps_free(&stats->timestamps);
	spin_unlock(&stats->lock);
	kfree(stats);
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
	if (WARN(!*stats, "No statistical data\n"))
		return;

	spin_lock(&(*stats)->lock);

	if (refcount_dec_and_test(&(*stats)->refc))
		brute_stats_free(*stats);
	else
		spin_unlock(&(*stats)->lock);
}

/**
 * brute_add_timestamp() - Add a new entry to the last crashes timestamps list.
 * @stats: Statistics that hold the last crashes timestamps list.
 * @new_entry: New timestamp to add to the list.
 *
 * The statistics that hold the last crashes timestamps list cannot be NULL. The
 * new timestamp to add to the list cannot be NULL.
 *
 * Context: Must be called with stats->lock held.
 */
static void brute_add_timestamp(struct brute_stats *stats,
				struct brute_timestamp *new_entry)
{
	list_add_tail(&new_entry->node, &stats->timestamps);
	stats->timestamps_size += 1;
}

/**
 * brute_old_timestamp_entry() - Get the oldest timestamp entry.
 * @head: Last crashes timestamps list.
 *
 * Context: Must be called with stats->lock held.
 * Return: The oldest entry added to the last crashes timestamps list.
 */
#define brute_old_timestamp_entry(head) \
	list_first_entry(head, struct brute_timestamp, node)

/**
 * brute_update_timestamps_list() - Update the last crashes timestamps list.
 * @stats: Statistics that hold the last crashes timestamps list.
 * @new_entry: New timestamp to update the list.
 *
 * Add a new timestamp structure to the list if this one has not reached the
 * maximum size yet. Replace the oldest timestamp entry otherwise.
 *
 * The statistics that hold the last crashes timestamps list cannot be NULL. The
 * new timestamp to update the list cannot be NULL.
 *
 * Context: Must be called with stats->lock held.
 * Return: The oldest timestamp that has been replaced. NULL otherwise.
 */
static struct brute_timestamp *
brute_update_timestamps_list(struct brute_stats *stats,
			     struct brute_timestamp *new_entry)
{
	unsigned int list_size;
	struct brute_timestamp *old_entry;

	list_size = (unsigned int)stats->timestamps_size;
	if (list_size < brute_timestamps_list_size) {
		brute_add_timestamp(stats, new_entry);
		return NULL;
	}

	old_entry = brute_old_timestamp_entry(&stats->timestamps);
	list_replace(&old_entry->node, &new_entry->node);
	list_rotate_left(&stats->timestamps);

	return old_entry;
}

/**
 * brute_get_crash_period() - Get the application crash period.
 * @new_entry: New timestamp added to the last crashes timestamps list.
 * @old_entry: Old timestamp replaced in the last crashes timestamps list.
 *
 * The application crash period is computed as the difference between the newest
 * crash timestamp and the oldest one divided by the size of the list. This way,
 * the scenario where an application crashes few times in a short period of time
 * due to reasons unrelated to a real attack is avoided.
 *
 * The new and old timestamp cannot be NULL.
 *
 * Context: Must be called with stats->lock held.
 * Return: The application crash period in milliseconds.
 */
static u64 brute_get_crash_period(struct brute_timestamp *new_entry,
				  struct brute_timestamp *old_entry)
{
	u64 jiffies;

	jiffies = new_entry->jiffies - old_entry->jiffies;
	jiffies /= (u64)brute_timestamps_list_size;

	return jiffies64_to_msecs(jiffies);
}

/**
 * brute_disabled() - Test the fork brute force attack detection disabling.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * The fork brute force attack detection enabling / disabling is based on the
 * last crashes timestamps list current size. A size of zero indicates that this
 * feature is disabled. A size greater than zero indicates that this attack
 * detection is enabled.
 *
 * The statistical data shared by all the fork hierarchy processes cannot be
 * NULL.
 *
 * It's mandatory to disable interrupts before acquiring the lock since the
 * task_free hook can be called from an IRQ context during the execution of the
 * task_fatal_signal hook.
 *
 * Return: True if the fork brute force attack detection is disabled. False
 *         otherwise.
 */
static bool brute_disabled(struct brute_stats *stats)
{
	unsigned long flags;
	bool disabled;

	spin_lock_irqsave(&stats->lock, flags);
	disabled = !stats->timestamps_size;
	spin_unlock_irqrestore(&stats->lock, flags);

	return disabled;
}

/**
 * brute_disable() - Disable the fork brute force attack detection.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * To disable the fork brute force attack detection it's only necessary to empty
 * the last crashes timestamps list. So, a list size of zero indicates that this
 * feature is disabled and a list size greater than zero indicates that this
 * attack detection is enabled.
 *
 * The statistical data shared by all the fork hierarchy processes cannot be
 * NULL.
 *
 * Context: Must be called with stats->lock held.
 */
static void brute_disable(struct brute_stats *stats)
{
	brute_timestamps_free(&stats->timestamps);
	stats->timestamps_size = 0;
}

/**
 * brute_kill_offending_tasks() - Kill the offending tasks.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * When a fork brute force attack is detected it is necessary to kill all the
 * offending tasks involved in the attack. In other words, it is necessary to
 * kill all the tasks that share the same statistical data but not the ones that
 * have the same group_leader that the current task since the latter are in the
 * path to be killed.
 *
 * When the SIGKILL signal is sent to the offending tasks, this function will be
 * called again from the task_fatal_signal hook due to a small crash period. So,
 * to avoid kill again the same tasks due to a recursive call of this function,
 * it is necessary to disable the attack detection for this fork hierarchy.
 *
 * The statistical data shared by all the fork hierarchy processes cannot be
 * NULL.
 *
 * Context: Must be called with stats->lock held.
 */
static void brute_kill_offending_tasks(struct brute_stats *stats)
{
	struct task_struct *p;
	struct brute_stats **p_stats;

	if (refcount_read(&stats->refc) == 1)
		return;

	brute_disable(stats);
	read_lock(&tasklist_lock);

	for_each_process(p) {
		if (p->group_leader == current->group_leader)
			continue;

		p_stats = brute_stats_ptr(p);
		if (READ_ONCE(*p_stats) != stats)
			continue;

		do_send_sig_info(SIGKILL, SEND_SIG_PRIV, p, PIDTYPE_PID);
		pr_warn_ratelimited("Offending process %d (%s) killed\n",
				    p->pid, p->comm);
	}

	read_unlock(&tasklist_lock);
}

/**
 * brute_task_fatal_signal() - Target for the task_fatal_signal hook.
 * @siginfo: Contains the signal information.
 *
 * To detect a fork brute force attack is necessary that the list that holds the
 * last crashes timestamps be updated in every fatal crash. Then, an only when
 * this list is large enough, the application crash period can be computed an
 * compared with the defined threshold. If at this moment an attack is detected,
 * all the offending tasks must be killed.
 *
 * It's mandatory to disable interrupts before acquiring the lock since the
 * task_free hook can be called from an IRQ context during the execution of the
 * task_fatal_signal hook.
 */
static void brute_task_fatal_signal(const kernel_siginfo_t *siginfo)
{
	struct brute_stats **stats;
	struct brute_timestamp *new_entry, *old_entry;
	unsigned long flags;
	u64 crash_period;

	stats = brute_stats_ptr(current);
	if (WARN(!*stats, "No statistical data\n"))
		return;

	if (brute_disabled(*stats))
		return;

	new_entry = brute_new_timestamp();
	if (WARN(!new_entry, "Cannot allocate last crash timestamp\n"))
		return;

	spin_lock_irqsave(&(*stats)->lock, flags);
	old_entry = brute_update_timestamps_list(*stats, new_entry);

	if (old_entry) {
		crash_period = brute_get_crash_period(new_entry, old_entry);
		kfree(old_entry);

		if (crash_period < (u64)brute_crash_period_threshold) {
			pr_warn("Fork brute force attack detected\n");
			brute_kill_offending_tasks(*stats);
		}
	}

	spin_unlock_irqrestore(&(*stats)->lock, flags);
}

/**
 * brute_hooks - Targets for the LSM's hooks.
 */
static struct security_hook_list brute_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_alloc, brute_task_alloc),
	LSM_HOOK_INIT(bprm_committing_creds, brute_task_execve),
	LSM_HOOK_INIT(task_free, brute_task_free),
	LSM_HOOK_INIT(task_fatal_signal, brute_task_fatal_signal),
};

#ifdef CONFIG_SYSCTL
static unsigned int uint_one = 1;
static unsigned int uint_max = UINT_MAX;
static unsigned int max_brute_timestamps_list_size = 10;

/**
 * brute_sysctl_path - Sysctl attributes path.
 */
static struct ctl_path brute_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "brute", },
	{ }
};

/**
 * brute_sysctl_table - Sysctl attributes.
 */
static struct ctl_table brute_sysctl_table[] = {
	{
		.procname	= "timestamps_list_size",
		.data		= &brute_timestamps_list_size,
		.maxlen		= sizeof(brute_timestamps_list_size),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= &uint_one,
		.extra2		= &max_brute_timestamps_list_size,
	},
	{
		.procname	= "crash_period_threshold",
		.data		= &brute_crash_period_threshold,
		.maxlen		= sizeof(brute_crash_period_threshold),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= &uint_one,
		.extra2		= &uint_max,
	},
	{ }
};

/**
 * brute_init_sysctl() - Initialize the sysctl interface.
 */
static void __init brute_init_sysctl(void)
{
	if (!register_sysctl_paths(brute_sysctl_path, brute_sysctl_table))
		panic("Cannot register the sysctl interface\n");
}

#else
static inline void brute_init_sysctl(void) { }
#endif /* CONFIG_SYSCTL */

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
	brute_init_sysctl();
	return 0;
}

DEFINE_LSM(brute) = {
	.name = KBUILD_MODNAME,
	.init = brute_init,
	.blobs = &brute_blob_sizes,
};

/**
 * brute_prctl_enable() - Enable the fork brute force attack detection.
 *
 * To enable the fork brute force attack detection the last crashes timestamps
 * list must not be empty. So, if this list already contains entries nothing
 * needs to be done. Otherwise, initialize the last crashes timestamps list with
 * one entry set to now. This way, the application crash period can be computed
 * at the next fault.
 *
 * It's mandatory to disable interrupts before acquiring the lock since the
 * task_free hook can be called from an IRQ context during the execution of the
 * prctl syscall.
 *
 * Return: -EFAULT if the current task doesn't have statistical data. -ENOMEM if
 *         the allocation of the new timestamp structure fails. Zero otherwise.
 */
int brute_prctl_enable(void)
{
	struct brute_stats **stats;
	struct brute_timestamp *timestamp;
	unsigned long flags;

	stats = brute_stats_ptr(current);
	if (!*stats)
		return -EFAULT;

	timestamp = brute_new_timestamp();
	if (!timestamp)
		return -ENOMEM;

	spin_lock_irqsave(&(*stats)->lock, flags);

	if (!list_empty(&(*stats)->timestamps)) {
		kfree(timestamp);
		goto unlock;
	}

	list_add_tail(&timestamp->node, &(*stats)->timestamps);
	(*stats)->timestamps_size = 1;

unlock:
	spin_unlock_irqrestore(&(*stats)->lock, flags);
	return 0;
}

/**
 * brute_prctl_disable() - Disable the fork brute force attack detection.
 *
 * It's mandatory to disable interrupts before acquiring the lock since the
 * task_free hook can be called from an IRQ context during the execution of the
 * prctl syscall.
 *
 * Return: -EFAULT if the current task doesn't have statistical data. Zero
 *         otherwise.
 */
int brute_prctl_disable(void)
{
	struct brute_stats **stats;
	unsigned long flags;

	stats = brute_stats_ptr(current);
	if (!*stats)
		return -EFAULT;

	spin_lock_irqsave(&(*stats)->lock, flags);
	brute_disable(*stats);
	spin_unlock_irqrestore(&(*stats)->lock, flags);

	return 0;
}

