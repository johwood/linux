// SPDX-License-Identifier: GPL-2.0
#include <asm/current.h>
#include <fbfam/fbfam.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/jiffies.h>
#include <linux/refcount.h>
#include <linux/slab.h>

/**
 * struct fbfam_stats - Fork brute force attack mitigation statistics.
 * @refc: Reference counter.
 * @faults: Number of crashes since jiffies.
 * @jiffies: First fork or execve timestamp.
 *
 * The purpose of this structure is to manage all the necessary information to
 * compute the crashing rate of an application. So, it holds a first fork or
 * execve timestamp and a number of crashes since then. This way the crashing
 * rate in milliseconds per fault can be compute when necessary with the
 * following formula:
 *
 * u64 delta_jiffies = get_jiffies_64() - fbfam_stats::jiffies;
 * u64 delta_time = jiffies64_to_msecs(delta_jiffies);
 * u64 crashing_rate = delta_time / (u64)fbfam_stats::faults;
 *
 * If the fbfam_stats::faults is zero, the above formula can't be used. In this
 * case, the crashing rate is zero.
 *
 * Moreover, since the same allocated structure will be used in every fork
 * since the first one or execve, it's also necessary a reference counter.
 */
struct fbfam_stats {
	refcount_t refc;
	unsigned int faults;
	u64 jiffies;
};

/**
 * fbfam_new_stats() - Allocation of new statistics structure.
 *
 * If the allocation is successful the reference counter is set to one to
 * indicate that there will be one task that points to this structure. The
 * faults field is initialize to zero and the timestamp for this moment is set.
 *
 * Return: NULL if the allocation fails. A pointer to the new allocated
 *         statistics structure if it success.
 */
static struct fbfam_stats *fbfam_new_stats(void)
{
	struct fbfam_stats *stats = kmalloc(sizeof(struct fbfam_stats),
					    GFP_KERNEL);

	if (stats) {
		refcount_set(&stats->refc, 1);
		stats->faults = 0;
		stats->jiffies = get_jiffies_64();
	}

	return stats;
}

/*
 * fbfam_fork() - Fork management.
 * @child: Pointer to the child task that will be created with the fork system
 *         call.
 *
 * For a correct management of a fork brute force attack it is necessary that
 * all the tasks hold statistical data. The same statistical data needs to be
 * shared between all the tasks that hold the same memory contents or in other
 * words, between all the tasks that have been forked without any execve call.
 *
 * To ensure this, if the current task doesn't have statistical data when forks
 * (only possible in the first fork of the zero task), it is mandatory to
 * allocate a new one. This way, the child task always will share the statistics
 * with its parent.
 *
 * Return: -ENOMEN if the allocation of the new statistics structure fails.
 *         Zero otherwise.
 */
int fbfam_fork(struct task_struct *child)
{
	struct fbfam_stats **stats = &current->fbfam_stats;

	if (!*stats) {
		*stats = fbfam_new_stats();
		if (!*stats)
			return -ENOMEM;
	}

	refcount_inc(&(*stats)->refc);
	child->fbfam_stats = *stats;
	return 0;
}

/**
 * fbfam_execve() - Execve management.
 *
 * When a forked task calls the execve system call, the memory contents are set
 * with new values. So, in this scenario the parent's statistical data no need
 * to be share. Instead, a new statistical data structure must be allocated to
 * start a new cycle. This condition is detected when the statistics reference
 * counter holds a value greater than or equal to two (a fork always sets the
 * statistics reference counter to two since the parent and the child task are
 * sharing the same data).
 *
 * However, if the execve function is called immediately after another execve
 * call, althought the memory contents are reset, there is no need to allocate
 * a new statistical data structure. This is possible because at this moment
 * only one task (the task that calls the execve function) points to the data.
 * In this case, the previous allocation is used and only the faults and time
 * fields are reset.
 *
 * Return: -ENOMEN if the allocation of the new statistics structure fails.
 *         -EFAULT if the current task doesn't have statistical data. Zero
 *         otherwise.
 */
int fbfam_execve(void)
{
	struct fbfam_stats **stats = &current->fbfam_stats;

	if (!*stats)
		return -EFAULT;

	if (!refcount_dec_not_one(&(*stats)->refc)) {
		/* execve call after an execve call */
		(*stats)->faults = 0;
		(*stats)->jiffies = get_jiffies_64();
		return 0;
	}

	/* execve call after a fork call */
	*stats = fbfam_new_stats();
	if (!*stats)
		return -ENOMEM;

	return 0;
}

/**
 * fbfam_exit() - Exit management.
 *
 * The statistical data that every task holds needs to be clear when a task
 * exits. Due to this data is shared across multiples tasks, the reference
 * counter is useful to free the previous allocated data only when there are
 * not other pointers to the same data. Or in other words, when the reference
 * counter reaches zero.
 *
 * Return: -EFAULT if the current task doesn't have statistical data. Zero
 *         otherwise.
 */
int fbfam_exit(void)
{
	struct fbfam_stats *stats = current->fbfam_stats;

	if (!stats)
		return -EFAULT;

	if (refcount_dec_and_test(&stats->refc))
		kfree(stats);

	return 0;
}

