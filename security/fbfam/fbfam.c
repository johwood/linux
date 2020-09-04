// SPDX-License-Identifier: GPL-2.0
#include <asm/current.h>
#include <fbfam/fbfam.h>
#include <linux/gfp.h>
#include <linux/jiffies.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/slab.h>

/**
 * sysctl_crashing_rate_threshold - Crashing rate threshold.
 *
 * The rate's units are in milliseconds per fault.
 *
 * A fork brute force attack will be detected if the application's crashing rate
 * falls under this threshold. So, the higher this value, the faster an attack
 * will be detected.
 */
unsigned long sysctl_crashing_rate_threshold = 30000;

/**
 * struct fbfam_stats - Fork brute force attack mitigation statistics.
 * @refc: Reference counter.
 * @faults: Number of crashes since jiffies.
 * @jiffies: First fork or execve timestamp. If zero, the attack detection is
 *           disabled.
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
 * fbfam_enable() - Enable the detection and mitigation of a fork brute force
 *                  attack.
 *
 * This function is implemented to be used in the prctl() system call.
 *
 * When a process calls the prctl() interface to enable the detection and
 * mitigation of a fork brute force attack its shared statistical data is reset.
 * This implies that the old information about times and crashes is lost.
 *
 * Return: -EFAULT if the current task doesn't have statistical data. Zero
 *         otherwise.
 */
int fbfam_enable(void)
{
	struct fbfam_stats *stats = current->fbfam_stats;

	if (!stats)
		return -EFAULT;

	stats->faults = 0;
	stats->jiffies = get_jiffies_64();
	return 0;
}

/**
 * fbfam_disable() - Disable the detection and mitigation of a fork brute force
 *                   attack.
 *
 * This function is implemented to be used in the prctl() system call.
 *
 * When a process calls the prctl() interface to disable the detection and
 * mitigation of a fork brute force attack it is only necessary to set the
 * jiffies stored in the shared statistical data to zero (as it is showed in the
 * struct fbfam_stats's documentation). This implies that the old information
 * about times is lost.
 *
 * Return: -EFAULT if the current task doesn't have statistical data. Zero
 *         otherwise.
 */
int fbfam_disable(void)
{
	struct fbfam_stats *stats = current->fbfam_stats;

	if (!stats)
		return -EFAULT;

	stats->jiffies = 0;
	return 0;
}

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

/**
 * fbfam_kill_tasks() - Kill the offending tasks
 *
 * When a fork brute force attack is detected it is necessary to kill all the
 * offending tasks. Since this function is called from fbfam_handle_attack(),
 * and so, every time a core dump is triggered, only is needed to kill the
 * others tasks that share the same statistical data, not the current one as
 * this is in the path to be killed.
 *
 * When the SIGKILL signal is sent to the offending tasks, this function will be
 * called again during the core dump due to the shared statistical data shows a
 * quickly crashing rate. So, to avoid kill again the same tasks due to a
 * recursive call of this function, it is necessary to disable the attack
 * detection setting the jiffies to zero.
 *
 * To improve the for_each_process loop it is possible to end it when all the
 * tasks that shared the same statistics are found.
 *
 * Return: -EFAULT if the current task doesn't have statistical data. Zero
 *         otherwise.
 */
static int fbfam_kill_tasks(void)
{
	struct fbfam_stats *stats = current->fbfam_stats;
	struct task_struct *p;
	unsigned int to_kill, killed = 0;

	if (!stats)
		return -EFAULT;

	to_kill = refcount_read(&stats->refc) - 1;
	if (!to_kill)
		return 0;

	/* Disable the attack detection */
	stats->jiffies = 0;
	rcu_read_lock();

	for_each_process(p) {
		if (p == current || p->fbfam_stats != stats)
			continue;

		do_send_sig_info(SIGKILL, SEND_SIG_PRIV, p, PIDTYPE_PID);
		pr_warn("fbfam: Offending process with PID %d killed\n",
			p->pid);

		killed += 1;
		if (killed >= to_kill)
			break;
	}

	rcu_read_unlock();
	return 0;
}

/**
 * fbfam_handle_attack() - Fork brute force attack detection and mitigation.
 * @signal: Signal number that causes the core dump.
 *
 * The crashing rate of an application is computed in milliseconds per fault in
 * each crash. So, if this rate goes under a certain threshold there is a clear
 * signal that the application is crashing quickly. At this moment, a fork brute
 * force attack is happening. Under this scenario it is necessary to kill all
 * the offending tasks in order to mitigate the attack.
 *
 * Return: -EFAULT if the current task doesn't have statistical data. Zero
 *         otherwise.
 */
int fbfam_handle_attack(int signal)
{
	struct fbfam_stats *stats = current->fbfam_stats;
	u64 delta_jiffies, delta_time;
	u64 crashing_rate;

	if (!stats)
		return -EFAULT;

	/* The attack detection is disabled */
	if (!stats->jiffies)
		return 0;

	if (!(signal == SIGILL || signal == SIGBUS || signal == SIGKILL ||
	      signal == SIGSEGV || signal == SIGSYS))
		return 0;

	stats->faults += 1;

	delta_jiffies = get_jiffies_64() - stats->jiffies;
	delta_time = jiffies64_to_msecs(delta_jiffies);
	crashing_rate = delta_time / (u64)stats->faults;

	if (crashing_rate >= (u64)sysctl_crashing_rate_threshold)
		return 0;

	pr_warn("fbfam: Fork brute force attack detected\n");
	fbfam_kill_tasks();
	return 0;
}

