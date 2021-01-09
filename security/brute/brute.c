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
//#include <asm/current.h>
//#include <asm/rwonce.h>
//#include <asm/siginfo.h>
//#include <asm/signal.h>
//#include <linux/binfmts.h>
//#include <linux/bug.h>
//#include <linux/compiler.h>
//#include <linux/cred.h>
//#include <linux/dcache.h>
//#include <linux/errno.h>
//#include <linux/fs.h>
//#include <linux/gfp.h>
//#include <linux/if.h>
//#include <linux/init.h>
//#include <linux/jiffies.h>
//#include <linux/kernel.h>
//#include <linux/lsm_hooks.h>
//#include <linux/math64.h>
//#include <linux/netdevice.h>
//#include <linux/path.h>
//#include <linux/printk.h>
//#include <linux/refcount.h>
//#include <linux/rwlock.h>
//#include <linux/rwlock_types.h>
//#include <linux/sched.h>
//#include <linux/sched/signal.h>
//#include <linux/sched/task.h>
//#include <linux/signal.h>
//#include <linux/skbuff.h>
//#include <linux/slab.h>
//#include <linux/spinlock.h>
//#include <linux/stat.h>
//#include <linux/types.h>
//#include <linux/uidgid.h>
//#include <linux/math64.h>
//#include <linux/netdevice.h>
//#include <linux/path.h>
//#include <linux/pid.h>
//#include <linux/printk.h>
//#include <linux/refcount.h>
//#include <linux/rwlock.h>
//#include <linux/rwlock_types.h>
//#include <linux/sched.h>
//#include <linux/sched/signal.h>
//#include <linux/sched/task.h>
//#include <linux/signal.h>
//#include <linux/skbuff.h>
//#include <linux/slab.h>
//#include <linux/spinlock.h>
//#include <linux/stat.h>
//#include <linux/types.h>
//#include <linux/uidgid.h>

/**
 * struct brute_cred - Saved credentials.
 * @uid: Real UID of the task.
 * @gid: Real GID of the task.
 * @suid: Saved UID of the task.
 * @sgid: Saved GID of the task.
 * @euid: Effective UID of the task.
 * @egid: Effective GID of the task.
 * @fsuid: UID for VFS ops.
 * @fsgid: GID for VFS ops.
 */
struct brute_cred {
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
};

/**
 * struct brute_stats - Fork brute force attack statistics.
 * @lock: Lock to protect the brute_stats structure.
 * @refc: Reference counter.
 * @faults: Number of crashes.
 * @jiffies: Last crash timestamp.
 * @period: Crash period's moving average.
 * @saved_cred: Saved credentials.
 * @network: Network activity flag.
 * @bounds_crossed: Privilege bounds crossed flag.
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
	struct brute_cred saved_cred;
	unsigned char network : 1;
	unsigned char bounds_crossed : 1;
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
 * Also, if the shared statistics indicate a previous network activity, the
 * bounds_crossed flag must be set to show that a network-to-local privilege
 * boundary has been crossed.
 *
 * To be defensive, kill the current process if it has no statistics. Treat this
 * as an attack.
 *
 * It's mandatory to disable interrupts before acquiring brute_stats_ptr_lock
 * and brute_stats::lock since the task_free hook can be called from an IRQ
 * context during the execution of the task_alloc hook.
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
		(*stats)->bounds_crossed |= (*stats)->network;
		return 0;
	}

	if (WARN_ON_ONCE(current->pid)) {
		brute_manage_no_stats_attack(p_stats, current);
		return -ESRCH;
	}

	WRITE_ONCE(*stats, brute_create_stats(false, false));
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
static void brute_reset_stats(struct brute_stats *stats, bool is_setid)
{
	const struct cred *cred = current_cred();

	memset(stats, 0, sizeof(*stats));
	brute_init_stats(stats);

	stats->saved_cred.uid = cred->uid;
	stats->saved_cred.gid = cred->gid;
	stats->saved_cred.suid = cred->suid;
	stats->saved_cred.sgid = cred->sgid;
	stats->saved_cred.euid = cred->euid;
	stats->saved_cred.egid = cred->egid;
	stats->saved_cred.fsuid = cred->fsuid;
	stats->saved_cred.fsgid = cred->fsgid;
	stats->bounds_crossed = stats->network || is_setid;
}

static struct kmem_cache *brute_cache;

/**
 * brute_new_stats() - Allocate a new statistics structure.
 * @network_to_local: Network activity followed by a fork or execve system call.
 * @is_setid: The executable file has the setid flags set.
 *
 * If the allocation is successful the reference counter is set to one to
 * indicate that there will be one task that points to this structure. Also, the
 * last crash timestamp is set to now. This way, it is possible to compute the
 * application crash period at the first fault.
 *
 * Moreover, the credentials of the current task are saved. Also, the network
 * and bounds_crossed flags are set based on the network_to_local and is_setid
 * parameters.
 *
 * Return: NULL if the allocation fails. A pointer to the new allocated
 *         statistics structure if it success.
 */
static struct brute_stats *brute_create_stats(bool network_to_local, bool is_setid)
{
	struct brute_stats *stats;
	const struct cred *cred = current_cred();

	stats = kmem_cache_zalloc(brute_cache, GFP_KERNEL);
	if (!stats)
		return NULL;

	brute_init_stats(stats);

	stats->saved_cred.uid = cred->uid;
	stats->saved_cred.gid = cred->gid;
	stats->saved_cred.suid = cred->suid;
	stats->saved_cred.sgid = cred->sgid;
	stats->saved_cred.euid = cred->euid;
	stats->saved_cred.egid = cred->egid;
	stats->saved_cred.fsuid = cred->fsuid;
	stats->saved_cred.fsgid = cred->fsgid;
	stats->network = network_to_local;
	stats->bounds_crossed = network_to_local || is_setid;

	return stats;
}

/**
 * brute_is_setid() - Test if the executable file has the setid flags set.
 * @bprm: Points to the linux_binprm structure.
 *
 * Return: True if the executable file has the setid flags set. False otherwise.
 */
static bool brute_is_setid(const struct linux_binprm *bprm)
{
	struct file *file = bprm->file;
	struct inode *inode;
	umode_t mode;

	if (!file)
		return false;

	inode = file->f_path.dentry->d_inode;
	mode = inode->i_mode;

	return !!(mode & (S_ISUID | S_ISGID));
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
 * Also, if the statistics of the process that calls the execve system call
 * indicate a previous network activity or the executable file has the setid
 * flags set, the bounds_crossed flag must be set to show that a network to
 * local privilege boundary or setid boundary has been crossed respectively.
 *
 * To be defensive, kill the current process if it has no statistics. Treat this
 * as an attack.
 *
 * It's mandatory to disable interrupts before acquiring brute_stats_ptr_lock
 * and brute_stats::lock since the task_free hook can be called from an IRQ
 * context during the execution of the bprm_committing_creds hook.
 */
static void brute_task_execve(struct linux_binprm *bprm)
{
	struct brute_stats **stats;
	bool network_to_local;
	bool is_setid = false;

	stats = brute_stats_ptr(current);
	if (WARN_ON_ONCE(IS_ERR_OR_NULL(*stats))) {
		brute_manage_no_stats_attack(stats, current);
		return;
	}

	spin_lock(&(*stats)->lock);///////quitar casi seguro
	network_to_local = (*stats)->network;

	/*
	 * A network_to_local flag equal to true will set the bounds_crossed
	 * flag. So, in this scenario the "is setid" test can be avoided.
	 */
	if (!network_to_local)
		is_setid = brute_is_setid(bprm);

	if (!refcount_dec_not_one(&(*stats)->refc)) {
		/* execve call after an execve call */
		brute_reset_stats(*stats, is_setid);
		return;
	}

	/* execve call after a fork call */
	WRITE_ONCE(*stats, brute_create_stats(network_to_local, is_setid));
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
 * brute_disabled() - Test if the brute force attack detection is disabled.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * The brute force attack detection enabling/disabling is based on the last
 * crash timestamp. A zero timestamp indicates that this feature is disabled. A
 * timestamp greater than zero indicates that the attack detection is enabled.
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
 * Return: True if the brute force attack detection is disabled. False
 *         otherwise.
 */
static bool brute_disabled(struct brute_stats *stats)
{
	bool disabled;

	spin_lock(&stats->lock);
	disabled = !stats->jiffies;
	spin_unlock(&stats->lock);

	return disabled;
}

/**
 * brute_disable() - Disable the brute force attack detection.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * To disable the brute force attack detection it is only necessary to set the
 * last crash timestamp to zero. A zero timestamp indicates that this feature is
 * disabled. A timestamp greater than zero indicates that the attack detection
 * is enabled.
 *
 * The statistical data shared by all the fork hierarchy processes cannot be
 * NULL.
 *
 * Context: Must be called with interrupts disabled and brute_stats_ptr_lock
 *          and brute_stats::lock held.
 */
static inline void brute_disable(struct brute_stats *stats)
{
	stats->jiffies = 0;
}

/**
 * enum brute_attack_type - Brute force attack type.
 * @BRUTE_ATTACK_TYPE_FORK: Attack that happens through the fork system call.
 * @BRUTE_ATTACK_TYPE_EXEC: Attack that happens through the execve system call.
 */
enum brute_attack_type {
	BRUTE_ATTACK_TYPE_FORK,
	BRUTE_ATTACK_TYPE_EXEC,
};

/**
 * brute_kill_offending_tasks() - Kill the offending tasks.
 * @attack_type: Brute force attack type.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * When a brute force attack is detected all the offending tasks involved in the
 * attack must be killed. In other words, it is necessary to kill all the tasks
 * that share the same statistical data. Moreover, if the attack happens through
 * the fork system call, the processes that have the same group_leader that the
 * current task must be avoided since they are in the path to be killed.
 *
 * When the SIGKILL signal is sent to the offending tasks, this function will be
 * called again from the task_fatal_signal hook due to a small crash period. So,
 * to avoid kill again the same tasks due to a recursive call of this function,
 * it is necessary to disable the attack detection for this fork hierarchy.
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
static void brute_kill_offending_tasks(enum brute_attack_type attack_type,
				       struct brute_stats *stats)
{
	struct task_struct *p;
	struct brute_stats **p_stats;

	spin_lock(&stats->lock);

	if (attack_type == BRUTE_ATTACK_TYPE_FORK &&
	    refcount_read(&stats->refc) == 1) {
		spin_unlock(&stats->lock);
		return;
	}

	brute_disable(stats);
	spin_unlock(&stats->lock);

	for_each_process(p) {
		if (attack_type == BRUTE_ATTACK_TYPE_FORK &&
		    p->group_leader == current->group_leader)
			continue;

		p_stats = brute_stats_ptr(p);
		if (*p_stats != stats)
			continue;

		do_send_sig_info(SIGKILL, SEND_SIG_PRIV, p, PIDTYPE_PID);
		pr_warn_ratelimited("Offending process %d [%s] killed\n",
				    p->pid, p->comm);
	}
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
	if (brute_attack_running(stats)) {
		brute_print_fork_attack_running();
		brute_kill_offending_tasks(BRUTE_ATTACK_TYPE_FORK, stats);
	}
}

/**
 * brute_exec_stats() - Get the exec statistics.
 * @stats: Current process' statistical data.
 * @exec_pid: If the exec statistics are found it returns the pid of the task
 *            that holds them.
 *
 * To manage a brute force attack that happens through the execve system call it
 * is not possible to use the statistical data hold by this process due to these
 * statistics disappear when this task is finished. In this scenario this data
 * should be tracked by the statistics of a higher fork hierarchy (the hierarchy
 * that contains the process that forks before the execve system call).
 *
 * To find these statistics the current fork hierarchy must be traversed up
 * until new statistics are found.
 *
 * Return: The exec statistics if they can be found. NULL otherwise.
 */
static struct brute_stats *brute_exec_stats(const struct brute_stats *stats,
					    pid_t *exec_pid)
{
	struct task_struct *task = current;
	struct brute_stats **exec_stats_ptr;
	struct brute_stats *exec_stats;
	bool found = false;

	rcu_read_lock();
	while (task->pid > 0) {
		if (!thread_group_leader(task))
			task = rcu_dereference(task->group_leader);

		task = rcu_dereference(task->real_parent);
		exec_stats_ptr = brute_stats_ptr(task);
		exec_stats = READ_ONCE(*exec_stats_ptr);

		if (WARN_ON_ONCE(IS_ERR_OR_NULL(exec_stats))) {
			brute_manage_no_stats_attack(exec_stats_ptr, task);
			continue;
		}
		
		if (stats != exec_stats) {
			*exec_pid = task->pid;
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found ? exec_stats : NULL;
}

/**
 * brute_update_exec_crash_period() - Update the exec crash period.
 * @stats: Current process' statistical data.
 * @now: The current timestamp in jiffies.
 * @last_fork_crash: The last fork crash timestamp before updating it.
 * @exec_pid: If there are exec statistics it returns the pid of the task that
 *            holds them.
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
 * Return: NULL if there are no exec statistics. The updated exec statistics
 *         otherwise.
 */
static struct brute_stats *
brute_update_exec_crash_period(const struct brute_stats *stats, u64 now,
			       u64 last_fork_crash, pid_t *exec_pid)
{
	struct brute_stats *exec_stats;

	exec_stats = brute_exec_stats(stats, exec_pid);
	if (!exec_stats)
		return NULL;

	if (!READ_ONCE(exec_stats->faults)) {
		spin_lock(&exec_stats->lock);
		WRITE_ONCE(exec_stats->jiffies, last_fork_crash);
		spin_unlock(&exec_stats->lock);
	}

	brute_update_crash_period(exec_stats, now);
	return exec_stats;
}

/**
 * brute_print_exec_attack_running() - Warn about an exec brute force attack.
 * @exec_pid: The pid of the task that holds the exec statistics.
 */
static void brute_print_exec_attack_running(pid_t exec_pid)
{
	struct pid *pid;
	struct task_struct *task;

	pid = find_get_pid(exec_pid);
	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	pr_warn("Exec brute force attack detected [pid %d, %s]\n", exec_pid,
		task ? task->comm : "unknown");
	rcu_read_unlock();
	put_pid(pid);
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
 * Also, the scenario where there are no exec statistics is not treated as an
 * attack since it is possible for the forks of the init task.
 */
static void brute_manage_exec_attack(const struct brute_stats *stats, u64 now,
				     u64 last_fork_crash)
{
	struct brute_stats *exec_stats;
	pid_t exec_pid;

	exec_stats = brute_update_exec_crash_period(stats, now, last_fork_crash,
						    &exec_pid);
	if (!exec_stats ||
	    READ_ONCE(stats->period) == READ_ONCE(exec_stats->period))
		return;

	if (brute_attack_running(exec_stats)) {
		brute_print_exec_attack_running(exec_pid);
		brute_kill_offending_tasks(BRUTE_ATTACK_TYPE_EXEC, exec_stats);
	}
>>>>>>> 7c04953badc3... security/brute: Mitigate a brute force attack
}

/**
 * brute_priv_have_changed() - Test if the privileges have changed.
 * @stats: Statistics that hold the saved credentials.
 *
 * The privileges have changed if the credentials of the current task are
 * different from the credentials saved in the statistics structure.
 *
 * The statistics that hold the saved credentials cannot be NULL.
 *
 * Context: Must be called with interrupts disabled and brute_stats_ptr_lock
 *          and brute_stats::lock held.
 * Return: True if the privileges have changed. False otherwise.
 */
static bool brute_priv_have_changed(struct brute_stats *stats)
{
	const struct cred *cred = current_cred();
	bool priv_have_changed;

	priv_have_changed = !uid_eq(stats->saved_cred.uid, cred->uid) ||
		!gid_eq(stats->saved_cred.gid, cred->gid) ||
		!uid_eq(stats->saved_cred.suid, cred->suid) ||
		!gid_eq(stats->saved_cred.sgid, cred->sgid) ||
		!uid_eq(stats->saved_cred.euid, cred->euid) ||
		!gid_eq(stats->saved_cred.egid, cred->egid) ||
		!uid_eq(stats->saved_cred.fsuid, cred->fsuid) ||
		!gid_eq(stats->saved_cred.fsgid, cred->fsgid);

	return priv_have_changed;
}

/**
 * brute_threat_model_supported() - Test if the threat model is supported.
 * @siginfo: Contains the signal information.
 * @stats: Statistical data shared by all the fork hierarchy processes.
 *
 * To avoid false positives during the attack detection it is necessary to
 * narrow the possible cases. Only the following scenarios are taken into
 * account:
 *
 * 1.- Launching (fork()/exec()) a setuid/setgid process repeatedly until a
 *     desirable memory layout is got (e.g. Stack Clash).
 * 2.- Connecting to an exec()ing network daemon (e.g. xinetd) repeatedly until
 *     a desirable memory layout is got (e.g. what CTFs do for simple network
 *     service).
 * 3.- Launching processes without exec() (e.g. Android Zygote) and exposing
 *     state to attack a sibling.
 * 4.- Connecting to a fork()ing network daemon (e.g. apache) repeatedly until
 *     the previously shared memory layout of all the other children is exposed
 *     (e.g. kind of related to HeartBleed).
 *
 * In each case, a privilege boundary has been crossed:
 *
 * Case 1: setuid/setgid process
 * Case 2: network to local
 * Case 3: privilege changes
 * Case 4: network to local
 *
 * Also, only the signals delivered by the kernel are taken into account with
 * the exception of the SIGABRT signal since the latter is used by glibc for
 * stack canary, malloc, etc failures, which may indicate that a mitigation has
 * been triggered.
 *
 * The signal information and the statistical data shared by all the fork
 * hierarchy processes cannot be NULL.
 *
 * It's mandatory to disable interrupts before acquiring the brute_stats::lock
 * since the task_free hook can be called from an IRQ context during the
 * execution of the task_fatal_signal hook.
 *
 * Context: Must be called with interrupts disabled and brute_stats_ptr_lock
 *          held.
 * Return: True if the threat model is supported. False otherwise.
 */
static bool brute_threat_model_supported(const kernel_siginfo_t *siginfo,
					 struct brute_stats *stats)
{
	bool bounds_crossed;

	if (siginfo->si_signo == SIGKILL && siginfo->si_code != SIGABRT)
		return false;

	spin_lock(&stats->lock);
	bounds_crossed = stats->bounds_crossed;
	bounds_crossed = bounds_crossed || brute_priv_have_changed(stats);
	stats->bounds_crossed = bounds_crossed;
	spin_unlock(&stats->lock);

	return bounds_crossed;
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

	if (!brute_threat_model_supported(siginfo, *stats))
		return;
	if (WARN(!*stats, "No statistical data\n") ||
	    brute_disabled(*stats) ||
	    !brute_threat_model_supported(siginfo, *stats))
		goto unlock;

	brute_manage_fork_attack(*stats, now);
}

/**
 * brute_network() - Target for the socket_sock_rcv_skb hook.
 * @sk: Contains the sock (not socket) associated with the incoming sk_buff.
 * @skb: Contains the incoming network data.
 *
 * A previous step to detect that a network to local boundary has been crossed
 * is to detect if there is network activity. To do this, it is only necessary
 * to check if there are data packets received from a network device other than
 * loopback.
 *
 * It's mandatory to disable interrupts before acquiring brute_stats_ptr_lock
 * and brute_stats::lock since the task_free hook can be called from an IRQ
 * context during the execution of the socket_sock_rcv_skb hook.
 *
 * Return: -EFAULT if the current task doesn't have statistical data. Zero
 *         otherwise.
 */
static int brute_network(struct sock *sk, struct sk_buff *skb)
{
	struct brute_stats **stats;
	unsigned long flags;

	if (!skb->dev || (skb->dev->flags & IFF_LOOPBACK))
		return 0;

	stats = brute_stats_ptr(current);
	read_lock_irqsave(&brute_stats_ptr_lock, flags);

	if (!*stats) {
		read_unlock_irqrestore(&brute_stats_ptr_lock, flags);
		return -EFAULT;
	}

	spin_lock(&(*stats)->lock);
	(*stats)->network = true;
	spin_unlock(&(*stats)->lock);
	read_unlock_irqrestore(&brute_stats_ptr_lock, flags);
	return 0;
}

/*
 * brute_hooks - Targets for the LSM's hooks.
 */
static struct security_hook_list brute_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_alloc, brute_task_alloc),
	LSM_HOOK_INIT(bprm_committing_creds, brute_task_execve),
	LSM_HOOK_INIT(task_free, brute_task_free),
	LSM_HOOK_INIT(task_fatal_signal, brute_task_fatal_signal),
	LSM_HOOK_INIT(socket_sock_rcv_skb, brute_network),
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
