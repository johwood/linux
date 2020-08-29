/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FBFAM_H_
#define _FBFAM_H_

#include <linux/sched.h>
#include <linux/sysctl.h>

#ifdef CONFIG_FBFAM
#ifdef CONFIG_SYSCTL
extern struct ctl_table fbfam_sysctls[];
#endif
int fbfam_fork(struct task_struct *child);
int fbfam_execve(void);
int fbfam_exit(void);
int fbfam_handle_attack(int signal);
#else
static inline int fbfam_fork(struct task_struct *child) { return 0; }
static inline int fbfam_execve(void) { return 0; }
static inline int fbfam_exit(void) { return 0; }
static inline int fbfam_handle_attack(int signal) { return 0; }
#endif

#endif /* _FBFAM_H_ */

