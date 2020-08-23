/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FBFAM_H_
#define _FBFAM_H_

#include <linux/sched.h>

#ifdef CONFIG_FBFAM
int fbfam_fork(struct task_struct *child);
int fbfam_execve(void);
int fbfam_exit(void);
#else
static inline int fbfam_fork(struct task_struct *child) { return 0; }
static inline int fbfam_execve(void) { return 0; }
static inline int fbfam_exit(void) { return 0; }
#endif

#endif /* _FBFAM_H_ */

