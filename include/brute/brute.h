/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BRUTE_H_
#define _BRUTE_H_

#include <linux/errno.h>

#ifdef CONFIG_SECURITY_FORK_BRUTE
int brute_prctl_enable(void);
int brute_prctl_disable(void);
#else
static inline int brute_prctl_enable(void) { return -EINVAL; }
static inline int brute_prctl_disable(void) { return -EINVAL; }
#endif

#endif /* _BRUTE_H_ */

