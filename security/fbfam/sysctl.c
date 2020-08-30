// SPDX-License-Identifier: GPL-2.0
#include <linux/sysctl.h>

extern unsigned long sysctl_crashing_rate_threshold;
static unsigned long ulong_one = 1;
static unsigned long ulong_max = ULONG_MAX;

struct ctl_table fbfam_sysctls[] = {
	{
		.procname	= "crashing_rate_threshold",
		.data		= &sysctl_crashing_rate_threshold,
		.maxlen		= sizeof(sysctl_crashing_rate_threshold),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= &ulong_one,
		.extra2		= &ulong_max,
	},
	{ }
};

