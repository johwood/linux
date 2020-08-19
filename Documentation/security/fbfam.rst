.. SPDX-License-Identifier: GPL-2.0
==================================
Fork Brute Force Attack Mitigation
==================================

Attacks with the purpose to break ASLR or bypass canaries traditionaly use some
level of brute force with the help of the fork system call. This is possible
since when creating a new process using fork its memory contents are the same as
those of the parent process (the process that called the fork system call). So,
the attacker can test the memory infinite times to find the correct memory
values or the correct memory addresses without worrying about crashing the
application.

Based on the above scenario it would be nice to have this detected and
mitigated, and this is the goal of this implementation.


Other implementations
=====================

The public version of grsecurity, as a summary, is based on the idea of delay
the fork system call if a child died due to a fatal error. This has some issues:

Bad practices
-------------

Add delays to the kernel is, in general, a bad idea.

Weak points
-----------

This protection can be bypassed using two different methods since it acts only
when the fork is called after a child has crashed.

Bypass 1
~~~~~~~~

So, it would still be possible for an attacker to fork a big amount of children
(in the order of thousands), then probe all of them, and finally wait the
protection time before repeat the steps.

Bypass 2
~~~~~~~~

This method is based on the idea that the protection doesn't act if the parent
crashes. So, it would still be possible for an attacker to fork a process and
probe itself. Then, fork the child process and probe itself again. This way,
these steps can be repeated infinite times without any mitigation.


This implementation
===================

The main idea behind this implementation is to improve the existing ones
focusing on the weak points annotated before. So, the solution for the first
bypass method is to detect a fast crash rate instead of only one simple crash.
For the second bypass method the solution is to detect both the crash of parent
and child processes. Moreover, as a mitigation method it is better to kill all
the offending tasks involve in the attack instead of use delays.

So, the solution to the two bypass methods previously commented is to use some
statistical data shared across all the processes that can have the same memory
contents. Or in other words, a statistical data shared between all the processes
that fork the task 0, and all the processes that fork after an execve system
call.

These statistics hold the timestamp for the first fork (case of a fork of task
zero) or the timestamp for the execve system call (the other case). Also, hold
the number of faults of all the tasks that share the same statistical data since
the commented timestamp.

With this information it is possible to detect a brute force attack when a task
die in a fatal way computing the crashing rate. This rate shows the milliseconds
per fault and when it goes under a certain threshold there is a clear signal
that something malicious is happening.

Once detected, the mitigation only kills the processes that share the same
statistical data and so, all the tasks that can have the same memory contents.
This way, an attack is rejected.

Per system enabling
-------------------

This feature can be enabled in build time using the config application under:

Security options  --->  Fork brute force attack mitigation

Per process enabling/disabling
------------------------------

To allow that specific applications can turn off or turn on the detection and
mitigation of a fork brute force attack when required, there are two new prctls.

prctl(PR_FBFAM_ENABLE, 0, 0, 0, 0)  -> To enable the feature
prctl(PR_FBFAM_DISABLE, 0, 0, 0, 0) -> To disable the feature

Both functions return zero on success and -EFAULT if the current task doesn't
have statistical data.

Fine tuning
-----------

To customize the detection's sensibility there is a new sysctl that allows to
set the crashing rate threshold. It is accessible through the file:

/proc/sys/kernel/fbfam/crashing_rate_threshold

The units are in milliseconds per fault and the attack's mitigation is triggered
if the crashing rate of an application goes under this threshold. So, the higher
this value, the faster an attack will be detected.

