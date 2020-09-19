.. SPDX-License-Identifier: GPL-2.0
===========================================================
Brute: Fork brute force attack detection and mitigation LSM
===========================================================

Attacks against vulnerable userspace applications with the purpose to break ASLR
or bypass canaries traditionaly use some level of brute force with the help of
the fork system call. This is possible since when creating a new process using
fork its memory contents are the same as those of the parent process (the
process that called the fork system call). So, the attacker can test the memory
infinite times to find the correct memory values or the correct memory addresses
without worrying about crashing the application.

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
focusing on the weak points annotated before. The solution for the first bypass
method is to detect a fast crash rate instead of only one simple crash. For the
second bypass method the solution is to detect both the crash of parent and
child processes. Moreover, as a mitigation method it is better to kill all the
offending tasks involve in the attack instead of use delays.

So, the solution to the two bypass methods previously commented is to use some
statistical data shared across all the processes that can have the same memory
contents. Or in other words, a statistical data shared between all the fork
hierarchy processes after an execve system call.

The purpose of these statistics is to compute the application crash period in
order to detect an attack. This crash period is the time between the execve
system call and the first fault or the time between two consecutives faults, but
this has a drawback. If an application crashes once quickly from the execve
system call or crashes twice in a short period of time for some reason, a false
positive attack will be triggered. To avoid this scenario the shared statistical
data holds a list of the i last crashes timestamps and the application crash
period is computed as follows:

crash_period = (n_last_timestamp - n_minus_i_timestamp) / i;

This ways, the size of the last crashes timestamps list allows to fine tuning
the detection sensibility.

When this crash period falls under a certain threshold there is a clear signal
that something malicious is happening. Once detected, the mitigation only kills
the processes that share the same statistical data and so, all the tasks that
can have the same memory contents. This way, an attack is rejected.

Per system enabling
-------------------

This feature can be enabled at build time using the CONFIG_SECURITY_FORK_BRUTE
option or using the visual config application under the following menu:

Security options  --->  Fork brute force attack detection and mitigation

Per process enabling/disabling
------------------------------

To allow that specific applications can turn off or turn on the detection and
mitigation of a fork brute force attack when required, there are two new prctls.

prctl(PR_SECURITY_FORK_BRUTE_ENABLE, 0, 0, 0, 0)  -> To enable the feature
prctl(PR_SECURITY_FORK_BRUTE_DISABLE, 0, 0, 0, 0) -> To disable the feature

Fine tuning
-----------

To customize the detection's sensibility there are two new sysctl attributes
that allow to set the last crashes timestamps list size and the application
crash period threshold (in milliseconds). Both are accessible through the
following files respectively.

/proc/sys/kernel/brute/timestamps_list_size
/proc/sys/kernel/brute/crash_period_threshold

The list size allows to avoid false positives due to crashes unrelated with a
real attack. The period threshold sets the time limit to detect an attack. And,
since a fork brute force attack will be detected if the application crash period
falls under this threshold, the higher this value, the more sensitive the
detection will be.

