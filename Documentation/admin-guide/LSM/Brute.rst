.. SPDX-License-Identifier: GPL-2.0
===========================================================
Brute: Fork brute force attack detection and mitigation LSM
===========================================================

Attacks against vulnerable userspace applications with the purpose to break ASLR
or bypass canaries traditionally use some level of brute force with the help of
the fork system call. This is possible since when creating a new process using
fork its memory contents are the same as those of the parent process (the
process that called the fork system call). So, the attacker can test the memory
infinite times to find the correct memory values or the correct memory addresses
without worrying about crashing the application.

Based on the above scenario it would be nice to have this detected and
mitigated, and this is the goal of this implementation. Specifically the
following attacks are expected to be detected:

1.- Launching (fork()/exec()) a setuid/setgid process repeatedly until a
    desirable memory layout is got (e.g. Stack Clash).
2.- Connecting to an exec()ing network daemon (e.g. xinetd) repeatedly until a
    desirable memory layout is got (e.g. what CTFs do for simple network
    service).
3.- Launching processes without exec() (e.g. Android Zygote) and exposing state
    to attack a sibling.
4.- Connecting to a fork()ing network daemon (e.g. apache) repeatedly until the
    previously shared memory layout of all the other children is exposed (e.g.
    kind of related to HeartBleed).

In each case, a privilege boundary has been crossed:

Case 1: setuid/setgid process
Case 2: network to local
Case 3: privilege changes
Case 4: network to local

So, what really needs to be detected are fork/exec brute force attacks that
cross any of the commented bounds.


Other implementations
=====================

The public version of grsecurity, as a summary, is based on the idea of delaying
the fork system call if a child died due to some fatal signal (SIGSEGV, SIGBUS,
SIGKILL or SIGILL). This has some issues:

Bad practices
-------------

Adding delays to the kernel is, in general, a bad idea.

Scenarios not detected (false negatives)
----------------------------------------

This protection acts only when the fork system call is called after a child has
crashed. So, it would still be possible for an attacker to fork a big amount of
children (in the order of thousands), then probe all of them, and finally wait
the protection time before repeating the steps.

Moreover, this method is based on the idea that the protection doesn't act if
the parent crashes. So, it would still be possible for an attacker to fork a
process and probe itself. Then, fork the child process and probe itself again.
This way, these steps can be repeated infinite times without any mitigation.

Scenarios detected (false positives)
------------------------------------

Scenarios where an application rarely fails for reasons unrelated to a real
attack.


This implementation
===================

The main idea behind this implementation is to improve the existing ones
focusing on the weak points annotated before. Basically, the adopted solution is
to detect a fast crash rate instead of only one simple crash and to detect both
the crash of parent and child processes. Also, fine tune the detection focusing
on privilege boundary crossing. And finally, as a mitigation method, kill all
the offending tasks involved in the attack instead of using delays.

To achieve this goal, and going into more details, this implementation is based
on the use of some statistical data shared across all the processes that can
have the same memory contents. Or in other words, a statistical data shared
between all the fork hierarchy processes after an execve system call.

The purpose of these statistics is, basically, collect all the necessary info
to compute the application crash period in order to detect an attack. This crash
period is the time between the execve system call and the first fault or the
time between two consecutive faults, but this has a drawback. If an application
crashes twice in a short period of time for some reason unrelated to a real
attack, a false positive will be triggered. To avoid this scenario the
exponential moving average (EMA) is used. This way, the application crash period
will be a value that is not prone to change due to spurious data and follows the
real crash period.

To detect a brute force attack it is necessary that the statistics shared by all
the fork hierarchy processes be updated in every fatal crash and the most
important data to update is the application crash period.

There are two types of brute force attacks that need to be detected. The first
one is an attack that happens through the fork system call and the second one is
an attack that happens through the execve system call. The first type uses the
statistics shared by all the fork hierarchy processes, but the second type
cannot use this statistical data due to these statistics dissapear when the
involved tasks finished. In this last scenario the attack info should be tracked
by the statistics of a higher fork hierarchy (the hierarchy that contains the
process that forks before the execve system call).

Moreover, these two attack types have two variants. A slow brute force attack
that is detected if a maximum number of faults per fork hierarchy is reached and
a fast brute force attack that is detected if the application crash period falls
below a certain threshold.

Exponential moving average (EMA)
--------------------------------

This kind of average defines a weight (between 0 and 1) for the new value to add
and applies the remainder of the weight to the current average value. This way,
some spurious data will not excessively modify the average and only if the new
values are persistent, the moving average will tend towards them.

Mathematically the application crash period's EMA can be expressed as follows:

period_ema = period * weight + period_ema * (1 - weight)

Related to the attack detection, the EMA must guarantee that not many crashes
are needed. To demonstrate this, the scenario where an application has been
running without any crashes for a month will be used.

The period's EMA can be written now as:

period_ema[i] = period[i] * weight + period_ema[i - 1] * (1 - weight)

If the new crash periods have insignificant values related to the first crash
period (a month in this case), the formula can be rewritten as:

period_ema[i] = period_ema[i - 1] * (1 - weight)

And by extension:

period_ema[i - 1] = period_ema[i - 2] * (1 - weight)
period_ema[i - 2] = period_ema[i - 3] * (1 - weight)
period_ema[i - 3] = period_ema[i - 4] * (1 - weight)

So, if the substitution is made:

period_ema[i] = period_ema[i - 1] * (1 - weight)
period_ema[i] = period_ema[i - 2] * pow((1 - weight) , 2)
period_ema[i] = period_ema[i - 3] * pow((1 - weight) , 3)
period_ema[i] = period_ema[i - 4] * pow((1 - weight) , 4)

And in a more generic form:

period_ema[i] = period_ema[i - n] * pow((1 - weight) , n)

Where n represents the number of iterations to obtain an EMA value. Or in other
words, the number of crashes to detect an attack.

So, if we isolate the number of crashes:

period_ema[i] / period_ema[i - n] = pow((1 - weight), n)
log(period_ema[i] / period_ema[i - n]) = log(pow((1 - weight), n))
log(period_ema[i] / period_ema[i - n]) = n * log(1 - weight)
n = log(period_ema[i] / period_ema[i - n]) / log(1 - weight)

Then, in the commented scenario (an application has been running without any
crashes for a month), the approximate number of crashes to detect an attack
(using the implementation values for the weight and the crash period threshold)
is:

weight = 7 / 10
crash_period_threshold = 30 seconds

n = log(crash_period_threshold / seconds_per_month) / log(1 - weight)
n = log(30 / (30 * 24 * 3600)) / log(1 - 0.7)
n = 9.44

So, with 10 crashes for this scenario an attack will be detected. If these steps
are repeated for different scenarios and the results are collected:

1 month without any crashes ----> 9.44 crashes to detect an attack
1 year without any crashes -----> 11.50 crashes to detect an attack
10 years without any crashes ---> 13.42 crashes to detect an attack

However, this computation has a drawback. The first data added to the EMA not
obtains a real average showing a trend. So the solution is simple, the EMA needs
a minimum number of data to be able to be interpreted. This way, the case where
a few first faults are fast enough followed by no crashes is avoided.

Per system enabling/disabling
-----------------------------

This feature can be enabled at build time using the CONFIG_SECURITY_FORK_BRUTE
option or using the visual config application under the following menu:

Security options  --->  Fork brute force attack detection and mitigation

Also, at boot time, this feature can be disable too, by changing the "lsm=" boot
parameter.

Kernel selftests
----------------

To validate all the expectations about this implementation, there is a set of
selftests. This tests cover fork/exec brute force attacks crossing the following
privilege boundaries:

1.- setuid process
2.- privilege changes
3.- network to local

Also, there are some tests to check that fork/exec brute force attacks without
crossing any privilege boundariy already commented doesn't trigger the detection
and mitigation stage.

To build the tests:
make -C tools/testing/selftests/ TARGETS=brute

To run the tests:
make -C tools/testing/selftests TARGETS=brute run_tests

To package the tests:
make -C tools/testing/selftests TARGETS=brute gen_tar
