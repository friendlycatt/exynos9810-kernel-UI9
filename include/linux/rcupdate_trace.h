/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Read-Copy Update mechanism for mutual exclusion, adapted for tracing.
 *
 * This tree has no RCU-tasks-trace implementation (it was introduced in
 * v5.8), and the only in-tree user is the BPF sleepable program support
 * which is not enabled here.  Provide the API as a thin wrapper around
 * plain RCU so that the backported BPF code compiles and behaves
 * conservatively.
 */

#ifndef __LINUX_RCUPDATE_TRACE_H
#define __LINUX_RCUPDATE_TRACE_H

#include <linux/sched.h>
#include <linux/rcupdate.h>

static inline int rcu_read_lock_trace_held(void)
{
	return rcu_read_lock_held();
}

static inline void rcu_read_lock_trace(void)
{
	rcu_read_lock();
}

static inline void rcu_read_unlock_trace(void)
{
	rcu_read_unlock();
}

static inline void call_rcu_tasks_trace(struct rcu_head *rhp,
					rcu_callback_t func)
{
	call_rcu(rhp, func);
}

static inline void synchronize_rcu_tasks_trace(void)
{
	synchronize_rcu();
}

#endif /* __LINUX_RCUPDATE_TRACE_H */
