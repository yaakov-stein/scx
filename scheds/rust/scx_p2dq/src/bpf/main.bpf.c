/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * scx_p2dq is a scheduler where the load balancing is done using a pick 2
 * algorithm.
 */

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/scx/bpf_arena_common.h"
#include "../../../../include/lib/sdt_task.h"
#include "../../../../include/lib/cpumask.h"
#include "../../../../include/lib/percpu.h"
#include "../../../../include/lib/topology.h"
#else
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.h>
#include <lib/sdt_task.h>
#include <lib/cpumask.h>
#include <lib/percpu.h>
#include <lib/topology.h>
#include <lib/arena.h>
#endif

#include "intf.h"
#include "types.h"


#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef P2DQ_CREATE_STRUCT_OPS
#define P2DQ_CREATE_STRUCT_OPS 1
#endif

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)
#define lookup_task_ctx(p) ((task_ptr) scx_task_data(p))
#define LBALLOC_PAGES_PER_ALLOC (16)

const volatile u32 nr_llcs = 32;
const volatile u32 nr_nodes = 32;
const volatile u32 nr_cpus = 64;
const volatile u32 nr_dsqs_per_llc = 3;
const volatile u64 dsq_shift = 2;
const volatile int init_dsq_index = 0;
const volatile u64 min_slice_us = 100;
const volatile u64 min_llc_runs_pick2 = 5;
const volatile u32 interactive_ratio = 10;
const volatile u32 min_nr_queued_pick2 = 10;

const volatile bool autoslice = true;
const volatile bool dispatch_pick2_disable = false;
const volatile bool eager_load_balance = true;
const volatile bool interactive_sticky = false;
const volatile bool interactive_fifo = false;
const volatile bool keep_running_enabled = true;
const volatile bool kthreads_local = true;
const volatile bool max_dsq_pick2 = false;
const volatile bool freq_control = false;
const volatile bool select_idle_in_enqueue = true;
const volatile u64 max_exec_ns = 20 * NSEC_PER_MSEC;

const volatile bool dispatch_lb_interactive = false;
const volatile u64 dispatch_lb_busy = 75;
const volatile u64 wakeup_lb_busy = 90;
const volatile bool wakeup_llc_migrations = false;
const volatile u64 lb_slack_factor = LOAD_BALANCE_SLACK;

const volatile bool smt_enabled = true;
const volatile bool has_little_cores = false;
const volatile u32 debug = 2;

const u32 zero_u32 = 0;
extern const volatile u32 nr_cpu_ids;

const u64 lb_timer_intvl_ns = 250LLU * NSEC_PER_MSEC;
const u64 lb_backoff_ns = 5LLU * NSEC_PER_MSEC;

static u32 llc_lb_offset = 1;

u64 llc_ids[MAX_LLCS];
u64 cpu_llc_ids[MAX_CPUS];
u64 cpu_node_ids[MAX_CPUS];
u64 cpu_smt_ids[MAX_CPUS];
u64 big_core_ids[MAX_CPUS];
u64 dsq_time_slices[MAX_DSQS_PER_LLC];

u64 min_slice_ns = 500;
u32 sched_mode = MODE_PERFORMANCE;

// private(LLC_BUDDY) struct scx_buddy buddy;

static u64 scx_malloc(size_t size)
{
	return (u64)scx_static_alloc(size, 1);
	// scx_buddy_alloc_internal(&buddy, size);
}

// static void scx_free(size_t addr)
// {
// 	scx_buddy_free(&buddy, addr);
// }

int allocator_init(void)
{
	// if (scx_buddy_init(&buddy, PAGE_SIZE)) {
	// 	scx_bpf_error("failed to initialize buddy allocator");
	// 	bpf_printk("failed to initialize buddy allocator");
	// }
	if (scx_static_init(1000)) {
		scx_bpf_error("failed to initialize static allocator");
		bpf_printk("failed to initialize static allocator");
	}

	return 0;
}


static u64 max(u64 a, u64 b)
{
	return a >= b ? a : b;
}

static __always_inline u64 dsq_time_slice(int dsq_index)
{
	if (dsq_index > nr_dsqs_per_llc || dsq_index < 0) {
		scx_bpf_error("Invalid DSQ index");
		return 0;
	}
	return dsq_time_slices[dsq_index];
}

static __always_inline bool valid_dsq(u64 dsq_id)
{
	return dsq_id != 0 && dsq_id != SCX_DSQ_INVALID;
}

static __always_inline u64 max_dsq_time_slice(void)
{
	return dsq_time_slices[nr_dsqs_per_llc - 1];
}

static __always_inline u64 task_slice_ns(struct task_struct *p, u64 slice_ns)
{
	return p->scx.weight * slice_ns / 100;
}

static __always_inline u64 task_dsq_slice_ns(struct task_struct *p, int dsq_index)
{
	return task_slice_ns(p, dsq_time_slice(dsq_index));
}

struct p2dq_timer p2dq_timers[MAX_TIMERS] = {
	{lb_timer_intvl_ns, CLOCK_BOOTTIME, 0},
};

struct timer_wrapper {
	struct bpf_timer timer;
	int	key;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TIMERS);
	__type(key, int);
	__type(value, struct timer_wrapper);
} timer_data SEC(".maps");

__hidden
cpu_ptr try_lookup_cpu_ctx(int cpu)
{
	if (cpu >= MAX_CPUS)
		return NULL;

	void *tmp = MEMBER_VPTR(topo_nodes, [TOPO_CPU][cpu]);
	if (!tmp)
		return NULL;

	void *tmp2 = (void *)topo_nodes[TOPO_CPU][cpu];
	if (!tmp2)
		return NULL;

	return (cpu_ptr)tmp2;
}

__hidden
cpu_ptr lookup_cpu_ctx(int cpu)
{
	cpu_ptr cpup;

	if (cpu < 0)
		cpup = try_lookup_cpu_ctx(0);
	else
		cpup = try_lookup_cpu_ctx(cpu);

	if (!cpup) {
		scx_bpf_error("Failed to lookup cpu[%u]", cpu);
		return NULL;
	}

	return cpup;
}

static __always_inline u64 cpu_dsq_id(int dsq_index, cpu_ptr cpuc) {
	if (!cpuc ||
	    dsq_index < 0 ||
	    dsq_index > nr_dsqs_per_llc ||
	    dsq_index >= MAX_DSQS_PER_LLC) {
		scx_bpf_error("cpuc invalid dsq index: %d", dsq_index);
		return 0;
	}
	u64 tmp = *MEMBER_VPTR(cpuc->dsqs, [dsq_index]);
	dbg("DSQ DBG cpu_dsq_id: %llu", tmp);
	return *MEMBER_VPTR(cpuc->dsqs, [dsq_index]);
}

__hidden
llc_ptr try_lookup_llc_ctx(u32 llc_id)
{
	if (llc_id >= MAX_LLCS || llc_id >= NR_CPUS)
		return NULL;

	void *tmp = MEMBER_VPTR(topo_nodes, [TOPO_LLC][llc_id]);
	if (!tmp)
		return NULL;

	void *tmp2 = (void *)topo_nodes[TOPO_LLC][llc_id];
	if (!tmp2)
		return NULL;

	// dbg("CFG llc_id: %u, MEMBER_VPTR addr: %p, REG addr: %p, llc_ptr->id: %u, reg_adds->id: %u, llc_ptr->index: %u",
	// 	llc_id,
	// 	(void *)MEMBER_VPTR(topo_nodes, [TOPO_LLC][llc_id]),
	// 	topo_nodes[TOPO_LLC][llc_id],
	// 	((llc_ptr)tmp)->id,
	// 	((llc_ptr)topo_nodes[TOPO_LLC][llc_id])->id,
	// 	((llc_ptr)tmp)->index);

	return (llc_ptr)tmp2;
}

__hidden
llc_ptr lookup_llc_ctx(u32 llc_id)
{
	llc_ptr llcp;

	llcp = try_lookup_llc_ctx(llc_id);
	if (!llcp)
		scx_bpf_error("Failed to lookup llc[%u]", llc_id);

	return llcp;
}

__hidden
node_ptr try_lookup_node_ctx(u32 node_id)
{
	if (node_id >= MAX_NUMA_NODES)
		return NULL;

	void *tmp = MEMBER_VPTR(topo_nodes, [TOPO_NODE][node_id]);
	if (!tmp)
		return NULL;

	void *tmp2 = (void *)topo_nodes[TOPO_NODE][node_id];
	if (!tmp2)
		return NULL;

	return (node_ptr)tmp2;
}

__hidden
node_ptr lookup_node_ctx(u32 node_id)
{
	node_ptr nodep;

	nodep = try_lookup_node_ctx(node_id);
	if (!nodep)
		scx_bpf_error("Failed to lookup node[%u]", node_id);

	return nodep;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, P2DQ_NR_STATS);
} stats SEC(".maps");

static inline void stat_add(enum stat_idx idx, u64 amount)
{
	u32 idx_v = idx;
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p) += amount;
}

static inline void stat_inc(enum stat_idx idx)
{
	stat_add(idx, 1);
}

/*
 * Returns if the task is interactive based on the tasks DSQ index.
 */
static bool is_interactive(task_ptr taskc)
{
	if (nr_dsqs_per_llc <= 1)
		return false;
	// For now only the shortest duration DSQ is considered interactive.
	return taskc->dsq_index == 0;
}

/*
 * Updates a tasks vtime based on the newly assigned cpu_ctx and returns the
 * updated vtime.
 */
static __always_inline void update_vtime(struct task_struct *p,
					 cpu_ptr cpuc,
					 task_ptr taskc,
					 u64 vtime_now)
{
	/*
	 * If in the same LLC we only need to clamp the vtime to ensure no task
	 * accumulates too much vtime.
	 */
	if (taskc->llc_id == cpuc->llc_id) {
		u64 max_slice = max_dsq_time_slice();
		u64 vtime_min = vtime_now - max_slice;

		p->scx.dsq_vtime = max(p->scx.dsq_vtime, vtime_min);
		return;
	}

	p->scx.dsq_vtime = vtime_now;

	return;
}

static bool scx_bitmap_test_and_clear_cpu(u32 cpu, llc_ptr llcx, bool interactive)
{
	return llcx && scx_bitmap_test_cpu(cpu, (smt_enabled && !interactive) ?
				llcx->idle_smtmask : llcx->idle_cpumask) &&
		    scx_bitmap_clear_cpu(cpu, (smt_enabled && !interactive) ?
				llcx->idle_smtmask : llcx->idle_cpumask);
}

/*
 * Returns a random llc_ctx
 */
static llc_ptr rand_llc_ctx(void)
{
	return lookup_llc_ctx(bpf_get_prandom_u32() % nr_llcs);
}

static bool keep_running(cpu_ptr cpuc, llc_ptr llcx, struct task_struct *p)
{
	int i;

	// Only tasks in the most interactive DSQs can keep running.
	if (!keep_running_enabled ||
	    cpuc->dsq_index == nr_dsqs_per_llc - 1 ||
	    p->scx.flags & SCX_TASK_QUEUED ||
	    cpuc->ran_for >= max_exec_ns)
		return false;

	int nr_queued = 0;
	bpf_for(i, 0, nr_dsqs_per_llc) {
		nr_queued += scx_bpf_dsq_nr_queued(llcx->dsqs[i]);
	}

	if (nr_queued >= llcx->nr_cpus)
		return false;

	u64 slice_ns = task_slice_ns(p, cpuc->slice_ns);
	cpuc->ran_for += slice_ns;
	p->scx.slice = slice_ns;
	stat_inc(P2DQ_STAT_KEEP);
	return true;
}

static s32 pick_idle_affinitized_cpu(struct task_struct *p, task_ptr taskc,
				     s32 prev_cpu, bool *is_idle)
{
	// struct bpf_cpumask *mask;
	llc_ptr llcx;
	s32 cpu = prev_cpu;

	if (!(llcx = lookup_llc_ctx(taskc->llc_id)) ||
	    !llcx->cpumask)
		goto found_cpu;

	// First try last CPU
	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		scx_bitmap_test_and_clear_cpu(prev_cpu, llcx, false)) { // we should be able to use llcx because it is affinitized and will be the same llc
		cpu = prev_cpu;
		*is_idle = true;
		goto found_cpu;
	}

	if (!taskc) {
		cpu = prev_cpu;
		goto found_cpu;
	}

	if (!taskc->cpumask) {
		cpu = prev_cpu;
		goto found_cpu;
	}

	// if (llcx->cpumask && p->cpus_ptr)
	// 	scx_bitmap_and_cpumask(taskc->cpumask, llcx->cpumask,
	// 			p->cpus_ptr);

	// First try to find an idle SMT in the LLC
	if (smt_enabled && llcx->idle_smtmask) {
		cpu = scx_bitmap_pick_any_cpu(llcx->idle_smtmask);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
	}

	// Next try to find an idle CPU in the LLC
	cpu = scx_bitmap_pick_any_cpu(llcx->idle_cpumask);
	if (cpu >= 0) {
		*is_idle = true;
		goto found_cpu;
	}

	// Next try to find an idle CPU in the node
	if (llcx->node_cpumask && llcx->idle_cpumask && p->cpus_ptr) {
		// scx_bitmap_and_cpumask(llcx->idle_cpumask, llcx->node_cpumask,
		// 		p->cpus_ptr);
		if ((cpu = scx_bitmap_pick_any_cpu(llcx->idle_cpumask)) >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
	}

	// Fallback to anywhere the task can run
	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);

found_cpu:
	return cpu;
}

static s32 pick_idle_cpu(struct task_struct *p, task_ptr taskc,
			 s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	llc_ptr llcx, prev_llcx;
	bool interactive = is_interactive(taskc);
	s32 cpu = prev_cpu;

	if (interactive_sticky && interactive &&
		(prev_llcx = lookup_llc_ctx(taskc->llc_id))) {
		cpu = prev_cpu;
		*is_idle = scx_bitmap_test_and_clear_cpu(prev_cpu, prev_llcx, interactive);
		goto found_cpu;
	}

	// First check if last CPU is idle
	if (taskc->all_cpus &&
		(prev_llcx = lookup_llc_ctx(taskc->llc_id)) &&
		scx_bitmap_test_and_clear_cpu(prev_cpu, prev_llcx, interactive)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto found_cpu;
	}

	if (!(llcx = lookup_llc_ctx(taskc->llc_id)) ||
	    !llcx->cpumask)
		goto found_cpu;

	if (!valid_dsq(taskc->dsq_id))
		if (!(llcx = rand_llc_ctx()))
			goto found_cpu;

	/*
	 * If the current task is waking up another task and releasing the CPU
	 * (WAKE_SYNC), attempt to migrate the wakee on the same CPU as the
	 * waker.
	 */
	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_struct *waker = (void *)bpf_get_current_task_btf();
		task_ptr waker_taskc = scx_task_data(waker);
		// Shouldn't happen, but makes code easier to follow
		if (!waker_taskc) {
			cpu = prev_cpu;
			goto found_cpu;
		}

		// Interactive tasks aren't worth migrating across LLCs.
		if (interactive) {
			cpu = prev_cpu;
			if (scx_bitmap_test_and_clear_cpu(cpu, llcx, interactive)) {
				stat_inc(P2DQ_STAT_WAKE_PREV);
				*is_idle = true;
				goto found_cpu;
			}
			// Try an idle CPU in the LLC.
			if (llcx->idle_cpumask &&
			    (cpu = scx_bitmap_pick_any_cpu(llcx->idle_cpumask)) >= 0) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			if (llcx->idle_smtmask &&
			    (cpu = scx_bitmap_pick_any_cpu(llcx->idle_smtmask)) >= 0) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Nothing idle, stay sticky
			cpu = prev_cpu;
			goto found_cpu;
		}
		if (waker_taskc->llc_id == llcx->id || !wakeup_llc_migrations) {
			// First check if the waking task is in the same LLC
			// and the prev cpu is idle
			cpu_ptr cpuc;
			if((prev_llcx ||
				((cpuc = lookup_cpu_ctx(prev_cpu)) &&
				(prev_llcx = lookup_llc_ctx(cpuc->llc_id)))) &&
				scx_bitmap_test_and_clear_cpu(prev_cpu, prev_llcx, interactive)) {
				cpu = prev_cpu;
				stat_inc(P2DQ_STAT_WAKE_PREV);
				*is_idle = true;
				goto found_cpu;
			}
			// Try an idle core in the LLC.
			if (llcx->idle_smtmask &&
			    ((cpu = scx_bitmap_pick_any_cpu(llcx->idle_smtmask))
							>= 0)) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Try an idle core in the LLC.
			if (llcx->idle_cpumask &&
			    ((cpu = scx_bitmap_pick_any_cpu(llcx->idle_smtmask))
							>= 0)) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Nothing idle, stay sticky
			cpu = prev_cpu;
			goto found_cpu;
		}
		// If wakeup LLC are allowed then migrate to the waker llc.
		llc_ptr waker_llcx = lookup_llc_ctx(waker_taskc->llc_id);
		if (!waker_llcx)
			goto found_cpu;

		if (waker_llcx->idle_cpumask &&
		    (cpu = scx_bitmap_pick_any_cpu(waker_llcx->idle_cpumask)
						 ) >= 0) {
			stat_inc(P2DQ_STAT_WAKE_MIG);
			*is_idle = true;
			goto found_cpu;
		}

		// Couldn't find an idle core so just migrate to the CPU
		if (waker_llcx->idle_smtmask &&
		    (cpu = scx_bitmap_pick_any_cpu(waker_llcx->idle_smtmask)
						 ) >= 0) {
			stat_inc(P2DQ_STAT_WAKE_MIG);
			*is_idle = true;
			goto found_cpu;
		}
		// Nothing idle, move to waker CPU
		cpu = scx_bpf_task_cpu(waker);
		goto found_cpu;
	}

	if (llcx->lb_llc_id < MAX_LLCS && taskc->llc_runs > min_llc_runs_pick2) {
		u32 target_llc_id = llcx->lb_llc_id;
		llcx->lb_llc_id = MAX_LLCS;
		if (!(llcx = lookup_llc_ctx(target_llc_id)))
			goto found_cpu;
		stat_inc(P2DQ_STAT_SELECT_PICK2);
	}

	if (has_little_cores && llcx->little_cpumask && llcx->big_cpumask) {
		if (interactive) {
			if ((cpu = scx_bitmap_pick_any_cpu(llcx->little_cpumask)
							 ) >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		} else {
			if ((cpu = scx_bitmap_pick_any_cpu(llcx->big_cpumask)
							 ) >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
	}

	// Next try in the local LLC
	if (!interactive &&
	    llcx->idle_smtmask &&
	    (cpu = scx_bitmap_pick_any_cpu(llcx->idle_smtmask)
							 ) >= 0) {
		*is_idle = true;
		goto found_cpu;
	}

	// Try a idle CPU in the llc
	if ( llcx->idle_cpumask &&
	    (cpu = scx_bitmap_pick_any_cpu(llcx->idle_cpumask)
							 ) >= 0) {
		*is_idle = true;
		goto found_cpu;
	}

	// Couldn't find anything idle just return something in the local LLC
	if (interactive && llcx->cpumask)
		cpu = scx_bitmap_pick_any_cpu(llcx->cpumask);
	else
		// non interactive tasks stay sticky
		cpu = prev_cpu;

found_cpu:
	if (cpu >= nr_cpus || cpu < 0)
		cpu = prev_cpu;

	return cpu;
}


static __always_inline s32 p2dq_select_cpu_impl(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	task_ptr taskc;
	bool is_idle = false;
	s32 cpu;

	if (!(taskc = lookup_task_ctx(p)))
		return prev_cpu;

	if (!taskc->all_cpus)
		cpu = pick_idle_affinitized_cpu(p, taskc, prev_cpu, &is_idle);
	else
		cpu = pick_idle_cpu(p, taskc, prev_cpu, wake_flags, &is_idle);

	if (is_idle) {
		stat_inc(P2DQ_STAT_IDLE);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON|cpu, taskc->slice_ns, 0);
	}
	trace("SELECT [%d][%s] %i->%i idle %i",
	      p->pid, p->comm, prev_cpu, cpu, is_idle);

	return cpu;
}


/*
 * Perform the enqueue logic for `p` but don't enqueue it where possible.  This
 * is primarily used so that scx_chaos can decide to enqueue a task either
 * immediately in `enqueue` or later in `dispatch`. This returns a tagged union
 * with three states:
 * - P2DQ_ENQUEUE_PROMISE_COMPLETE: Either the task has been enqueued, or there
 *     is nothing to do (enqueue failed).
 * - P2DQ_ENQUEUE_PROMISE_FIFO: The completer should enqueue this task on a fifo dsq.
 * - P2DQ_ENQUEUE_PROMISE_VTIME: The completer should enqueue this task on a vtime dsq.
 */
static __always_inline void async_p2dq_enqueue(struct enqueue_promise *ret,
					       struct task_struct *p,
					       u64 enq_flags)
{
	cpu_ptr cpuc;
	llc_ptr llcx;
	task_ptr taskc;
	s32 cpu = scx_bpf_task_cpu(p);

	dbg("DSQ DBG: Entering enqueue");
	/*
	 * Per-cpu kthreads are considered interactive and dispatched directly
	 * into the local DSQ.
	 */
	if ((p->flags & PF_KTHREAD) &&
	    p->cpus_ptr == &p->cpus_mask &&
	    p->nr_cpus_allowed != nr_cpus &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
	    kthreads_local) {
		stat_inc(P2DQ_STAT_DIRECT);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON|cpu, dsq_time_slices[0], enq_flags);
		ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
		dbg("DSQ DBG: Return 1");
		return;
	}

	if(!(taskc = lookup_task_ctx(p))) {
		scx_bpf_error("invalid lookup");
		ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
		dbg("DSQ DBG: Return 2");
		return;
	}

	// Handle affinitized tasks separately
	if (!taskc->all_cpus ||
	    (p->cpus_ptr == &p->cpus_mask && p->nr_cpus_allowed != nr_cpus)) {
		bool is_idle = false;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			cpu = pick_idle_affinitized_cpu(p, taskc, cpu, &is_idle);
		else
			is_idle = scx_bpf_test_and_clear_cpu_idle(cpu);

		if (!(cpuc = lookup_cpu_ctx(cpu)) ||
		    !(llcx = lookup_llc_ctx(cpuc->llc_id))) {
			scx_bpf_error("invalid lookup");
			ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
			return;
		}

		taskc->dsq_id = cpuc->affn_dsq;
		update_vtime(p, cpuc, taskc, llcx->vtime);

		// Idle affinitized tasks can be direct dispatched.
		if (is_idle) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON|cpu, taskc->slice_ns, enq_flags);
			stat_inc(P2DQ_STAT_IDLE);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
			return;
		}

		if (interactive_fifo && taskc->dsq_index == 0)
			scx_bpf_dsq_insert(p, taskc->dsq_id, taskc->slice_ns, enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, taskc->dsq_id, taskc->slice_ns, p->scx.dsq_vtime, enq_flags);

		ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
		dbg("DSQ DBG: Return 3");
		return;
	}

	// If an idle CPU hasn't been found in select_cpu find one now
	if (select_idle_in_enqueue && !__COMPAT_is_enq_cpu_selected(enq_flags)) {
		bool is_idle = false;
		cpu = pick_idle_cpu(p, taskc, cpu, 0, &is_idle);
		if (!(cpuc = lookup_cpu_ctx(cpu)) ||
		     !(llcx = lookup_llc_ctx(cpuc->llc_id))) {
			scx_bpf_error("invalid lookup");
			ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
			dbg("DSQ DBG: Return 4");
			return;
		}

		update_vtime(p, cpuc, taskc, llcx->vtime);
		if (is_idle) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON|cpu, taskc->slice_ns, enq_flags);
			stat_inc(P2DQ_STAT_IDLE);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
			dbg("DSQ DBG: Return 5");
			return;
		}

		taskc->dsq_id = cpu_dsq_id(taskc->dsq_index, cpuc);
		if (interactive_fifo && taskc->dsq_index == 0)
			scx_bpf_dsq_insert(p, taskc->dsq_id, taskc->slice_ns, enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, taskc->dsq_id, taskc->slice_ns, p->scx.dsq_vtime, enq_flags);

		ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
		dbg("DSQ DBG: Return 6");
		return;
	}

	if (!(cpuc = lookup_cpu_ctx(scx_bpf_task_cpu(p))) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id))) {
		scx_bpf_error("invalid lookup");
		ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
		dbg("DSQ DBG: Return 7");
		return;
	}

	update_vtime(p, cpuc, taskc, llcx->vtime);
	if ((llcx = lookup_llc_ctx(cpuc->llc_id)) &&
		scx_bitmap_test_and_clear_cpu(cpu, llcx, is_interactive(taskc))) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON|cpu, taskc->slice_ns, enq_flags);
		stat_inc(P2DQ_STAT_IDLE);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
		dbg("DSQ DBG: Return 8");
		return;
	}
	taskc->dsq_id = cpu_dsq_id(taskc->dsq_index, cpuc);

	if (interactive_fifo && taskc->dsq_index == 0) {
		ret->kind = P2DQ_ENQUEUE_PROMISE_FIFO;
		ret->fifo.dsq_id = taskc->dsq_id;
		ret->fifo.enq_flags = enq_flags;
		ret->fifo.slice_ns = taskc->slice_ns;
	} else {
		ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
		ret->vtime.dsq_id = taskc->dsq_id;
		ret->vtime.enq_flags = enq_flags;
		ret->vtime.slice_ns = taskc->slice_ns;
		ret->vtime.vtime = p->scx.dsq_vtime;
	}
	dbg("DSQ DBG: Return 9 with kind %d and dsq_id %llu", ret->kind, ret->vtime.dsq_id);
}

static __always_inline void complete_p2dq_enqueue(struct enqueue_promise *pro,
						  struct task_struct *p)
{
	switch (pro->kind) {
	case P2DQ_ENQUEUE_PROMISE_COMPLETE:
		goto out;
	case P2DQ_ENQUEUE_PROMISE_FIFO:
		dbg("DSQ DBG ID [767] %d", pro->fifo.dsq_id);
		scx_bpf_dsq_insert(p, pro->fifo.dsq_id, pro->fifo.slice_ns,
				   pro->fifo.enq_flags);
		goto out;
	case P2DQ_ENQUEUE_PROMISE_VTIME:
		dbg("DSQ DBG ID [772] %d", pro->vtime.dsq_id);
		scx_bpf_dsq_insert_vtime(p, pro->vtime.dsq_id, pro->vtime.slice_ns,
				         pro->vtime.vtime, pro->vtime.enq_flags);
		dbg("DSQ DBG: Completed enqueue");
		goto out;
	}
out:
	pro->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
}

static __always_inline int p2dq_running_impl(struct task_struct *p)
{
	task_ptr taskc;
	cpu_ptr cpuc;
	llc_ptr llcx;
	s32 task_cpu = scx_bpf_task_cpu(p);

	if (!(taskc = lookup_task_ctx(p)) ||
	    !(cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return -EINVAL;

	if (taskc->llc_id != cpuc->llc_id) {
		taskc->llc_runs = 0;
		stat_inc(P2DQ_STAT_LLC_MIGRATION);
		trace("RUNNING %d cpu %d->%d llc %d->%d",
		      p->pid, cpuc->id, task_cpu,
		      taskc->llc_id, llcx->id);
	} else {
		taskc->llc_runs += 1;
	}
	if (taskc->node_id != cpuc->node_id) {
		stat_inc(P2DQ_STAT_NODE_MIGRATION);
	}

	taskc->llc_id = llcx->id;
	taskc->node_id = llcx->node_id;
	cpuc->interactive = taskc->dsq_index == 0;
	cpuc->dsq_index = taskc->dsq_index;
	cpuc->dsq_id = taskc->dsq_id;
	cpuc->slice_ns = taskc->slice_ns;
	cpuc->ran_for = 0;
	// racy, but don't care
	if (p->scx.dsq_vtime > llcx->vtime &&
	    p->scx.dsq_vtime < llcx->vtime + max_dsq_time_slice()) {
		__sync_val_compare_and_swap(&llcx->vtime, llcx->vtime, p->scx.dsq_vtime);
	}

	// For non affinitized tasks update the vtime if it is larger than the
	// current LLC vtime. Affinitized tasks are direct dispatched and don't
	// strictly follow vtime.
	if ((taskc->dsq_index >= 0 && taskc->dsq_index < nr_dsqs_per_llc) &&
	    taskc->all_cpus &&
	    p->scx.dsq_vtime > llcx->dsq_max_vtime[taskc->dsq_index])
		llcx->dsq_max_vtime[taskc->dsq_index] = p->scx.dsq_vtime;

	// Affinitized task vtime is handled separately
	if (!taskc->all_cpus &&
	    !(interactive_fifo && taskc->dsq_index == 0) &&
	    !((p->flags & PF_KTHREAD) && kthreads_local) &&
	     p->scx.dsq_vtime > llcx->affn_max_vtime &&
	     p->scx.dsq_vtime < llcx->vtime + max_dsq_time_slice()) {
		__sync_val_compare_and_swap(&llcx->affn_max_vtime, llcx->affn_max_vtime, p->scx.dsq_vtime);
		cpuc->affn_max_vtime = p->scx.dsq_vtime;

		u64 max_lag = llcx->vtime - max_dsq_time_slice();
		if (cpuc->affn_max_vtime < max_lag)
			cpuc->affn_max_vtime = max_lag;
	}


	// If the task is running in the least interactive DSQ, bump the
	// frequency.
	if (freq_control && taskc->dsq_index == nr_dsqs_per_llc-1) {
		scx_bpf_cpuperf_set(task_cpu, SCX_CPUPERF_ONE);
	}

	u64 now = bpf_ktime_get_ns();
	if (taskc->last_run_started == 0)
		taskc->last_run_started = now;

	taskc->last_run_at = now;

	return 0;
}

void BPF_STRUCT_OPS(p2dq_stopping, struct task_struct *p, bool runnable)
{
	task_ptr taskc;
	cpu_ptr cpuc;
	llc_ptr llcx;
	u64 used, scaled_used, last_dsq_slice_ns;
	u64 now = bpf_ktime_get_ns();

	if (!(taskc = lookup_task_ctx(p)) ||
	    !(llcx = lookup_llc_ctx(taskc->llc_id)))
		return;

	// can't happen, appease the verifier
	int dsq_index = taskc->dsq_index;
	if (dsq_index < 0 || dsq_index >= nr_dsqs_per_llc) {
		scx_bpf_error("taskc invalid dsq index");
		return;
	}

	taskc->last_dsq_id = taskc->dsq_id;
	taskc->last_dsq_index = taskc->dsq_index;
	taskc->used = 0;

	last_dsq_slice_ns = taskc->slice_ns;
	used = now - taskc->last_run_at;
	scaled_used = used * 100 / p->scx.weight;

	p->scx.dsq_vtime += scaled_used;
	__sync_fetch_and_add(&llcx->vtime, used);
	__sync_fetch_and_add(&llcx->load, used);
	__sync_fetch_and_add(&llcx->dsq_load[dsq_index], used);

	if (taskc->all_cpus) {
		__sync_fetch_and_add(&llcx->dsq_max_vtime[dsq_index], used);
	} else {
		// Note that affinitized load is absolute load, not scaled.
		__sync_fetch_and_add(&llcx->affn_load, used);

		if ((cpuc = lookup_cpu_ctx(scx_bpf_task_cpu(p)))) {
			cpuc->affn_max_vtime += used;
		}
	}

	trace("STOPPING %s weight %d slice %llu used %llu scaled %llu",
	      p->comm, p->scx.weight, last_dsq_slice_ns, used, scaled_used);

	if (!runnable) {
		used = now - taskc->last_run_started;
		// On stopping determine if the task can move to a longer DSQ by
		// comparing the used time to the scaled DSQ slice.
		if (used >= ((9 * last_dsq_slice_ns) / 10)) {
			if (taskc->dsq_index < nr_dsqs_per_llc - 1) {
				taskc->dsq_index += 1;
				stat_inc(P2DQ_STAT_DSQ_CHANGE);
				trace("%s[%p]: DSQ inc %llu -> %u", p->comm, p,
				      taskc->last_dsq_index, taskc->dsq_index);
			} else {
				stat_inc(P2DQ_STAT_DSQ_SAME);
			}
		// If under half the slice was consumed move the task back down.
		} else if (used < last_dsq_slice_ns / 2) {
			if (taskc->dsq_index > 0) {
				taskc->dsq_index -= 1;
				stat_inc(P2DQ_STAT_DSQ_CHANGE);
				trace("%s[%p]: DSQ dec %llu -> %u", p->comm, p,
				      taskc->last_dsq_index, taskc->dsq_index);
			} else {
				stat_inc(P2DQ_STAT_DSQ_SAME);
			}
		} else {
			stat_inc(P2DQ_STAT_DSQ_SAME);
		}
		taskc->slice_ns = task_dsq_slice_ns(p, taskc->dsq_index);
		taskc->last_run_started = 0;
	}
}

static __always_inline int dispatch_cpu(u64 dsq_id, s32 cpu)
{
	struct task_struct *p;
	int dispatched = 0;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		/*
		 * This is a workaround for the BPF verifier's pointer
		 * validation limitations. Once the verifier gets smarter
		 * we can remove this bpf_task_from_pid().
		 */
		p = bpf_task_from_pid(p->pid); // Does this need to be removed?
		if (!p)
			continue;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			scx_task_free(p);
			continue;
		}

		if (!__COMPAT_scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL_ON | cpu, 0)) {
			scx_task_free(p);
			continue;
		}
		dispatched += 1;
		stat_inc(P2DQ_STAT_DISPATCH_PICK2);
		scx_task_free(p);
		break;
	}

	return dispatched;
}

static __always_inline bool consume_llc_compat(llc_ptr cur_llcx, llc_ptr llcx)
{
	u64 dsq_id;
	int i;

	if (dispatch_lb_interactive &&
	    scx_bpf_dsq_move_to_local(llcx->dsqs[0])) {
			stat_inc(P2DQ_STAT_DISPATCH_PICK2);
			return true;
	}

	if (llcx->load > cur_llcx->load) {
		bpf_for(i, 1 , nr_dsqs_per_llc) {
			dsq_id = llcx->dsqs[nr_dsqs_per_llc - i];
			if (scx_bpf_dsq_move_to_local(dsq_id)) {
				stat_inc(P2DQ_STAT_DISPATCH_PICK2);
				return true;
			}
		}
	}

	return false;
}

static __always_inline bool consume_llc(llc_ptr cur_llcx, llc_ptr llcx, s32 cpu)
{
	u64 dsq_id;
	int i;

	if (!cur_llcx || !llcx || !bpf_ksym_exists(scx_bpf_dsq_move))
		return false;

	if (dispatch_lb_interactive &&
	    scx_bpf_dsq_move_to_local(llcx->dsqs[0])) {
		stat_inc(P2DQ_STAT_DISPATCH_PICK2);
		return true;
	}

	bpf_for(i, 1, nr_dsqs_per_llc) {
		dsq_id = llcx->dsqs[nr_dsqs_per_llc - i];
		if (dispatch_cpu(dsq_id, cpu) > 0)
			return true;
	}

	return false;
}


static __always_inline int dispatch_pick_two(s32 cpu, llc_ptr cur_llcx, cpu_ptr cpuc)
{
	llc_ptr first, second, left, right;
	int i;

	// If on a single LLC there isn't anything left to try.
	if (nr_llcs == 1 || dispatch_pick2_disable || nr_llcs >= MAX_LLCS)
		return -EINVAL;


	if (min_nr_queued_pick2 > 0) {
		u32 cur_queued = 0;
		bpf_for(i, 0, nr_llcs) {
			if (i >= nr_dsqs_per_llc || i < 0)
				continue;

			u64 cur_dsq_id = *MEMBER_VPTR(cur_llcx->dsqs, [i]);
			cur_queued += scx_bpf_dsq_nr_queued(cur_dsq_id);
		}
		if (cur_queued < min_nr_queued_pick2)
			return -EINVAL;
	}

	if (lb_backoff_ns > 0) {
		u64 now = scx_bpf_now();
		if (now - cur_llcx->last_period_ns < lb_backoff_ns)
			return -EINVAL;
	}


	/*
	 * For pick two load balancing we randomly choose two LLCs. We then
	 * first try to consume from the LLC with the largest load. If we are
	 * unable to consume from the first LLC then the second LLC is consumed
	 * from. This yields better work conservation on machines with a large
	 * number of LLCs.
	 */
	left = rand_llc_ctx();
	right = rand_llc_ctx();

	if (!left || !right)
		return -EINVAL;

	if (right->load > left->load) {
		first = right;
		second = left;
	} else {
		first = left;
		second = right;
	}

	// The compat macro doesn't work properly, so on older kernels best
	// effort by moving to local directly instead of iterating.
	if (!bpf_ksym_exists(scx_bpf_dsq_move)) {
		if (consume_llc_compat(cur_llcx, first))
			return 0;
		if (consume_llc_compat(cur_llcx, second))
			return 0;
	}

	if (first->load > cur_llcx->load &&
	    consume_llc(cur_llcx, first, cpu))
		return 0;

	if (second->load > cur_llcx->load &&
	    consume_llc(cur_llcx, second, cpu))
		return 0;

	return 0;
}


static __always_inline void p2dq_dispatch_impl(s32 cpu, struct task_struct *prev)
{
	cpu_ptr cpuc;
	llc_ptr llcx;
	u64 dsq_id = 0;
	int i;

	if (!(cpuc = lookup_cpu_ctx(cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	if (nr_dsqs_per_llc > MAX_DSQS_PER_LLC) {
		scx_bpf_error("can't happen");
		return;
	}

	u64 min_vtime = llcx->vtime;

	bpf_for(i, 0, nr_dsqs_per_llc) {
		if (llcx->dsq_max_vtime[i] < min_vtime) {
			min_vtime = llcx->dsq_max_vtime[i];
			dsq_id = llcx->dsqs[i];
		}
	}

	if (cpuc->affn_max_vtime < min_vtime &&
	    llcx->affn_load < llcx->load / 2)
		dsq_id = cpuc->affn_dsq;

	trace("DISPATCH cpu[%d] vtime %llu affn_vtime %llu min_vtime %llu dsq_id %llu",
	      cpu, llcx->vtime, cpuc->affn_max_vtime, min_vtime, dsq_id);

	if (valid_dsq(dsq_id) && scx_bpf_dsq_move_to_local(dsq_id))
		return;

	// Try the last DSQ, this is to keep tasks sticky to their dsq type.
	if (valid_dsq(cpuc->dsq_id) &&
	    scx_bpf_dsq_move_to_local(cpuc->dsq_id))
			return;

	bpf_for(i, 0, nr_dsqs_per_llc) {
		dsq_id = llcx->dsqs[i];
		if (dsq_id != cpuc->dsq_id &&
		    scx_bpf_dsq_move_to_local(dsq_id))
		    return;
	}

	if (prev && keep_running(cpuc, llcx, prev))
		return;

	if (scx_bpf_dsq_move_to_local(cpuc->affn_dsq))
		return;

	dispatch_pick_two(cpu, llcx, cpuc);
}

void BPF_STRUCT_OPS(p2dq_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	task_ptr taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	taskc->all_cpus = p->cpus_ptr == &p->cpus_mask && p->nr_cpus_allowed == nr_cpus;
}

static __always_inline s32 p2dq_init_task_impl(struct task_struct *p,
					       struct scx_init_task_args *args)
{
	// struct mask_wrapper *wrapper;
	// scx_bitmap_t cpumask;
	task_ptr taskc;
	cpu_ptr cpuc;
	llc_ptr llcx;
	scx_bitmap_t temp_mask;
	int ret;

	s32 task_cpu = scx_bpf_task_cpu(p);

	taskc = (task_ptr)scx_task_alloc(p);
	if (!taskc) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	if (!(cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return -EINVAL;

	ret = create_save_scx_bitmap(&temp_mask);
	if (ret)
		return ret;

	taskc->cpumask = temp_mask;
	taskc->llc_id = cpuc->llc_id;
	taskc->node_id = cpuc->node_id;
	taskc->dsq_index = init_dsq_index;
	taskc->last_dsq_index = init_dsq_index;
	taskc->slice_ns = dsq_time_slice(init_dsq_index);
	taskc->all_cpus = p->cpus_ptr == &p->cpus_mask && p->nr_cpus_allowed == nr_cpus;
	p->scx.dsq_vtime = llcx->vtime;

	// When a task is initialized set the DSQ id to invalid. This causes
	// the task to be randomized on a LLC.
	if (taskc->all_cpus)
		taskc->dsq_id = SCX_DSQ_INVALID;
	else
		taskc->dsq_id = llcx->dsqs[init_dsq_index];

	return 0;
}

void BPF_STRUCT_OPS(p2dq_update_idle, s32 cpu, bool idle)
{
	llc_ptr llcx;
	cpu_ptr cpuc;

	scx_arena_subprog_init();

	if (!(cpuc = lookup_cpu_ctx(cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	if (idle) {
		if (llcx->idle_cpumask)
			scx_bitmap_set_cpu(cpu, llcx->idle_cpumask);
	} else {
		if (llcx->idle_cpumask)
			scx_bitmap_clear_cpu(cpu, llcx->idle_cpumask);
	}
}

void BPF_STRUCT_OPS(p2dq_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	scx_task_free(p);
}

static llc_ptr llc_alloc(u32 llc_index)
{
	llc_ptr llcx;
	scx_bitmap_t temp_bitmap;
	int ret;

	llcx = (llc_ptr)scx_malloc(sizeof(struct llc_ctx));
	if (!llcx)
		return NULL;

	llcx->vtime = 0;
	llcx->id = *MEMBER_VPTR(llc_ids, [llc_index]);
	llcx->index = llc_index;
	llcx->nr_cpus = 0;

	// Topology related setup, first we assume all CPUs are big. When CPUs
	// initialize they will update this as needed.
	llcx->all_big = true;

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return NULL;
	llcx->cpumask = temp_bitmap;

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return NULL;
	llcx->big_cpumask = temp_bitmap;

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return NULL;
	llcx->little_cpumask = temp_bitmap;

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return NULL;
	llcx->node_cpumask = temp_bitmap;

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return NULL;
	llcx->smt_cpumask = temp_bitmap;

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return NULL;
	llcx->idle_cpumask = temp_bitmap;

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return NULL;
	llcx->idle_smtmask = temp_bitmap;

	return llcx;
}

static int init_llc(u32 llc_index)
{
	llc_ptr llcx;

	if (llc_index >= MAX_LLCS) {
		scx_bpf_error("Max llc ID %u exceeded (%u)", MAX_LLCS, llc_index);
		return -EINVAL;
	}

	llcx = llc_alloc(llc_index);
	if (!llcx)
		return -ENOMEM;

	topo_nodes[TOPO_LLC][llc_index] = (u64)llcx;

	llc_ptr llc = lookup_llc_ctx(llc_index);
	if (!llc)
		return -EINVAL;

	dbg("CFG: llc_index[%d], llcx->id[%d], llcx->index[%d] with llcx->nr_cpus[%u] configured with llc->id[%u], llc->index[%d] with llc->nr_cpus[%u]", llc_index, llcx->id, llcx->index, llcx->nr_cpus, llc->id, llc->index, llc->nr_cpus);

	return 0;
}

static int init_node(u32 node_index)
{
	node_ptr nodec;
	scx_bitmap_t temp_bitmap;
	int ret;

	nodec = (node_ptr)scx_malloc(sizeof(struct node_ctx));
	if (!nodec) {
		scx_bpf_error("No node %u", node_index);
		return -ENOENT;
	}

	// Topology related setup, first we assume all CPUs are big. When CPUs
	// initialize they will update this as needed.
	nodec->all_big = true;

	nodec->id = node_index; // Should we consider updating this? At the moment, it's "hardcoded"

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return ret;
	nodec->cpumask = temp_bitmap;

	ret = create_save_scx_bitmap(&temp_bitmap);
	if (ret)
		return ret;
	nodec->big_cpumask = temp_bitmap;

	topo_nodes[TOPO_NODE][node_index] = (u64)nodec;

	dbg("CFG NODE[%u] configured", node_index);

	return 0;
}

// Initializes per CPU data structures.
static s32 init_cpu(int cpu)
{
	node_ptr nodec;
	llc_ptr llcx;
	cpu_ptr cpuc;

	cpuc = (cpu_ptr)scx_malloc(sizeof(struct cpu_ctx));
	if (!cpuc)
		return -ENOENT;

	cpuc->id = cpu;
	// dbg("Assigned llc_id=%u to cpu=%u (cpu_llc_ids[%u]=%u)", cpu_llc_ids[cpu], cpu, cpu, cpu_llc_ids[cpu]);
	cpuc->llc_id = cpu_llc_ids[cpu];
	cpuc->smt = cpu_smt_ids[cpu] == 0;
	cpuc->node_id = cpu_node_ids[cpu];
	cpuc->is_big = big_core_ids[cpu] == 1;
	cpuc->affn_max_vtime = 0;
	cpuc->dsq_id = 0;
	cpuc->slice_ns = 1;

	if (!(llcx = lookup_llc_ctx(cpuc->llc_id)) ||
	    !(nodec = lookup_node_ctx(cpuc->node_id))) {
		scx_bpf_error("failed to get ctxs for cpu %u", cpu);
		return -ENOENT;
	}

	// copy for each cpu, doesn't matter if it gets overwritten.
	llcx->nr_cpus += 1;
	// dbg("llcx=%p: assigned id=%u from cpu_llc_ids[%u]=%u", llcx, cpu_llc_ids[cpu], cpu, cpu_llc_ids[cpu]);
	llcx->id = cpu_llc_ids[cpu];
	llcx->node_id = cpu_node_ids[cpu];
	nodec->id = cpu_node_ids[cpu];

	topo_nodes[TOPO_CPU][cpu] = (u64)cpuc;

	if (cpuc->is_big) {
		trace("CPU[%d] is big", cpu);
		bpf_rcu_read_lock();
		if (nodec->big_cpumask)
			scx_bitmap_set_cpu(cpu, nodec->big_cpumask);
		if (llcx->big_cpumask)
			scx_bitmap_set_cpu(cpu, llcx->big_cpumask);
		bpf_rcu_read_unlock();
	} else {
		bpf_rcu_read_lock();
		if (llcx->little_cpumask)
			scx_bitmap_set_cpu(cpu, llcx->little_cpumask);
		bpf_rcu_read_unlock();
		llcx->all_big = false;
		nodec->all_big = false;
	}

	bpf_rcu_read_lock();
	if (cpuc->smt && llcx->smt_cpumask)
		scx_bitmap_set_cpu(cpu, llcx->smt_cpumask);
	if (nodec->cpumask)
		scx_bitmap_set_cpu(cpu, nodec->cpumask);
	if (llcx->cpumask)
		scx_bitmap_set_cpu(cpu, llcx->cpumask);
	bpf_rcu_read_unlock();

	trace("CFG CPU[%d]NODE[%d]LLC[%d] initialized",
	    cpu, cpuc->node_id, cpuc->llc_id);

	return 0;
}

static bool load_balance_timer(void)
{
	llc_ptr llcx, lb_llcx;
	int j;
	u64 ideal_sum, load_sum = 0, interactive_sum = 0;
	u32 llc_id, llc_index, lb_llc_index, lb_llc_id;

	bpf_for(llc_index, 0, nr_llcs) {
		// verifier
		if (llc_index >= MAX_LLCS)
			break;

		llc_id = *MEMBER_VPTR(llc_ids, [llc_index]);
		if (!(llcx = lookup_llc_ctx(llc_id))) {
			scx_bpf_error("failed to lookup llc");
			return false;
		}

		lb_llc_index = (llc_index + llc_lb_offset) % nr_llcs;
		if (lb_llc_index < 0 || lb_llc_index >= MAX_LLCS) {
			scx_bpf_error("failed to lookup lb_llc");
			return false;
		}

		lb_llc_id = *MEMBER_VPTR(llc_ids, [lb_llc_index]);
		if (!(lb_llcx = lookup_llc_ctx(lb_llc_id))) {
			scx_bpf_error("failed to lookup lb llc");
			return false;
		}

		load_sum += llcx->load;
		interactive_sum += llcx->dsq_load[0];

		s64 load_imbalance = 0;
		if(llcx->load > lb_llcx->load)
			load_imbalance = (100 * (llcx->load - lb_llcx->load)) / llcx->load;

		u32 lb_slack = (lb_slack_factor > 0 ? lb_slack_factor : LOAD_BALANCE_SLACK);

		if (load_imbalance > lb_slack)
			llcx->lb_llc_id = lb_llc_id;
		else
			llcx->lb_llc_id = MAX_LLCS;

		dbg("LB llcx[%u] %llu lb_llcx[%u] %llu imbalance %lli",
		    llc_id, llcx->load, lb_llc_id, lb_llcx->load, load_imbalance);
	}

	dbg("LB Total load %llu, Total interactive %llu",
	    load_sum, interactive_sum);

	llc_lb_offset = (llc_lb_offset % (nr_llcs - 1)) + 1;

	if (!autoslice || load_sum == 0 || load_sum < interactive_sum)
		goto reset_load;

	if (interactive_sum == 0) {
		dsq_time_slices[0] = (11 * dsq_time_slices[0]) / 10;
		bpf_for(j, 1, nr_dsqs_per_llc) {
			dsq_time_slices[j] = dsq_time_slices[0] << j << dsq_shift;
		}
	} else {
		ideal_sum = (load_sum * interactive_ratio) / 100;
		dbg("LB autoslice ideal/sum %llu/%llu", ideal_sum, interactive_sum);
		if (interactive_sum < ideal_sum) {
			dsq_time_slices[0] = (11 * dsq_time_slices[0]) / 10;

			bpf_for(j, 1, nr_dsqs_per_llc) {
				dsq_time_slices[j] = dsq_time_slices[0] << j << dsq_shift;
			}
		} else {
			dsq_time_slices[0] = max((10 * dsq_time_slices[0]) / 11, min_slice_ns);
			bpf_for(j, 1, nr_dsqs_per_llc) {
				dsq_time_slices[j] = dsq_time_slices[0] << j << dsq_shift;
			}
		}
	}


reset_load:

	bpf_for(llc_index, 0, nr_llcs) {
		llc_id = *MEMBER_VPTR(llc_ids, [llc_index]);
		if (!(llcx = lookup_llc_ctx(llc_id)))
			return false;

		llcx->load = 0;
		__sync_fetch_and_and(&llcx->affn_load, 0);
		llcx->last_period_ns = scx_bpf_now();
		bpf_for(j, 0, nr_dsqs_per_llc) {
			llcx->dsq_load[j] = 0;
			if (llc_id == 0 && autoslice) {
				if (j > 0 && dsq_time_slices[j] < dsq_time_slices[j-1]) {
					dsq_time_slices[j] = dsq_time_slices[j-1] << dsq_shift;
				}
				dbg("LB autoslice interactive slice %llu", dsq_time_slices[j]);
			}
		}
	}

	return true;
}

static bool run_timer_cb(int key)
{
	switch (key) {
	case EAGER_LOAD_BALANCER_TMR:
		return load_balance_timer();
	default:
		return false;
	}
}


static int timer_cb(void *map, int key, struct timer_wrapper *timerw)
{
	if (timerw->key < 0 || timerw->key > MAX_TIMERS) {
		return 0;
	}

	struct p2dq_timer *cb_timer = &p2dq_timers[timerw->key];
	bool resched = run_timer_cb(timerw->key);

	if (!resched || !cb_timer || cb_timer->interval_ns == 0) {
		trace("TIMER timer %d stopped", timerw->key);
		return 0;
	}

	bpf_timer_start(&timerw->timer,
			cb_timer->interval_ns,
			cb_timer->start_flags);

	return 0;
}


s32 static start_timers(void)
{
	struct timer_wrapper *timerw;
	int timer_id, err;

	bpf_for(timer_id, 0, MAX_TIMERS) {
		timerw = bpf_map_lookup_elem(&timer_data, &timer_id); // should we be putting this in arenas as well? Going to assume not for now.
		if (!timerw || timer_id < 0 || timer_id > MAX_TIMERS) {
			scx_bpf_error("Failed to lookup timer");
			return -ENOENT;
		}

		struct p2dq_timer *new_timer = &p2dq_timers[timer_id];
		if (!new_timer) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
		timerw->key = timer_id;

		err = bpf_timer_init(&timerw->timer, &timer_data, new_timer->init_flags);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_set_callback(&timerw->timer, &timer_cb);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_start(&timerw->timer,
				      new_timer->interval_ns,
				      new_timer->start_flags);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
	}

	return 0;
}

static __always_inline s32 p2dq_init_impl()
{
	int i, j, ret;

	ret = allocator_init();
	if (ret)
		return ret;

	if (init_dsq_index >= nr_dsqs_per_llc) {
		scx_bpf_error("invalid init_dsq_index");
		return -EINVAL;
	}

	// First we initialize LLCs because DSQs are created at the LLC level.
	bpf_for(i, 0, nr_llcs) {
		ret = init_llc(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_llcs) {
		llc_ptr llcx;
		llcx = lookup_llc_ctx(i);
		dbg("CFG llc_id = [%d], llcx->id = [%d]", i, llcx->id);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_nodes) {
		ret = init_node(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_cpus) {
		ret = init_cpu(i);
		if (ret)
			return ret;
	}

	// Create DSQs for the LLCs
	llc_ptr llcx;
	u64 dsq_id;
	u32 llc_id, llc_index;
	bpf_for(llc_index, 0, nr_llcs) {
		llc_id = *MEMBER_VPTR(llc_ids, [llc_index]);
		if (!(llcx = lookup_llc_ctx(llc_id)))
			return -EINVAL;

		bpf_for(i, 0, nr_dsqs_per_llc) {
			dsq_id = ((llc_index << nr_dsqs_per_llc) | i) + 1;
			dbg("CFG creating DSQ[%d][%llu] slice_us %llu for LLC[%u]",
			    i, dsq_id, dsq_time_slice(i), llc_id);
			ret = scx_bpf_create_dsq(dsq_id, llcx->node_id);
			if (ret < 0) {
				scx_bpf_error("failed to create DSQ %llu", dsq_id);
				return ret;
			}

			dbg("CFG llcx[%d]->dsqs[%d] = %llu", llcx->id, i, dsq_id);
			llcx->dsqs[i] = dsq_id;
			llcx->dsq_max_vtime[i] = 0;
			llcx->vtime = 0;
		}
	}
	cpu_ptr cpuc;
	bpf_for(i, 0, nr_cpus) {
		if (!(cpuc = lookup_cpu_ctx(i)) ||
		    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
			return -EINVAL;

		if (cpuc &&
		    llcx->node_cpumask &&
		    llcx->node_id == cpuc->node_id) {
			bpf_rcu_read_lock();
			if (llcx->node_cpumask)
				scx_bitmap_set_cpu(cpuc->id, llcx->node_cpumask);
			bpf_rcu_read_unlock();
		}

		bpf_for(j, 0, nr_dsqs_per_llc) {
			dbg("CFG cpuc->dsqs[%d] = %llu from llcx[%d]", j, llcx->dsqs[j], llcx->id);
			cpuc->dsqs[j] = llcx->dsqs[j];
			dbg("CFG CPU[%d]DSQ[%d] %llu",
			    i, j, cpuc->dsqs[j]);
		}

		dsq_id = ((MAX_DSQS_PER_LLC * MAX_LLCS) << 2) + i;
		dbg("CFG creating affn CPU[%d]DSQ[%llu]", i, dsq_id);
		ret = scx_bpf_create_dsq(dsq_id, llcx->node_id);
		if (ret < 0) {
			scx_bpf_error("failed to create DSQ %llu", dsq_id);
			return ret;
		}
		cpuc->affn_dsq = dsq_id;
	}

	min_slice_ns = 1000 * min_slice_us;

	if (start_timers() < 0)
		return -EINVAL;

	return 0;
}

void BPF_STRUCT_OPS(p2dq_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

#if P2DQ_CREATE_STRUCT_OPS
s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init)
{
	return p2dq_init_impl();
}

void BPF_STRUCT_OPS(p2dq_running, struct task_struct *p)
{
	p2dq_running_impl(p);
}

void BPF_STRUCT_OPS(p2dq_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	struct enqueue_promise pro;
	async_p2dq_enqueue(&pro, p, enq_flags);
	complete_p2dq_enqueue(&pro, p);
}

void BPF_STRUCT_OPS(p2dq_dispatch, s32 cpu, struct task_struct *prev)
{
	return p2dq_dispatch_impl(cpu, prev);
}

s32 BPF_STRUCT_OPS(p2dq_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return p2dq_select_cpu_impl(p, prev_cpu, wake_flags);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	return p2dq_init_task_impl(p, args);
}

SCX_OPS_DEFINE(p2dq,
	       .select_cpu		= (void *)p2dq_select_cpu,
	       .enqueue			= (void *)p2dq_enqueue,
	       .dispatch		= (void *)p2dq_dispatch,
	       .running			= (void *)p2dq_running,
	       .stopping		= (void *)p2dq_stopping,
	       .set_cpumask		= (void *)p2dq_set_cpumask,
		   .update_idle		= (void *)p2dq_update_idle,
	       .init_task		= (void *)p2dq_init_task,
	       .exit_task		= (void *)p2dq_exit_task,
	       .init			= (void *)p2dq_init,
	       .exit			= (void *)p2dq_exit,
	       .timeout_ms		= 20000,
	       .name			= "p2dq");
#endif
