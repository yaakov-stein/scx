#pragma once

#define arena_lock_t arena_spinlock_t __arena *

typedef struct task_p2dq __arena *task_ptr;
struct task_p2dq;

typedef struct cpu_ctx __arena *cpu_ptr;
struct cpu_ctx;

typedef struct llc_ctx __arena *llc_ptr;
struct llc_ctx;

typedef struct node_ctx __arena *node_ptr;
struct node_ctx;

struct p2dq_timer {
	// if set to 0 the timer will only be scheduled once
	u64 interval_ns;
	u64 init_flags;
	int start_flags;
};

struct cpu_ctx {
	int				id;
	u32				llc_id;
	u64				affn_dsq;
	u32				dsq_index;
	u64				dsq_id;
	u64				slice_ns;
	u32				perf;
	bool			smt;
	bool			interactive;
	bool			is_big;
	u64				ran_for;
	u32				node_id;
	u64				affn_max_vtime;
	u64				dsqs[MAX_DSQS_PER_LLC];
	u64				max_load_dsq;
};

struct llc_ctx {
	u32				id;
	u32				nr_cpus;
	u32				node_id;
	u64				vtime;
	u32				lb_llc_id;
	u64				last_period_ns;
	u64				load;
	u32				index;
	bool				all_big;
	u64				affn_load;
	u64				affn_max_vtime;
	u64				dsqs[MAX_DSQS_PER_LLC];
	u64				dsq_max_vtime[MAX_DSQS_PER_LLC];
	u64				dsq_load[MAX_DSQS_PER_LLC];

	scx_bitmap_t		cpumask;
	scx_bitmap_t		idle_cpumask;
	scx_bitmap_t		idle_smtmask;
	scx_bitmap_t		smt_cpumask;
	scx_bitmap_t		big_cpumask;
	scx_bitmap_t		little_cpumask;
	scx_bitmap_t		node_cpumask;
};

struct node_ctx {
	u32						id;
	bool					all_big;
	scx_bitmap_t	cpumask; // Should these have a __arena?
	scx_bitmap_t	big_cpumask;
};

struct task_p2dq {
	u64			dsq_id;
	u64			slice_ns;
	int			dsq_index;
	u32			llc_id;
	u32			node_id;
	u64			used;
	u64			last_dsq_id;
	u64 		last_run_started;
	u64 		last_run_at;
	u64			llc_runs; /* how many runs on the current LLC */
	int			last_dsq_index;

	/* The task is a workqueue worker thread */
	bool			is_kworker;

	/* Allowed to run on all CPUs */
	bool			all_cpus;

	scx_bitmap_t cpumask;
};

// typedef struct task_p2dq __arena task_ctx; Believe this can be removed due to line 5/6

struct enqueue_promise_vtime {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;
	u64	vtime;
};

struct enqueue_promise_fifo {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;
};

struct enqueue_promise {
	enum enqueue_promise_kind	kind;
	union {
		struct enqueue_promise_vtime	vtime;
		struct enqueue_promise_fifo	fifo;
	};
};
