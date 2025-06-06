#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>
#include <lib/percpu.h>

extern const volatile u32 nr_cpu_ids;

extern size_t mask_size;

__weak int
scx_bitmap_to_bpf(struct bpf_cpumask __kptr *bpfmask __arg_trusted,
		   scx_bitmap_t __arg_arena scx_bitmap)
{
	struct scx_bitmap *tmp;
	int ret;

	tmp = scx_percpu_scx_bitmap_stack();
	scx_bitmap_copy_to_stack(tmp, scx_bitmap);

	ret = bpf_cpumask_populate((struct cpumask *)bpfmask, tmp->bits, sizeof(tmp->bits));
	if (unlikely(ret))
		scx_bpf_error("error %d when calling bpf_cpumask_populate", ret);

	return 0;
}

__weak
bool scx_bitmap_subset_cpumask(scx_bitmap_t __arg_arena big, const struct cpumask *small __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, small);

	return scx_bitmap_subset(big, tmp);
}

__weak
bool scx_bitmap_intersects_cpumask(scx_bitmap_t __arg_arena scx, const struct cpumask *bpf __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, bpf);

	return scx_bitmap_intersects(scx, tmp);
}

__weak
int scx_bitmap_and_cpumask(scx_bitmap_t dst __arg_arena,
			       scx_bitmap_t scx __arg_arena,
			       const struct cpumask *bpf __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, bpf);

	scx_bitmap_and(dst, scx, tmp);

	return 0;
}

__weak
s32 scx_bitmap_pick_idle_cpu(scx_bitmap_t mask __arg_arena, int flags)
{
	struct bpf_cpumask __kptr *bpf = scx_percpu_bpfmask();
	s32 cpu;

	if (!bpf)
		return -1;

	scx_bitmap_to_bpf(bpf, mask);
	cpu = scx_bpf_pick_idle_cpu(cast_mask(bpf), flags);

	scx_bitmap_from_bpf(mask, cast_mask(bpf));

	return cpu;
}

__weak
s32 scx_bitmap_any_distribute(scx_bitmap_t mask __arg_arena)
{
	struct bpf_cpumask __kptr *bpf = scx_percpu_bpfmask();
	s32 cpu;

	if (!bpf)
		return -1;

	scx_bitmap_to_bpf(bpf, mask);
	cpu = bpf_cpumask_any_distribute(cast_mask(bpf));

	return cpu;
}

__weak
s32 scx_bitmap_any_and_distribute(scx_bitmap_t scx __arg_arena, const struct cpumask *bpf)
{
	struct bpf_cpumask *tmp = scx_percpu_bpfmask();
	s32 cpu;

	if (!bpf || !tmp)
		return -1;

	scx_bitmap_to_bpf(tmp, scx);
	cpu = bpf_cpumask_any_and_distribute(cast_mask(tmp), bpf);

	return cpu;
}
