/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/version.h>

#include "dim_hash.h"
#include "dim_measure_log.h"
#include "dim_baseline.h"

#include "dim_core_symbol.h"
#include "dim_core_policy.h"
#include "dim_core_measure.h"

#include "dim_core_measure_task.h"
#include "dim_core_measure_process.h"

/* max number of tasks to kill */
#define DIM_KILL_TASKS_MAX (1024)

struct task_kill_ctx {
	struct task_struct **buf;
	int len;
	int size;
	int ret;
};

static struct vm_area_struct *next_module_text_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *v = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	for (v = vma->vm_next; v != NULL &&
	     !(vma_is_file_text(v) && !vma_file_is_same(v, vma));
	     v = v->vm_next) {}
#else
	VMA_ITERATOR(vmi, vma->vm_mm, vma->vm_end);
	for_each_vma(vmi, v) {
		if (vma_is_file_text(v) && !vma_file_is_same(v, vma))
			break;
	}
#endif
	return v;
}

static int store_task_tree(struct task_struct *p, void *data)
{
	unsigned int new_size = 0;
	struct task_struct **tmp = NULL;
	struct task_kill_ctx *ctx = (struct task_kill_ctx *)data;

	if (ctx->len == ctx->size) {
		if (ctx->size >= DIM_KILL_TASKS_MAX)
			return -ERANGE;

		/* realloc to size * 2 */
		new_size = ctx->size << 1;
		tmp = dim_krealloc_atom(ctx->buf,
				new_size * sizeof(struct task_struct *));
		if (tmp == NULL)
			return -ENOMEM;

		ctx->buf = tmp;
	}

	ctx->buf[ctx->len++] = get_task_struct(p);
	return 1;
}

static int kill_task_tree(struct task_struct *tsk)
{
	int i = 0;
	const int def_size = 32;
	struct task_kill_ctx ctx = { .size = def_size };

	if (tsk->pid == 1) {
		/* dont kill the init process */
		dim_warn("the pid of tampered task is 1, don't kill it\n");
		return 0;
	}

	ctx.buf = dim_kzalloc_gfp(def_size * sizeof(struct task_struct *));
	if (ctx.buf == NULL)
		return -ENOMEM;

	dim_core_kernel_symbol.walk_process_tree(tsk, store_task_tree, &ctx);
	if (ctx.len != 0) {
		for (i = ctx.len; i >= 0; i--) {
			send_sig(SIGKILL, ctx.buf[i], 1);
			put_task_struct(ctx.buf[i]);
		}
	}

	dim_kfree(ctx.buf);
	send_sig(SIGKILL, tsk, 1);
	return 0;
}

static bool vm_file_match_policy(struct file *vm_file,
				 struct task_measure_ctx *ctx)
{
	struct dim_digest dig = { 0 };

	/* get the module path string */
	ctx->path = d_path(&vm_file->f_path, ctx->path_buf, PATH_MAX);
	if (IS_ERR(ctx->path)) {
		dim_warn("failed to get path of vma: %ld\n", PTR_ERR(ctx->path));
		ctx->path = NULL;
		return false;
	}

	if (ctx->mode == DIM_BASELINE)
		return dim_core_policy_match(DIM_POLICY_OBJ_BPRM_TEXT,
					     DIM_POLICY_KEY_PATH, ctx->path);

	return dim_measure_dynamic_baseline_search(ctx->m, ctx->path,
		DIM_BASELINE_USER, &dig) == 0;
}

static int check_process_digest(struct dim_digest *digest,
				void *data)
{
	int ret = 0;
	int log_flag = 0;
	int action = 0;
	struct task_measure_ctx *ctx = data;

	if (digest == NULL || data == NULL)
		return -EINVAL;

	ret = dim_measure_process_static_result(ctx->m, ctx->mode, ctx->path,
						digest, &log_flag);
	if (ret < 0) {
		dim_err("failed to check user digest: %d\n", ret);
		return ret;
	}

	if (log_flag != LOG_TAMPERED ||
	    dim_core_measure_action_get() == DIM_MEASURE_ACTION_DISABLE)
		return 0;

	/* now the process is tampered, check if action need to be taken */
	action = dim_core_policy_get_action(DIM_POLICY_OBJ_BPRM_TEXT,
					    DIM_POLICY_KEY_PATH, ctx->path);
	if (action == DIM_POLICY_ACTION_KILL) {
		dim_warn("kill action is set, process %s will be killed\n",
			 ctx->path);
		ctx->task_kill = true; /* this task need to be killed */
	}

	return 0;
}

static void measure_task_module(struct vm_area_struct *vma,
				struct task_measure_ctx *ctx)
{
	int ret = 0;

	/* vma is the first file mapping text vma of the module,
	   so vm_file is not NULL */
	if (!vm_file_match_policy(get_vm_file(vma), ctx))
		return; /* no need to measure */

	ctx->task_measure = true;

	/* now we only measure the text memory */
	ret = measure_process_text(vma, ctx);
	if (ret < 0)
		dim_err("failed to measure module file text: %d", ret);
}

static int measure_task(struct task_struct *task, struct task_measure_ctx *ctx)
{
	int ret = 0;
	struct mm_struct *mm = NULL;
	struct vm_area_struct *v = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	struct vma_iterator vmi = { 0 };
#endif
	mm = get_task_mm(task);
	if (mm == NULL)
		return 0;

	ret = down_read_killable(&mm->mmap_lock);
	if (ret < 0) {
		mmput(mm);
		return ret; /* need to return if killed */
	}

	ctx->path = NULL;
	ctx->task = task;
	ctx->task_kill = false;
	ctx->task_measure = false;

	/* find the first file mapping text vma, which is the
	   start vma of a module */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	for (v = mm->mmap; v != NULL &&
	     !vma_is_file_text(v); v = v->vm_next) {}
#else
	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, v) {
		if (vma_is_file_text(v))
			break;
	}
#endif
	if (v == NULL) {
		dim_warn("no valid file text vma");
		ret = -ENOENT;
		goto out;
	}

	for (; v != NULL; v = next_module_text_vma(v))
		measure_task_module(v, ctx);
out:
	up_read(&mm->mmap_lock);
	mmput(mm);

	if (ctx->task_kill) {
		ret = kill_task_tree(task);
		if (ret < 0)
			dim_err("failed to kill tampered task, pid = %d: %d\n",
			       task->pid, ret);
	}

	/* do schedule if this task is measured */
	if (ctx->task_measure)
		dim_measure_schedule(ctx->m);

	return 0;
}

static int store_task_pids(pid_t **pid_buf, unsigned int *pid_cnt)
{
	struct task_struct *tsk = NULL;
	pid_t *buf = NULL;
	unsigned int cnt = 0;
	unsigned int max_cnt = (PID_MAX_DEFAULT << 1);

	/* maximum processing of PID_MAX_DEFAULT * 2 pids */
	buf = dim_vzalloc(max_cnt);
	if (buf == NULL) {
		dim_err("failed to allocate memory for pid buffer\n");
		return -ENOMEM;
	}

	cnt = 0;
	rcu_read_lock();
	for_each_process(tsk) {
		/* don't measure kernel thread */
		if (tsk->flags & PF_KTHREAD)
			continue;

		buf[cnt++] = tsk->pid;
		if (cnt >= max_cnt) {
			dim_warn("pid number reaches the limit\n");
			break;
		}
	}
	rcu_read_unlock();

	*pid_buf = buf;
	*pid_cnt = cnt;
	return 0;
}

static int walk_measure_tasks(struct task_measure_ctx *ctx)
{
	int ret = 0;
	unsigned int i = 0;
	unsigned int pid_cnt = 0;
	pid_t *pid_buf = NULL;
	struct task_struct *task = NULL;

	ret = store_task_pids(&pid_buf, &pid_cnt);
	if (ret < 0)
		return ret;

	for (i = 0; i < pid_cnt; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
		task = find_get_task_by_vpid(pid_buf[i]);
#else
		task = dim_core_kernel_symbol.find_get_task_by_vpid(pid_buf[i]);
#endif
		if (task == NULL)
			continue;

		ret = measure_task(task, ctx);
		put_task_struct(task);
		if (ret < 0) {
			dim_err("failed to measure task, pid = %d: %d", pid_buf[i], ret);
			if (ret == -EINTR)
				break;
		}
	}

	dim_vfree(pid_buf);
	return 0;
}

static int user_text_measure(int mode, struct dim_measure *m)
{
	int ret = 0;
	struct task_measure_ctx *ctx = NULL;

	if (m == NULL)
		return -EINVAL;

	ctx = dim_vzalloc(sizeof(struct task_measure_ctx));
	if (ctx == NULL)
		return -ENOMEM;

	ctx->mode = mode;
	ctx->m = m;
	ctx->check = check_process_digest;

	ret = walk_measure_tasks(ctx);
	dim_vfree(ctx);
	return ret;
}

struct dim_measure_task dim_core_measure_task_user_text = {
	.name = "dim_core_measure_task_user_text",
	.measure = user_text_measure,
};
