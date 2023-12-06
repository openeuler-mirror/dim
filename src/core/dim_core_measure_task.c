/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/hugetlb_inline.h>
#include <linux/fs.h>
#include <linux/version.h>

#include "dim_hash.h"
#include "dim_measure_log.h"
#include "dim_baseline.h"

#include "dim_core.h"
#include "dim_core_symbol.h"
#include "dim_core_policy.h"
#include "dim_core_measure.h"
#include "dim_core_baseline.h"

static struct file *get_vm_file(struct vm_area_struct *vma)
{
#ifdef CONFIG_EULEROS_EXEC_HUGEPAGES
	if (is_vm_exec_hugepages(vma) && vma->vm_real_file != NULL)
		return vma->vm_real_file;
#endif
	return vma->vm_file;
}

/* Dont process vsyscall and vdso vma currently */
static bool vma_is_special_text(struct vm_area_struct *vma)
{
	const char *name = NULL;

	if (vma->vm_ops == NULL || vma->vm_ops->name == NULL)
		return false;

	name = vma->vm_ops->name(vma);
	if (name == NULL)
		return false;

	return (strcmp(name, "[vsyscall]") == 0) ||
	       (strcmp(name, "[vdso]") == 0);
}

static inline bool vma_is_text(struct vm_area_struct *vma)
{
	return (vma->vm_flags & VM_READ) && (vma->vm_flags & VM_EXEC) &&
	       !(vma->vm_flags & VM_WRITE) && !vma_is_special_text(vma);
}

static inline bool vma_is_file_text(struct vm_area_struct *vma)
{
	return vma_is_text(vma) && get_vm_file(vma) != NULL;
}

static inline bool vma_is_anon_text(struct vm_area_struct *vma)
{
	return vma_is_text(vma) && get_vm_file(vma) == NULL;
}

static inline bool vma_file_is_same(struct vm_area_struct *first,
				    struct vm_area_struct *second)
{
	return get_vm_file(first) == get_vm_file(second);
}

static inline bool vma_can_merge(struct vm_area_struct *first,
				 struct vm_area_struct *second)
{
	return (first->vm_end == second->vm_start) &&
	       (vma_file_is_same(first, second));
}

static inline bool vma_is_not_same_module(struct vm_area_struct *a,
					  struct vm_area_struct *b)
{
	struct file *fa = get_vm_file(a);
	struct file *fb = get_vm_file(b);
	return (fa != NULL && fb != NULL && fa != fb);
}

static struct vm_area_struct *next_file_text_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *v = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	for (v = vma->vm_next; v != NULL &&
	     !vma_is_file_text(v); v = v->vm_next) {}
#else
	VMA_ITERATOR(vmi, vma->vm_mm, vma->vm_end);
	for_each_vma(vmi, v) {
		if (vma_is_file_text(v))
			break;
	}
#endif
	return v;
}

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

static struct vm_area_struct *find_text_vma_end(struct vm_area_struct *vma)
{
	struct vm_area_struct *v = NULL;
	struct vm_area_struct *vma_end = vma;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	for (v = vma->vm_next; v != NULL &&
	     vma_can_merge(vma_end, v); v = v->vm_next) {}
#else
	VMA_ITERATOR(vmi, vma->vm_mm, vma->vm_end);
	for_each_vma(vmi, v) {
		if (!vma_is_file_text(v) || !vma_can_merge(vma_end, v))
			break;

		vma_end = v;
	}
#endif
	return vma_end;
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
		tmp = krealloc(ctx->buf,
			       new_size * sizeof(struct task_struct *),
			       GFP_ATOMIC);
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

	ctx.buf = kmalloc(def_size * sizeof(struct task_struct *), GFP_KERNEL);
	if (ctx.buf == NULL)
		return -ENOMEM;

	dim_core_kernel_symbol.walk_process_tree(tsk, store_task_tree, &ctx);
	if (ctx.len != 0) {
		for (i = ctx.len; i >= 0; i--) {
			send_sig(SIGKILL, ctx.buf[i], 1);
			put_task_struct(ctx.buf[i]);
		}
	}

	kfree(ctx.buf);
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

	if (ctx->baseline)
		return dim_core_policy_match(DIM_POLICY_OBJ_BPRM_TEXT,
					     DIM_POLICY_KEY_PATH, ctx->path);

	return dim_core_search_dynamic_baseline(ctx->path, DIM_BASELINE_USER,
						&dig) == 0;
}

static int update_vma_digest(struct vm_area_struct *vma_start,
			     struct vm_area_struct *vma_end,
			     struct shash_desc *shash)
{
	long i;
	long ret_pages = 0;
	void *page_ptr = NULL;
	struct page **pages = NULL;
	unsigned long addr_start = vma_start->vm_start;
	unsigned long addr_end = vma_end->vm_end;
	unsigned long addr_len = addr_end - addr_start;
	unsigned long nr_pages = DIV_ROUND_UP(addr_len, PAGE_SIZE);

	pages = vzalloc(nr_pages * sizeof(struct page *));
	if (pages == NULL)
		return -ENOMEM;

	ret_pages = get_user_pages_remote(vma_start->vm_mm, addr_start, nr_pages,
					  0, pages, NULL, NULL);
	if (ret_pages < 0) {
		dim_err("failed to get vma pages: %ld\n", ret_pages);
		vfree(pages);
		return ret_pages;
	}

	for (i = 0; i < ret_pages; i++) {
		page_ptr = kmap(pages[i]);
		if (page_ptr == NULL) {
			dim_err("failed to kmap page\n");
			put_page(pages[i]);
			continue;
		}

		(void)crypto_shash_update(shash, page_ptr, PAGE_SIZE);
		kunmap(pages[i]);
		put_page(pages[i]);
	}

	vfree(pages);
	return 0;
}

static int check_user_digest(struct dim_digest *digest,
			     struct task_measure_ctx *ctx)
{
	int ret = 0;
	int log_flag = 0;
	int action = 0;

	ret = dim_core_check_user_digest(ctx->baseline, ctx->path,
					 digest, &log_flag);
	if (ret < 0) {
		dim_err("failed to check user digest: %d\n", ret);
		return ret;
	}

	if (log_flag != LOG_TAMPERED || !dim_core_tampered_action_get())
		return 0;

	action = dim_core_policy_get_action(DIM_POLICY_OBJ_BPRM_TEXT,
					    DIM_POLICY_KEY_PATH, ctx->path);
	if (action == DIM_POLICY_KILL)
		ctx->task_kill = true; /* this task need to be killed */

	return 0;
}

#ifdef DIM_CORE_MEASURE_ANON_TEXT
static int measure_anon_text_vma(struct vm_area_struct *vma,
				 struct task_measure_ctx *ctx)
{
	int ret = 0;
	struct dim_digest digest = { .algo = dim_core_hash.algo };
	SHASH_DESC_ON_STACK(shash, dim_core_hash.tfm);

	shash->tfm = dim_core_hash.tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	ret = update_vma_digest(vma, vma, shash);
	if (ret < 0)
		return ret;

	ret = crypto_shash_final(shash, digest.data);
	if (ret < 0)
		return ret;

	return check_user_digest(&digest, ctx);
}

/* For anonymous text segment, measure individual vma */
static int measure_task_module_anon_text(struct vm_area_struct *vma,
					 struct task_measure_ctx *ctx)
{
	int ret = 0;
	struct vm_area_struct *v = vma;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	for (; v != NULL && !vma_is_not_same_module(v, vma); v = v->vm_next) {
#else
	VMA_ITERATOR(vmi, vma->vm_mm, vma->vm_start);
	for_each_vma(vmi, v) {
		if (vma_is_not_same_module(v, vma))
			break;
#endif
		if (!vma_is_anon_text(v))
			continue;

		ret = measure_anon_text_vma(v, ctx);
		if (ret < 0)
			dim_err("failed to measure anon text vma: %d\n", ret);
	}

	return 0;
}
#endif

/* For file text segment, merge all file mapping text vma and measure */
static int measure_task_module_file_text(struct vm_area_struct *vma,
					 struct task_measure_ctx *ctx)
{
	int ret = 0;
	struct vm_area_struct *v = vma;
	struct vm_area_struct *v_end = NULL;
	struct dim_digest digest = { .algo = dim_core_hash.algo };
	SHASH_DESC_ON_STACK(shash, dim_core_hash.tfm);

	shash->tfm = dim_core_hash.tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	while (v != NULL && vma_file_is_same(v, vma)) {
		v_end = find_text_vma_end(v);
		ret = update_vma_digest(v, v_end, shash);
		if (ret < 0)
			return ret;
	
		v = next_file_text_vma(v_end);
	}

	ret = crypto_shash_final(shash, digest.data);
	if (ret < 0)
		return ret;

	return check_user_digest(&digest, ctx);
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

	ret = measure_task_module_file_text(vma, ctx);
	if (ret < 0)
		dim_err("failed to measure module file text: %d", ret);
#ifdef DIM_CORE_MEASURE_ANON_TEXT
	ret = measure_task_module_anon_text(vma, ctx);
	if (ret < 0)
		dim_err("failed to measure module anon text: %d", ret);
#endif
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
	if (ctx->task_measure && measure_schedule)
		schedule_timeout_uninterruptible(measure_schedule_jiffies);

	return 0;
}

static int store_task_pids(pid_t **pid_buf, unsigned int *pid_cnt)
{
	struct task_struct *tsk = NULL;
	pid_t *buf = NULL;
	unsigned int cnt = 0;
	unsigned int max_cnt = (PID_MAX_DEFAULT << 1);

	/* maximum processing of PID_MAX_DEFAULT * 2 pids */
	buf = vmalloc(max_cnt);
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

static int walk_tasks(task_measurer f, struct task_measure_ctx *ctx)
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

		ret = f(task, ctx);
		put_task_struct(task);
		if (ret < 0) {
			dim_err("failed to measure task, pid = %d: %d", pid_buf[i], ret);
			if (ret == -EINTR)
				break;
		}
	}

	vfree(pid_buf);
	return 0;
}

int dim_core_measure_task(int baseline_init)
{
	int ret = 0;
	struct task_measure_ctx *ctx = NULL;

	ctx = kzalloc(sizeof(struct task_measure_ctx), GFP_KERNEL);
	if (ctx == NULL)
		return -ENOMEM;

	ctx->baseline = baseline_init;
	ret = walk_tasks(measure_task, ctx);
	kfree(ctx);
	return ret;
}

