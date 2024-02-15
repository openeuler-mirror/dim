/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_MEASURE_PROCESS_H
#define __DIM_CORE_MEASURE_PROCESS_H

#include <linux/fs.h>
#include <linux/mm.h>

/* callback funtion to check results when do measurement */
typedef int (*process_digest_check_func) (struct dim_digest *digest,
					  void *ctx);

/* the context used in user process measurement */
struct task_measure_ctx {
	struct dim_measure *m;
	/* DIM_BASELINE or DIM_MEASURE */
	int mode;
	char path_buf[PATH_MAX];
	/* current measured process name */
	const char *path;
	/* current measured process */
	struct task_struct *task;
	/* this process need to be killed */
	bool task_kill;
	/* this process is measured */
	bool task_measure;
	/* check function */
	process_digest_check_func check;
};

static inline struct file *get_vm_file(struct vm_area_struct *vma)
{
	return vma == NULL ? NULL : vma->vm_file;
}

static inline bool vma_is_text(struct vm_area_struct *vma)
{
	return (vma->vm_flags & VM_READ) && (vma->vm_flags & VM_EXEC) &&
	       !(vma->vm_flags & VM_WRITE);
}

static inline bool vma_is_file_text(struct vm_area_struct *vma)
{
	return vma_is_text(vma) && get_vm_file(vma) != NULL;
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

#ifdef DIM_CORE_MEASURE_PROCESS_ELF
int measure_process_module_text_elf(struct vm_area_struct *vma,
			       struct task_measure_ctx *ctx);
#define measure_process_text measure_process_module_text_elf
#else
int measure_process_module_text_vma(struct vm_area_struct *vma,
			       struct task_measure_ctx *ctx);
#define measure_process_text measure_process_module_text_vma
#endif

extern struct dim_measure_task dim_core_measure_task_user_text;

#endif