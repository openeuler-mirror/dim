/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/version.h>
#include <linux/mm.h>

#include "dim_measure.h"
#include "dim_vm_hash.h"
#include "dim_core_measure_process.h"

static struct vm_area_struct *find_text_vma_end(struct vm_area_struct *vma)
{
	struct vm_area_struct *v = NULL;
	struct vm_area_struct *vma_end = vma;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	for (v = vma->vm_next; v != NULL && vma_is_file_text(v) &&
	     vma_can_merge(vma_end, v); v = v->vm_next)
		vma_end = v;
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

	if (!vma_is_file_text(v))
		v = NULL;
#endif
	return v;
}

/* For file text segment, merge all file mapping text vma and measure */
int measure_text_vma(struct vm_area_struct *vma, struct task_measure_ctx *ctx)
{
	int ret = 0;
	struct vm_area_struct *v = vma;
	struct vm_area_struct *v_end = NULL;
	struct dim_digest digest = {
		.algo = ctx->m->hash.algo
	};
	SHASH_DESC_ON_STACK(shash, ctx->m->hash.tfm);

	shash->tfm = ctx->m->hash.tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	/* now the vma is the first file text vma of a process module */
	while (v != NULL && vma_file_is_same(v, vma)) {
		v_end = find_text_vma_end(v);
		/* update all the continuous text vma */
		ret = dim_vm_hash_update_vmas(v, v_end, shash);
		if (ret < 0)
			return ret;

		v = next_file_text_vma(v_end);
	}

	ret = crypto_shash_final(shash, digest.data);
	if (ret < 0)
		return ret;

	return ctx->check(&digest, ctx);
}

int measure_process_module_text_vma(struct vm_area_struct *vma,
				    struct task_measure_ctx *ctx)
{
	if (vma == NULL || !vma_is_file_text(vma) || ctx == NULL
	    || ctx->m == NULL || ctx->check == NULL)
		return -EINVAL;

	return measure_text_vma(vma, ctx);
}
