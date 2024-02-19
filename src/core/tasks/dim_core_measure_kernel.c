/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/kallsyms.h>
#include <linux/jump_label.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>
#include <linux/utsname.h>

#include "dim_measure.h"

#include "dim_core_symbol.h"
#include "dim_core_measure.h"
#include "dim_core_policy.h"

#include "dim_core_measure_task.h"

/* max size of x86 */
#define DIM_JUMP_LABEL_NOP_SIZE_MAX 5

static int code_cmp(const void *a, const void *b)
{
	return *(unsigned long *)a > *(unsigned long *)b ? 1 : 0;
}

static int sort_jump_table(struct jump_entry *sjump,
			   unsigned int jump_counts,
			   unsigned long **code)
{
	unsigned int i;
	unsigned long *buf = NULL;

	buf = vzalloc(sizeof(unsigned long) * jump_counts);
	if (buf == NULL)
		return -ENOMEM;

	dim_core_kernel_symbol.jump_label_lock();
	for (i = 0; i < jump_counts; i++)
		buf[i] = jump_entry_code(&sjump[i]);
	dim_core_kernel_symbol.jump_label_unlock();

	sort(buf, jump_counts, sizeof(unsigned long), code_cmp, NULL);
	*code = buf;
	return 0;
}

static int do_calc_kernel_digest(uintptr_t saddr,
				 uintptr_t eaddr,
				 uintptr_t *jcode_sort,
				 unsigned int jcode_cnt,
				 struct dim_hash *hash,
				 struct dim_digest *digest)
{
	int ret = 0;
	unsigned int i;
	uintptr_t jump_code;
	uintptr_t cur_addr = saddr;
	SHASH_DESC_ON_STACK(shash, hash->tfm);

	shash->tfm = hash->tfm;
	if (shash->tfm == NULL)
		return -EINVAL;

	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	/* if jump label is not enabled, jcode_cnt is 0 */
	for (i = 0; i < jcode_cnt && cur_addr < eaddr; i++) {
		jump_code = jcode_sort[i];
		if (jump_code < cur_addr) /* jump_code can be 0 */
			continue;

		if (jump_code >= eaddr) /* no more valid jump code */
			break;

		/* skip addresses that may be changed */
		if (jump_code > cur_addr) {
			ret = crypto_shash_update(shash, (char *)cur_addr,
						  jump_code - cur_addr);
			if (ret < 0)
				return ret;
		}
#ifdef JUMP_LABEL_NOP_SIZE
		cur_addr = jump_code + JUMP_LABEL_NOP_SIZE;
#else
		cur_addr = jump_code + DIM_JUMP_LABEL_NOP_SIZE_MAX;
#endif
	}

	if (cur_addr < eaddr) {
		ret = crypto_shash_update(shash, (char *)cur_addr,
					  eaddr - cur_addr);
		if (ret < 0)
			return ret;
	}

	return crypto_shash_final(shash, digest->data);
}

static int calc_kernel_digest(struct dim_hash *hash, struct dim_digest *digest)
{
	int ret = 0;
	uintptr_t stext = 0;
	uintptr_t etext = 0;
	struct jump_entry *sjump = NULL;
	struct jump_entry *ejump = NULL;
	uintptr_t *jcode_sort = NULL;
	unsigned int jcode_cnt = 0;

	stext = (uintptr_t)dim_core_kernel_symbol.stext;
	etext = (uintptr_t)dim_core_kernel_symbol.etext;
	sjump = dim_core_kernel_symbol.start_jump_table;
	ejump = dim_core_kernel_symbol.stop_jump_table;
	if (sjump != NULL && ejump != NULL && sjump < ejump) {
		jcode_cnt = ((uintptr_t)ejump - (uintptr_t)sjump) /
			sizeof(struct jump_entry);
		ret = sort_jump_table(sjump, jcode_cnt, &jcode_sort);
		if (ret < 0) {
			dim_err("failed to sort kernel jump table: %d\n", ret);
			return ret;
		}
	} else {
		jcode_sort = NULL;
		jcode_cnt = 0;
	}

	ret = do_calc_kernel_digest(stext, etext, jcode_sort,
				    jcode_cnt, hash, digest);
	if (ret < 0)
		dim_err("failed to calculate kernel digest: %d\n", ret);

	dim_vfree(jcode_sort);
	return ret;
}

static int kernel_text_measure(int mode, struct dim_measure *m)
{
	int ret = 0;
	const char *kr = init_uts_ns.name.release;
	struct dim_digest digest = {
		.algo = m->hash.algo,
	};

	if (m == NULL)
		return -EINVAL;

	if (!dim_core_policy_match(DIM_POLICY_OBJ_KERNEL_TEXT,
				   DIM_POLICY_KEY_NAME, kr))
		return 0;

	ret = calc_kernel_digest(&m->hash, &digest);
	if (ret < 0) {
		dim_err("failed to calculate kernel digest: %d\n", ret);
		return ret;
	}

	ret = dim_measure_process_dynamic_result(m, mode, kr, &digest, NULL);
	if (ret < 0)
		dim_err("failed to check kernel digest: %d\n", ret);

	return ret;
}

struct dim_measure_task dim_core_measure_task_kernel_text = {
	.name = "dim_core_measure_task_kernel_text",
	.measure = kernel_text_measure,
};
