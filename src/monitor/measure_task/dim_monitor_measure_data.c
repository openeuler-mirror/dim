/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_measure.h"
#include "dim_core_mem_pool.h"

#include "dim_monitor.h"

#include "dim_monitor_measure_task.h"

static void calculate_chunk(struct gen_pool *pool,
			    struct gen_pool_chunk *chunk,
			    void *data)
{
	struct shash_desc *shash = (struct shash_desc *)data;

	if (chunk == NULL || shash == NULL)
		return;

	(void)crypto_shash_update(shash, (char *)chunk->start_addr,
				  chunk->end_addr - chunk->start_addr);
}

static int module_text_measure(int mode, struct dim_measure *m)
{
	int ret = 0;
	int log_flag = LOG_DYNAMIC_BASELINE;
	struct dim_digest digest = {
		.algo = m->hash.algo,
	};

	SHASH_DESC_ON_STACK(shash, m->hash.tfm);
	shash->tfm = m->hash.tfm;

	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	dim_mem_pool_walk_chunk(calculate_chunk, shash);
	ret = crypto_shash_final(shash, digest.data);
	if (ret < 0)
		return ret;

	ret = dim_measure_process_dynamic_result(m, mode, DIM_CORE_DATA,
						 &digest, &log_flag);
	if (ret < 0)
		dim_err("failed to check dim_core data digest: %d\n", ret);

	return 0;
}

struct dim_measure_task dim_monitor_measure_data = {
	.name = "dim_monitor_measure_data",
	.measure = module_text_measure,
};
