/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_measure.h"

static int cfg_check(struct dim_measure_cfg *cfg)
{
	if (cfg->log_cap < MEASURE_LOG_CAP_MIN ||
	    cfg->log_cap > MEASURE_LOG_CAP_MAX) {
		dim_err("invalid log capacity: %d\n", cfg->log_cap);
		return -ERANGE;
	}

	if (cfg->schedule_ms > MEASURE_SCHEDULE_MAX) {
		dim_err("invalid measure schedule: %d\n", cfg->schedule_ms);
		return -ERANGE;
	}

	if (cfg->pcr > DIM_PCR_MAX) {
		dim_err("invalid TPM pcr number: %d\n", cfg->pcr);
		return -ERANGE;
	}

	return 0;
}

int dim_measure_init(struct dim_measure *m, struct dim_measure_cfg *cfg)
{
	int ret = 0;

	if (m == NULL || cfg == NULL || cfg_check(cfg) < 0)
		return -EINVAL;

	INIT_LIST_HEAD(&m->task_list);

	/* 1. init hash algorithm */
	ret = dim_hash_init(cfg->alg_name, &m->hash);
	if (ret < 0) {
		dim_err("failed to init hash algorithm: %d\n", ret);
		goto err;
	}

	/* 2. init TPM, dont break if init fail */
	if (cfg->pcr > 0) {
		ret = dim_tpm_init(&m->tpm, HASH_ALGO_SHA256);
		if (ret < 0)
			dim_warn("failed to init tpm chip: %d\n", ret);
	} else {
		memset(&m->tpm, 0, sizeof(struct dim_tpm));
	}

	/* 3. init baseline data (static and dynamic) */
	ret = dim_baseline_init_tree(cfg->sta_malloc, cfg->sta_free,
				     &m->static_baseline);
	if (ret < 0) {
		dim_err("failed to init static baseline root: %d\n", ret);
		goto err;
	}

	ret = dim_baseline_init_tree(cfg->dyn_malloc, cfg->dyn_free,
				     &m->dynamic_baseline);
	if (ret < 0) {
		dim_err("failed to init dynamic baseline root: %d\n", ret);
		goto err;
	}

	/* 4. init measure log */
	ret = dim_measure_log_init_tree(&m->log, &m->hash, &m->tpm,
					cfg->log_cap, cfg->pcr);
	if (ret < 0) {
		dim_err("failed to init measure log: %d\n", ret);
		goto err;
	}

	/* 5. set measure schedule time */
	m->schedule_jiffies = cfg->schedule_ms == 0 ? 0 :
		msecs_to_jiffies(cfg->schedule_ms);

	/* 6. set initial status */
	atomic_set(&m->status, MEASURE_STATUS_NO_BASELINE);
	return 0;
err:
	dim_measure_destroy(m);
	return ret;
}

void dim_measure_destroy(struct dim_measure *m)
{
	if (m == NULL)
		return;

	mutex_lock(&m->measure_lock);
	dim_measure_log_destroy_tree(&m->log);
	dim_baseline_destroy_tree(&m->static_baseline);
	dim_baseline_destroy_tree(&m->dynamic_baseline);
	dim_tpm_destroy(&m->tpm);
	dim_hash_destroy(&m->hash);
	mutex_unlock(&m->measure_lock);
}
