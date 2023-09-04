/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_hash.h"
#include "dim_tpm.h"
#include "dim_measure_log.h"
#include "dim_baseline.h"

#include "dim_core.h"
#include "dim_core_measure.h"
#include "dim_core_baseline.h"

int dim_core_add_measure_log(const char *name, struct dim_digest *digest, int flag)
{
	int ret = dim_measure_log_add(&dim_core_log, name, digest, flag);
	if (ret < 0 && ret != -EEXIST) {
		dim_err("fail to add measure log of %s: %d\n", name, ret);
		return ret;
	}

	return 0;
}

int dim_core_check_kernel_digest(int baseline_init,
				 const char *name,
				 struct dim_digest *digest)
{
	int ret = 0;
	struct dim_digest digest_static = { 0 };

	/* in the measure stage, do nothing if baseline matched */
	if (!baseline_init &&
	    !dim_core_match_dynamic_baseline(name, DIM_BASELINE_KERNEL, digest)) {
		dim_err("mismatch dynamic baseline of kernel %s\n", name);
		return dim_core_add_measure_log(name, digest, LOG_TAMPERED);
	}

	/* in the baseline init stage */
	/* 1. add digest to dynamic baseline */
	ret = dim_core_add_dynamic_baseline(name, DIM_BASELINE_KERNEL, digest);
	if (ret < 0)
		return ret;

	/* 2. search digest from static baseline */
	ret = dim_core_search_static_baseline(name, DIM_BASELINE_KERNEL, &digest_static);
	if (ret < 0)
		/* 2.1. if not find, log the dynamic baseline */
		return dim_core_add_measure_log(name, digest, LOG_NO_SATIC_BASELINE);

	/* 2.2. if find, log the static baseline */
	return dim_core_add_measure_log(name, &digest_static, LOG_STATIC_BASELINE);
}

int dim_core_check_user_digest(int baseline_init,
			       const char *name,
			       struct dim_digest *digest,
			       int *log_flag)
{
	int ret = 0;
	struct dim_digest digest_static = { 0 };

	/* in the measure stage, do nothing if baseline matched */
	if (!baseline_init &&
	    !dim_core_match_dynamic_baseline(name, DIM_BASELINE_USER, digest)) {
		dim_warn("mismatch dynamic baseline of user process %s\n", name);
		return dim_core_add_measure_log(name, digest, LOG_TAMPERED);
	}

	/* in the baseline init stage */
	/* 1. add digest to dynamic baseline */
	ret = dim_core_add_dynamic_baseline(name, DIM_BASELINE_USER, digest);
	if (ret < 0)
		return ret;

	/* 2. search digest from static baseline */
	ret = dim_core_search_static_baseline(name, DIM_BASELINE_USER, &digest_static);
	if (ret < 0) /* 2.1. if not find, log the dynamic baseline */
		return dim_core_add_measure_log(name, digest, LOG_NO_SATIC_BASELINE);

	/* 2.2. if find, compare with the static baseline */
	if (dim_core_match_static_baseline(name, DIM_BASELINE_USER, digest))
		return dim_core_add_measure_log(name, digest, LOG_STATIC_BASELINE);

	dim_warn("mismatch static baseline of user process %s\n", name);
	return dim_core_add_measure_log(name, digest, LOG_TAMPERED);
}
