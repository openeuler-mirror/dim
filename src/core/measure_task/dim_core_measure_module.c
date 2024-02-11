/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/module.h>
#include <linux/version.h>

#include "dim_utils.h"
#include "dim_hash.h"
#include "dim_baseline.h"
#include "dim_measure_log.h"

#include "dim_core_measure.h"
#include "dim_core_policy.h"
#include "dim_core_symbol.h"

#include "dim_core_measure_task.h"

struct module_text_measure_ctx {
	struct dim_measure *m;
	int mode;
};

static int calculate_module_digest(const char *name,
				   struct dim_hash *hash,
				   struct dim_digest *digest)
{
	int ret = 0;
	struct module *mod = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	mutex_lock(&module_mutex);
	mod = find_module(name);
#else
	rcu_read_lock_sched();
	mod = dim_core_kernel_symbol.find_module(name);
#endif
	if (mod == NULL || mod->state != MODULE_STATE_LIVE ||
	    !try_module_get(mod))
		mod = NULL; /* target module not exist or is not alive */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	mutex_unlock(&module_mutex);
#else
	rcu_read_unlock_sched();
#endif
	if (mod == NULL)
		return -ENOENT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	ret = dim_hash_calculate(mod->core_layout.base,
				 mod->core_layout.text_size,
				 hash, digest);
#else
	ret = dim_hash_calculate(mod->mem[MOD_TEXT].base,
				 mod->mem[MOD_TEXT].size,
				 hash, digest);
#endif
	module_put(mod);
	return ret;
}

static int measure_module(struct dim_policy *policy, void *data)
{
	int ret = 0;
	struct module_text_measure_ctx *ctx = data;
	const char *mod_name = policy->val;
	struct dim_digest digest = { 0 };

	if (policy == NULL || policy->obj != DIM_POLICY_OBJ_MODULE_TEXT ||
	    policy->key != DIM_POLICY_KEY_NAME || mod_name == NULL)
		return 0;

	/* if module is not inserted in baseline_init stage, ignore it */
	if (ctx->mode == DIM_MEASURE &&
	    dim_measure_dynamic_baseline_search(ctx->m, mod_name,
	    					DIM_BASELINE_KERNEL, &digest) < 0)
		return 0;

	digest.algo = ctx->m->hash.algo;
	ret = calculate_module_digest(mod_name, &ctx->m->hash, &digest);
	if (ret < 0) {
		dim_err("fail to calculate digest of module %s: %d\n",
			mod_name, ret);
		return ret == -ENOENT ? 0 : ret;
	}

	ret = dim_measure_process_dynamic_result(ctx->m, ctx->mode,
						 mod_name, &digest, NULL);
	if (ret < 0)
		dim_err("failed to check module digest: %d\n", ret);

	return 0;
}

static int module_text_measure(int mode, struct dim_measure *m)
{
	struct module_text_measure_ctx ctx = {
		.m = m,
		.mode = mode,
	};

	if (m == NULL)
		return -EINVAL;

	return dim_core_policy_walk(measure_module, &ctx);
}

struct dim_measure_task dim_core_measure_task_module_text = {
	.name = "dim_core_measure_task_module_text",
	.measure = module_text_measure,
};
