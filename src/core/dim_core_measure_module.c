/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/module.h>
#include <linux/version.h>

#include "dim_utils.h"
#include "dim_hash.h"
#include "dim_baseline.h"
#include "dim_measure_log.h"

#include "dim_core.h"
#include "dim_core_measure.h"
#include "dim_core_baseline.h"
#include "dim_core_policy.h"
#include "dim_core_symbol.h"

static int calculate_module_digest(const char *name,
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
				 &dim_core_hash, digest);
#else
	ret = dim_hash_calculate(mod->mem[MOD_TEXT].base,
				 mod->mem[MOD_TEXT].size,
				 &dim_core_hash, digest);
#endif
	module_put(mod);
	return ret;
}

static int measure_module(struct dim_policy *policy, void *data)
{
	int ret = 0;
	int baseline_init = *(int *)data;
	const char *mod_name = policy->val;
	struct dim_digest digest = { 0 };

	if (policy == NULL || policy->obj != DIM_POLICY_OBJ_MODULE_TEXT ||
	    policy->key != DIM_POLICY_KEY_NAME || mod_name == NULL)
		return 0;

	/* if module is not inserted in baseline_init stage, ignore it */
	if (!baseline_init &&
	    dim_core_search_dynamic_baseline(mod_name, DIM_BASELINE_KERNEL,
					     &digest) < 0)
		return 0;

	digest.algo = dim_core_hash.algo;
	ret = calculate_module_digest(mod_name, &digest);
	if (ret < 0) {
		dim_err("fail to calculate digest of module %s: %d\n",
			mod_name, ret);
		return ret == -ENOENT ? 0 : ret;
	}

	ret = dim_core_check_kernel_digest(baseline_init, mod_name, &digest);
	if (ret < 0)
		dim_err("fail to check kernel digest: %d\n", ret);

	return 0;
}

int dim_core_measure_module(int baseline_init)
{
	return dim_core_policy_walk(measure_module, &baseline_init);
}
