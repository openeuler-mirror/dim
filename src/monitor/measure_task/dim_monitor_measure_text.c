/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/version.h>
#include <linux/module.h>

#include "dim_measure.h"

#include "dim_monitor.h"

#include "dim_monitor_measure_task.h"

static int module_text_measure(int mode, struct dim_measure *m)
{
	int ret = 0;
	int log_flag = LOG_DYNAMIC_BASELINE;
	struct module *mod = NULL;
	struct dim_digest digest = { 0 };

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	mutex_lock(&module_mutex);
	mod = find_module(DIM_CORE);
#else
	rcu_read_lock_sched();
	mod = dim_monitor_kernel_symbol.find_module(DIM_CORE);
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
				 &m->hash, &digest);
#else
	ret = dim_hash_calculate(mod->mem[MOD_TEXT].base,
				 mod->mem[MOD_TEXT].size,
				 &m->hash, &digest);
#endif
	module_put(mod);
	if (ret < 0)
		return ret;

	ret = dim_measure_process_dynamic_result(m, mode, DIM_CORE_TEXT,
						 &digest, &log_flag);
	if (ret < 0)
		dim_err("failed to check dim_core text digest: %d\n", ret);

	return 0;
}

struct dim_measure_task dim_monitor_measure_text = {
	.name = "dim_monitor_measure_text",
	.init = NULL,
	.destroy = NULL,
	.measure = module_text_measure,
};
