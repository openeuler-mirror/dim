/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/module.h>

#include "dim_core.h"
#include "dim_core_symbol.h"
#include "dim_core_fs.h"
#include "dim_core_measure.h"
#include "dim_core_mem_pool.h"
#include "dim_core_sig.h"

static char *measure_hash = NULL;
bool signature = false;

module_param(measure_log_capacity, uint, 0);
MODULE_PARM_DESC(measure_log_capacity, "Max number of measure log");

module_param(measure_schedule, uint, 0);
MODULE_PARM_DESC(measure_schedule, "Schedule time (ms) for each measure object");

module_param(measure_interval, uint, 0);
MODULE_PARM_DESC(measure_interval, "Interval time (min) for automatic measurement");

module_param(measure_hash, charp, 0);
MODULE_PARM_DESC(measure_hash, "Hash algorithm for measurement");

module_param(measure_pcr, uint, 0);
MODULE_PARM_DESC(measure_pcr, "TPM PCR index to extend measure log");

module_param(signature, bool, 0);
MODULE_PARM_DESC(signature, "Require signature for policy and static baseline");

static int __init dim_core_init(void)
{
	int ret;

	ret = dim_core_kallsyms_init();
	if (ret < 0) {
		dim_err("failed to initialize dim kernel symbol: %d\n", ret);
		goto err;
	}

	ret = dim_mem_pool_init();
	if (ret < 0) {
		dim_err("failed to initialize dim memory pool: %d\n", ret);
		goto err;
	}

	if (signature) {
		ret = dim_core_sig_init();
		if (ret < 0) {
			dim_err("failed to initialize dim signature: %d\n", ret);
			goto err;
		}
	}

	ret = dim_core_measure_init(measure_hash == NULL ?
				    DIM_CORE_HASH_DEFAULT : measure_hash);
	if (ret < 0) {
		dim_err("failed to initialize dim measurement: %d\n", ret);
		goto err;
	}

	ret = dim_core_create_fs();
	if (ret < 0) {
		dim_err("failed to create dim fs entry: %d\n", ret);
		goto err;
	}

	return 0;
err:
	dim_core_destroy_fs();
	dim_core_destroy_measure();
	dim_mem_pool_destroy();
	return ret;
}

static void __exit dim_core_exit(void)
{
	dim_core_destroy_measure();
	dim_core_destroy_fs();
	dim_mem_pool_destroy();

	if (signature)
		dim_core_sig_destroy();
}

module_init(dim_core_init);
module_exit(dim_core_exit);
MODULE_LICENSE("GPL");
