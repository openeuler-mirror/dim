/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/module.h>

#include "dim_measure.h"

#include "dim_monitor.h"
#include "dim_monitor_symbol.h"

/* common measurement configuration */
static struct dim_measure_cfg cfg = {
	.alg_name = DIM_MONITOR_HASH_DEFAULT,
	.log_cap = DIM_MONITOR_LOG_CAP_DEFAULT,
};

module_param_named(measure_log_capacity, cfg.log_cap, uint, 0);
MODULE_PARM_DESC(measure_log_capacity, "Max number of measure log");

module_param_named(measure_hash, cfg.alg_name, charp, 0);
MODULE_PARM_DESC(measure_hash, "Hash algorithm for measurement");

module_param_named(measure_pcr, cfg.pcr, uint, 0);
MODULE_PARM_DESC(measure_pcr, "TPM PCR index to extend measure log");

static int __init dim_monitor_init(void)
{
	int ret;

	ret = dim_monitor_kallsyms_init();
	if (ret < 0) {
		dim_err("fail to initialize dim kernel symbol: %d\n", ret);
		goto err;
	}

	ret = dim_monitor_measure_init(&cfg);
	if (ret < 0) {
		dim_err("fail to initialize dim measurement: %d\n", ret);
		goto err;
	}

	ret = dim_monitor_create_fs();
	if (ret < 0) {
		dim_err("fail to create dim fs entry: %d\n", ret);
		goto err;
	}

	return 0;
err:
	dim_monitor_measure_destroy();
	dim_monitor_destroy_fs();
	return ret;
}

static void __exit dim_monitor_exit(void)
{
	dim_monitor_measure_destroy();
	dim_monitor_destroy_fs();
}

module_init(dim_monitor_init);
module_exit(dim_monitor_exit);
MODULE_LICENSE("GPL");
