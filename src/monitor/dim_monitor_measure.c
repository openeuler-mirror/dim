/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/version.h>
#include <linux/genalloc.h>

#include "dim_measure.h"

#include "dim_core_mem_pool.h"

#include "dim_monitor.h"
#include "dim_monitor_symbol.h"

#include "measure_task/dim_monitor_measure_task.h"

/* measurement tasks */
static struct dim_measure_task *dim_core_tasks[] = {
	&dim_monitor_measure_data,
	&dim_monitor_measure_text,
};

/* the global measurement handle */
struct dim_measure dim_monitor_handle = { 0 };

/* lock to prevent trigger multiple measurement */
DEFINE_MUTEX(dim_monitor_measure_lock);

const char *dim_monitor_status_print(void)
{
	return dim_measure_status_print(&dim_monitor_handle);
}

int dim_monitor_measure_blocking(void)
{
	if (!mutex_trylock(&dim_monitor_measure_lock))
		return -EBUSY;

	dim_measure_task_measure(DIM_MEASURE, &dim_monitor_handle);
	mutex_unlock(&dim_monitor_measure_lock);
	return 0;
}

int dim_monitor_baseline_blocking(void)
{
	if (!mutex_trylock(&dim_monitor_measure_lock))
		return -EBUSY;

	dim_measure_task_measure(DIM_BASELINE, &dim_monitor_handle);
	mutex_unlock(&dim_monitor_measure_lock);
	return 0;
}

static int baseline_prepare(struct dim_measure *m)
{
	dim_baseline_destroy_tree(&m->static_baseline);
	dim_baseline_destroy_tree(&m->dynamic_baseline);
	dim_measure_log_refresh(&m->log);
	return 0;
}

int dim_monitor_measure_init(struct dim_measure_cfg *cfg)
{
	int ret = 0;

	/* init the measurement handle */
	ret = dim_measure_init(&dim_monitor_handle, cfg);
	if (ret < 0) {
		dim_err("failed to init measurement handle\n");
		return ret;
	}

	/* set the baseline prepare function */
	dim_monitor_handle.baseline_prepare = baseline_prepare;

	/* register all measurement tasks */
	ret = dim_measure_tasks_register(&dim_monitor_handle, dim_core_tasks,
					 DIM_ARRAY_LEN(dim_core_tasks));
	if (ret < 0) {
		dim_err("failed to register measure tasks: %d\n", ret);
		goto err;
	}

	return 0;
err:
	dim_measure_destroy(&dim_monitor_handle);
	return ret;
}

void dim_monitor_measure_destroy(void)
{
	mutex_lock(&dim_monitor_measure_lock);
	dim_measure_destroy(&dim_monitor_handle);
	mutex_unlock(&dim_monitor_measure_lock);
}
