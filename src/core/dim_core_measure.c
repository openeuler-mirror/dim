/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/workqueue.h>

#include "dim_core_policy.h"
#include "dim_core_mem_pool.h"
#include "dim_core_static_baseline.h"
#include "dim_core_measure_task.h"
#include "dim_core_measure.h"

/* measurement tasks */
static struct dim_measure_task *dim_core_tasks[] = {
	&dim_core_measure_task_user_text,
	&dim_core_measure_task_kernel_text,
	&dim_core_measure_task_module_text,
};

/* the global measurement handle */
struct dim_measure dim_core_handle = {
	.task_list = LIST_HEAD_INIT(dim_core_handle.task_list),
};

/* lock to prevent trigger multiple measurement */
DEFINE_MUTEX(dim_core_measure_lock);

/* dim measurement work */
static struct workqueue_struct *dim_work_queue = NULL;
static struct delayed_work dim_measure_work;
static struct work_struct dim_baseline_work;

/* special measurement parameters for dim_core */
static atomic_t measure_interval = ATOMIC_INIT(0);
static atomic_t measure_action = ATOMIC_INIT(0);

/* interface to print measure status string */
const char *dim_core_status_print(void)
{
	return dim_measure_status_print(&dim_core_handle);
}

/* interface to get tampered action */
long dim_core_measure_action_get(void)
{
	return atomic_read(&measure_action);
}

/* interface to set measure action */
int dim_core_measure_action_set(unsigned int act)
{
	if (act >= DIM_MEASURE_ACTION_MAX)
		return -ERANGE;

	atomic_set(&measure_action, act);
	return 0;
}

/* interface to get measure interval */
long dim_core_interval_get(void)
{
	return atomic_read(&measure_interval);
}

/* interface to set measure interval */
int dim_core_interval_set(unsigned int min)
{
	unsigned long jiffies = 0;

	if (min > DIM_INTERVAL_MAX ||
	    (unsigned long)min * DIM_MINUTE_TO_SEC > MAX_SEC_IN_JIFFIES)
		return -ERANGE;

	atomic_set(&measure_interval, min);
	if (min == 0) {
		dim_info("cancel dim timed measure work");
		cancel_delayed_work_sync(&dim_measure_work);
	} else {
		jiffies = nsecs_to_jiffies64((unsigned long)min *
					     DIM_MINUTE_TO_NSEC);
		dim_info("modify dim measure interval to %u min "
			 "(jittfies = 0x%lx)", min, jiffies);
		mod_delayed_work(dim_work_queue, &dim_measure_work, jiffies);
	}

	return 0;
}

static int baseline_prepare(struct dim_measure *m)
{
	int ret = 0;

	if (m == NULL)
		return -EINVAL;

	/* 1. reload dim policy */
	ret = dim_core_policy_load();
	if (ret < 0) {
		dim_err("failed to load dim core policy: %d\n", ret);
		return ret;
	}

	/* 2. clear dim baseline */
	dim_baseline_destroy_tree(&m->static_baseline);
	dim_baseline_destroy_tree(&m->dynamic_baseline);

	/* 3. reload dim baseline */
	ret = dim_core_static_baseline_load(m);
	if (ret < 0) {
		dim_err("failed to load dim static baseline: %d\n", ret);
		dim_core_policy_destroy();
		return ret;
	}

	/* 4. refresh measure log */
	dim_measure_log_refresh(&m->log);
	return 0;
}

static void queue_delayed_measure_work(void)
{
	unsigned long jiffies = 0;
	unsigned int interval = atomic_read(&measure_interval);

	if (interval == 0)
		return;

	jiffies = nsecs_to_jiffies64((unsigned long)interval *
					DIM_MINUTE_TO_NSEC);
	queue_delayed_work(dim_work_queue, &dim_measure_work, jiffies);
}

static void measure_work_cb(struct work_struct *work)
{
	dim_measure_task_measure(DIM_MEASURE, &dim_core_handle);
	queue_delayed_measure_work();
}

static void baseline_work_cb(struct work_struct *work)
{
	dim_measure_task_measure(DIM_BASELINE, &dim_core_handle);
	/* if baseline is failed, dont perform measurement */
	if (dim_measure_status_error(&dim_core_handle))
		return;

	queue_delayed_measure_work();
}

/* trigger a measurement and wait for it to complete */
int dim_core_measure_blocking(void)
{
	int ret = 0;

	if (!mutex_trylock(&dim_core_measure_lock))
		return -EBUSY;

	/* clean the running work */
	flush_delayed_work(&dim_measure_work);
	cancel_delayed_work_sync(&dim_measure_work);
	/* queue and flush measure work */
	queue_delayed_work(dim_work_queue, &dim_measure_work, 0);
	flush_delayed_work(&dim_measure_work);

	/* check error status */
	if (dim_measure_status_error(&dim_core_handle))
		ret = -EFAULT;

	mutex_unlock(&dim_core_measure_lock);
	return ret;
}

/* trigger a dynamic baseline and wait for it to complete */
int dim_core_baseline_blocking(void)
{
	int ret = 0;

	if (!mutex_trylock(&dim_core_measure_lock))
		return -EBUSY;

	/* clean the running work */
	flush_delayed_work(&dim_measure_work);
	cancel_delayed_work_sync(&dim_measure_work);

	/* queue and flush baseline work */
	queue_work(dim_work_queue, &dim_baseline_work);
	flush_work(&dim_baseline_work);

	/* check error status */
	if (dim_measure_status_error(&dim_core_handle))
		ret = -EFAULT;

	mutex_unlock(&dim_core_measure_lock);
	return ret;
}

int dim_core_measure_init(struct dim_measure_cfg *cfg, unsigned int interval)
{
	int ret = 0;

	/* set the special baseline memory functions */
	cfg->dyn_malloc = dim_mem_pool_alloc;
	cfg->dyn_free = dim_mem_pool_free;

	/* init the measurement handle */
	ret = dim_measure_init(&dim_core_handle, cfg);
	if (ret < 0) {
		dim_err("failed to init measurement handle\n");
		return ret;
	}

	/* set the baseline prepare function */
	dim_core_handle.baseline_prepare = baseline_prepare;

	/* register all measurement tasks */
	ret = dim_measure_tasks_register(&dim_core_handle, dim_core_tasks,
					 DIM_ARRAY_LEN(dim_core_tasks));
	if (ret < 0) {
		dim_err("failed to register measure tasks: %d\n", ret);
		goto err;
	}

	/* init the measurement working thread */
	dim_work_queue = create_singlethread_workqueue("dim_core");
	if (dim_work_queue == NULL) {
		ret = -ENOMEM;
		dim_err("failed to create dim work queue: %d\n", ret);
		goto err;
	}

	/* init the measurement work */
	INIT_WORK(&dim_baseline_work, baseline_work_cb);
	INIT_DELAYED_WORK(&dim_measure_work, measure_work_cb);

	/* if the interval is set, start to do baseline and measure */
	if (interval) {
		ret = dim_core_baseline_blocking();
		if (ret < 0) {
			dim_err("failed to do baseline init: %d\n", ret);
			goto err;
		}

		ret = dim_core_interval_set(interval);
		if (ret < 0)
			dim_warn("failed to set measure interval: %d\n", ret);
	}

	return 0;
err:
	dim_measure_destroy(&dim_core_handle);
	if (dim_work_queue != NULL)
		destroy_workqueue(dim_work_queue);

	return ret;
}

void dim_core_measure_destroy(void)
{
	mutex_lock(&dim_core_measure_lock);
	if (dim_work_queue != NULL) {
		/* 1. wait the measure work to finish */
		flush_delayed_work(&dim_measure_work);
		cancel_delayed_work_sync(&dim_measure_work);
		/* 2. do clean job */
		destroy_workqueue(dim_work_queue);
	}

	dim_measure_destroy(&dim_core_handle);
	dim_core_policy_destroy();
	mutex_unlock(&dim_core_measure_lock);
}
