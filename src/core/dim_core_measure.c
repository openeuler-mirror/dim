/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/highmem.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>

#include "dim_measure_log.h"
#include "dim_tpm.h"

#include "dim_core.h"
#include "dim_core_status.h"
#include "dim_core_policy.h"
#include "dim_core_static_baseline.h"
#include "dim_core_baseline.h"
#include "dim_core_measure.h"

/* lock to prevent concurrent measurement */
DEFINE_MUTEX(dim_core_measure_lock);
/* lock to prevent concurrent baseline_init */
DEFINE_MUTEX(dim_core_baseline_lock);
/* lock to prevent concurrent setting interval */
DEFINE_MUTEX(dim_core_interval_lock);
/* lock to prevent concurrent setting tampered_action */
DEFINE_MUTEX(dim_core_tampered_action_lock);
/* dim work quee */
static struct workqueue_struct *dim_work_queue = NULL;
static struct delayed_work dim_measure_work;
/* parameters set by module commandline */
unsigned int measure_log_capacity = 100000;
unsigned int measure_schedule = 0;
unsigned int measure_interval = 0;
unsigned int measure_pcr = 0;
bool tampered_action = false;

/* time (jiffies) to set */
unsigned long measure_schedule_jiffies = 0;
static unsigned long measure_interval_jiffies = 0;

struct dim_tpm dim_core_tpm = { 0 };
struct dim_hash dim_core_hash = { 0 };
struct dim_measure_log_tree dim_core_log = { 0 };

long dim_core_interval_get(void)
{
	long p = 0;

	mutex_lock(&dim_core_interval_lock);
	p = measure_interval;
	mutex_unlock(&dim_core_interval_lock);
	return p;
}

unsigned long dim_core_interval_jiffies_get(void)
{
	unsigned long p = 0;

	mutex_lock(&dim_core_interval_lock);
	p = measure_interval_jiffies;
	mutex_unlock(&dim_core_interval_lock);
	return p;
}

int dim_core_interval_set(unsigned int min)
{
	unsigned long min_jiffies = 0;

	if (min > DIM_INTERVAL_MAX ||
	    (unsigned long)min * DIM_MINUTE_TO_SEC > MAX_SEC_IN_JIFFIES)
		return -ERANGE;

	min_jiffies = (min == 0) ? 0 :
		nsecs_to_jiffies64((unsigned long)min * DIM_MINUTE_TO_NSEC);

	mutex_lock(&dim_core_interval_lock);
	measure_interval = min;
	measure_interval_jiffies = min_jiffies;
	if (measure_interval == 0) {
		dim_info("cancel dim timed measure work");
		cancel_delayed_work_sync(&dim_measure_work);
	} else {
		dim_info("modify dim measure interval to %u min "
			 "(jittfies = 0x%lx)", min, min_jiffies);
		mod_delayed_work(dim_work_queue, &dim_measure_work,
				 min_jiffies);
	}

	mutex_unlock(&dim_core_interval_lock);
	return 0;
}

long dim_core_tampered_action_get(void)
{
	long p = 0;

	mutex_lock(&dim_core_tampered_action_lock);
	p = tampered_action ? 1 : 0;
	mutex_unlock(&dim_core_tampered_action_lock);
	return p;
}

int dim_core_tampered_action_set(unsigned int p)
{
	if (p != 0 && p != 1)
		return -EINVAL;

	mutex_lock(&dim_core_tampered_action_lock);
	tampered_action = !!p;
	mutex_unlock(&dim_core_tampered_action_lock);
	return 0;
}

static void do_measure(void)
{
	int ret = 0;
	int bi = 0;

	/* dont do measure when doing baseline_init */
	if (!mutex_trylock(&dim_core_baseline_lock))
		return;

	bi = (dim_core_status_get() == DIM_BASELINE_RUNNING ? 1 : 0);
	dim_info("start dim measure work, baseline_init = %d\n", bi);

	ret = dim_core_measure_task(bi);
	if (ret < 0)
		dim_err("fail to measure user process: %d\n", ret);

	ret = dim_core_measure_module(bi);
	if (ret < 0)
		dim_err("fail to measure kernel modules: %d\n", ret);

	ret = dim_core_measure_kernel(bi);
	if (ret < 0)
		dim_err("fail to measure kernel: %d\n", ret);

	mutex_unlock(&dim_core_baseline_lock);
}

static int do_baseline(void)
{
	int ret = 0;

	ret = dim_core_policy_load();
	if (ret < 0) {
		dim_err("fail to load dim core policy: %d\n", ret);
		return ret;
	}

	dim_core_baseline_destroy();
	ret = dim_core_static_baseline_load();
	if (ret < 0) {
		dim_err("fail to load dim static baseline: %d\n", ret);
		dim_core_policy_destroy();
		return ret;
	}

	dim_measure_log_refresh(&dim_core_log);
	return 0;
}

static void dim_worker_work_cb(struct work_struct *work)
{
	unsigned long p;

	do_measure();
	p = dim_core_interval_jiffies_get();
	if (p != 0)
		queue_delayed_work(dim_work_queue, &dim_measure_work, p);
}

int dim_core_measure(int baseline_init)
{
	int ret = 0;

	if (!mutex_trylock(&dim_core_measure_lock))
		return -EBUSY;

	/* clean the running work */
	flush_delayed_work(&dim_measure_work);
	cancel_delayed_work_sync(&dim_measure_work);

	if (dim_core_status_get() == DIM_NO_BASELINE)
		baseline_init = 1;

	if (baseline_init) {
		mutex_lock(&dim_core_baseline_lock);
		dim_core_status_set(DIM_BASELINE_RUNNING);
		ret = do_baseline();
		mutex_unlock(&dim_core_baseline_lock);
		if (ret < 0)
			goto out;
	} else {
		dim_core_status_set(DIM_MEASURE_RUNNING);
	}

	queue_delayed_work(dim_work_queue, &dim_measure_work, 0);
	flush_delayed_work(&dim_measure_work);
out:
	dim_core_status_set(ret < 0 ? DIM_ERROR : DIM_PROTECTED);
	mutex_unlock(&dim_core_measure_lock);
	return ret;
}

int dim_core_measure_init(const char *alg_name)
{
	int ret = 0;

	/* 1. check the measure parameter */
	if (measure_log_capacity < MEASURE_LOG_CAP_MIN ||
	    measure_log_capacity > MEASURE_LOG_CAP_MAX) {
		dim_err("invalid measure_log_capacity parameter\n");
		return -ERANGE;
	}

	if (measure_schedule > MEASURE_SCHEDULE_MAX) {
		dim_err("invalid measure_schedule parameter\n");
		return -ERANGE;
	}

	if (measure_interval > DIM_INTERVAL_MAX) {
		dim_err("invalid measure_interval parameter\n");
		return -ERANGE;
	}

	if (measure_pcr > DIM_PCR_MAX) {
		dim_err("invalid measure_pcr parameter\n");
		return -ERANGE;
	}

	/* 2. init measure hash algorithm */
	ret = dim_hash_init(alg_name, &dim_core_hash);
	if (ret < 0) {
		dim_err("fail to initialize hash algorithm: %d\n", ret);
		goto err;
	}

	/* 3. init TPM, dont break if init fail */
	if (measure_pcr > 0) {
		ret = dim_tpm_init(&dim_core_tpm, HASH_ALGO_SHA256);
		if (ret < 0)
			dim_warn("fail to initialize tpm chip: %d\n", ret);
	}

	/* 4. init measurement status */
	ret = dim_core_status_init();
	if (ret < 0) {
		dim_err("fail to initialize dim status: %d\n", ret);
		goto err;
	}

	/* 5. init baseline data (static and dynamic) */
	ret = dim_core_baseline_init();
	if (ret < 0) {
		dim_err("fail to initialize dim baseline: %d\n", ret);
		goto err;
	}

	/* 6. init measure log */
	ret = dim_measure_log_init_tree(&dim_core_log,
					&dim_core_hash, &dim_core_tpm,
					measure_log_capacity, measure_pcr);
	if (ret < 0) {
		dim_err("fail to initialize measure log root: %d\n", ret);
		goto err;
	}

	/* 7. init measure work thread */
	INIT_DELAYED_WORK(&dim_measure_work, dim_worker_work_cb);
	dim_work_queue = create_singlethread_workqueue("dim_core");
	if (dim_work_queue == NULL) {
		ret = -ENOMEM;
		dim_err("fail to create dim work queue: %d\n", ret);
		goto err;
	}
	
	/* 8. if the interval is set, start to do baseline and measure */
	if (measure_interval) {
		ret = dim_core_measure(1);
		if (ret < 0) {
			dim_err("fail to do baseline init: %d\n", ret);
			goto err;
		}

		dim_core_interval_set(measure_interval);
	}

	if (measure_schedule)
		measure_schedule_jiffies = msecs_to_jiffies(measure_schedule);

	return 0;
err:
	dim_hash_destroy(&dim_core_hash);
	dim_tpm_destroy(&dim_core_tpm);
	dim_core_baseline_destroy();
	dim_measure_log_destroy_tree(&dim_core_log);
	return ret;
}

void dim_core_destroy_measure(void)
{
	mutex_lock(&dim_core_measure_lock);
	if (dim_work_queue != NULL) {
		/* 1. wait the measure work to finish */
		flush_delayed_work(&dim_measure_work);
		cancel_delayed_work_sync(&dim_measure_work);
		/* 2. do clean job */
		destroy_workqueue(dim_work_queue);
	}

	dim_measure_log_destroy_tree(&dim_core_log);
	dim_core_baseline_destroy();
	dim_core_policy_destroy();
	dim_tpm_destroy(&dim_core_tpm);
	dim_hash_destroy(&dim_core_hash);
}
