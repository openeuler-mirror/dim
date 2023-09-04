/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/genalloc.h>

#include "dim_baseline.h"
#include "dim_hash.h"
#include "dim_measure_log.h"
#include "dim_tpm.h"
#include "dim_utils.h"

#include "dim_core_mem_pool.h"

#include "dim_monitor.h"
#include "dim_monitor_symbol.h"

static const char *dim_monitor_status_name[DIM_MONITOR_STATUS_LAST] = {
	[DIM_MONITOR_READY] = "ready",
	[DIM_MONITOR_RUNNING] = "running",
	[DIM_MONITOR_PROTECTED] = "protected",
	[DIM_MONITOR_ERROR] = "error",
};

static struct dim_hash dim_monitor_hash = { 0 };
static struct dim_tpm dim_monitor_tpm = { 0 };
static struct dim_baseline_tree dim_monitor_baseline = { 0 };

struct dim_status dim_monitor_status = { 0 };
struct dim_measure_log_tree dim_monitor_log = { 0 };

unsigned int measure_log_capacity = 100000;
unsigned int measure_pcr = 0;

/* lock to prevent concurrent measurement */
DEFINE_MUTEX(dim_monitor_measure_lock);

static void dim_monitor_status_set(unsigned int status)
{
	dim_status_set(&dim_monitor_status, status);
}

static int add_measure_log(const char *name, struct dim_digest *digest, int type)
{
	int ret = 0;

	ret = dim_measure_log_add(&dim_monitor_log, name, digest, type);
	if (ret < 0 && ret != -EEXIST) {
		dim_err("fail to add measure log of %s: %d\n", name, ret);
		return ret;
	}

	return 0;
}

static int add_baseline(const char *name, struct dim_digest *digest, int type)
{
	int ret = 0;

	ret = dim_baseline_add(&dim_monitor_baseline, name, type, digest);
	if (ret < 0) {
		dim_err("fail to add dim baseline of %s: %d\n", name, ret);
		return ret;
	}

	return add_measure_log(name, digest, LOG_DYNAMIC_BASELINE);
}

static int check_digest(const char *name, struct dim_digest *digest, int type)
{
	return dim_baseline_match(&dim_monitor_baseline, name, type, digest) ?
		0 : add_measure_log(name, digest, LOG_TAMPERED);
}

static void calculate_chunk(struct gen_pool *pool,
			    struct gen_pool_chunk *chunk,
			    void *data)
{
	struct shash_desc *shash = (struct shash_desc *)data;

	if (chunk == NULL || shash == NULL)
		return;

	(void)crypto_shash_update(shash, (char *)chunk->start_addr,
				  chunk->end_addr - chunk->start_addr);
}

static int measure_data(int baseline_init)
{
	int ret = 0;
	struct dim_digest digest = { .algo = dim_monitor_hash.algo };

	SHASH_DESC_ON_STACK(shash, dim_monitor_hash.tfm);
	shash->tfm = dim_monitor_hash.tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	dim_mem_pool_walk_chunk(calculate_chunk, shash);
	ret = crypto_shash_final(shash, digest.data);
	if (ret < 0)
		return ret;

	return baseline_init ?
		add_baseline(DIM_CORE_DATA, &digest, DIM_BASELINE_DATA) :
		check_digest(DIM_CORE_DATA, &digest, DIM_BASELINE_DATA);
}

static int measure_text(int baseline_init)
{
	int ret = 0;
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
				 &dim_monitor_hash, &digest);
#else
	ret = dim_hash_calculate(mod->mem[MOD_TEXT].base,
				 mod->mem[MOD_TEXT].size,
				 &dim_monitor_hash, &digest);
#endif
	module_put(mod);
	if (ret < 0)
		return ret;

	return baseline_init ?
		add_baseline(DIM_CORE_TEXT, &digest, DIM_BASELINE_KERNEL) :
		check_digest(DIM_CORE_TEXT, &digest, DIM_BASELINE_KERNEL);
}

int dim_monitor_measure(int baseline_init)
{
	int ret = 0;

	if (!mutex_trylock(&dim_monitor_measure_lock))
		return -EBUSY;

	dim_monitor_status_set(DIM_MONITOR_RUNNING);
	dim_info("start dim monitor measure, baseline_init = %d\n",
		 baseline_init);

	if (baseline_init) {
		dim_baseline_destroy_tree(&dim_monitor_baseline);
		dim_measure_log_refresh(&dim_monitor_log);
	}

	ret = measure_text(baseline_init);
	if (ret < 0) {
		dim_err("fail to measure dim_core text");
		goto out;
	}

	ret = measure_data(baseline_init);
	if (ret < 0)
		dim_err("fail to measure dim_core data");
out:
	mutex_unlock(&dim_monitor_measure_lock);
	dim_monitor_status_set(ret < 0 ? DIM_MONITOR_ERROR :
					 DIM_MONITOR_PROTECTED);
	return ret;
}

int dim_monitor_measure_init(const char *alg_name)
{
	int ret = 0;

	/* 1. check the measure parameter */
	if (measure_log_capacity < MEASURE_LOG_CAP_MIN ||
	    measure_log_capacity > MEASURE_LOG_CAP_MAX) {
		dim_err("invalid measure_log_capacity parameter\n");
		return -ERANGE;
	}

	if (measure_pcr > DIM_PCR_MAX) {
		dim_err("invalid measure_pcr parameter\n");
		return -ERANGE;
	}

	/* init TPM, dont break if init fail */
	if (measure_pcr > 0) {
		ret = dim_tpm_init(&dim_monitor_tpm, HASH_ALGO_SHA256);
		if (ret < 0)
			dim_warn("fail to initialize tpm chip: %d\n", ret);
	}

	ret = dim_hash_init(alg_name, &dim_monitor_hash);
	if (ret < 0) {
		dim_err("fail to initialize hash algorithm: %d\n", ret);
		goto err;
	}

	ret = dim_status_init(&dim_monitor_status, dim_monitor_status_name,
			      DIM_MONITOR_STATUS_LAST);
	if (ret < 0) {
		dim_err("fail to initialize status: %d\n", ret);
		goto err;
	}

	ret = dim_baseline_init_tree(dim_kmalloc_gfp, dim_kfree,
				     &dim_monitor_baseline);
	if (ret < 0) {
		dim_err("fail to initialize static baseline root: %d\n", ret);
		goto err;
	}

	ret = dim_measure_log_init_tree(&dim_monitor_log, &dim_monitor_hash,
					&dim_monitor_tpm, measure_log_capacity,
					measure_pcr);
	if (ret < 0) {
		dim_err("fail to initialize measure log: %d\n", ret);
		goto err;
	}

	dim_status_set(&dim_monitor_status, DIM_MONITOR_READY);
	return 0;
err:
	dim_measure_log_destroy_tree(&dim_monitor_log);
	dim_baseline_destroy_tree(&dim_monitor_baseline);
	dim_hash_destroy(&dim_monitor_hash);
	dim_tpm_destroy(&dim_monitor_tpm);
	return ret;
}

void dim_monitor_destroy_measure(void)
{
	mutex_lock(&dim_monitor_measure_lock);
	dim_measure_log_destroy_tree(&dim_monitor_log);
	dim_baseline_destroy_tree(&dim_monitor_baseline);
	dim_hash_destroy(&dim_monitor_hash);
	dim_tpm_destroy(&dim_monitor_tpm);
}
