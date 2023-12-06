/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/atomic.h>
#include <linux/utsname.h>

#include "dim_baseline.h"
#include "dim_hash.h"
#include "dim_utils.h"

#include "dim_core.h"
#include "dim_core_mem_pool.h"

static struct dim_baseline_tree static_baseline = { 0 };
static struct dim_baseline_tree dynamic_baseline = { 0 };

static const char *process_static_name(const char *name, int type,
				       char *buf, int buf_len)
{
	const char *kr = init_uts_ns.name.release;

	if (type != DIM_BASELINE_KERNEL || strcmp(name, kr) == 0)
		return name;

	/* name of kernel module has a kernel prefix in static baseline */
	if (sprintf(buf, "%s/%s", kr, name) < 0)
		return NULL;

	return buf;
}

int dim_core_add_static_baseline(const char *name, int type,
				 struct dim_digest *digest)
{
	int ret = dim_baseline_add(&static_baseline, name, type, digest);
	if (ret < 0 && ret != -EEXIST) {
		dim_err("failed to add static baseline of %s\n", name);
		return ret;
	}

	return 0;
}

int dim_core_add_dynamic_baseline(const char *name, int type,
				  struct dim_digest *digest)
{
	int ret = dim_baseline_add(&dynamic_baseline, name, type, digest);
	if (ret < 0 && ret != -EEXIST) {
		dim_err("failed to add dynamic baseline of %s\n", name);
		return ret;
	}

	return 0;
}

bool dim_core_match_static_baseline(const char *name, int type,
				    struct dim_digest *digest)
{
	char buf[NAME_MAX + NAME_MAX + 1 + 1] = { 0 };
	return dim_baseline_match(&static_baseline,
		process_static_name(name, type, buf, sizeof(buf)),
		type, digest);
}

bool dim_core_match_dynamic_baseline(const char *name, int type,
				     struct dim_digest *digest)
{
	return dim_baseline_match(&dynamic_baseline, name, type, digest);
}

int dim_core_search_static_baseline(const char *name, int type,
				     struct dim_digest *digest)
{
	char buf[NAME_MAX + NAME_MAX + 1 + 1] = { 0 };
	return dim_baseline_search_digest(&static_baseline,
		process_static_name(name, type, buf, sizeof(buf)),
		type, digest);
}

int dim_core_search_dynamic_baseline(const char *name, int type,
				     struct dim_digest *digest)
{
	return dim_baseline_search_digest(&dynamic_baseline, name,
					  type, digest);
}

int dim_core_baseline_init(void)
{
	int ret;

	ret = dim_baseline_init_tree(dim_kmalloc_gfp,
				     dim_kfree,
				     &static_baseline);
	if (ret < 0) {
		dim_err("failed to initialize static baseline root: %d\n", ret);
		return ret;
	}

	ret = dim_baseline_init_tree(dim_mem_pool_alloc,
				     dim_mem_pool_free,
				     &dynamic_baseline);
	if (ret < 0) {
		dim_err("failed to initialize dynamic baseline root: %d\n", ret);
		return ret;
	}

	return 0;
}

void dim_core_baseline_destroy(void)
{
	dim_baseline_destroy_tree(&static_baseline);
	dim_baseline_destroy_tree(&dynamic_baseline);
}
