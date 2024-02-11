/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/utsname.h>

#include "dim_measure.h"

static inline bool is_valid_mode(int mode)
{
	return mode == DIM_BASELINE || mode == DIM_MEASURE;
}

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

static int static_baseline_add(struct dim_measure *m,
			       const char *name, int type,
			       struct dim_digest *digest)
{
	int ret = dim_baseline_add(&m->static_baseline, name, type, digest);
	if (ret < 0 && ret != -EEXIST) {
		dim_err("failed to add static baseline of %s\n", name);
		return ret;
	}

	return 0;
}

static int dynamic_baseline_add(struct dim_measure *m,
				const char *name, int type,
				struct dim_digest *digest)
{
	int ret = dim_baseline_add(&m->dynamic_baseline, name, type, digest);
	if (ret < 0 && ret != -EEXIST) {
		dim_err("failed to add dynamic baseline of %s\n", name);
		return ret;
	}

	return 0;
}

static bool static_baseline_match(struct dim_measure *m,
				  const char *name, int type,
				  struct dim_digest *digest)
{
	char buf[NAME_MAX + NAME_MAX + 1 + 1] = { 0 };
	return dim_baseline_match(&m->static_baseline,
		process_static_name(name, type, buf, sizeof(buf)),
		type, digest);
}

static bool dynamic_baseline_match(struct dim_measure *m,
				   const char *name, int type,
				   struct dim_digest *digest)
{
	return dim_baseline_match(&m->dynamic_baseline, name, type, digest);
}

static int static_baseline_search(struct dim_measure *m,
				  const char *name, int type,
				  struct dim_digest *digest)
{
	char buf[NAME_MAX + NAME_MAX + 1 + 1] = { 0 };
	return dim_baseline_search_digest(&m->static_baseline,
		process_static_name(name, type, buf, sizeof(buf)),
		type, digest);
}

static int dynamic_baseline_search(struct dim_measure *m,
				   const char *name, int type,
				   struct dim_digest *digest)
{
	return dim_baseline_search_digest(&m->dynamic_baseline, name,
					  type, digest);
}

static int measure_log_add(struct dim_measure *m, const char *name,
			   struct dim_digest *digest, int flag)
{
	int ret = dim_measure_log_add(&m->log, name, digest, flag);
	if (ret < 0 && ret != -EEXIST) {
		dim_err("failed to add measure log of %s: %d\n", name, ret);
		return ret;
	}

	return 0;
}

/* check dynamic measurement result in baseline stage */
static int process_dynamic_baseline(struct dim_measure *m, const char *name,
				    struct dim_digest *digest, int *log_flag) // TODO
{
	int ret = 0;
	struct dim_digest digest_static = { 0 };
	int def_flag = log_flag == NULL ? LOG_NO_SATIC_BASELINE : *log_flag;

	if (m == NULL || name == NULL || digest == NULL)
		return -EINVAL;

	/* 1. add digest to dynamic baseline */
	ret = dynamic_baseline_add(m, name, DIM_BASELINE_KERNEL, digest);
	if (ret < 0)
		return ret;

	/* 2. search digest from static baseline */
	ret = static_baseline_search(m, name, DIM_BASELINE_KERNEL, &digest_static);
	if (ret < 0)
		/* 2.1. if not find, log the dynamic baseline */
		return measure_log_add(m, name, digest, def_flag);

	/* 2.2. if find, log the static baseline */
	return measure_log_add(m, name, &digest_static, LOG_STATIC_BASELINE);
}

/* process dynamic measurement result in measure stage */
static int process_dynamic_measure(struct dim_measure *m, const char *name,
				   struct dim_digest *digest, int *log_flag)
{
	if (m == NULL || name == NULL || digest == NULL)
		return -EINVAL;

	if(!dynamic_baseline_match(m, name, DIM_BASELINE_KERNEL, digest)) {
		dim_err("mismatch dynamic baseline of kernel %s\n", name);
		if (log_flag != NULL) // TODO
			*log_flag = LOG_TAMPERED;

		return measure_log_add(m, name, digest, LOG_TAMPERED);
	}

	return 0;
}

/* process static measurement result in baseline stage */
static int process_static_baseline(struct dim_measure *m, const char *name,
				   struct dim_digest *digest, int *log_flag)
{
	int ret = 0;
	struct dim_digest digest_static = { 0 };

	/* 1. add digest to dynamic baseline */
	ret = dynamic_baseline_add(m, name, DIM_BASELINE_USER, digest);
	if (ret < 0)
		return ret;

	/* 2. search digest from static baseline */
	ret = static_baseline_search(m, name, DIM_BASELINE_USER, &digest_static);
	if (ret < 0) /* 2.1. if not find, log the dynamic baseline */
		return measure_log_add(m, name, digest, LOG_NO_SATIC_BASELINE);

	/* 2.2. if find, compare with the static baseline */
	if (static_baseline_match(m, name, DIM_BASELINE_USER, digest))
		return measure_log_add(m, name, digest, LOG_STATIC_BASELINE);

	dim_warn("mismatch static baseline of user process %s\n", name);
	if (log_flag != NULL) // TODO
		*log_flag = LOG_TAMPERED;

	return measure_log_add(m, name, digest, LOG_TAMPERED);
}

/* process static measurement result in measure stage */
static int process_static_measure(struct dim_measure *m, const char *name,
				  struct dim_digest *digest, int *log_flag)
{
	if(!dynamic_baseline_match(m, name, DIM_BASELINE_USER, digest)) {
		dim_err("mismatch dynamic baseline of user %s\n", name);
		if (log_flag != NULL) // TODO
			*log_flag = LOG_TAMPERED;

		return measure_log_add(m, name, digest, LOG_TAMPERED);
	}

	return 0;
}

int dim_measure_process_static_result(struct dim_measure *m, int mode,
				      const char *name,
				      struct dim_digest *digest,
				      int *log_flag)
{
	if (m == NULL || name == NULL || digest == NULL ||
	    !is_valid_mode(mode))
		return -EINVAL;

	return mode == DIM_BASELINE ?
		process_static_baseline(m, name, digest, log_flag) :
		process_static_measure(m, name, digest, log_flag);
}

int dim_measure_process_dynamic_result(struct dim_measure *m, int mode,
				       const char *name,
				       struct dim_digest *digest,
				       int *log_flag)
{
	if (m == NULL || name == NULL || digest == NULL ||
	    !is_valid_mode(mode))
		return -EINVAL;

	return mode == DIM_BASELINE ?
		process_dynamic_baseline(m, name, digest, log_flag) :
		process_dynamic_measure(m, name, digest, log_flag);
}

int dim_measure_static_baseline_add(struct dim_measure *m,
				    const char *name, int type,
				    struct dim_digest *digest)
{
	if (m == NULL)
		return -EINVAL;

	return static_baseline_add(m, name, type, digest);
}

int dim_measure_dynamic_baseline_search(struct dim_measure *m,
					const char *name, int type,
					struct dim_digest *digest)
{
	if (m == NULL)
		return -EINVAL;

	return dynamic_baseline_search(m, name, type, digest);
}
