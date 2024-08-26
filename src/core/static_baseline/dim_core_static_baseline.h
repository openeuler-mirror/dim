/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_STATIC_BASELINE_H
#define __DIM_CORE_STATIC_BASELINE_H

#include <linux/fs.h>

#include "dim_measure.h"

/* directory to store the static baseline files */
#define DIM_STATIC_BASELINE_ROOT "/etc/dim/digest_list"

/* callback function to check if a baseline is matched the policy */
typedef bool (*baseline_match_func)(const char *name, int type);

/* callback function to add baseline to measurement handle */
typedef int (*baseline_add_func)(const char *name, int type,
				  struct dim_digest *digest,
				  struct dim_measure *m);

/* the context used in directory walking and file parsing */
struct baseline_parse_ctx {
	/* context for directory walking */
	struct dir_context ctx;
	/* entry to store the filenames in directory */
	struct list_head name_list;
	struct dim_measure *m;
	baseline_match_func match;
	baseline_add_func add;
};

/* function implemented to parse the static baseline file in complex format */
int baseline_parse_complex_format(char *buf, size_t buf_len,
				  struct baseline_parse_ctx *ctx);
#define dim_baseline_parse baseline_parse_complex_format

/* build or rebuild the static baseline into the measurement handle */
int dim_core_static_baseline_load(struct dim_measure *m);

#endif
