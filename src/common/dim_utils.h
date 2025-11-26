/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_UTILS_H
#define __DIM_UTILS_H

#include <linux/module.h>
#include <linux/path.h>

#define DIM_ARRAY_LEN(ARR) (sizeof(ARR) / sizeof(ARR[0]))
#define DIM_MAX_FILE_SIZE (10 * 1024 * 1024)

#define DIM_KERNEL "dim_kernel"

#ifdef CONFIG_MODULES
#define DIM_FMT_FLAG (THIS_MODULE->name)
#else
#define DIM_FMT_FLAG DIM_KERNEL
#endif

#define dim_fmt(fmt) "%s: " fmt
#define dim_err(fmt, ...) pr_err(dim_fmt(fmt), DIM_FMT_FLAG, ##__VA_ARGS__)
#define dim_warn(fmt, ...) pr_warn(dim_fmt(fmt), DIM_FMT_FLAG, ##__VA_ARGS__)
#define dim_info(fmt, ...) pr_info(dim_fmt(fmt), DIM_FMT_FLAG, ##__VA_ARGS__)
#define dim_devel(fmt, ...)

int dim_get_absolute_path(const char *path, const char **result);
int dim_parse_line_buf(char *buf, loff_t len, int (*line_parser)(char *, int, void *), void *data);
int dim_read_file(struct path *root, const char *name, void **buf);

#endif
