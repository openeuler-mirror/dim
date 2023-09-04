/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_UTILS_H
#define __DIM_UTILS_H

#include <linux/module.h>
#include <linux/path.h>

#define DIM_ARRAY_LEN(ARR) (sizeof(ARR) / sizeof(ARR[0]))

#define dim_fmt(fmt) DIM_MODULE ": " fmt

#define dim_err(fmt, ...) pr_err(dim_fmt(fmt), ##__VA_ARGS__)
#define dim_warn(fmt, ...) pr_warn(dim_fmt(fmt), ##__VA_ARGS__)
#define dim_info(fmt, ...) pr_info(dim_fmt(fmt), ##__VA_ARGS__)
#define dim_devel(fmt, ...)

void *dim_kmalloc_gfp(size_t size);
void dim_kfree(void *data);
const char *dim_absolute_path(const char *path, char *buf, int len);
bool dim_string_end_with(const char *str, const char *ext);
int dim_parse_line_buf(char *buf, loff_t len, int (*line_parser)(char *, int));

#endif