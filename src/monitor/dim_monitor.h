/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_MONITOR_H
#define __DIM_MONITOR_H

#include "dim_status.h"
#include "dim_utils.h"

#define DIM_MONITOR_HASH_DEFAULT "sha256"
#define DIM_MODULE "dim_monitor"
#define DIM_CORE "dim_core"
#define DIM_CORE_TEXT "dim_core.text"
#define DIM_CORE_DATA "dim_core.data"

/* limit of measure parameter */
#define MEASURE_LOG_CAP_MAX (UINT_MAX)
#define MEASURE_LOG_CAP_MIN (100)

enum dim_monitor_status {
	DIM_MONITOR_READY,
	DIM_MONITOR_RUNNING,
	DIM_MONITOR_PROTECTED,
	DIM_MONITOR_ERROR,
	DIM_MONITOR_STATUS_LAST,
};

extern struct dim_status dim_monitor_status;
extern struct dim_measure_log_tree dim_monitor_log;
extern unsigned int measure_log_capacity;
extern unsigned int measure_pcr;

void dim_monitor_destroy_fs(void);
int dim_monitor_create_fs(void);

int dim_monitor_measure_init(const char *alg_name);
void dim_monitor_destroy_measure(void);
int dim_monitor_measure(int baseline);

#endif