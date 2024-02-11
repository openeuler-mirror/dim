/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_MONITOR_H
#define __DIM_MONITOR_H

#include "dim_measure.h"

#define DIM_MONITOR_HASH_DEFAULT "sha256"
#define DIM_MONITOR_LOG_CAP_DEFAULT 100000

#define DIM_CORE "dim_core"
#define DIM_CORE_TEXT "dim_core.text"
#define DIM_CORE_DATA "dim_core.data"

extern struct dim_measure dim_monitor_handle;

void dim_monitor_destroy_fs(void);
int dim_monitor_create_fs(void);

int dim_monitor_measure_init(struct dim_measure_cfg *cfg);
void dim_monitor_measure_destroy(void);
int dim_monitor_measure_blocking(void);
int dim_monitor_baseline_blocking(void);
const char *dim_monitor_status_print(void);

#endif
