/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_MEASURE_H
#define __DIM_CORE_MEASURE_H

#include "dim_measure.h"

/* default configuration */
#define DIM_CORE_HASH_DEFAULT "sha256"
#define DIM_CORE_LOG_CAP_DEFAULT 100000

/* max measure interval = 1 year */
#define DIM_INTERVAL_MAX (365 * 24 * 60)
#define DIM_MINUTE_TO_SEC (60UL)
#define DIM_MINUTE_TO_NSEC (60UL * 1000 * 1000 * 1000)

extern bool dim_core_measure_action_enabled;
extern struct dim_measure dim_core_handle;

/* global init and destroy */
int dim_core_measure_init(struct dim_measure_cfg *cfg, unsigned int interval);
void dim_core_measure_destroy(void);

/* control function for measurement parameters */
const char *dim_core_status_print(void);
long dim_core_interval_get(void);
int dim_core_interval_set(unsigned int p);
long dim_core_tampered_action_get(void);
int dim_core_tampered_action_set(unsigned int p);

/* measurement trigger functions */
int dim_core_measure_blocking(void);
int dim_core_baseline_blocking(void);

#endif
