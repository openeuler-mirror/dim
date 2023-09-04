/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_STATUS_H
#define __DIM_CORE_STATUS_H

enum dim_core_status {
	DIM_OFF,
	DIM_NO_BASELINE,
	DIM_BASELINE_RUNNING,
	DIM_MEASURE_RUNNING,
	DIM_PROTECTED,
	DIM_ERROR,
	DIM_STATUS_LAST,
};

extern struct dim_status dim_core_status;

int dim_core_status_init(void);
void dim_core_status_set(unsigned int status);
int dim_core_status_get(void);

#endif
