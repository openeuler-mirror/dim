/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_status.h"

#include "dim_core.h"
#include "dim_core_status.h"

static const char* dim_core_status_name[DIM_STATUS_LAST] = {
	[DIM_OFF] = "DIM_OFF",
	[DIM_NO_BASELINE] = "DIM_NO_BASELINE",
	[DIM_BASELINE_RUNNING] = "DIM_BASELINE_RUNNING",
	[DIM_MEASURE_RUNNING] = "DIM_MEASURE_RUNNING",
	[DIM_PROTECTED] = "DIM_PROTECTED",
	[DIM_ERROR] = "DIM_ERROR",
};

struct dim_status dim_core_status = { 0 };

int dim_core_status_init(void)
{
	int ret = 0;

	ret = dim_status_init(&dim_core_status, dim_core_status_name,
			      DIM_STATUS_LAST);
	if (ret < 0)
		return ret;

	dim_status_set(&dim_core_status, DIM_NO_BASELINE);
	return 0;
}

void dim_core_status_set(unsigned int status)
{
	dim_status_set(&dim_core_status, status);
}

int dim_core_status_get(void)
{
	return dim_status_get(&dim_core_status);
}
