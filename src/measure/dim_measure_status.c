/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_measure.h"

static const char* status_name[MEASURE_STATUS_LAST + 1] = {
	[MEASURE_STATUS_OFF] = "DIM_OFF",
	[MEASURE_STATUS_NO_BASELINE] = "DIM_NO_BASELINE",
	[MEASURE_STATUS_BASELINE_RUNNING] = "DIM_BASELINE_RUNNING",
	[MEASURE_STATUS_MEASURE_RUNNING] = "DIM_MEASURE_RUNNING",
	[MEASURE_STATUS_PROTECTED] = "DIM_PROTECTED",
	[MEASURE_STATUS_ERROR] = "DIM_ERROR",
	[MEASURE_STATUS_LAST] = "DIM_UNKNOWN",
};

const char *dim_measure_status_print(struct dim_measure *m)
{
	int status = 0;
        
        if (m == NULL)
                return status_name[MEASURE_STATUS_LAST];

        status = atomic_read(&m->status);
	if (status < 0 || status >= MEASURE_STATUS_LAST)
		status = MEASURE_STATUS_LAST;

	return status_name[status];
}

bool dim_measure_status_error(struct dim_measure *m)
{
	return atomic_read(&m->status) == MEASURE_STATUS_ERROR;
}
