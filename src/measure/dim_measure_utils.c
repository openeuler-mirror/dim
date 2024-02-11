/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_measure.h"

void dim_measure_schedule(struct dim_measure *m)
{
	if (m == NULL || m->schedule_jiffies == 0)
		return;

	schedule_timeout_uninterruptible(m->schedule_jiffies);
}
