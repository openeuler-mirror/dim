/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/err.h>

#include "dim_status.h"

int dim_status_init(struct dim_status *status,
		    const char **table,
		    unsigned int len)
{
	if (status == NULL || table == NULL || len == 0)
		return -EINVAL;

	status->table = table;
	status->table_len = len;
	atomic_set(&status->status_cur, 0);
	return 0;
}

int dim_status_get(struct dim_status *status)
{
	return status == NULL ? 0 : atomic_read(&status->status_cur);
}

const char *dim_status_get_name(struct dim_status *status)
{
	return status == NULL ? NULL :
		status->table[atomic_read(&status->status_cur)];
}

void dim_status_set(struct dim_status *status, unsigned int s)
{
	if (status == NULL || s >= status->table_len)
		return;

	atomic_set(&status->status_cur, s);
}