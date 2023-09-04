/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_STATUS_H
#define __DIM_STATUS_H

#include <linux/atomic.h>

struct dim_status {
	const char **table;
	int table_len;
	atomic_t status_cur;
};

int dim_status_init(struct dim_status *status,
		    const char **table,
		    unsigned int len);
int dim_status_get(struct dim_status *status);
const char *dim_status_get_name(struct dim_status *status);
void dim_status_set(struct dim_status *status, unsigned int s);

#endif