/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_STATIC_BASELINE_H
#define __DIM_CORE_STATIC_BASELINE_H

#include "dim_measure.h"

#define DIM_STATIC_BASELINE_ROOT "/etc/dim/digest_list"
#define DIM_STATIC_BASELINE_LINE_MAX 10000

#define DIM_STATIC_BASELINE_PREFIX "dim"
/* dim KERNEL sha256:{digest} {PATH_MAX}\n*/
#define DIM_STATIC_BASELINE_LEN_MAX (strlen(DIM_STATIC_BASELINE_PREFIX) + 1 + \
				     NAME_MAX + 1 + NAME_MAX + 1 + \
				     PATH_MAX + 1 + 1)

int dim_core_static_baseline_load(void);

#endif
