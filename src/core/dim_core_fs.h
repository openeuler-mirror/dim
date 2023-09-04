/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_FS_H
#define __DIM_CORE_FS_H

#include "dim_entry.h"

void dim_core_destroy_fs(void);
int dim_core_create_fs(void);
struct dim_entry *dim_root_entry(void);

#endif
