/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_SYMBOL_H
#define __DIM_SYMBOL_H

#define DIM_KALLSYMS_LOOKUP_NAME "kallsyms_lookup_name"
#define DIM_TRY_COUNT 100

typedef void* (*DIM_SYMBOL_LOOKUP_FUNC)(const char *);

DIM_SYMBOL_LOOKUP_FUNC dim_get_symbol_lookup_func(void);

#endif