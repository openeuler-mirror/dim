/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_BASELINE_H
#define __DIM_CORE_BASELINE_H

#include "dim_hash.h"

int dim_core_baseline_init(void);
void dim_core_baseline_destroy(void);
int dim_core_add_static_baseline(const char *name, int type,
				 struct dim_digest *digest);
int dim_core_add_dynamic_baseline(const char *name, int type,
				  struct dim_digest *digest);
bool dim_core_match_static_baseline(const char *name, int type,
				    struct dim_digest *digest);
bool dim_core_match_dynamic_baseline(const char *name, int type,
				    struct dim_digest *digest);
int dim_core_search_static_baseline(const char *name, int type,
				     struct dim_digest *digest);
int dim_core_search_dynamic_baseline(const char *name, int type,
				     struct dim_digest *digest);

#endif
