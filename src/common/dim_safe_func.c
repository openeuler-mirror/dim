/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_safe_func.h"

#ifdef DIM_DEBUG_MEMORY_LEAK
atomic_t dim_alloc_num = ATOMIC_INIT(0);;

void dim_check_memory_leak(void)
{
	unsigned int n = atomic_read(&dim_alloc_num);
	if (n != 0)
		dim_warn("warning: detect %u memory leakage\n", n);
	else
		dim_info("not detect memory leakage\n");
}
#endif