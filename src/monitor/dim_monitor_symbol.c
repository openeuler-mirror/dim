/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */
 
#include <linux/kallsyms.h>

#include "dim_symbol.h"

#include "dim_monitor.h"
#include "dim_monitor_symbol.h"

struct dim_monitor_kallsyms dim_monitor_kernel_symbol;

int dim_monitor_kallsyms_init(void)
{
	struct dim_monitor_kallsyms *k = &dim_monitor_kernel_symbol;
	DIM_SYMBOL_LOOKUP_FUNC dim_kallsyms_lookup_name = NULL;

	dim_kallsyms_lookup_name = dim_get_symbol_lookup_func();
	if (dim_kallsyms_lookup_name  == NULL) {
		dim_err("fail to get symbol_lookup_func\n");
		return -EINVAL;
	}

	memset(k, 0, sizeof(struct dim_monitor_kallsyms));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	k->find_module = (DIM_FIND_MODULE)
		dim_kallsyms_lookup_name("find_module");
	return k->find_module == NULL ? -ENOENT : 0;
#else
	return 0;
#endif
}