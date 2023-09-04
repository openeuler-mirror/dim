/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_MONITOR_SYMBOL_H
#define __DIM_MONITOR_SYMBOL_H

#include <linux/module.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
typedef struct module *(*DIM_FIND_MODULE)(const char *);
#endif

struct dim_monitor_kallsyms {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	DIM_FIND_MODULE find_module;
#endif
};

extern struct dim_monitor_kallsyms dim_monitor_kernel_symbol;

int dim_monitor_kallsyms_init(void);

#endif
