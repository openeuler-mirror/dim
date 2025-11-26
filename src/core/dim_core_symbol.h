/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_SYMBOL_H
#define __DIM_CORE_SYMBOL_H

#include <linux/jump_label.h>
#include <linux/sched/signal.h>
#include <linux/version.h>

typedef void (*DIM_JUMP_LABEL_LOCK)(void);
typedef void (*DIM_JUMP_LABEL_UNLOCK)(void);
typedef void (*DIM_WALK_PROCESS_TREE)(struct task_struct *,
				      proc_visitor, void *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
typedef struct module *(*DIM_FIND_MODULE)(const char *);
typedef struct task_struct *(*DIM_FIND_GET_TASK_BY_VPID)(pid_t);
#endif

#ifdef CONFIG_JUMP_LABEL
 #ifndef JUMP_LABEL_NOP_SIZE
typedef int (*DIM_ARCH_JUMP_ENTRY_SIZE)(struct jump_entry *);
 #endif
#endif

struct dim_core_kallsyms {
	char *stext;
	char *etext;
#ifdef CONFIG_JUMP_LABEL
	struct jump_entry *start_jump_table;
	struct jump_entry *stop_jump_table;
	DIM_JUMP_LABEL_LOCK jump_label_lock;
	DIM_JUMP_LABEL_LOCK jump_label_unlock;
 #ifndef JUMP_LABEL_NOP_SIZE
	DIM_ARCH_JUMP_ENTRY_SIZE arch_jump_entry_size;
 #endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
 #ifdef CONFIG_MODULES
	DIM_FIND_MODULE find_module;
 #endif
	DIM_FIND_GET_TASK_BY_VPID find_get_task_by_vpid;
#endif
	DIM_WALK_PROCESS_TREE walk_process_tree;
};

extern struct dim_core_kallsyms dim_core_kernel_symbol;

int dim_core_kallsyms_init(void);

#endif
