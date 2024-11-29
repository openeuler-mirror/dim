/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */
 
#include <linux/kallsyms.h>
#include <linux/jump_label.h>

#include "dim_symbol.h"
#include "dim_utils.h"

#include "dim_core_symbol.h"

struct dim_core_kallsyms dim_core_kernel_symbol;

int dim_core_kallsyms_init(void)
{
	struct dim_core_kallsyms *k = &dim_core_kernel_symbol;
	DIM_SYMBOL_LOOKUP_FUNC dim_kallsyms_lookup_name = NULL;

	if (memset(k, 0,
	    sizeof(struct dim_core_kallsyms)) != k)
		return -EINVAL;

	dim_kallsyms_lookup_name = dim_get_symbol_lookup_func();
	if (dim_kallsyms_lookup_name  == NULL) {
		dim_err("failed to get symbol_lookup_func\n");
		return -EINVAL;
	}
	k->stext = (char *)dim_kallsyms_lookup_name("_stext");
	k->etext = (char *)dim_kallsyms_lookup_name("_etext");

	k->start_jump_table = (struct jump_entry *)
		dim_kallsyms_lookup_name("__start___jump_table");
	k->stop_jump_table = (struct jump_entry *)
		dim_kallsyms_lookup_name("__stop___jump_table");
	k->jump_label_lock = (DIM_JUMP_LABEL_LOCK)
		dim_kallsyms_lookup_name("jump_label_lock");
	k->jump_label_unlock = (DIM_JUMP_LABEL_UNLOCK)
		dim_kallsyms_lookup_name("jump_label_unlock");
	k->walk_process_tree = (DIM_WALK_PROCESS_TREE)
		dim_kallsyms_lookup_name("walk_process_tree");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	k->find_module = (DIM_FIND_MODULE)
		dim_kallsyms_lookup_name("find_module");
	k->find_get_task_by_vpid = (DIM_FIND_GET_TASK_BY_VPID)
		dim_kallsyms_lookup_name("find_get_task_by_vpid");
#endif

	return (k->stext == NULL || k->etext == NULL ||
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
		k->find_module == NULL || k->find_get_task_by_vpid == NULL ||
#endif
		k->start_jump_table == NULL || k->stop_jump_table == NULL ||
		k->jump_label_lock == NULL || k->jump_label_unlock == NULL ||
		k->walk_process_tree == NULL) ? -ENOENT : 0;
}
