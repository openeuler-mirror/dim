/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/module.h>

#include "dim_utils.h"

#include "dim_core_measure.h"
#include "dim_core_fs.h"

/*
 * measure trigger interface
 * dim_entry struct: dim_measure_entry
 * file entry name: measure
 * function: dim_core_measure_blocking()
 */
dim_trigger_entry(dim_measure, measure, dim_core_measure_blocking);

/*
 * baseline_init trigger interface
 * dim_entry struct: dim_baseline_init_entry
 * file entry name: baseline_init
 * function: dim_core_baseline_blocking(0)
 */
dim_trigger_entry(dim_baseline_init, baseline_init,
		  dim_core_baseline_blocking);

/*
 * measure log read interface
 * dim_entry struct: dim_measure_log_entry
 * file entry name: runtime_status
 * status to read: dim_measure_log_tree
 */
dim_measure_log_entry(dim_measure_log, ascii_runtime_measurements,
		      &dim_core_handle.log);

/*
 * status print interface
 * dim_entry struct: dim_status_entry
 * file entry name: runtime_status
 * print function: dim_core_status_print
 */
dim_string_print_entry(dim_status, runtime_status, dim_core_status_print);

/*
 * measure interval set and read interface
 * dim_entry struct: dim_interval_entry
 * file entry name: interval
 * read function: dim_core_interval_get
 * write function: dim_core_interval_set
 */
dim_uint_rw_entry(dim_interval, interval, dim_core_interval_get,
		  dim_core_interval_set);

#ifdef DIM_CORE_TAMPERED_ACTION
/*
 * tampered action set and read interface
 * dim_entry struct: dim_tampered_action_entry
 * file entry name: tampered_action
 * read function: dim_core_tampered_action_get
 * write function: dim_core_tampered_action_set
 */
dim_uint_rw_entry(dim_tampered_action, tampered_action,
		  dim_core_tampered_action_get, dim_core_tampered_action_set);
#endif

/*
 * dim directory
 */
static struct dim_entry dim_core_dir = {
	.name = "dim",
	.mode = DIM_ENTRY_DIR_MASK,
	.fops = NULL,
	.dentry = NULL,
};

static struct dim_entry *dim_core_files[] = {
	&dim_measure_entry,
	&dim_baseline_init_entry,
	&dim_measure_log_entry,
	&dim_status_entry,
	&dim_interval_entry,
#ifdef DIM_CORE_TAMPERED_ACTION
	&dim_tampered_action_entry,
#endif
};

void dim_core_destroy_fs(void)
{
	unsigned int len = DIM_ARRAY_LEN(dim_core_files);
	dim_entry_remove_list(dim_core_files, len);
	dim_entry_remove(&dim_core_dir);
}

int dim_core_create_fs(void)
{
	int ret = 0;
	unsigned int len = DIM_ARRAY_LEN(dim_core_files);

	ret = dim_entry_create(&dim_core_dir, NULL);
	if (ret < 0) {
		dim_err("failed to create dim dir entry: %d\n", ret);
		return ret;
	}

	ret = dim_entry_create_list(dim_core_files, len, dim_core_dir.dentry);
	if (ret < 0)
		dim_entry_remove(&dim_core_dir);

	return ret;
}

struct dim_entry *dim_root_entry(void)
{
	return &dim_core_dir;
}
EXPORT_SYMBOL_GPL(dim_root_entry);
