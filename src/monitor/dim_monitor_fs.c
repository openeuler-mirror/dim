/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/module.h>

#include "dim_entry.h"
#include "dim_utils.h"

#include "dim_measure.h"

#include "dim_monitor.h"

extern struct dim_entry *dim_root_entry(void);

/*
 * monitor trigger interface
 * dim_entry struct: dim_monitor_measure_entry
 * file entry name: monitor_run
 * function: dim_monitor_measure_blocking()
 */
dim_trigger_entry(dim_monitor_measure, monitor_run, dim_monitor_measure_blocking);

/*
 * monitor baseline trigger interface
 * dim_entry struct: dim_monitor_baseline_entry
 * file entry name: monitor_baseline
 * function: dim_monitor_baseline_blocking()
 */
dim_trigger_entry(dim_monitor_baseline, monitor_baseline, dim_monitor_baseline_blocking);

/*
 * status print interface
 * dim_entry struct: dim_status_entry
 * file entry name: monitor_status
 * print function: dim_core_status_print
 */
dim_string_print_entry(dim_monitor_status, monitor_status, dim_monitor_status_print);

/*
 * measure log read interface
 * dim_entry struct: dim_measure_log_entry
 * file entry name: runtime_status
 * status to read: dim_measure_log_tree
 */
dim_measure_log_entry(dim_monitor_log, monitor_ascii_runtime_measurements,
		      &dim_monitor_handle.log);

static struct dim_entry *dim_monitor_files[] = {
	&dim_monitor_measure_entry,
	&dim_monitor_baseline_entry,
	&dim_monitor_status_entry,
	&dim_monitor_log_entry,
};

void dim_monitor_destroy_fs(void)
{
	unsigned int len = DIM_ARRAY_LEN(dim_monitor_files);
	dim_entry_remove_list(dim_monitor_files, len);
}

int dim_monitor_create_fs(void)
{
	struct dim_entry *dim_root = dim_root_entry();
	unsigned int len = DIM_ARRAY_LEN(dim_monitor_files);

	if (dim_root == NULL || dim_root->dentry == NULL)
		return -ENOENT;

	return dim_entry_create_list(dim_monitor_files, len, dim_root->dentry);
}
