/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_MEASURE_H
#define __DIM_MEASURE_H

#include <linux/list.h>
#include <linux/mutex.h>

#include "dim_baseline.h"
#include "dim_hash.h"
#include "dim_measure_log.h"
#include "dim_tpm.h"
#include "dim_utils.h"

#define DIM_MEASURE 0
#define DIM_BASELINE 1

/* limit of measure parameter */
#define MEASURE_LOG_CAP_MAX (UINT_MAX)
#define MEASURE_LOG_CAP_MIN (100)
#define MEASURE_SCHEDULE_MAX (1000)

/* status of measurement */
enum dim_measure_status {
	MEASURE_STATUS_OFF,
	MEASURE_STATUS_NO_BASELINE,
	MEASURE_STATUS_BASELINE_RUNNING,
	MEASURE_STATUS_MEASURE_RUNNING,
	MEASURE_STATUS_PROTECTED,
	MEASURE_STATUS_ERROR,
	MEASURE_STATUS_LAST,
};

/* the common configuration for measurement */
struct dim_measure_cfg {
	/* hash algorithm for measurement */
	char *alg_name;
	/* schedule time (ms) after one valid measurement */
	unsigned int schedule_ms;
	/* PCR number for TPM extending */
	unsigned int pcr;
	/* max measure log number */
	unsigned int log_cap;
	/* memory function for baseline store */
	malloc_func dyn_malloc;
	free_func dyn_free;
	malloc_func sta_malloc;
	free_func sta_free;
};

/* the dim measurement global handle */
struct dim_measure {
	/* schedule time (jittfies) after one valid measurement */
	unsigned long schedule_jiffies;
	/* lock to prevent concurrent measurement */
	struct mutex measure_lock;
	/* measure hash algorithm */
	struct dim_hash hash;
	/* TPM chip handle */
	struct dim_tpm tpm;
	/* measure log */
	struct dim_measure_log_tree log;
	/* measure baseline */
	struct dim_baseline_tree static_baseline;
	struct dim_baseline_tree dynamic_baseline;
	/* function called before doing baseline */
	int (*baseline_prepare)(struct dim_measure *m);
	/* measure status */
	atomic_t status;
	/* task list */
	struct list_head task_list;
};

/* the task definition for measurement function */
struct dim_measure_task {
	struct list_head node;
	/* task name for log printing */
	const char *name;
	/* measure function */
	int (*measure)(int mode, struct dim_measure *m);
};

/* functions for dim measure handle */
int dim_measure_init(struct dim_measure *m, struct dim_measure_cfg *cfg);
void dim_measure_destroy(struct dim_measure *m);

/* functions for measurement results processing */
int dim_measure_process_static_result(struct dim_measure *m, int mode,
				      const char *name,
				      struct dim_digest *digest,
				      int *log_flag);
int dim_measure_process_dynamic_result(struct dim_measure *m, int mode,
				       const char *name,
				       struct dim_digest *digest,
				       int *log_flag);
int dim_measure_static_baseline_add(struct dim_measure *m,
				    const char *name, int type,
				    struct dim_digest *digest);
int dim_measure_dynamic_baseline_search(struct dim_measure *m,
					const char *name, int type,
					struct dim_digest *digest);
/* functions for dim measurement task */
int dim_measure_tasks_register(struct dim_measure *m,
			       struct dim_measure_task **tasks,
			       unsigned int num);
void dim_measure_task_measure(int mode, struct dim_measure *m);

/* functions for dim measurement status */
const char *dim_measure_status_print(struct dim_measure *m);
bool dim_measure_status_error(struct dim_measure *m);

/* tool functions used for implementing measure tasks */
void dim_measure_schedule(struct dim_measure *m);

#endif
