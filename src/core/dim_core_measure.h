/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_MEASURE_H
#define __DIM_CORE_MEASURE_H

#include "dim_hash.h"

/* max measure interval = 1 year */
#define DIM_INTERVAL_MAX (365 * 24 * 60)
#define DIM_MINUTE_TO_SEC (60UL)
#define DIM_MINUTE_TO_NSEC (60UL * 1000 * 1000 * 1000)
/* max number of kill tasks */
#define DIM_KILL_TASKS_MAX (1024)
/* limit of measure parameter */
#define MEASURE_LOG_CAP_MAX (UINT_MAX)
#define MEASURE_LOG_CAP_MIN (100)
#define MEASURE_SCHEDULE_MAX (1000)

struct vm_text_area {
	struct mm_struct *mm;
	struct vm_area_struct *vma_start;
	struct vm_area_struct *vma_end;
};

struct task_measure_ctx {
	int baseline; /* measure or baseline init */
	char path_buf[PATH_MAX];
	const char *path;
	struct task_struct *task; /* current measured task */
	bool task_kill;
	bool task_measure;
};

struct task_kill_ctx {
	struct task_struct **buf;
	int len;
	int size;
	int ret;
};

typedef int (*task_measurer)(struct task_struct *, struct task_measure_ctx *);

extern struct dim_hash dim_core_hash;
extern struct dim_measure_log_tree dim_core_log;
extern struct dim_tpm dim_core_tpm;
extern unsigned int measure_log_capacity;
extern unsigned int measure_schedule;
extern unsigned int measure_interval;
extern unsigned int measure_pcr;
extern unsigned long measure_schedule_jiffies;

int dim_core_measure_init(const char *alg_name);
void dim_core_destroy_measure(void);
int dim_core_measure(int baseline_init);
long dim_core_interval_get(void);
int dim_core_interval_set(unsigned int p);
long dim_core_tampered_action_get(void);
int dim_core_tampered_action_set(unsigned int p);

int dim_core_measure_kernel(int baseline_init);
int dim_core_measure_module(int baseline_init);
int dim_core_measure_task(int baseline_init);

int dim_core_add_measure_log(const char *name,
			     struct dim_digest *digest,
			     int flag);
int dim_core_check_kernel_digest(int baseline_init,
				 const char *name,
				 struct dim_digest *digest);
int dim_core_check_user_digest(int baseline_init,
			       const char *name,
			       struct dim_digest *digest,
			       int *log_flag);

#endif
