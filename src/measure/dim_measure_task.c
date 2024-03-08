/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_measure.h"

static void call_measure_func(int mode, struct dim_measure_task *t,
			      struct dim_measure *m)
{
	int ret = 0;
	
	if (t->measure == NULL) {
		dim_warn("no measure function in %s task", t->name);
		return;
	}

	dim_info("start to call %s measure task\n", t->name);
	ret = t->measure(mode, m);
	if (ret < 0) {
		dim_err("failed to call measure task %s: %d\n", t->name, ret);
		return;
	}

	dim_info("succeed to call measure task %s\n", t->name);
}

void dim_measure_task_measure(int mode, struct dim_measure *m)
{
	int ret = 0;
	int status = 0;
	struct dim_measure_task *task = NULL;

	if (m == NULL)
		return;

	mutex_lock(&m->measure_lock);
	status = atomic_read(&m->status);
	if (mode == DIM_MEASURE && status != MEASURE_STATUS_PROTECTED) {
		dim_info("no baseline, do baseline init instead\n");
		mode = DIM_BASELINE;
	}

	atomic_set(&m->status, mode == DIM_BASELINE ?
		MEASURE_STATUS_BASELINE_RUNNING :
		MEASURE_STATUS_MEASURE_RUNNING);

	if (mode == DIM_BASELINE && m->baseline_prepare != NULL) {
		ret = m->baseline_prepare(m);
		if (ret < 0) {
			atomic_set(&m->status, MEASURE_STATUS_ERROR);
			mutex_unlock(&m->measure_lock);
			return;
		}
	}

	list_for_each_entry(task, &m->task_list, node)
		call_measure_func(mode, task, m);

	atomic_set(&m->status, MEASURE_STATUS_PROTECTED);
	mutex_unlock(&m->measure_lock);
}

static int task_register(struct dim_measure *m, struct dim_measure_task *t)
{
	int ret = 0;

	if (t == NULL || t->name == NULL || t->measure == NULL)
		return -EINVAL;

	if (t->init != NULL) {
		ret = t->init();
		if (ret < 0)
			return ret;
	}

	list_add_tail(&t->node, &m->task_list);
	return 0;
}

static void task_unregister(struct dim_measure_task *t)
{
	if (t->destroy != NULL)
		t->destroy();

	list_del(&t->node);
}

int dim_measure_tasks_register(struct dim_measure *m,
			       struct dim_measure_task **tasks,
			       unsigned int num)
{
	int ret = 0;
	int i = 0;

	if (m == NULL || tasks == NULL || num == 0)
		return -EINVAL;

	for (; i < num; i++) {
		ret = task_register(m, tasks[i]);
		if (ret < 0) {
			dim_measure_tasks_unregister_all(m);
			return ret;
		}

		dim_info("register measure task: %s\n", tasks[i]->name);
	}

	return 0;
}

void dim_measure_tasks_unregister_all(struct dim_measure *m)
{
	struct dim_measure_task *pos = NULL;
	struct dim_measure_task *n = NULL;

	if (m == NULL)
		return;

	list_for_each_entry_safe(pos, n, &m->task_list, node)
		task_unregister(pos);
}
