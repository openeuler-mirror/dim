/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_POLICY_H
#define __DIM_CORE_POLICY_H

#include <linux/rbtree.h>

/* the policy filepath */
#define DIM_POLICY_PATH "/etc/dim/policy"
/* max number of lines for parsing */
#define DIM_POLICY_LINE_MAX 10000

/* measurement object of policy */
enum dim_policy_obj {
	DIM_POLICY_OBJ_BPRM_TEXT,
	DIM_POLICY_OBJ_MODULE_TEXT,
	DIM_POLICY_OBJ_KERNEL_TEXT,
	DIM_POLICY_OBJ_LAST,
};

/* key of measurement condition */
enum dim_policy_key {
	DIM_POLICY_KEY_OBJ,
	DIM_POLICY_KEY_NAME,
	DIM_POLICY_KEY_PATH,
	DIM_POLICY_KEY_ACTION,
	DIM_POLICY_KEY_LAST,
};

/* action to perform when dim detected a tampering  */
enum dim_policy_action {
	/* add to measure log (default) */
	DIM_POLICY_ACTION_LOG,
	/* kill the tampered user process */
	DIM_POLICY_ACTION_KILL,
	DIM_POLICY_ACTION_LAST,
};

struct dim_policy {
	struct rb_node rb_node;
	int obj; /* enum dim_policy_obj */
	const char *path; /* user process path */
	const char *name; /* module name */
	int action; /* enum dim_policy_action */
};

/* callback funtion to walk dim policy nodes */
typedef int (*dim_policy_visitor)(struct dim_policy *, void *);

/* callback funtion to add a policy item when parsing policy file */
typedef int (*policy_add_func)(struct dim_policy *);

/* parse dim policy in complex format */
int policy_parse_complex_format(char *buf, size_t buf_len,
				policy_add_func policy_add);
#define dim_policy_parse policy_parse_complex_format

/* export for implementing the policy parser */
void policy_destroy(struct dim_policy *policy);

int dim_core_policy_load(void);
void dim_core_policy_destroy(void);
bool dim_core_policy_match(int obj, int key, const char *val);
int dim_core_policy_walk(dim_policy_visitor f, void *data);
int dim_core_policy_get_action(int obj, int key, const char *val);

#endif
