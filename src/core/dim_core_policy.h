/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_POLICY_H
#define __DIM_CORE_POLICY_H

#include <linux/rbtree.h>

#define DIM_POLICY_PATH "/etc/dim/policy"
#define DIM_POLICY_LINE_MAX 10000

/* policy key */
#define DIM_POLICY_MEASURE "measure"

/* DIM_POLICY_OBJECT */
enum dim_policy_obj {
	DIM_POLICY_OBJ_BPRM_TEXT,
	DIM_POLICY_OBJ_MODULE_TEXT,
	DIM_POLICY_OBJ_KERNEL_TEXT,
	DIM_POLICY_OBJ_LAST,
};

/* DIM_POLICY_KEY */
enum dim_policy_key {
	DIM_POLICY_KEY_NAME,
	DIM_POLICY_KEY_PATH,
	DIM_POLICY_KEY_LAST,
};

 /* measure obj=MODULE_TEXT path={PATH_MAX}\n*/
 #define DIM_POLICY_OBJ_MAX_LEN 15
 #define DIM_POLICY_KEY_MAX_LEN 5
 #define DIM_POLICY_MAX_LEN (strlen(DIM_POLICY_MEASURE) + 1 + \
			     DIM_POLICY_OBJ_MAX_LEN + 1 + \
			     DIM_POLICY_KEY_MAX_LEN + 1 + PATH_MAX + 1 + 1)

struct dim_policy {
	struct rb_node rb_node;
	int obj; /* enum dim_policy_obj */
	int key; /* enum dim_policy_key */
	const char *val;
	int action; /* enum dim_policy_action */
};

/* funtion to walk dim policy nodes */
typedef int (*dim_policy_visitor)(struct dim_policy *, void *);

enum dim_policy_action {
	DIM_POLICY_LOG,
	DIM_POLICY_KILL,
	DIM_POLICY_LAST,
};

int dim_core_policy_load(void);
void dim_core_policy_destroy(void);
bool dim_core_policy_match(int obj, int key, const char *val);
int dim_core_policy_walk(dim_policy_visitor f, void *data);
int dim_core_policy_get_action(int obj __always_unused,
			       int key __always_unused,
			       const char *val __always_unused);

#endif
