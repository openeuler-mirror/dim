/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/namei.h>
#include <linux/utsname.h>

#include "dim_rb.h"
#include "dim_utils.h"
#include "dim_safe_func.h"

#include "dim_core_sig.h"
#include "dim_core_policy.h"

static struct rb_root policy_root = RB_ROOT;

static int dim_policy_compare(struct dim_policy *x, struct dim_policy *y)
{
	if (x->obj != y->obj)
		return x->obj - y->obj;

	switch (x->obj) {
	case DIM_POLICY_OBJ_BPRM_TEXT:
		return dim_strcmp(x->path, y->path);
	case DIM_POLICY_OBJ_MODULE_TEXT:
		return dim_strcmp(x->name, y->name);
	case DIM_POLICY_OBJ_KERNEL_TEXT:
		return 0;
	default:
		break;
	}

	return -1;
}

/*
static int dim_policy_rb_find(struct rb_root *root,
			      struct dim_policy *data,
			      struct dim_policy **find_data)
*/
dim_rb_find(dim_policy);
/*
static int dim_policy_rb_add(struct rb_root *root,
			     struct dim_policy *data,
			     struct dim_policy **find_data)
*/
dim_rb_add(dim_policy);

void policy_destroy(struct dim_policy *policy)
{
	if (policy == NULL)
		return;

	dim_kfree(policy->name);
	dim_kfree(policy->path);
	dim_kfree(policy);
}

static int policy_check_add_bprm_text(struct dim_policy *policy)
{
	int ret = 0;
	const char *apath = NULL;
	struct dim_policy *p = NULL;

	/* check the policy is valid */
	if (policy->path == NULL) {
		dim_err("path must be set for BPRM_TEXT policy\n");
		return -EINVAL;
	}

	if (strlen(policy->path) + 1 > PATH_MAX) {
		dim_err("path must be shorter than %d\n", PATH_MAX);
		return -ENAMETOOLONG;
	}

	if (policy->name != NULL)
		dim_warn("name is ignored for BPRM_TEXT policy\n");

	/* firstly, add the current node */
	ret = dim_policy_rb_add(&policy_root, policy, NULL);
	if (ret < 0)
		return ret;

	/* secondly, try to add another node with absolute path. beacuse
	   sometimes users may not sure whether to write /usr/bin/bash
	   or /bin/bash in policy */
	ret = dim_get_absolute_path(policy->path, &apath);
	if (ret < 0) {
		dim_warn("failed to get absolute path of %s in policy: %d\n",
			 policy->path, ret);
		return 0;
	}

	if (dim_strcmp(apath, policy->path) == 0) {
		/* the two paths are same, no need to add another policy */
		dim_kfree(apath);
		return 0;
	}

	p = dim_kmemdup_gfp(policy, sizeof(struct dim_policy));
	if (p == NULL) {
		dim_kfree(apath);
		return -ENOMEM;
	}

	/* set the absolute path and add the policy node */
	p->path = apath;
	ret = dim_policy_rb_add(&policy_root, p, NULL);
	if (ret < 0)
		policy_destroy(p);

	/* the EEXIST error must be processed here */
	return ret == -EEXIST ? 0 : ret;
}

static int policy_check_add_module_text(struct dim_policy *policy)
{
	if (policy->name == NULL) {
		dim_err("name must be set for MODULE_TEXT policy\n");
		return -EINVAL;
	}

	if (strlen(policy->name) + 1 > NAME_MAX) {
		dim_err("name must be shorter than %d\n", NAME_MAX);
		return -ENAMETOOLONG;
	}

	if (policy->path != NULL)
		dim_warn("path is ignored for BPRM_TEXT policy\n");

	if (policy->action != DIM_POLICY_ACTION_LOG)
		dim_warn("action is ignored for MODULE_TEXT policy\n");

	return dim_policy_rb_add(&policy_root, policy, NULL);
}

static int policy_check_add_kernel_text(struct dim_policy *policy)
{
	if (policy->name != NULL || policy->path != NULL ||
	    policy->action != DIM_POLICY_ACTION_LOG)
		dim_warn("all parameters are ignored for KERNEL_TEXT policy\n");

	return dim_policy_rb_add(&policy_root, policy, NULL);
}

static int policy_check_add(struct dim_policy *policy)
{
	switch (policy->obj)
	{
	case DIM_POLICY_OBJ_BPRM_TEXT:
		return policy_check_add_bprm_text(policy);
	case DIM_POLICY_OBJ_MODULE_TEXT:
		return policy_check_add_module_text(policy); 
	case DIM_POLICY_OBJ_KERNEL_TEXT:
		return policy_check_add_kernel_text(policy); 
	default:
		break;
	}

	return -EINVAL;
}

int dim_core_policy_load(void)
{
	int ret = 0;
	void *buf = NULL;
	loff_t buf_len = 0;

	if (!RB_EMPTY_ROOT(&policy_root))
		dim_core_policy_destroy();

	ret = dim_read_verify_file(NULL, DIM_POLICY_PATH, &buf);
	if (ret < 0 || buf == NULL) {
		dim_err("failed to read policy file: %d\n", ret);
		return ret;
	}

	buf_len = ret;
	ret = dim_policy_parse(buf, buf_len, policy_check_add);
	if (ret < 0) {
		dim_err("failed to parse policy: %d\n", ret);
		dim_core_policy_destroy();
	}

	dim_vfree(buf);
	return ret;
}

void dim_core_policy_destroy(void)
{
	struct dim_policy *pos = NULL;
	struct dim_policy *n = NULL;

	rbtree_postorder_for_each_entry_safe(pos, n, &policy_root, rb_node)
		policy_destroy(pos);

	policy_root = RB_ROOT;
}

static int policy_find(int obj, int key __always_unused, const char *val,
			 struct dim_policy **find)
{
	struct dim_policy policy = { 0 };

	/* now the key parameter is unused */
	switch (obj) {
	case DIM_POLICY_OBJ_BPRM_TEXT:
		policy.path = val;
		break;
	case DIM_POLICY_OBJ_MODULE_TEXT:
		policy.name = val;
		break;
	case DIM_POLICY_OBJ_KERNEL_TEXT:
		break;
	default:
		return -EINVAL;
	}

	policy.obj = obj;
	return dim_policy_rb_find(&policy_root, &policy, find);
}

bool dim_core_policy_match(int obj, int key, const char *val)
{
	if (val == NULL)
		return false;

	return policy_find(obj, key, val, NULL) == 0;
}

int dim_core_policy_get_action(int obj, int key, const char *val)
{
	int ret = 0;
	struct dim_policy *find = NULL;

	if (val == NULL)
		return DIM_POLICY_ACTION_LAST;

	ret = policy_find(obj, key, val, &find);
	if (ret < 0)
		return DIM_POLICY_ACTION_LAST;

	return find->action;
}

int dim_core_policy_walk(int (*f)(struct dim_policy *, void *), void *data)
{
	int ret = 0;
	struct dim_policy *pos = NULL;
	struct dim_policy *n = NULL;

	rbtree_postorder_for_each_entry_safe(pos, n, &policy_root, rb_node) {
		ret = f(pos, data);
		if (ret < 0)
			return ret;
	}

	return 0;
}
