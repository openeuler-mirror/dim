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

#include "dim_utils.h"
#include "dim_rb.h"

#include "dim_core_sig.h"
#include "dim_core_policy.h"

static const char *dim_policy_obj_str[DIM_POLICY_OBJ_LAST] = {
	[DIM_POLICY_OBJ_BPRM_TEXT] = "obj=BPRM_TEXT",
	[DIM_POLICY_OBJ_MODULE_TEXT] = "obj=MODULE_TEXT",
	[DIM_POLICY_OBJ_KERNEL_TEXT] = "obj=KERNEL_TEXT",
};

static const char *dim_policy_key_str[DIM_POLICY_KEY_LAST] = {
	[DIM_POLICY_KEY_NAME] = "name=",
	[DIM_POLICY_KEY_PATH] = "path=",
};

static struct rb_root policy_root = RB_ROOT;

static int dim_policy_compare(struct dim_policy *x,
			      struct dim_policy *y)
{
	if (x->obj != y->obj)
		return x->obj - y->obj;

	if (x->key != y->key)
		return x->key - y->key;

	return strcmp(x->val, y->val);
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

static void policy_destroy(struct dim_policy *policy)
{
	kfree(policy->val);
	kfree(policy);
}

static int policy_add(int obj, int key, const char *val, int action)
{
	int ret = 0;
	struct dim_policy *policy = NULL;

	policy = dim_kmalloc_gfp(sizeof(struct dim_policy));
	if (policy == NULL)
		return -ENOMEM;

	policy->obj = obj;
	policy->key = key;
	policy->action = action;
	policy->val = kstrdup(val, GFP_KERNEL);
	if (policy->val == NULL) {
		kfree(policy);
		return -ENOMEM;
	}

	ret = dim_policy_rb_add(&policy_root, policy, NULL);
	if (ret < 0)
		policy_destroy(policy);

	return ret == -EEXIST ? 0 : ret;
}

static int policy_add_kernel(int action)
{
	return policy_add(DIM_POLICY_OBJ_KERNEL_TEXT, DIM_POLICY_KEY_NAME,
			  init_uts_ns.name.release, action);
}

static int policy_add_module(const char *name, int action)
{
	return policy_add(DIM_POLICY_OBJ_MODULE_TEXT, DIM_POLICY_KEY_NAME,
			  name, action);
}

static int policy_add_path(const char *path, int action)
{
	int ret = 0;
	char *path_buf = NULL;
	const char *apath = NULL;

	/* This element is a filepath */
	ret = policy_add(DIM_POLICY_OBJ_BPRM_TEXT, DIM_POLICY_KEY_PATH,
			 path, action);
	if (ret < 0)
		return ret;

	/* Try to get the absolute path */
	path_buf = dim_kmalloc_gfp(PATH_MAX);
	if (path_buf == NULL)
		return -ENOMEM;

	apath = dim_absolute_path(path, path_buf, PATH_MAX);
	if (IS_ERR(apath)) {
		dim_warn("failed to get absolute path of %s in policy: %ld\n",
			path, PTR_ERR(apath));
		kfree(path_buf);
		return 0;
	}

	if (strcmp(path, apath) != 0)
		ret = policy_add(DIM_POLICY_OBJ_BPRM_TEXT, DIM_POLICY_KEY_PATH,
				 apath, action);

	kfree(path_buf);
	return ret;
}

static int policy_parse_key_value(const char *s, int *key, const char **val)
{
	int i = 0;
	int len = 0;

	for (; i < DIM_POLICY_KEY_LAST; i++) {
		len = strlen(dim_policy_key_str[i]);
		if (strncmp(s, dim_policy_key_str[i], len) == 0) {
			*key = i;
			*val = s + len;
			return 0;
		}
	}

	return -EINVAL;
}

static int policy_parse_obj(const char *s, int *key)
{
	int ret = match_string(dim_policy_obj_str, DIM_POLICY_OBJ_LAST, s);
	if (ret < 0)
		return ret;

	*key = ret;
	return 0;
}

static int policy_parse_line(char* line, int line_no)
{
	int ret = 0;
	char *p = NULL;
	char *line_str = line;
	/* currently only support log action */
	int action = DIM_POLICY_LOG;
	int obj = 0;
	int key = 0;
	const char *val = NULL;

	if (line_no > DIM_POLICY_LINE_MAX) {
		dim_warn("more than %d policy items will be ignored\n",
			 DIM_POLICY_LINE_MAX);
		return -E2BIG;
	}

	if (strlen(line) == 0 || line[0] == '#')
		return 0; /* ignore blank line and comment */

	if (strlen(line) > DIM_POLICY_MAX_LEN) {
		dim_err("overlength item at line %d\n", line_no);
		return -EINVAL;
	}

	if ((p = strsep(&line_str, " ")) == NULL ||
	    strcmp(p, DIM_POLICY_MEASURE) != 0) {
		dim_err("invalid policy prefix at line %d\n", line_no);
		return -EINVAL;
	}

	if ((p = strsep(&line_str, " ")) == NULL ||
	     (policy_parse_obj(p, &obj)) < 0) {
		dim_err("invalid policy object at line %d\n", line_no);
		return -EINVAL;
	}

	/* for kernel policy, ignore other parameters */
	if (obj == DIM_POLICY_OBJ_KERNEL_TEXT) {
		ret = policy_add_kernel(action);
		if (ret < 0)
			dim_err("failed to add measure policy line %d: %d\n",
				line_no, ret);
		return ret;
	}

	if ((p = strsep(&line_str, " ")) == NULL ||
	    (policy_parse_key_value(p, &key, &val)) < 0) {
		dim_err("invalid policy key at line %d\n", line_no);
		return -EINVAL;
	    }

	if ((obj == DIM_POLICY_OBJ_BPRM_TEXT && key != DIM_POLICY_KEY_PATH) ||
	    (obj == DIM_POLICY_OBJ_MODULE_TEXT && key != DIM_POLICY_KEY_NAME)) {
		dim_err("mismatch policy object and key at line %d\n", line_no);
		return -EINVAL;
	}

	ret =  obj == DIM_POLICY_OBJ_BPRM_TEXT ?
		policy_add_path(val, action) :
		policy_add_module(val, action);
	if (ret < 0)
		dim_err("failed to add measure policy line %d: %d\n",
			line_no, ret);
	return ret;
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
	ret = dim_parse_line_buf(buf, buf_len, policy_parse_line);
	if (ret < 0) {
		dim_err("failed to parse policy: %d\n", ret);
		dim_core_policy_destroy();
	}

	vfree(buf);
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

bool dim_core_policy_match(int obj, int key, const char *val)
{
	struct dim_policy policy = {
		.obj = obj,
		.key = key,
		.val = val,
	};

	if (obj < 0 || obj >= DIM_POLICY_OBJ_LAST ||
	    key < 0 || key >= DIM_POLICY_KEY_LAST ||
	    val == NULL)
		return false;

	return dim_policy_rb_find(&policy_root, &policy, NULL) == 0;
}

int dim_core_policy_get_action(int obj __always_unused,
			       int key __always_unused,
			       const char *val __always_unused)
{
	return DIM_POLICY_LOG;
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

