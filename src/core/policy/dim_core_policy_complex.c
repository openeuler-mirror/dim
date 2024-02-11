/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/slab.h>

#include "dim_utils.h"

#include "dim_core_policy.h"

/* policy key */
#define DIM_POLICY_MEASURE "measure"

/* measure obj=MODULE_TEXT path={PATH_MAX} action=kill\n */
#define DIM_POLICY_MAX_KEY_FIELDS 3
#define DIM_POLICY_OBJ_MAX_LEN 15
#define DIM_POLICY_KEY_MAX_LEN 5
#define DIM_POLICY_ACTION_MAX_LEN 11
#define DIM_POLICY_MAX_LEN (strlen(DIM_POLICY_MEASURE) + 1 + \
			    DIM_POLICY_OBJ_MAX_LEN + 1 + \
			    DIM_POLICY_KEY_MAX_LEN + 1 + PATH_MAX + 1 + \
			    DIM_POLICY_ACTION_MAX_LEN + 1)

static const char *dim_policy_key_str[DIM_POLICY_KEY_LAST] = {
	[DIM_POLICY_KEY_OBJ] = "obj=",
	[DIM_POLICY_KEY_NAME] = "name=",
	[DIM_POLICY_KEY_PATH] = "path=",
	[DIM_POLICY_KEY_ACTION] = "action=",
};

static const char *dim_policy_obj_str[DIM_POLICY_OBJ_LAST] = {
	[DIM_POLICY_OBJ_BPRM_TEXT] = "BPRM_TEXT",
	[DIM_POLICY_OBJ_MODULE_TEXT] = "MODULE_TEXT",
	[DIM_POLICY_OBJ_KERNEL_TEXT] = "KERNEL_TEXT",
};

static const char *dim_policy_action_str[DIM_POLICY_KEY_LAST] = {
	[DIM_POLICY_ACTION_LOG] = "log",
	[DIM_POLICY_ACTION_KILL] = "kill",
};

static const char *policy_get_string_value(const char *s)
{
	return kstrdup(s, GFP_KERNEL);
}

static int policy_get_action(const char *s)
{
	return match_string(dim_policy_action_str, DIM_POLICY_ACTION_LAST, s);
}

static int policy_get_obj(const char *s)
{
	return match_string(dim_policy_obj_str, DIM_POLICY_OBJ_LAST, s);
}

static int policy_get_key(const char *s, const char **val)
{
	unsigned int i = 0;
	unsigned int len = 0;

	for (; i < DIM_POLICY_KEY_LAST; i++) {
		len = strlen(dim_policy_key_str[i]);
		if (strncmp(s, dim_policy_key_str[i], len) == 0) {
			*val = s + len;
			return i;
		}
	}

	return -EINVAL;
}

static int policy_parse_key_value(char *s, struct dim_policy *policy)
{
	char *p = NULL;
	int key = 0;
	int filed_num = 0;
	const char *val = NULL;

	while ((p = strsep(&s, " ")) != NULL) {
		key = policy_get_key(p, &val);
		if (key < 0 || val == NULL)
			return -EINVAL;

		if (++filed_num > DIM_POLICY_MAX_KEY_FIELDS)
			return -EINVAL;

		switch (key)
		{
		case DIM_POLICY_KEY_OBJ:
			policy->obj = policy_get_obj(val);
			if (policy->obj < 0)
				return -EINVAL;
			break;
		case DIM_POLICY_KEY_NAME:
			policy->name = policy_get_string_value(val);
			if (policy->name == NULL)
				return -ENOMEM;
			break;
		case DIM_POLICY_KEY_PATH:
			policy->path = policy_get_string_value(val);
			if (policy->path == NULL)
				return -ENOMEM;
			break;
		case DIM_POLICY_KEY_ACTION:
			policy->action = policy_get_action(val);
			if (policy->action < 0)
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int parse_line(char *line_str, struct dim_policy *policy)
{
	int ret = 0;
	char *p = NULL;

	if ((p = strsep(&line_str, " ")) == NULL ||
	    strcmp(p, DIM_POLICY_MEASURE) != 0) {
		dim_err("invalid policy prefix, must start with %s\n",
			DIM_POLICY_MEASURE);
		return -EINVAL;
	}

	ret = policy_parse_key_value(line_str, policy);
	if (ret < 0) {
		dim_err("fail to parse policy key and value: %d\n", ret);
		return ret;
	}

	return 0;
}

static int policy_parse_line(char* line, int line_no, void *data)
{
	int ret = 0;
	struct dim_policy *policy = NULL;
	policy_add_func policy_add = data;

	if (line_no > DIM_POLICY_LINE_MAX) {
		dim_warn("more than %d policy items will be ignored\n",
			 DIM_POLICY_LINE_MAX);
		return -E2BIG;
	}

	if (strlen(line) == 0 || line[0] == '#')
		return 0; /* ignore blank line and comment */

	if (strlen(line) > DIM_POLICY_MAX_LEN) {
		dim_err("overlength line %d\n", line_no);
		return -EINVAL;
	}

	policy = dim_kmalloc_gfp(sizeof(struct dim_policy));
	if (policy == NULL)
		return -ENOMEM;

	memset(policy, 0, sizeof(struct dim_policy));

	ret = parse_line(line, policy);
	if (ret < 0) {
		dim_err("fail to parse policy at line %d: %d\n", line_no, ret);
		return ret;
	}

	ret = policy_add(policy);
	if (ret < 0) {
		policy_destroy(policy);
		/* ignore the repeat add */
		if (ret != -EEXIST)
			dim_err("fail to add policy at line %d: %d\n", line_no, ret);
		return ret == -EEXIST ? 0 : ret;
	}

	return 0;
}

int policy_parse_complex_format(char *buf, size_t buf_len,
				policy_add_func policy_add)
{
	if (buf == NULL || buf_len == 0 || policy_add == NULL)
		return -EINVAL;

	return dim_parse_line_buf(buf, buf_len, policy_parse_line, policy_add);
}