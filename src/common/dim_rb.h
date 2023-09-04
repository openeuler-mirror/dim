/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_RB_H
#define __DIM_RB_H

#define dim_rb_find(name)						\
static int name##_rb_find(struct rb_root *root, struct name *data,	\
			  struct name **find_data)			\
{									\
	int ret = 0;							\
	struct rb_node *cur = root->rb_node;				\
	struct name *find = NULL;					\
									\
	while (cur != NULL) {						\
		find = rb_entry(cur, struct name, rb_node);		\
		ret = name##_compare(find, data);			\
		if (ret == 0) {						\
			if (find_data != NULL)				\
				*find_data = find;			\
			return 0;					\
		}							\
									\
		cur = ret < 0 ? cur->rb_left : cur->rb_right;		\
	}								\
									\
	return -ENOENT;							\
};

#define dim_rb_add(name)						\
static int name##_rb_add(struct rb_root *root, struct name *data,	\
			 struct name **find_data)			\
{									\
	int ret = 0;							\
	struct rb_node **cur = &(root->rb_node);			\
	struct rb_node *parent = NULL;					\
	struct name *find = NULL;					\
									\
	while (*cur != NULL) {						\
		find = rb_entry(*cur, struct name, rb_node);		\
		ret = name##_compare(find, data);			\
		if (ret == 0) {						\
			if (find_data != NULL)				\
				*find_data = find;			\
			return -EEXIST;					\
		}							\
									\
		parent = *cur;						\
		cur = ret < 0 ? &(*cur)->rb_left : &(*cur)->rb_right;	\
	}								\
									\
	rb_link_node(&data->rb_node, parent, cur);			\
	rb_insert_color(&data->rb_node, root);				\
	return 0;							\
};

#endif
