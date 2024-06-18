/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_BASELINE_H
#define __DIM_BASELINE_H

#include <linux/rbtree.h>
#include "dim_hash.h"

typedef void *(*malloc_func)(size_t);
typedef void (*free_func)(const void*);

enum dim_baseline_type {
	DIM_BASELINE_USER, /* baseline of user process */
	DIM_BASELINE_KERNEL, /* baseline of kernel or kernel modules */
	DIM_BASELINE_DATA,
	DIM_BASELINE_TRAMPOLINE,
	DIM_BASELINE_LAST,
};

static const char *const dim_baseline_name[DIM_BASELINE_LAST] = {
	[DIM_BASELINE_USER] = "USER",
	[DIM_BASELINE_KERNEL] = "KERNEL",
	[DIM_BASELINE_DATA] = "DATA",
	[DIM_BASELINE_TRAMPOLINE] = "TRAMPOLINE",
};

struct dim_baseline_tree {
	struct rb_root rb_root; /* rb tree of baseline nodes */
	rwlock_t lock;
	malloc_func malloc;
	free_func free;
};

/* dim baseline node */
struct dim_baseline {
	struct rb_node rb_node;
	const char *name;
	int type; /* enum dim_baseline_type */
	struct dim_digest digest;
};

static inline bool dim_baseline_type_is_valid(int type)
{
	return (type < DIM_BASELINE_LAST && type >= 0);
}

static inline int dim_baseline_get_type(const char *name)
{
	int idx = match_string(dim_baseline_name, DIM_BASELINE_LAST, name);
	return idx < 0 ? DIM_BASELINE_LAST : idx;
}

int dim_baseline_init_tree(malloc_func malloc, free_func free,
			   struct dim_baseline_tree *root);
void dim_baseline_destroy_tree(struct dim_baseline_tree *root);
int dim_baseline_search_digest(struct dim_baseline_tree *root, const char *name,
			       int type, struct dim_digest *digest);
bool dim_baseline_match(struct dim_baseline_tree *root, const char *name,
			int type, struct dim_digest *digest);
int dim_baseline_add(struct dim_baseline_tree *root, const char *name,
		     int type, struct dim_digest *digest);

#endif
