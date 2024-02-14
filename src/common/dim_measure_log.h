/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_MEASURE_LOG_H
#define __DIM_MEASURE_LOG_H

#include <linux/list.h>
#include <linux/rbtree.h>

#include "dim_hash.h"
#include "dim_safe_func.h"

#define DIM_NG "dim-ng"
#define LOG_MAX_LENGTH_PCR 3
#define LOG_NUMBER_FILE_MAX 10

enum dim_measure_log_type {
	LOG_NO_SATIC_BASELINE,
	LOG_STATIC_BASELINE,
	LOG_DYNAMIC_BASELINE,
	LOG_TAMPERED,
	LOG_MATCHED,
	LOG_LAST,
};

static const char *dim_measure_log_type_name[LOG_LAST] = {
	[LOG_NO_SATIC_BASELINE] = "[no static baseline]",
	[LOG_STATIC_BASELINE] = "[static baseline]",
	[LOG_DYNAMIC_BASELINE] = "[dynamic baseline]",
	[LOG_TAMPERED] = "[tampered]",
	[LOG_MATCHED] = "[matched]",
};

struct dim_measure_log_tree {
	struct rb_root rb_root; /* rb tree root for searching measure log */
	struct list_head list_root; /* list root for printing logs in order */
	struct dim_hash *hash; /* algorithm for calculating log hash */
	struct dim_tpm *tpm;
	char pcr;
	rwlock_t lock;
	unsigned int count; /* number of log */
	unsigned int cap; /* capacity of log */
};

struct dim_measure_name {
	struct rb_node rb_node;
	struct list_head log_root; /* total dim_measure_log list */
	struct list_head *log_cur; /* current dim_measure_log list */
	const char *name;
};

struct dim_measure_log {
	struct list_head node;
	struct list_head node_order;
	struct dim_measure_name *name_head;
	char pcr;
	int type; /* enum log_type */
	struct dim_digest digest; /* measure digest */
	struct dim_digest log_digest; /* measure log digest */
};

static inline int dim_measure_name_compare(struct dim_measure_name *x,
					   struct dim_measure_name *y)
{
	return dim_strcmp(x->name, y->name);
}

static inline const char *dim_measure_log_type_to_name(int type)
{
	return (type < 0 || type >= LOG_LAST) ? NULL :
	       dim_measure_log_type_name[type];
}

static inline const char *dim_measure_log_name(struct dim_measure_log *log)
{
	return log->name_head->name;
}

static inline bool is_valid_dim_measure_log_type(int type)
{
	return type < LOG_LAST && type >= 0;
}

static inline bool is_same_dim_measure_log(struct dim_measure_log *x,
					   struct dim_measure_log *y)
{
	if (x->type != y->type)
		return false;

	return dim_digest_compare(&x->digest, &y->digest) == 0;
}

int dim_measure_log_init_tree(struct dim_measure_log_tree *root,
			      struct dim_hash *hash, struct dim_tpm *tpm,
			      unsigned int cap, char pcr);
void dim_measure_log_destroy_tree(struct dim_measure_log_tree *root);
int dim_measure_log_add(struct dim_measure_log_tree *root,
			     const char *name_str,
			     struct dim_digest *digest, int flag);
int dim_measure_log_seq_show(struct seq_file *m, struct dim_measure_log *log);
void dim_measure_log_refresh(struct dim_measure_log_tree *root);

#endif
