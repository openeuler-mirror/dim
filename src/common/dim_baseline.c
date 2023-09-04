/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_rb.h"
#include "dim_baseline.h"

static int dim_baseline_compare(struct dim_baseline *x,
				struct dim_baseline *y)
{
	int ret = 0;

	if (x->type != y->type)
		return x->type > y->type ? 1 : -1;

	ret = strcmp(x->name, y->name);
	if (ret != 0)
		return ret;

	/* in rb_tree search code, x is the find data, y is the target data,
	   if the digest of y is zero, means we want to search digest by
	   baseline name and type. */
	return dim_digest_is_zero(&y->digest) ? 0 :
	       dim_digest_compare(&x->digest, &y->digest);
}

/*
static int dim_baseline_rb_find(struct rb_root *root,
				struct dim_baseline *data,
				struct dim_baseline **find_data)
*/
dim_rb_find(dim_baseline);
/*
static int dim_baseline_rb_add(struct rb_root *root,
			       struct dim_baseline *data,
			       struct dim_baseline **find_data)
*/
dim_rb_add(dim_baseline);

int dim_baseline_search_digest(struct dim_baseline_tree *root, const char *name,
			       int type, struct dim_digest *digest)
{
	int ret = 0;
	struct dim_baseline *find = NULL;
	struct dim_baseline search = { .name = name, .type = type };

	if (root == NULL || name == NULL || digest == NULL ||
	    !dim_baseline_type_is_valid(type))
		return -EINVAL;

	/* using zero digest means searching the digest */
	memset(&search.digest, 0, sizeof(struct dim_digest));

	read_lock(&root->lock);
	ret = dim_baseline_rb_find(&root->rb_root, &search, &find);
	read_unlock(&root->lock);
	if (ret < 0)
		return ret;

	return dim_digest_copy(digest, &find->digest);
}

bool dim_baseline_match(struct dim_baseline_tree *root, const char *name,
			int type, struct dim_digest *digest)
{
	bool matched = false;
	struct dim_baseline search = { .name = name, .type = type };

	if (root == NULL || name == NULL || digest == NULL ||
	    !dim_baseline_type_is_valid(type) ||
	    dim_digest_copy(&search.digest, digest) < 0)
		return false;

	read_lock(&root->lock);
	matched = (dim_baseline_rb_find(&root->rb_root, &search, NULL) == 0);
	read_unlock(&root->lock);
	return matched;
}

int dim_baseline_add(struct dim_baseline_tree *root, const char *name,
		     int type, struct dim_digest *digest)
{
	int ret = 0;
	int buf_len = 0;
	struct dim_baseline *baseline = NULL;

	if (root == NULL || root->malloc == NULL || root->free == NULL ||
	    !dim_baseline_type_is_valid(type) || name == NULL || digest == NULL)
		return -EINVAL;

	baseline = root->malloc(sizeof(struct dim_baseline));
	if (baseline == NULL)
		return -ENOMEM;

	buf_len = strlen(name) + 1;
	baseline->name = root->malloc(buf_len);
	if (baseline->name == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	baseline->type = type;
	ret = dim_digest_copy(&baseline->digest, digest);
	if (ret < 0)
		goto err;

	strcpy((char *)baseline->name, name);

	write_lock(&root->lock);
	ret = dim_baseline_rb_add(&root->rb_root, baseline, NULL);
	write_unlock(&root->lock);
	if (ret < 0)
		goto err;

	return 0;
err:
	if (baseline->name != NULL)
		root->free((char *)baseline->name);

	root->free(baseline);
	return ret;
}

void dim_baseline_destroy_tree(struct dim_baseline_tree *root)
{
	struct dim_baseline *pos = NULL;
	struct dim_baseline *n = NULL;

	if (root == NULL || root->free == NULL)
		return;

	write_lock(&root->lock);
	rbtree_postorder_for_each_entry_safe(pos, n, &root->rb_root, rb_node) {
		root->free((void *)pos->name);
		root->free(pos);
	}

	root->rb_root = RB_ROOT;
	write_unlock(&root->lock);
}

int dim_baseline_init_tree(malloc_func malloc, free_func free,
			   struct dim_baseline_tree *root)
{
	if (malloc == NULL || free == NULL || root == NULL)
		return -EINVAL;

	rwlock_init(&root->lock);
	root->rb_root = RB_ROOT;
	root->malloc = malloc;
	root->free = free;
	return 0;
}
