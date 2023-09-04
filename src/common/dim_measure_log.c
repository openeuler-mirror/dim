/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/seq_file.h>

#include "dim_rb.h"
#include "dim_tpm.h"
#include "dim_measure_log.h"

/*
static int dim_measure_name_rb_add(struct rb_root *root,
				   struct dim_baseline *data,
				   struct dim_baseline **find_data)
*/
dim_rb_add(dim_measure_name);

static int cal_measure_log_digest(const char *name,
				  struct dim_measure_log *info,
				  struct dim_hash *hash)
{
	/* templet hash is hash(
		"file hash algorithm string size + file digest size"
		+ "file hash algorithm string"
		+ "file digest"
		+ "file path string size"
		+ "file path"), and the "\0" of algorithm/path string should
		be calculated in also.
	*/
	int ret, size;
	const char *algo_name = dim_hash_name(info->digest.algo);
	int digest_size = dim_digest_size(info->digest.algo);
	SHASH_DESC_ON_STACK(shash, hash->tfm);

	shash->tfm = hash->tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	size = strlen(algo_name) + strlen(":") + 1 + digest_size;
	if ((ret = crypto_shash_update(shash, (char *)&size, sizeof(size))) ||
	    (ret = crypto_shash_update(shash, algo_name, strlen(algo_name))) ||
	    (ret = crypto_shash_update(shash, ":", strlen(":") + 1)) ||
	    (ret = crypto_shash_update(shash, info->digest.data, digest_size)))
		return ret;

	size = strlen(name) + 1;
	if ((ret = crypto_shash_update(shash, (char *)&size, sizeof(size))) ||
	    (ret = crypto_shash_update(shash, name, size))) /* + "\0" */
		return ret;

	info->log_digest.algo = hash->algo;
	return crypto_shash_final(shash, info->log_digest.data);
}

int dim_measure_log_seq_show(struct seq_file *m, struct dim_measure_log *info)
{
	char log_digest_buf[(DIM_MAX_DIGEST_SIZE << 1) + 1] = { 0 };
	char digest_buf[(DIM_MAX_DIGEST_SIZE << 1) + 1] = { 0 };

	bin2hex(log_digest_buf, info->log_digest.data,
		dim_digest_size(info->log_digest.algo));

	bin2hex(digest_buf, info->digest.data,
		dim_digest_size(info->digest.algo));

	seq_printf(m, "%d %s %s:%s %s %s\n",
		   info->pcr,
		   log_digest_buf,
		   dim_hash_name(info->digest.algo),
		   digest_buf,
		   dim_measure_log_name(info),
		   dim_measure_log_type_to_name(info->type));
	return 0;
}

static int measure_info_insert(struct dim_measure_name *name,
			       struct dim_measure_log *info)
{
	struct list_head *list_search_from = NULL;
	struct dim_measure_log *pos = NULL;
	int cnt = 0;

	/* For error type log, search from last baseline */
	list_search_from = info->type == LOG_TAMPERED ?
		name->log_cur->next : name->log_root.next;

	pos = list_entry(list_search_from, struct dim_measure_log, node);
	list_for_each_entry_from(pos, &name->log_root, node) {
		if (is_same_dim_measure_log(pos, info))
			return -EEXIST;

		cnt++;
	}

	if (cnt > LOG_NUMBER_FILE_MAX && info->type == LOG_TAMPERED)
		return -ENOSPC;

	list_add_tail(&info->node, &name->log_root);
	return 0;
}

static void measure_log_destroy_info(struct dim_measure_log *info)
{
	kfree(info);
}

static void measure_log_destroy_name(struct dim_measure_name *name)
{
	struct dim_measure_log *pos = NULL;
	struct dim_measure_log *n = NULL;

	/* free all measure info */
	list_for_each_entry_safe(pos, n, &name->log_root, node)
		measure_log_destroy_info(pos);
	/* free self */
	kfree(name->name);
	kfree(name);
}

static int measure_log_create_name(const char *name_str,
				   struct dim_measure_name **name)
{
	struct dim_measure_name *new = NULL;

	new = kzalloc(sizeof(struct dim_measure_name), GFP_KERNEL);
	if (new == NULL)
		return -ENOMEM;

	new->name = kstrdup(name_str, GFP_KERNEL);
	if (new->name == NULL) {
		kfree(new);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&new->log_root);
	new->log_cur = &new->log_root;
	*name = new;
	return 0;
}

static int measure_log_create_info(char pcr, struct dim_digest *digest,
				   int flag, struct dim_measure_log **info)
{
	int ret = 0;
	struct dim_measure_log *new = NULL;

	new = kzalloc(sizeof(struct dim_measure_log), GFP_KERNEL);
	if (new == NULL)
		return -ENOMEM;

	new->pcr = pcr;
	new->type = flag;
	ret = dim_digest_copy(&new->digest, digest);
	if (ret < 0) {
		kfree(new);
		return ret;
	}

	*info = new;
	return 0;
}

static int measure_log_add_info(struct dim_measure_log_tree *root,
				const char *name_str,
				struct dim_measure_log *info)
{
	int ret = 0;
	struct dim_measure_name *name = NULL;
	struct dim_measure_name *name_find = NULL;

	ret = cal_measure_log_digest(name_str, info, root->hash);
	if (ret < 0)
		return ret;

	ret = measure_log_create_name(name_str, &name);
	if (ret < 0)
		return ret;

	write_lock(&root->lock);
	ret = dim_measure_name_rb_add(&root->rb_root, name, &name_find);
	if (ret == -EEXIST && name_find != NULL) { /* name node exist */
		measure_log_destroy_name(name);
		info->name_head = name_find;
	} else if (ret < 0) { /* unknown error */
		measure_log_destroy_name(name);
		write_unlock(&root->lock);
		return ret;
	} else { /* name node insert ok */
		info->name_head = name;
	}

	ret = measure_info_insert(info->name_head, info);
	if (ret < 0) {
		write_unlock(&root->lock);
		return ret;
	}

	list_add_tail(&info->node_order, &root->list_root);
	root->count++;
	write_unlock(&root->lock);

	return root->tpm == NULL && root->pcr != 0 ? 0 :
		dim_tpm_pcr_extend(root->tpm, root->pcr,
				   &info->log_digest);
}

static bool measure_log_is_full(struct dim_measure_log_tree *root)
{
	bool ret = false;

	read_lock(&root->lock);
	ret = ((root->cap > 0) && (root->count >= root->cap));
	read_unlock(&root->lock);
	return ret;
}

int dim_measure_log_add(struct dim_measure_log_tree *root,
			const char *name_str,
			struct dim_digest *digest, int flag)
{
	int ret = 0;
	struct dim_measure_log *info = NULL;

	if (root == NULL || name_str == NULL ||
	    !is_valid_dim_measure_log_type(flag) || digest == NULL)
		return -EINVAL;

	if (measure_log_is_full(root))
		return -ENOSPC;

	ret = measure_log_create_info(root->pcr, digest, flag, &info);
	if (ret < 0)
		return ret;

	ret = measure_log_add_info(root, name_str, info);
	if (ret < 0)
		measure_log_destroy_info(info);

	return ret;
}

void dim_measure_log_refresh(struct dim_measure_log_tree *root)
{
	struct dim_measure_name *pos = NULL;
	struct dim_measure_name *n = NULL;

	write_lock(&root->lock);
	rbtree_postorder_for_each_entry_safe(pos, n, &root->rb_root, rb_node)
		pos->log_cur = pos->log_root.prev;

	write_unlock(&root->lock);
}

void dim_measure_log_destroy_tree(struct dim_measure_log_tree *root)
{
	struct dim_measure_name *pos = NULL;
	struct dim_measure_name *n = NULL;

	write_lock(&root->lock);
	rbtree_postorder_for_each_entry_safe(pos, n, &root->rb_root, rb_node)
		measure_log_destroy_name(pos);

	INIT_LIST_HEAD(&root->list_root);
	root->hash = NULL;
	root->rb_root = RB_ROOT;
	write_unlock(&root->lock);
}

int dim_measure_log_init_tree(struct dim_measure_log_tree *root,
			      struct dim_hash *hash, 
			      struct dim_tpm *tpm,
			      unsigned int cap,
			      char pcr)
{
	if (root == NULL || hash == NULL || pcr < 0)
		return -EINVAL;

	rwlock_init(&root->lock);
	INIT_LIST_HEAD(&root->list_root);
	root->hash = hash;
	root->rb_root = RB_ROOT;
	root->pcr = pcr;
	root->tpm = tpm;
	root->cap = cap;
	return 0;
}
