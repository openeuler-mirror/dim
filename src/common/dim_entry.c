/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/err.h>
#include <linux/security.h>
#include <linux/delay.h>

#include "dim_entry.h"

#define WAIT_TIME_MAX 1000

int dim_entry_create(struct dim_entry *entry, struct dentry *parent)
{
	int ret = 0;

	if (entry == NULL || entry->name == NULL)
		return -EINVAL;

	entry->dentry = securityfs_create_file(entry->name, entry->mode,
					       parent, NULL, entry->fops);
	if (IS_ERR(entry->dentry)) {
		ret = PTR_ERR(entry->dentry);
		entry->dentry = NULL;
		return ret;
	}

	return 0;
}

void dim_entry_remove(struct dim_entry *entry)
{
	int time_ms = 0;

	if (entry != NULL && entry->dentry != NULL) {
		while (d_is_dir(entry->dentry) &&
		       !simple_empty(entry->dentry) &&
		       time_ms < WAIT_TIME_MAX) {
			time_ms++;
			msleep(1);
		}
		securityfs_remove(entry->dentry);
		entry->dentry = NULL;
	}
}

int dim_entry_create_list(struct dim_entry **list,
			  unsigned int len,
			  struct dentry *parent)
{
	int ret = 0;
	int i = 0;

	if (list == NULL)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		ret = dim_entry_create(list[i], parent);
		if (ret < 0) {
			dim_entry_remove_list(list, len);
			return ret;
		}
	}

	return 0;
}

void dim_entry_remove_list(struct dim_entry **list, unsigned int len)
{
	int i = 0;

	for (i = 0; i < len; i++)
		dim_entry_remove(list[i]);
}
