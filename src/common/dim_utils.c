/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "dim_utils.h"

void *dim_kmalloc_gfp(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

void dim_kfree(void *data)
{
	kfree(data);
}

const char *dim_absolute_path(const char *path, char *buf, int len)
{
	int ret;
	struct path p;
	char *apath = NULL;

	if (path == NULL || buf == NULL)
		return ERR_PTR(-EINVAL);

	ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret < 0)
		return ERR_PTR(ret);

	apath = d_path(&p, buf, len);
	path_put(&p);
	return apath;
}

bool dim_string_end_with(const char *str, const char *ext)
{
	int name_len, ext_len;

	if (str == NULL || ext == NULL)
		return false;

	name_len = strlen(str);
	ext_len = strlen(ext);
	if (name_len < ext_len)
		return false;

	return strcmp(str + name_len - ext_len, ext) == 0;
}

int dim_parse_line_buf(char *buf, loff_t len, int (*line_parser)(char *, int))
{
	int ret = 0;
	int i = 0;
	int line_no = 1;
	char *line = buf;
	char *line_buf = NULL;
	size_t line_len = 0;

	if (len == 0)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		if (buf[i] != '\n' && i != len - 1)
			continue;

		if (buf[i] == '\n') {
			buf[i] = '\0';
			ret = line_parser(line, line_no);
			line = &buf[i + 1];
		} else {
			line_len = buf + i - line + 1;
			line_buf = kzalloc(line_len + 1, GFP_KERNEL);
			if (line_buf == NULL)
				return -ENOMEM;

			memcpy(line_buf, line, line_len);
			ret = line_parser(line_buf, line_no);
		}

		if (ret < 0) {
			/*
			 * if the parser returns -E2BIG, means the line number
			 * is too large, the excess lines will be ignored.
			 */
			ret = (ret == -E2BIG) ? 0 : ret;
			goto out;
		}

		line_no++;
	}
out:
	if (line_buf != NULL)
		kfree(line_buf);

	return ret;
}
