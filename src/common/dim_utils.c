/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/err.h>
#include <linux/namei.h>

#include "dim_safe_func.h"
#include "dim_utils.h"

#define DIM_MAX_LINE_BUF (8 * 1024)

int dim_get_absolute_path(const char *path, const char **result)
{
	int ret = 0;
	struct path p;
	char *buf = NULL;
	char *apath = NULL;

	if (path == NULL)
		return -EINVAL;

	ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret < 0)
		return ret;

	buf = dim_kzalloc_gfp(PATH_MAX);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	apath = d_path(&p, buf, PATH_MAX);
	if (IS_ERR(apath)) {
		ret = PTR_ERR(apath);
		goto out;
	}

	*result = dim_kstrdup_gfp(apath);
	if (*result == NULL) {
		ret = -ENOMEM;
		goto out;
	}
out:
	path_put(&p);
	dim_kfree(buf);
	return ret;	
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

	return dim_strcmp(str + name_len - ext_len, ext) == 0;
}

int dim_parse_line_buf(char *buf, loff_t len, int (*line_parser)(char *, int, void *), void *data)
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
			ret = line_parser(line, line_no, data);
			line = &buf[i + 1];
		} else {
			line_len = buf + i - line + 1;
			if (line_len + 1 > DIM_MAX_LINE_BUF) {
				dim_err("failed to alloc memory for line buff\n");
				return -ENOMEM;
			}

			line_buf = dim_kzalloc_gfp(line_len + 1);
			if (line_buf == NULL)
				return -ENOMEM;

			memcpy(line_buf, line, line_len);
			ret = line_parser(line_buf, line_no, data);
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
		dim_kfree(line_buf);

	return ret;
}
