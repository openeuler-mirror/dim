/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/kernel_read_file.h>

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

int dim_read_file(struct path *root, const char *name, void **buf)
{
	int ret = 0;
	struct file *file = NULL;

	if (root == NULL) {
		ret = kernel_read_file_from_path(name, 0, buf,
						  DIM_MAX_FILE_SIZE,
						  NULL, READING_UNKNOWN);
#ifdef DIM_DEBUG_MEMORY_LEAK
		if (*buf != NULL)
			dim_alloc_debug_inc();
#endif
		return ret;
	}

	file = file_open_root(root, name, O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);

	ret = kernel_read_file(file, 0, buf, DIM_MAX_FILE_SIZE,
			       NULL, READING_UNKNOWN);
#ifdef DIM_DEBUG_MEMORY_LEAK
	if (*buf != NULL)
		dim_alloc_debug_inc();
#endif
	(void)filp_close(file, NULL);
	return ret;
}
