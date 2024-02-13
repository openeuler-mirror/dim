/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_utils.h"
#include "dim_core_static_baseline.h"

#define DIM_STATIC_BASELINE_LINE_MAX 10000

#define DIM_STATIC_BASELINE_PREFIX "dim"
/* dim KERNEL sha256:{digest} {PATH_MAX}\n*/
#define DIM_STATIC_BASELINE_LEN_MAX (strlen(DIM_STATIC_BASELINE_PREFIX) + 1 + \
				     NAME_MAX + 1 + NAME_MAX + 1 + \
				     PATH_MAX + 1 + 1)

static int parse_line(char* line, int line_no, void *data)
{
	int type = 0;
	size_t len = 0;
	char *p = NULL;
	char *line_str = line;
	struct dim_digest digest = { 0 };
	struct baseline_parse_ctx *ctx = data;

	if (line_no > DIM_STATIC_BASELINE_LINE_MAX) {
		dim_warn("more than %d baseline items will be ignored\n",
			 DIM_STATIC_BASELINE_LINE_MAX);
		return -E2BIG;
	}

	if (strlen(line) == 0 || line[0] == '#')
		return 0; /* ignore blank line and comment */

	if (strlen(line) > DIM_STATIC_BASELINE_LEN_MAX) {
		dim_err("overlength item at line %d\n", line_no);
		return 0; /* ignore baseline parsing failed */
	}

	if ((p = strsep(&line_str, " ")) == NULL ||
	    strcmp(p, DIM_STATIC_BASELINE_PREFIX) != 0) {
		dim_warn("invalid baseline prefix at line %d\n", line_no);
		return 0;
	}

	if ((p = strsep(&line_str, " ")) == NULL ||
	    (type = dim_baseline_get_type(p)) == DIM_BASELINE_LAST) {
		dim_warn("invalid baseline type at line %d\n", line_no);
		return 0;
	}

	if ((p = strsep(&line_str, ":")) == NULL ||
	    (digest.algo = dim_hash_algo(p)) == HASH_ALGO__LAST) {
		dim_warn("invalid baseline algo at line %d\n", line_no);
		return 0;
	}

	if ((p = strsep(&line_str, " ")) == NULL ||
	    strlen(p) != (dim_digest_size(digest.algo) << 1) ||
	    hex2bin(digest.data, p, dim_digest_size(digest.algo)) < 0) {
		dim_warn("invalid baseline digest at line %d\n", line_no);
		return 0;
	}

	if (line_str == NULL) {
		dim_warn("no baseline name at line %d\n", line_no);
		return 0;
	}

	len = strlen(line_str);
	if (len == 0 || len > PATH_MAX) {
		dim_warn("invalid baseline name at line %d\n", line_no);
		return 0;
	}

	if (!ctx->match(line_str, type))
		return 0;

	return ctx->add(line_str, type, &digest, ctx->m);
}

int baseline_parse_complex_format(char *buf, size_t buf_len,
				  struct baseline_parse_ctx *ctx)
{
	if (buf == NULL || buf_len == 0 || ctx == NULL || ctx->m == NULL ||
	    ctx->match == NULL || ctx->add == NULL)
		return -EINVAL;

	return dim_parse_line_buf(buf, buf_len, parse_line, ctx);
}
