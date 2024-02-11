/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/limits.h>
#include <linux/vmalloc.h>
#include <linux/utsname.h>
#include <linux/namei.h>
#include <linux/version.h>

#include "dim_utils.h"
#include "dim_hash.h"
#include "dim_baseline.h"

#include "dim_core_sig.h"
#include "dim_core_policy.h"
#include "dim_core_measure.h"
#include "dim_core_static_baseline.h"

static bool match_policy(const char *name, int type)
{
	const char *kr = init_uts_ns.name.release;
	unsigned int kr_len = strlen(kr);
	unsigned int name_len = strlen(name);
	const char *mod_name = NULL;

	if (type != DIM_BASELINE_KERNEL)
		return dim_core_policy_match(DIM_POLICY_OBJ_BPRM_TEXT,
					     DIM_POLICY_KEY_PATH, name);

	if (strcmp(name, kr) == 0)
		return dim_core_policy_match(DIM_POLICY_OBJ_KERNEL_TEXT,
					     DIM_POLICY_KEY_NAME, kr);

	if (name_len <= kr_len + 2 || /* <kernel release>/<mod_name> */
	    strncmp(kr, name, kr_len) != 0 ||
	    *(name + kr_len) != '/')
		return false;

	mod_name = name + kr_len + 1;
	return dim_core_policy_match(DIM_POLICY_OBJ_MODULE_TEXT,
				     DIM_POLICY_KEY_NAME, mod_name);
}

static int parse_simple_baseline_line(char* line, int line_no, void *data)
{
	int ret = 0;
	int type = 0;
	size_t len = 0;
	char *p = NULL;
	char *line_str = line;
	struct dim_digest digest = { 0 };

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

	if (!match_policy(line_str, type))
		return 0;

	ret = dim_measure_static_baseline_add(&dim_core_handle, line_str,
					      type, &digest);
	if (ret < 0)
		dim_warn("failed to add static baseline at line %d: %d\n",
			 line_no, ret);
	return 0;
}

struct readdir_ctx {
	struct dir_context ctx;
	struct path *path;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
static int
#else
static bool
#endif
static_baseline_load(struct dir_context *__ctx,
		     const char *name,
		     int name_len,
		     loff_t offset,
		     unsigned long long ino,
		     unsigned d_type)
{
	struct readdir_ctx *ctx = container_of(__ctx, typeof(*ctx), ctx);
	int ret;
	void *buf = NULL;
	unsigned long buf_len = 0;

	if (d_type != DT_REG || (!dim_string_end_with(name, ".hash")))
		goto out; /* ignore invalid files */

	ret = dim_read_verify_file(ctx->path, name, &buf);
	if (ret < 0 || buf == NULL) {
		dim_err("failed to read and verify %s: %d\n", name, ret);
		goto out;
	}

	buf_len = ret;
	ret = dim_parse_line_buf(buf, buf_len, parse_simple_baseline_line, NULL);
	if (ret < 0)
		dim_err("failed to parse baseline file %s: %d\n", name, ret);
out:
	if (buf != NULL)
		vfree(buf);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	return 0; /* ignore fail */
#else
	return true;
#endif
}

int dim_core_static_baseline_load(void)
{
	int ret = 0;
	struct path kpath;
	struct file *file = NULL;
	struct readdir_ctx buf = {
		.ctx.actor = static_baseline_load,
		.path = &kpath,
	};

	ret = kern_path(DIM_STATIC_BASELINE_ROOT, LOOKUP_DIRECTORY, &kpath);
	if (ret < 0) {
		dim_err("failed to get dim baseline root path: %d", ret);
		return ret;
	}

	file = filp_open(DIM_STATIC_BASELINE_ROOT, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		dim_err("failed to open %s: %d\n", DIM_STATIC_BASELINE_ROOT, ret);
		path_put(&kpath);
		return ret;
	}

	(void)iterate_dir(file, &buf.ctx);

	path_put(&kpath);
	filp_close(file, NULL);
	return 0;
}
