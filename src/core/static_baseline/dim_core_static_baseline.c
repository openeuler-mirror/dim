/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/utsname.h>
#include <linux/namei.h>
#include <linux/version.h>

#include "dim_utils.h"
#include "dim_hash.h"

#include "dim_core_sig.h"
#include "dim_core_policy.h"
#include "dim_core_measure.h"
#include "dim_core_static_baseline.h"

static bool baseline_match_policy(const char *name, int type)
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

static int baseline_check_add(const char *name, int type,
			      struct dim_digest *digest,
			      struct dim_measure *m)
{
	return dim_measure_static_baseline_add(m, name, type, digest);
}

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
	struct baseline_parse_ctx *ctx = container_of(__ctx, typeof(*ctx), ctx);
	int ret;
	void *buf = NULL;
	unsigned long buf_len = 0;

	/* baseline file must end with '.hash' */
	if (d_type != DT_REG || (!dim_string_end_with(name, ".hash")))
		goto out; /* ignore invalid files */

	ret = dim_read_verify_file(ctx->path, name, &buf);
	if (ret < 0 || buf == NULL) {
		dim_err("failed to read and verify %s: %d\n", name, ret);
		goto out;
	}

	buf_len = ret;
	ret = dim_baseline_parse(buf, buf_len, ctx);
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

int dim_core_static_baseline_load(struct dim_measure *m)
{
	int ret = 0;
	struct path kpath;
	struct file *file = NULL;
	struct baseline_parse_ctx buf = {
		.ctx.actor = static_baseline_load,
		.path = &kpath,
		.m = m,
		.add = baseline_check_add,
		.match = baseline_match_policy,
	};

	if (m == NULL)
		return -EINVAL;

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
