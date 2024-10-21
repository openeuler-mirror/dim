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

#define BASELINE_FILE_SUFFIX ".hash"
#define BASELINE_FILE_SUFFIX_LEN 5

static bool baseline_match_policy(const char *name, int type)
{
	const char *kr = init_uts_ns.name.release;
	unsigned int kr_len = strlen(kr);
	unsigned int name_len = strlen(name);
	const char *mod_name = NULL;

	if (type != DIM_BASELINE_KERNEL)
		return dim_core_policy_match(DIM_POLICY_OBJ_BPRM_TEXT,
					     DIM_POLICY_KEY_PATH, name);

	if (dim_strcmp(name, kr) == 0)
		return dim_core_policy_match(DIM_POLICY_OBJ_KERNEL_TEXT,
					     DIM_POLICY_KEY_NAME, kr);

	if (name_len <= kr_len + 2 || /* <kernel release>/<mod_name> */
	    dim_strncmp(kr, name, kr_len) != 0 ||
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
	int ret = 0;
	const char *real_path = NULL;

	if (type == DIM_BASELINE_KERNEL)
		return dim_measure_static_baseline_add(m, name, type, digest);

	/* for process, try to add the absolute path */
	ret = dim_get_absolute_path(name, &real_path);
	if (ret < 0) {
		dim_warn("failed to get absolute path of %s in static baeline: %d\n",
			 name, ret);
		return dim_measure_static_baseline_add(m, name, type, digest);
	}

	ret = dim_measure_static_baseline_add(m, real_path, type, digest);
	dim_kfree(real_path);
	return ret;
}

struct name_entry {
	char name[NAME_MAX];
	struct list_head list;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
static int
#else
static bool
#endif
baseline_fill_dir(struct dir_context *__ctx,
		  const char *name,
		  int name_len,
		  loff_t offset,
		  unsigned long long ino,
		  unsigned d_type)
{
	struct baseline_parse_ctx *ctx = container_of(__ctx, typeof(*ctx), ctx);
	struct name_entry *entry = NULL;

	/* baseline file must end with '.hash' */
	if (d_type != DT_REG || name_len >= NAME_MAX ||
	    name_len <= BASELINE_FILE_SUFFIX_LEN ||
	    strncmp(name + name_len - BASELINE_FILE_SUFFIX_LEN,
	    BASELINE_FILE_SUFFIX, BASELINE_FILE_SUFFIX_LEN))
		goto out; /* ignore invalid files */

	entry = dim_kzalloc_gfp(sizeof(struct name_entry));
	if (entry == NULL)
		goto out;

	strncpy(entry->name, name, name_len);
	list_add( &entry->list, &ctx->name_list);
out:
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
	struct name_entry *entry = NULL;
	struct name_entry *tmp = NULL;
	void *buf = NULL;
	unsigned long buf_len = 0;
	struct baseline_parse_ctx ctx = {
		.m = m,
		.ctx.actor = baseline_fill_dir,
		.add = baseline_check_add,
		.match = baseline_match_policy,
		.name_list = LIST_HEAD_INIT(ctx.name_list)
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

	(void)iterate_dir(file, &ctx.ctx);
	filp_close(file, NULL);

	list_for_each_entry_safe(entry, tmp, &ctx.name_list, list) {
		ret = dim_read_verify_file(&kpath, entry->name, &buf);
		if (ret < 0 || buf == NULL) {
			dim_err("failed to read and verify %s: %d\n", entry->name, ret);
			dim_kfree(entry);
			continue;
		}

		buf_len = ret;
		ret = dim_baseline_parse(buf, buf_len, &ctx);
		if (ret < 0)
			dim_err("failed to parse baseline file %s: %d\n", entry->name, ret);

		dim_vfree(buf);
		dim_kfree(entry);
	}

	path_put(&kpath);
	return 0;
}
