/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_STATIC_BASELINE_H
#define __DIM_CORE_STATIC_BASELINE_H

#define DIM_BASELINE_ROOT "/etc/dim/digest_list"

/* key field in baseline json file */
#define KEY_PRODUCTS "products"
#define KEY_FILES "ccFiles"
#define KEY_FPATCHES "patches"
#define KEY_FILENAME "fileName"
#define KEY_FILETYPE "fileType"
#define KEY_PATCH_FILES "files"
#define KEY_SHA256 "sha256"

#define DIM_BASELINE_PREFIX "dim"
 /* dim KERNEL sha256:{digest} {PATH_MAX}\n*/
 #define DIM_BASELINE_MAX_LEN (strlen(DIM_BASELINE_PREFIX) + 1 + \
			       NAME_MAX + 1 + NAME_MAX + 1 + PATH_MAX + 1 + 1)


int dim_core_static_baseline_load(void);

#endif
