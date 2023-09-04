/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_SIG_H
#define __DIM_CORE_SIG_H

#include <linux/key.h>

#define DIM_CORE_MAX_FILE_SIZE (10 * 1024 * 1024)
#define DIM_CORE_KEYRING_NAME "_dim"
#define DIM_CORE_CERT_PATH "/etc/keys/x509_dim.der"
#define DIM_CORE_SIG_FILE_SUFFIX ".sig"
#define DIM_CORE_KEYRING_PERM  ((KEY_POS_ALL & ~KEY_POS_SETATTR)	\
				| KEY_USR_VIEW | KEY_USR_READ 		\
				| KEY_USR_WRITE | KEY_USR_SEARCH)
#define DIM_CORE_KEY_PERM ((KEY_POS_ALL & ~KEY_POS_SETATTR) 	\
			   | KEY_USR_VIEW | KEY_USR_READ)

int dim_core_sig_init(void);
void dim_core_sig_destroy(void);
int dim_read_verify_file(struct path *root, const char *name, void **buf);

#endif
