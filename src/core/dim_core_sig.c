/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <crypto/public_key.h>
#include <linux/key.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/kernel_read_file.h>
#include <keys/asymmetric-type.h>

#include "dim_hash.h"
#include "dim_utils.h"
#include "dim_safe_func.h"

#include "dim_core_sig.h"

static struct key *dim_core_keyring = NULL;
static struct key *dim_core_key = NULL;
static struct dim_hash dim_core_sig_hash = { 0 };

static char *add_suffix(const char *str, const char *suffix)
{
	int len = 0;
	char *buf = NULL;

	len = strlen(str) + strlen(suffix) + 1;
	buf = dim_kzalloc_gfp(len);
	if (buf == NULL)
		return NULL;

	sprintf(buf, "%s%s", str, suffix);
	return buf;
}

static int read_file_root(struct path *root, const char *name, void **buf)
{
	int ret = 0;
	struct file *file = NULL;

	if (root == NULL) {
		ret = kernel_read_file_from_path(name, 0, buf,
						  DIM_CORE_MAX_FILE_SIZE,
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

	ret = kernel_read_file(file, 0, buf, DIM_CORE_MAX_FILE_SIZE,
			       NULL, READING_UNKNOWN);
#ifdef DIM_DEBUG_MEMORY_LEAK
	if (*buf != NULL)
		dim_alloc_debug_inc();
#endif
	(void)filp_close(file, NULL);
	return ret;
}

static int dim_core_sig_verify(const char *buf, loff_t buf_len,
			       const char *sbuf, loff_t sbuf_len)
{
	int ret = 0;
	struct dim_digest digest = { 0 };
	/* Currently only support RSA-SHA256 */
	struct public_key_signature key_sig = {
		.pkey_algo = "rsa",
		.hash_algo = "sha256",
		.encoding = "pkcs1"
	};

	if (buf == NULL || sbuf == NULL)
		return -EINVAL;

	ret = dim_hash_calculate(buf, buf_len, &dim_core_sig_hash, &digest);
	if (ret < 0)
		return ret;

	key_sig.s = (char *)sbuf;
	key_sig.s_size = sbuf_len;
	key_sig.digest = digest.data;
	key_sig.digest_size = dim_digest_size(digest.algo);

	return verify_signature(dim_core_key, &key_sig);
}

int dim_read_verify_file(struct path *root, const char *name, void **buf)
{
	int ret = 0;
	char *sig_name = NULL;
	void *file_buf = NULL;
	void *sig_buf = NULL;
	size_t file_size = 0;
	size_t sig_size = 0;

	if (name == NULL || buf == NULL)
		return -EINVAL;

	sig_name = add_suffix(name, DIM_CORE_SIG_FILE_SUFFIX);
	if (sig_name == NULL)
		return -ENOMEM;

	ret = read_file_root(root, name, &file_buf);
	if (ret < 0)
		goto out;

	file_size = ret;
	ret = 0;

	if (dim_core_key == NULL)
		goto out; /* no need to verify signature */

	ret = read_file_root(root, sig_name, &sig_buf);
	if (ret < 0)
		goto out;

	sig_size = ret;
	ret = dim_core_sig_verify(file_buf, file_size, sig_buf, sig_size);
out:
	dim_kfree(sig_name);
	dim_vfree(sig_buf);
	if (ret < 0)
		dim_vfree(file_buf);
	if (ret == 0) {
		*buf = file_buf;
		ret = file_size;
	}

	return ret;
}

int dim_core_sig_init(void)
{
	ssize_t ret = 0;
	void *data = NULL;
	key_ref_t key;

	dim_core_keyring = keyring_alloc(DIM_CORE_KEYRING_NAME, KUIDT_INIT(0),
					 KGIDT_INIT(0), current_cred(),
					 DIM_CORE_KEYRING_PERM,
					 KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(dim_core_keyring)) {
		ret = PTR_ERR(dim_core_keyring);
		dim_err("failed to allocate DIM keyring: %ld\n", ret);
		return ret;
	}

	ret = kernel_read_file_from_path(DIM_CORE_CERT_PATH, 0, &data,
					 DIM_CORE_MAX_FILE_SIZE, NULL,
					 READING_X509_CERTIFICATE);
	if (ret < 0) {
		dim_err("failed to read DIM cert file: %ld\n", ret);
		goto err;
	}

	key = key_create_or_update(make_key_ref(dim_core_keyring, 1),
				   "asymmetric", NULL, data, ret,
				   DIM_CORE_KEY_PERM, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		dim_err("failed to load DIM cert: %ld\n", ret);
		goto err;
	}

	ret = dim_hash_init("sha256", &dim_core_sig_hash);
	if (ret < 0) {
		dim_err("failed to init dim signature hash: %ld\n", ret);
		goto err;
	}

	key_ref_put(key);
	dim_core_key = key_ref_to_ptr(key);
	dim_info("load DIM cert: %s\n", dim_core_key->description);
	ret = 0;
err:
	dim_vfree(data);
	if (ret < 0)
		key_put(dim_core_keyring);
	return ret;
}

void dim_core_sig_destroy(void)
{
	if (dim_core_keyring != NULL)
		key_put(dim_core_keyring);

	dim_hash_destroy(&dim_core_sig_hash);
}
