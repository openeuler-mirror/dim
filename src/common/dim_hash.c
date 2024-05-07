/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/err.h>

#include "dim_hash.h"
#include "dim_utils.h"

static const char *allow_hash[] = {
	"sha256",
#ifdef DIM_HASH_SUPPORT_SM3
	"sm3",
#endif
};

int dim_hash_init(const char *algo_name, struct dim_hash *hash)
{
	int ret = 0;

	if (algo_name == NULL || hash == NULL ||
	    match_string(allow_hash, DIM_ARRAY_LEN(allow_hash), algo_name) < 0)
		return -EINVAL;

	hash->algo = dim_hash_algo(algo_name);
	if (hash->algo == HASH_ALGO__LAST)
		return -EINVAL;

	hash->tfm = crypto_alloc_shash(algo_name, 0, 0);
	if (IS_ERR(hash->tfm)) {
		ret = PTR_ERR(hash->tfm);
		hash->tfm = NULL;
	}

	hash->name = algo_name;
	return ret;
}

void dim_hash_destroy(struct dim_hash *hash)
{
	if (hash == NULL)
		return;

	crypto_free_shash(hash->tfm);
	hash->tfm = NULL;
}

int dim_hash_calculate(const void *data, unsigned int len,
		       struct dim_hash *alg,
		       struct dim_digest *digest)
{
	int ret = 0;
	SHASH_DESC_ON_STACK(shash, alg->tfm);

	if (data == NULL || alg == NULL || digest == NULL || alg->tfm == NULL)
		return -EINVAL;

	digest->algo = alg->algo;
	shash->tfm = alg->tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	ret = crypto_shash_update(shash, data, len);
	if (ret < 0)
		return ret;

	return crypto_shash_final(shash, digest->data);
}
