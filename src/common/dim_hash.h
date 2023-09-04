/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_HASH_H
#define __DIM_HASH_H

#include <crypto/hash.h>
#include <crypto/hash_info.h>

#define DIM_MAX_DIGEST_SIZE 32 /* now is the size of SHA256 */

struct dim_hash {
	const char *name; /* algorithm name */
	struct crypto_shash *tfm;
	int algo; /* enum hash_algo */
};

struct dim_digest {
	int algo; /* enum hash_algo */
	char data[DIM_MAX_DIGEST_SIZE];
};

static inline int dim_hash_algo(const char *name)
{
	int idx = match_string(hash_algo_name, HASH_ALGO__LAST, name);
	return idx < 0 ? HASH_ALGO__LAST : idx;
}

static inline const char *dim_hash_name(int algo)
{
	return (algo < 0 || algo >= HASH_ALGO__LAST) ?
		NULL : hash_algo_name[algo];
}

static inline int dim_digest_size(int algo)
{
	return (algo < 0 || algo >= HASH_ALGO__LAST) ?
		0 : hash_digest_size[algo];
}

static inline bool dim_digest_is_zero(struct dim_digest *digest)
{
	struct dim_digest z_digest = { 0 };
	return memcmp(&z_digest, digest, sizeof(struct dim_digest)) == 0;
}

static inline int dim_digest_compare(struct dim_digest *x,
				     struct dim_digest *y)
{
	if (x->algo != y->algo)
		return x->algo > y->algo ? 1 : -1;

	return memcmp(x->data, y->data, dim_digest_size(x->algo));
}

static inline int dim_digest_copy(struct dim_digest *dst,
				  struct dim_digest *src)
{
	dst->algo = src->algo;
	memcpy(dst->data, src->data, dim_digest_size(dst->algo));
	return 0;
}

int dim_hash_init(const char *algo_name, struct dim_hash *hash);
void dim_hash_destroy(struct dim_hash *hash);
int dim_hash_calculate(const void *data, unsigned int len,
		       struct dim_hash *alg,
		       struct dim_digest *digest);

#endif
