/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifdef CONFIG_TCG_TPM

#include <linux/tpm.h>
#include <linux/crypto.h>

#include "dim_rot.h"
#include "dim_safe_func.h"
#include "dim_utils.h"

#define DIM_PCR_MAX 128
enum tpm_pcrs { TPM_PCR0 = 0, TPM_PCR10 = 10 };

/* TPM chip instance */
static struct tpm_chip *dim_tpm_chip = NULL;
/* Buffer for TPM digest extending */
struct tpm_digest *dim_tpm_digests = NULL;
/* TPM algorithm bank */
static int dim_tpm_bank = 0;
/* TPM pcr index */
static unsigned int dim_tpm_pcr = 0;

static int dim_tpm_init(struct dim_rot *rot, int algo, int pcr)
{
	int ret = 0;
	int i = 0;

	dim_tpm_chip = tpm_default_chip();
	if (dim_tpm_chip == NULL)
		return -ENODEV;

	dim_tpm_digests = dim_kcalloc_gfp(dim_tpm_chip->nr_allocated_banks,
					  sizeof(struct tpm_digest));
	if (dim_tpm_digests == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	dim_tpm_bank = -1;
	for (i = 0; i < dim_tpm_chip->nr_allocated_banks; i++) {
		dim_tpm_digests[i].alg_id =
			dim_tpm_chip->allocated_banks[i].alg_id;
		if (dim_tpm_chip->allocated_banks[i].crypto_id == algo)
			dim_tpm_bank = i;

		memset(dim_tpm_digests[i].digest, 0xff, TPM_MAX_DIGEST_SIZE);
	}

	if (dim_tpm_bank == -1) {
		ret = -ENOENT; /* fail to find matched TPM bank */
		goto err;
	}

	dim_tpm_pcr = pcr;
	if (dim_tpm_pcr > DIM_PCR_MAX)
		return -EINVAL;

	return 0;
err:
	put_device(&dim_tpm_chip->dev);
	if (dim_tpm_digests != NULL) {
		dim_kfree(dim_tpm_digests);
		dim_tpm_digests = NULL;
	}

	dim_tpm_chip = NULL;
	return ret;
}

static int dim_tpm_extend(struct dim_rot *rot, struct dim_digest *digest)
{
	int size = 0;

	if (digest == NULL)
		return -EINVAL;

	if (dim_tpm_chip == NULL)
		return 0;

	size = dim_digest_size(digest->algo);
	if (size == 0 || size > TPM_MAX_DIGEST_SIZE)
		return -EINVAL;

	memcpy(dim_tpm_digests[dim_tpm_bank].digest, digest->data, size);
	return tpm_pcr_extend(dim_tpm_chip, dim_tpm_pcr, dim_tpm_digests);
}

static int dim_tpm_get_pcr(struct dim_rot *rot)
{
	if (dim_tpm_chip == NULL)
		return 0;

	return dim_tpm_pcr;
}

static void dim_tpm_destroy(struct dim_rot *rot)
{
	if (dim_tpm_chip == NULL)
		return;

	put_device(&dim_tpm_chip->dev);
	dim_kfree(dim_tpm_digests);
	dim_tpm_chip = NULL;
	dim_tpm_digests = NULL;
}

static int tpm_hash_algo(int algo)
{
	int tpm_algo = -1;

	switch (algo) {
	case HASH_ALGO_SHA256:
		tpm_algo = TPM_ALG_SHA256;
		break;
	case HASH_ALGO_SM3_256:
		tpm_algo = TPM_ALG_SM3_256;
		break;
	    default:
		break;
	}

	return tpm_algo;
}

static int dim_tpm_calc_boot_aggregate(struct dim_digest *digest,
				       struct dim_hash *hash)
{
	int ret = 0;
	int i = 0;
	struct tpm_digest d = { 0 };
	SHASH_DESC_ON_STACK(shash, hash->tfm);

	shash->tfm = hash->tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	/* cumulative digest over TPM registers 0-10 */
	d.alg_id = tpm_hash_algo(digest->algo);
	for (i = TPM_PCR0; i < TPM_PCR10; i++) {
		ret = tpm_pcr_read(dim_tpm_chip, i, &d);
		if (ret < 0)
			return ret;

		ret = crypto_shash_update(shash, d.digest,
					  dim_digest_size(digest->algo));
		if (ret < 0)
			return ret;
	}

	return crypto_shash_final(shash, digest->data);
}

struct dim_rot dim_rot_tpm = {
	.name = "tpm",
	.init = dim_tpm_init,
	.destroy = dim_tpm_destroy,
	.slot = dim_tpm_get_pcr,
	.extend = dim_tpm_extend,
	.calc_boot_aggregate = dim_tpm_calc_boot_aggregate,
};

#endif