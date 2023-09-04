/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/crypto.h>

#include "dim_tpm.h"

int dim_tpm_init(struct dim_tpm *tpm, int algo)
{
	int ret = 0;
	int i = 0;

	tpm->chip = tpm_default_chip();
	if (tpm->chip == NULL)
		return -ENODEV;

	tpm->digests = kcalloc(tpm->chip->nr_allocated_banks,
			       sizeof(struct tpm_digest), GFP_KERNEL);
	if (tpm->digests == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	tpm->bank = -1;
	for (i = 0; i < tpm->chip->nr_allocated_banks; i++) {
		tpm->digests[i].alg_id = tpm->chip->allocated_banks[i].alg_id;
		if (tpm->chip->allocated_banks[i].crypto_id == algo)
			tpm->bank = i;

		memset(tpm->digests[i].digest, 0xff, TPM_MAX_DIGEST_SIZE);
	}

	if (tpm->bank == -1) {
		ret = -ENOENT; /* fail to find matched TPM bank */
		goto err;
	}

	return 0;
err:
	put_device(&tpm->chip->dev);
	if (tpm->digests != NULL) {
		kfree(tpm->digests);
		tpm->digests = NULL;
	}

	tpm->chip = NULL;
	return ret;
}

int dim_tpm_pcr_extend(struct dim_tpm *tpm, int pcr, struct dim_digest *digest)
{
	int size = 0;

	if (tpm == NULL || digest == NULL)
		return -EINVAL;

	if (tpm->chip == NULL)
		return 0;

	size = dim_digest_size(digest->algo);
	if (size == 0 || size > TPM_MAX_DIGEST_SIZE)
		return -EINVAL;

	memcpy(tpm->digests[tpm->bank].digest, digest->data, size);
	return tpm_pcr_extend(tpm->chip, pcr, tpm->digests);
}

void dim_tpm_destroy(struct dim_tpm *tpm)
{
	if (tpm == NULL || tpm->chip == NULL)
		return;

	put_device(&tpm->chip->dev);
	kfree(tpm->digests);
}