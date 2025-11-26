// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifdef CONFIG_HISI_VIRTCCA_GUEST

#include <asm/virtcca_cvm_smc.h>
#include <asm/virtcca_cvm_guest.h>
#include <crypto/hash_info.h>

#define DEFAULT_CCA_REM_IDX 4
static enum hash_algo virtcca_algo;
static int dim_virtcca_enable = 0;
static int dim_virtcca_init_algo(int algo)
{
	unsigned long result;
	struct virtcca_cvm_config cfg = { 0 };

	result = tsi_get_cvm_config(&cfg);
	if (result != TSI_SUCCESS) {
		pr_info("Error reading cvm config\n");
		return -EFAULT;
	}

	/* 0: SHA256, 1: SHA512 */
	virtcca_algo = cfg.algorithm ? HASH_ALGO_SHA512 : HASH_ALGO_SHA256;

	return 0;
}

static int dim_virtcca_init(struct dim_rot *rot, int algo, int rem) // TODO
{
	int rc;

	if (!is_virtcca_cvm_world() || tsi_get_version() == SMCCC_RET_NOT_SUPPORTED)
		return -ENODEV;

	rc = dim_virtcca_init_algo(virtcca_algo);
	if (rc)
		return rc;

	dim_virtcca_enable = 1;
	return 0;
}

static int dim_virtcca_get_rem(struct dim_rot *rot)
{
	if (dim_virtcca_enable == 0)
		return 0;

	return DEFAULT_CCA_REM_IDX; // TODO
}

static int dim_virtcca_extend(struct dim_digest *digests)
{
	struct virtcca_cvm_measurement_extend cme;

	if (dim_virtcca_enable == 0)
		return -EINVAL;

	// Now, in virtCCA, DIM can only use REM4
	cme.index = DEFAULT_CCA_REM_IDX;
	cme.size = hash_digest_size[virtcca_algo];

	/*
	 * virtcca has only one slot, so the algorithm of digests_arg[0] is always
	 * virtcca_algo according to the init process of ima_init_crypto() and
	 * ima_init_digets()
	 */
	memcpy(cme.value, digests[0].data, cme.size);

	return tsi_measurement_extend(&cme) == TSI_SUCCESS ? 0 : -EFAULT;
}

static int dim_virtcca_calc_boot_aggregate(struct dim_digest *digest)
{
	unsigned long result;
	struct virtcca_cvm_measurement cm = { 0 };

	digest->algo = virtcca_algo;

	/* Read the measurement result of RIM as the boot aggregate */

	cm.index = RIM_MEASUREMENT_SLOT;

	result = tsi_measurement_read(&cm);
	if (result != TSI_SUCCESS) {
		pr_err("Error reading cvm measurement 0 for boot aggregate\n");
		return -EFAULT;
	}

	memcpy(digest->data, cm.value, dim_digest_size(virtcca_algo));
	return 0;
}

static void dim_virtcca_destroy(struct dim_rot *rot)
{
	return;
}

struct dim_rot dim_rot_virtcca = {
	.name = "virtcca",
	.init = dim_virtcca_init,
	.destroy = dim_virtcca_destroy,
	.slot = dim_virtcca_get_rem,
	.extend = dim_virtcca_extend,
	.calc_boot_aggregate = dim_virtcca_calc_boot_aggregate,
};

#endif