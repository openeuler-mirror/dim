/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_TPM_H
#define __DIM_TPM_H

#include <linux/tpm.h>
#include "dim_hash.h"

#define DIM_PCR_MAX 128

struct dim_tpm {
	struct tpm_chip *chip;
	struct tpm_digest *digests;
	int bank;
};

int dim_tpm_init(struct dim_tpm *tpm, int algo);
int dim_tpm_pcr_extend(struct dim_tpm *tpm, int pcr, struct dim_digest *digest);
void dim_tpm_destroy(struct dim_tpm *tpm);

#endif