/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */
#ifndef __DIM_ROT_H
#define __DIM_ROT_H

#include "dim_hash.h"

struct dim_rot {
	const char *name;

	int (*init)(struct dim_rot *rot, int algo, int slot);
	void (*destroy)(struct dim_rot *rot);
	int (*slot)(struct dim_rot *rot);
	int (*extend)(struct dim_rot *rot, struct dim_digest *digest);
	int (*calc_boot_aggregate)(struct dim_digest *digest);
};

#ifdef CONFIG_TCG_TPM
extern struct dim_rot dim_rot_tpm;
#endif
#ifdef CONFIG_HISI_VIRTCCA_GUEST
extern struct dim_rot dim_rot_virtcca;
#endif

int dim_rot_init(const char *name, int algo, int slot);
int dim_rot_extend(struct dim_digest *digest);
int dim_calc_boot_aggregate(struct dim_digest *digest);
int dim_rot_slot(void);
void dim_rot_destroy(void);

#endif