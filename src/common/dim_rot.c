/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include "dim_utils.h"
#include "dim_rot.h"

static struct dim_rot *dim_rot_prefered = NULL;

/* Support list: TPM, virtCCA */
static struct dim_rot *dim_supported_rots[] = {
#ifdef CONFIG_TCG_TPM
	&dim_rot_tpm,
#endif
#ifdef CONFIG_HISI_VIRTCCA_GUEST
	&dim_rot_virtcca,
#endif
};

int dim_rot_init(const char *name, int algo, int slot)
{
	int i = 0;
	int ret = 0;

	if (name == NULL || name[0] == '\0') {
		dim_info("No specified RoT device\n");
		return 0;
	}

	if (DIM_ARRAY_LEN(dim_supported_rots) == 0) {
		dim_info("No supported RoT device\n");
		return 0;
	}

	for (i = 0; i < DIM_ARRAY_LEN(dim_supported_rots); i++) {
		if (strcmp(name, dim_supported_rots[i]->name) == 0) {
			dim_rot_prefered = dim_supported_rots[i];
			break;
		}
	}

	if (dim_rot_prefered == NULL) {
		/* If not find, use the default device */
		dim_rot_prefered = dim_supported_rots[0];
		dim_info("Cannot find the specified RoT %s\n",
			 dim_rot_prefered->name);

		return -EINVAL;
	}

	ret = dim_rot_prefered->init(dim_rot_prefered, algo, slot);
	if (ret < 0)
		dim_err("Failed to initialize RoT device %s: %d\n",
			dim_rot_prefered->name, ret);
	else
		dim_info("Succeed to initialize RoT device %s\n",
			 dim_rot_prefered->name);

	return ret;
}

int dim_rot_extend(struct dim_digest *digest)
{
	if (dim_rot_prefered == NULL)
		return 0;

	return dim_rot_prefered->extend(dim_rot_prefered, digest);
}

int dim_calc_boot_aggregate(struct dim_digest *digest)
{
	if (dim_rot_prefered == NULL)
		return -ENXIO;

	return dim_rot_prefered->calc_boot_aggregate(digest);
}

void dim_rot_destroy(void)
{
	if (dim_rot_prefered == NULL)
		return;

	dim_rot_prefered->destroy(dim_rot_prefered);
}

int dim_rot_slot(void)
{
	if (dim_rot_prefered == NULL)
		return 0;

	return dim_rot_prefered->slot(dim_rot_prefered);
}