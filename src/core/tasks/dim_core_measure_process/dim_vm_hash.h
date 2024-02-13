/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_VM_HASH_H
#define __DIM_VM_HASH_H

#include <linux/mm.h>

#include "dim_hash.h"

int dim_vm_hash_update_address(struct mm_struct *mm,
			       unsigned long addr_start,
			       unsigned long addr_len,
			       struct shash_desc *shash);

int dim_vm_hash_update_vmas(struct vm_area_struct *vma_start,
			    struct vm_area_struct *vma_end,
			    struct shash_desc *shash);

int dim_vm_hash_calculate_vma(struct vm_area_struct *vma,
			      struct dim_hash *hash,
			      struct dim_digest *digest);

#endif