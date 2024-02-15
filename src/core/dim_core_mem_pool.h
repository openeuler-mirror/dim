/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_CORE_MEM_POOL
#define __DIM_CORE_MEM_POOL

#include <linux/genalloc.h>

/* Mininum allocation: 2 ^ 3 = 8 bytes */
#define DIM_MIN_ALLOC_ORDER 3
/* Expand allocation: 2 ^ 2 * 4k = 16k */
#define DIM_EXPEND_ALLOC_PAGE_ORDER 2
#define DIM_MAX_ALLOC_SIZE ((1 << DIM_EXPEND_ALLOC_PAGE_ORDER) << PAGE_SHIFT)

struct dim_pool_mem {
	size_t size;
	char data[0];
};

typedef void (*pool_chunk_visitor)(struct gen_pool *,
				   struct gen_pool_chunk *,
				   void *);

int dim_mem_pool_init(void);
void dim_mem_pool_destroy(void);
void *dim_mem_pool_alloc(size_t size);
void dim_mem_pool_free(const void *data);
void dim_mem_pool_walk_chunk(pool_chunk_visitor f, void *data);

#endif
