/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/mm.h>

#include "dim_safe_func.h"
#include "dim_utils.h"

#include "dim_core_mem_pool.h"

static struct gen_pool *dim_pool = NULL;

static int dim_mem_pool_expand(unsigned int order)
{
	int ret = -ENOMEM;
	struct page *pages = NULL;
	unsigned long pages_addr = 0;
	size_t size = (1 << order) << PAGE_SHIFT;

	pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (pages == NULL) {
		dim_err("failed to allocate pages for memory pool\n");
		return -ENOMEM;
	}

	pages_addr = (unsigned long)page_address(pages);
	dim_devel("alloc_pages: addr = 0x%lx, order = %d\n", pages_addr, order);

	ret = gen_pool_add(dim_pool, pages_addr, size, -1);
	if (ret < 0) {
		dim_err("failed to add pages to memory pool: %d\n", ret);
		return ret;
	}

	dim_devel("dim_mem_pool_expand: %lu\n", size);
	return 0;
}

int dim_mem_pool_init(void)
{
	int ret = 0;

	dim_pool = gen_pool_create(DIM_MIN_ALLOC_ORDER, -1);
	if (dim_pool == NULL) {
		dim_err("failed to generate memory pool\n");
		return -ENOMEM;
	}

	ret = dim_mem_pool_expand(DIM_EXPEND_ALLOC_PAGE_ORDER);
	if (ret < 0) {
		gen_pool_destroy(dim_pool);
		dim_pool = NULL;
	}

	return ret;
}

static void free_chunk(struct gen_pool *pool,
		       struct gen_pool_chunk *chunk,
		       void *data __always_unused)
{
	if (chunk == NULL)
		return;

	dim_devel("free_pages: addr = 0x%lx, order = %d\n",
		  chunk->start_addr, DIM_EXPEND_ALLOC_PAGE_ORDER);
	free_pages(chunk->start_addr, DIM_EXPEND_ALLOC_PAGE_ORDER);
}

void dim_mem_pool_destroy(void)
{
	if (dim_pool == NULL)
		return;

	if (gen_pool_avail(dim_pool) != gen_pool_size(dim_pool)) {
		dim_err("dim_mem_pool_destroy failed, memory leak detected\n");
		return;
	}

	gen_pool_for_each_chunk(dim_pool, free_chunk, NULL);
	gen_pool_destroy(dim_pool);
	dim_pool = NULL;
}

void *dim_mem_pool_alloc(size_t size)
{
	int ret = 0;
	struct dim_pool_mem *data = NULL;
	size_t mem_size = size + sizeof(struct dim_pool_mem);

	if (size > DIM_MAX_ALLOC_SIZE || mem_size > DIM_MAX_ALLOC_SIZE) {
		dim_err("memory pool over allocate size: %lu", size);
		return NULL;
	}

	data = (struct dim_pool_mem *)gen_pool_alloc(dim_pool, mem_size);
	if (data != NULL)
		goto out;

	dim_devel("gen_pool_alloc failed, try dim_mem_pool_expand\n");
	ret = dim_mem_pool_expand(DIM_EXPEND_ALLOC_PAGE_ORDER);
	if (ret < 0) {
		dim_err("failed to expand memory pool: %d\n", ret);
		return NULL;
	}

	data = (struct dim_pool_mem *)gen_pool_alloc(dim_pool, mem_size);
	if (data == NULL)
		return NULL;
out:
	#ifdef DIM_DEBUG_MEMORY_LEAK
		dim_alloc_debug_inc();
	#endif
	data->size = mem_size;
	return data->data;
}

void dim_mem_pool_free(const void *data)
{
	struct dim_pool_mem *mem = NULL;

	if (!gen_pool_has_addr(dim_pool, (uintptr_t)data, 1)) {
		dim_err("addr 0x%lx is not in the memory pool\n",
		       (uintptr_t)data);
		return;
	}

	mem = container_of(data, struct dim_pool_mem, data);
	if (!gen_pool_has_addr(dim_pool, (uintptr_t)mem, mem->size)) {
		dim_err("addr 0x%lx (size %lu) is not in the memory pool\n",
		       (uintptr_t)mem, mem->size);
		       return;
	}

	gen_pool_free(dim_pool, (uintptr_t)mem, mem->size);

	#ifdef DIM_DEBUG_MEMORY_LEAK
		dim_alloc_debug_dec();
	#endif
}

void dim_mem_pool_walk_chunk(pool_chunk_visitor f, void *data)
{
	gen_pool_for_each_chunk(dim_pool, f, data);
}
EXPORT_SYMBOL_GPL(dim_mem_pool_walk_chunk);
