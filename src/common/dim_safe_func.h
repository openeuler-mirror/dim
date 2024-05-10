/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_SAFE_FUNC_H
#define __DIM_SAFE_FUNC_H

#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include "dim_utils.h"

#ifdef DIM_DEBUG_MEMORY_LEAK
extern atomic_t dim_alloc_num;

static inline void dim_alloc_debug_inc(void)
{
	atomic_inc(&dim_alloc_num);
}

static inline void dim_alloc_debug_dec(void)
{
	atomic_dec(&dim_alloc_num);
}

static inline void dim_print_alloc_num(const char *s)
{
	dim_info("%s: dim_alloc_num=%d\n", s, atomic_read(&dim_alloc_num));
}

void dim_check_memory_leak(void);
#endif

static inline void *dim_kzalloc_gfp(size_t size)
{
#ifdef DIM_DEBUG_MEMORY_LEAK
	void *data = kzalloc(size, GFP_KERNEL);
	if (data != NULL)
		dim_alloc_debug_inc();
	return data;
#else
	return kzalloc(size, GFP_KERNEL);
#endif
}

static inline void *dim_kcalloc_gfp(size_t n, size_t size)
{
#ifdef DIM_DEBUG_MEMORY_LEAK
	void *data = kcalloc(n, size, GFP_KERNEL);
	if (data != NULL)
		dim_alloc_debug_inc();
	return data;
#else
	return kcalloc(n, size, GFP_KERNEL);
#endif
}

static inline void *dim_krealloc_atom(const void *p, size_t new_size)
{
	return krealloc(p, new_size, GFP_ATOMIC);
}

static inline void *dim_kmemdup_gfp(const void *src, size_t len)
{
#ifdef DIM_DEBUG_MEMORY_LEAK
	void *data = kmemdup(src, len, GFP_KERNEL);
	if (data != NULL)
		dim_alloc_debug_inc();
	return data;
#else
	return kmemdup(src, len, GFP_KERNEL);
#endif
}

static inline void dim_kfree(const void *objp)
{
#ifdef DIM_DEBUG_MEMORY_LEAK
	if (objp != NULL)
		dim_alloc_debug_dec();
#endif
	kfree(objp);
}

static inline void *dim_vzalloc(size_t size)
{
#ifdef DIM_DEBUG_MEMORY_LEAK
	void *data = vzalloc(size);
	if (data != NULL)
		dim_alloc_debug_inc();
	return data;
#else
	return vzalloc(size);
#endif
}

static inline void dim_vfree(void *data)
{
#ifdef DIM_DEBUG_MEMORY_LEAK
	if (data != NULL)
		dim_alloc_debug_dec();
#endif
	vfree(data);
}

static inline char *dim_kstrdup_gfp(const char *s)
{
#ifdef DIM_DEBUG_MEMORY_LEAK
	void *data = kstrdup(s, GFP_KERNEL);
	if (data != NULL)
		dim_alloc_debug_inc();
	return data;
#else
	return kstrdup(s, GFP_KERNEL);
#endif
}

static inline int dim_strcmp(const char *cs, const char *ct)
{
	if (cs == NULL || ct == NULL)
		return -1;

	return strcmp(cs, ct);
}

static inline int dim_strncmp(const char *cs, const char *ct, size_t count)
{
	if (cs == NULL || ct == NULL)
		return -1;

	return strncmp(cs, ct, count);
}

#endif
