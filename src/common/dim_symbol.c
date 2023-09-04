/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/kallsyms.h>

#include "dim_symbol.h"

static int find_kernel_symbol(unsigned long addr,
			      char *buf,
			      size_t *offset,
			      size_t *size)
{
	char tmp[KSYM_SYMBOL_LEN] = { 0 };

	sprint_symbol(tmp, addr);

	memset(buf, 0, KSYM_NAME_LEN);
	return sscanf(tmp, "%127[^+]+%lx/%lx", buf, offset, size) == 3
		? 0 : -EINVAL;
}

DIM_SYMBOL_LOOKUP_FUNC dim_get_symbol_lookup_func(void)
{
	unsigned long kaddr = (unsigned long)&sprint_symbol;
	unsigned long prev = kaddr - 1;
	unsigned long next = kaddr;
	size_t offset, size;
	int i, ret;
	char symbol_name[KSYM_NAME_LEN] = { 0 };

	for (i = 0; i < DIM_TRY_COUNT; i++) {
		ret = find_kernel_symbol(kaddr, symbol_name, &offset, &size);
		if (ret < 0 || offset > size)
			break;

		if (strcmp(symbol_name, DIM_KALLSYMS_LOOKUP_NAME) == 0)
			return (DIM_SYMBOL_LOOKUP_FUNC)(kaddr - offset);

		if (kaddr == next) {
			next = next + size - offset;
			kaddr = prev;
		} else {
			prev = prev - offset - 1;
			kaddr = next;
		}
	}

	return NULL;
}