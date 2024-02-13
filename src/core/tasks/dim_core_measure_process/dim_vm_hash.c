/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>

#include "dim_utils.h"

#include "dim_vm_hash.h"

int dim_vm_hash_update_address(struct mm_struct *mm,
			       unsigned long addr_start,
			       unsigned long addr_len,
			       struct shash_desc *shash)
{
	int ret = 0;
	unsigned long i = 0;
	long ret_pages = 0;
	void *page_ptr = NULL;
	struct page **pages = NULL;
	unsigned int update_size = PAGE_SIZE;
	unsigned long nr_pages = DIV_ROUND_UP(addr_len, PAGE_SIZE);

	if (mm == NULL || addr_len == 0 || shash == NULL)
		return -EINVAL;

	pages = vzalloc(nr_pages * sizeof(struct page *));
	if (pages == NULL)
		return -ENOMEM;

	ret_pages = get_user_pages_remote(mm, addr_start, nr_pages,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,4,0)
					  0, pages, NULL, NULL);
#else
					  0, pages, NULL);
#endif
	if (ret_pages < 0) {
		dim_err("failed to get remote pages: %ld\n", ret_pages);
		vfree(pages);
		return ret_pages;
	} else if (ret_pages != nr_pages) {
		dim_warn("failed to get all remote pages\n");
	}

	for (i = 0; i < ret_pages; i++) {
		page_ptr = kmap(pages[i]);
		if (page_ptr == NULL) {
			dim_err("failed to kmap remote page\n");
			put_page(pages[i]);
			continue;
		}

		if (i == ret_pages - 1)
			update_size = addr_len % PAGE_SIZE ?
				addr_len % PAGE_SIZE : PAGE_SIZE;

		ret = crypto_shash_update(shash, page_ptr, update_size);
		if (ret < 0)
			dim_warn("failed to update hash: %d\n", ret);

		kunmap(pages[i]);
		put_page(pages[i]);
	}

	vfree(pages);
	return 0;
}

/* calculate hash digest of continuous vma */
int dim_vm_hash_update_vmas(struct vm_area_struct *vma_start,
			    struct vm_area_struct *vma_end,
			    struct shash_desc *shash)
{
	if (vma_start == NULL || vma_end == NULL || shash == NULL ||
	    vma_start->vm_mm != vma_end->vm_mm ||
	    vma_start->vm_start >= vma_end->vm_end)
		return -EINVAL;

	return dim_vm_hash_update_address(vma_start->vm_mm, vma_start->vm_start,
				vma_end->vm_end - vma_start->vm_start, shash);
}

/* calculate hash digest of vma */
int dim_vm_hash_calculate_vma(struct vm_area_struct *vma,
			      struct dim_hash *hash,
			      struct dim_digest *digest)
{
	int ret = 0;
	/* check here to avoid code check warning */
	SHASH_DESC_ON_STACK(shash, hash == NULL ? NULL : hash->tfm);

	if (vma == NULL || hash == NULL || digest == NULL)
		return -EINVAL;

	shash->tfm = hash->tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;

	ret = dim_vm_hash_update_vmas(vma, vma, shash);
	if (ret < 0)
		return ret;

	return crypto_shash_final(shash, digest->data);
}
