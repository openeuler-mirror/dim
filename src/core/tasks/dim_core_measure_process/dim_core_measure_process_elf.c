/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "dim_hash.h"
#include "dim_utils.h"
#include "dim_measure.h"

#include "dim_vm_hash.h"
#include "dim_core_measure_process.h"

#define TRAMPOLINE_SECTION_NAME ".vos_patch_trampoline_seg"

static inline bool is_text_phdr(struct elf_phdr *phdr)
{
	return (phdr->p_type == PT_LOAD) && (phdr->p_flags & PF_R) &&
		(phdr->p_flags & PF_X) && !(phdr->p_flags & PF_W);
}

/* parse ELF header from an ELF file */
static int get_elf_ehdr(struct file *elf_file, struct elfhdr *ehdr)
{
	loff_t pos = 0;
	ssize_t size = 0;

	size = kernel_read(elf_file, ehdr, sizeof(struct elfhdr), &pos);
	if (size != sizeof(struct elfhdr))
		return size < 0 ? (int)size : -EIO;

	/* check elf header valid, now we only support the little end */
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr->e_ident[EI_CLASS] != ELF_CLASS ||
	    ehdr->e_ident[EI_DATA]  != ELFDATA2LSB ||
	    (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN))
		return -ENOEXEC;

	return 0;
}

/* parse ELF phders from an ELF file */
static int get_elf_phdrs(struct file *elf_file, struct elfhdr *ehdr,
			 struct elf_phdr **phdrs, unsigned int *num)
{
	struct elf_phdr *elf_phdata = NULL;
	size_t phdr_size = 0;
	ssize_t read_size = 0;

	if (ehdr->e_phentsize != sizeof(struct elf_phdr) ||
	    ehdr->e_phnum < 1 ||
	    ehdr->e_phnum > 65536U / sizeof(struct elf_phdr))
		return -ENOEXEC;

	phdr_size = sizeof(struct elf_phdr) * ehdr->e_phnum;
	elf_phdata = dim_kzalloc_gfp(phdr_size);
	if (elf_phdata == NULL)
		return -ENOMEM;

	read_size = kernel_read(elf_file, elf_phdata, phdr_size,
				&ehdr->e_phoff);
	if (read_size != phdr_size) {
		dim_kfree(elf_phdata);
		return read_size < 0 ? (int)read_size : -EIO;
	}

	*phdrs = elf_phdata;
	*num = ehdr->e_phnum;
	return 0;
}

/* parse ELF section by name from an ELF file */
static int get_elf_section(struct file *elf_file, struct elfhdr *ehdr,
			   const char *name, struct elf_shdr *shdr)
{
	int ret = 0;
	int i = 0;
	ssize_t size = 0;
	ssize_t name_len = 0;
	ssize_t str_size = 0;
	struct elf_shdr *sh_table = NULL;
	char *sh_str = NULL;
	loff_t pos;

	if (ehdr->e_shentsize != sizeof(struct elf_shdr))
		return -EBADF;

	sh_table = dim_kzalloc_gfp(ehdr->e_shentsize);
	if (sh_table == NULL)
		return -ENOMEM;

	/* find the shdr for section name */
	pos = ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shstrndx;
	size = kernel_read(elf_file, sh_table, ehdr->e_shentsize, &pos);
	if (size != ehdr->e_shentsize) {
		dim_kfree(sh_table);
		return size < 0 ? (int)size : -EBADF;
	}

	str_size = sh_table->sh_size;
	if (str_size > i_size_read(file_inode(elf_file))) {
		dim_kfree(sh_table);
		return -EBADF;
	}

	sh_str = dim_vzalloc(str_size);
	if (sh_str == NULL) {
		dim_kfree(sh_table);
		return -ENOMEM;
	}

	pos = sh_table->sh_offset;
	size = kernel_read(elf_file, sh_str, sh_table->sh_size, &pos);
	if (size != sh_table->sh_size) {
		dim_kfree(sh_table);
		dim_vfree(sh_str);
		return size < 0 ? (int)size : -EBADF;
	}

	ret = -ENOENT;
	pos = ehdr->e_shoff;
	name_len = strlen(name);
	for (i = 0; i < ehdr->e_shnum; i++) {
		size = kernel_read(elf_file, sh_table, ehdr->e_shentsize, &pos);
		if (size != ehdr->e_shentsize) {
			ret = size < 0 ? (int)size : -EBADF;
			break;
		}

		if (sh_table->sh_name + name_len < sh_table->sh_name ||
		    sh_table->sh_name + name_len >= str_size)
		    	break;

		if (dim_strcmp(name, sh_str + sh_table->sh_name) == 0) {
			memcpy(shdr, sh_table, sizeof(struct elf_shdr));
			ret = 0;
			break;
		}
	}

	dim_kfree(sh_table);
	dim_vfree(sh_str);
	return ret;
}

static int get_elf_text_phdrs(struct file *elf_file,
			      struct elfhdr *ehdr,
			      struct elf_phdr **phdrs_find,
			      unsigned int *phdrs_find_num)
{
	int ret = 0;
	int i = 0;
	struct elf_phdr *phdr = NULL;
	unsigned int phdr_idx = 0;
	struct elf_phdr *phdrs_get = NULL;
	unsigned int phdrs_get_num = 0;
	struct elf_phdr *phdrs_text = NULL;
	unsigned int phdrs_text_num = 0;

	/* get all elf program headers */
	ret = get_elf_phdrs(elf_file, ehdr, &phdrs_get, &phdrs_get_num);
	if (ret < 0)
		return ret;

	/* get the number of the text phdr */
	for (i = 0, phdr = phdrs_get; i < phdrs_get_num; i++, phdr++) {
		if (!is_text_phdr(phdr))
			continue;
		phdrs_text_num++;
	}

	if (phdrs_text_num == 0) {
		dim_kfree(phdrs_get);
		return -ENOEXEC;
	}

	/* alloc memory buffer for phdrs */
	phdrs_text = dim_kzalloc_gfp(phdrs_text_num * sizeof(struct elf_phdr));
	if (phdrs_text == NULL) {
		dim_kfree(phdrs_get);
		return -ENOMEM;
	}

	/* store the text phdrs */
	for (i = 0, phdr = phdrs_get; i < phdrs_get_num; i++, phdr++) {
		if (!is_text_phdr(phdr))
			continue;

		memcpy(&phdrs_text[phdr_idx], phdr, sizeof(struct elf_phdr));
		if (++phdr_idx >= phdrs_text_num)
			break;
	}

	*phdrs_find = phdrs_text;
	*phdrs_find_num = phdrs_text_num;
	dim_kfree(phdrs_get);
	return 0;
}

static int get_elf_measure_area(struct file *elf_file,
				struct elf_phdr **phdrs_text,
				unsigned int *phdrs_text_num,
				struct elf_shdr *shdr_trampoline,
				bool *shdr_trampoline_find)
{
	int ret = 0;
	struct elfhdr ehdr = { 0 };

	ret = get_elf_ehdr(elf_file, &ehdr);
	if (ret < 0) {
		dim_err("fail to get ELF header: %d\n", ret);
		return ret;
	}

	ret = get_elf_text_phdrs(elf_file, &ehdr, phdrs_text, phdrs_text_num);
	if (ret < 0) {
		dim_err("fail to get ELF text phdrs: %d\n", ret);
		return ret;
	}

	// TODO
	ret = get_elf_section(elf_file, &ehdr, TRAMPOLINE_SECTION_NAME, shdr_trampoline);
	if (ret == 0)
		*shdr_trampoline_find = true;
	else if (ret < 0 && ret != -ENOENT)
		dim_warn("fail to get ELF trampoline shdr: %d\n", ret);

	return 0;
}

static int measure_elf_trampoline(struct vm_area_struct *vma,
				  struct elf_shdr *shdr_trampoline,
				  struct task_measure_ctx *ctx)
{
	int ret = 0;
	struct vm_area_struct *vma_trampoline = NULL;
	unsigned long addr_trampoline = 0;
	struct dim_digest digest = {
		.algo = ctx->m->hash.algo,
	};

	addr_trampoline = vma->vm_start + shdr_trampoline->sh_addr;
	vma_trampoline = find_vma(vma->vm_mm, addr_trampoline);
	if (vma_trampoline == NULL || !vma_is_text(vma_trampoline) ||
	    vma_trampoline->vm_start != addr_trampoline)
		return -ENOENT;

	ret = dim_vm_hash_calculate_vma(vma_trampoline, &ctx->m->hash, &digest);
	if (ret < 0) {
		dim_err("failed to calculate trampoline vma digest\n");
		return ret;
	}

	return ctx->check(&digest, ctx);
}

static int measure_elf_text(struct vm_area_struct *vma,
			    struct elf_phdr *phdrs_text,
			    unsigned int phdrs_text_num,
			    struct task_measure_ctx *ctx)
{
	int ret = 0;
	unsigned int i = 0;
	unsigned long addr = 0;
	struct elf_phdr *phdr = NULL;
	struct dim_digest digest = {
		.algo = ctx->m->hash.algo,
	};
	SHASH_DESC_ON_STACK(shash, ctx->m->hash.tfm);

	shash->tfm = ctx->m->hash.tfm;
	ret = crypto_shash_init(shash);
	if (ret < 0)
		return ret;
	
	for (; i < phdrs_text_num; i++) {
		phdr = &phdrs_text[i];
		addr = vma->vm_start + phdr->p_vaddr - vma->vm_pgoff * PAGE_SIZE;
		ret = dim_vm_hash_update_address(vma->vm_mm, addr,
						 phdr->p_memsz, shash);
		if (ret < 0)
			dim_err("failed to update elf text: %d\n", ret);
	}

	ret = crypto_shash_final(shash, digest.data);
	if (ret < 0)
		return ret;

	return ctx->check(&digest, ctx);
}

int measure_process_module_text_elf(struct vm_area_struct *vma,
				    struct task_measure_ctx *ctx)
{
	int ret = 0;
	struct file *elf_file = get_vm_file(vma);
	struct elf_phdr *phdrs_text = NULL;
	unsigned int phdrs_text_num = 0;
	struct elf_shdr shdr_trampoline = { 0 };
	bool shdr_trampoline_find = false;

	if (vma == NULL || !vma_is_file_text(vma) || ctx == NULL
	    || ctx->m == NULL || ctx->check == NULL)
		return -EINVAL;

	if (elf_file == NULL) {
		dim_err("failed to get elf file from vma\n");
		return -ENOEXEC;
	}

	ret = get_elf_measure_area(elf_file, &phdrs_text, &phdrs_text_num,
				   &shdr_trampoline, &shdr_trampoline_find);
	if (ret < 0) {
		dim_err("failed to get elf measure area from vma\n");
		return ret;
	}

	ret = measure_elf_text(vma, phdrs_text, phdrs_text_num, ctx);
	dim_kfree(phdrs_text);
	if (ret < 0) {
		dim_err("failed to measure elf text: %d\n", ret);
		return ret;
	}

	if (shdr_trampoline_find) {
		ret = measure_elf_trampoline(vma, &shdr_trampoline, ctx);
		if (ret < 0) {
			dim_err("failed to measure elf trampoline: %d\n", ret);
			return ret;
		}
	}

	return 0;
}
