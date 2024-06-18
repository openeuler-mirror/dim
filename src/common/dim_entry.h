/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#ifndef __DIM_ENTRY_H
#define __DIM_ENTRY_H

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/seq_file.h>

#include "dim_measure_log.h"

#define DIM_ENTRY_DIR_MASK (S_IFDIR | S_IXUSR | S_IRUSR)
#define DIM_ENTRY_RW_MASK (S_IWUSR | S_IRUSR)
#define DIM_ENTRY_W_MASK (S_IWUSR)
#define DIM_ENTRY_R_MASK (S_IRUSR)
#define DIM_FS_TMP_BUF_SIZE 512

struct dim_entry {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
	struct dentry *dentry;
};

/* the file interface for trigger by 'echo 1 > file_path' */
#define dim_trigger_entry(sname, fname, function)			\
static ssize_t sname##_trigger(struct file *file,			\
			       const char __user *buf,			\
			       size_t count, loff_t *ppos)		\
{									\
	int val = 0;							\
	int ret = 0;							\
									\
	if (*ppos != 0 || count > 2)					\
		return -EINVAL;						\
									\
	ret = kstrtoint_from_user(buf, count, 10, &val);		\
	if (ret < 0 || val != 1)					\
		return ret < 0 ? ret : -EINVAL;				\
									\
	ret = function();						\
	if (ret < 0)							\
		return ret;						\
									\
	return count;							\
}									\
									\
static const struct file_operations sname##_ops = {			\
	.owner = THIS_MODULE,						\
	.write = sname##_trigger,					\
	.llseek = generic_file_llseek,					\
};									\
									\
static struct dim_entry sname##_entry = {				\
	.name = #fname,							\
	.mode = DIM_ENTRY_W_MASK,					\
	.fops = &sname##_ops,						\
};

/* the file interface for reading measure log */
#define dim_measure_log_entry(sname, fname, root_ptr)			\
static void *measure_log_read_start(struct seq_file *m, loff_t *pos)	\
{									\
	read_lock(&(root_ptr)->lock);					\
	return seq_list_start(&(root_ptr)->list_root, *pos);		\
}									\
									\
static void *measure_log_read_next(struct seq_file *m,			\
				   void *v, loff_t *pos)		\
{									\
	return seq_list_next(v, &(root_ptr)->list_root, pos);		\
}									\
									\
static void measure_log_read_stop(struct seq_file *m, void *v)		\
{									\
	read_unlock(&(root_ptr)->lock);					\
}									\
									\
static int measure_log_read_show(struct seq_file *m, void *v)		\
{									\
	struct dim_measure_log *log =					\
		list_entry(v, struct dim_measure_log, node_order);	\
									\
	return dim_measure_log_seq_show(m, log);			\
}									\
									\
const struct seq_operations sname##_seqops = {				\
	.start = measure_log_read_start,				\
	.next = measure_log_read_next,					\
	.stop = measure_log_read_stop,					\
	.show = measure_log_read_show,					\
};									\
									\
static int sname##_open(struct inode *inode, struct file *file)		\
{									\
	return seq_open(file, &sname##_seqops);				\
}									\
									\
static const struct file_operations sname##_ops = {			\
	.owner = THIS_MODULE,						\
	.open = sname##_open,						\
	.read = seq_read,						\
	.llseek = seq_lseek,						\
	.release = seq_release,						\
};									\
									\
static struct dim_entry sname##_entry = {				\
	.name = #fname,							\
	.mode = DIM_ENTRY_R_MASK,					\
	.fops = &sname##_ops,						\
};

/* the file interface for print string */
#define dim_string_print_entry(sname, fname, function)			\
static ssize_t sname##_read(struct file *file,				\
			    char __user *buf,				\
			    size_t count, loff_t *ppos)			\
{									\
	char tmpbuf[DIM_FS_TMP_BUF_SIZE];				\
	ssize_t len;							\
									\
	len = scnprintf(tmpbuf,						\
			DIM_FS_TMP_BUF_SIZE,				\
			"%s\n",						\
			function());					\
									\
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);	\
}									\
									\
static const struct file_operations sname##_ops = {			\
	.owner = THIS_MODULE,						\
	.read = sname##_read,						\
	.llseek = generic_file_llseek,					\
};									\
									\
static struct dim_entry sname##_entry = {				\
	.name = #fname,							\
	.mode = DIM_ENTRY_R_MASK,					\
	.fops = &sname##_ops,						\
};

/* the file interface for reading and writing uint parameter */
#define dim_uint_rw_entry(sname, fname, read_func, write_func)		\
static ssize_t sname##_read(struct file *file,				\
			    char __user *buf,				\
			    size_t count, loff_t *ppos)			\
{									\
	long len = 0;							\
	long val = 0;							\
	char tmpbuf[DIM_FS_TMP_BUF_SIZE];				\
									\
	val = read_func();						\
	if (val < 0)							\
		return val;						\
									\
	len = scnprintf(tmpbuf, DIM_FS_TMP_BUF_SIZE, "%ld\n", val);	\
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);	\
}									\
									\
static ssize_t sname##_write(struct file *file,				\
			     const char __user *buf,			\
			     size_t count, loff_t *ppos)		\
{									\
	int ret = 0;							\
	unsigned int val;						\
									\
	ret = kstrtouint_from_user(buf, count, 10, &val);		\
	if (ret < 0)							\
		return -EINVAL;						\
									\
	ret = write_func(val);						\
	return ret < 0 ? ret : count;					\
}									\
									\
static const struct file_operations sname##_ops = {			\
	.owner = THIS_MODULE,						\
	.read = sname##_read,						\
	.write = sname##_write,						\
	.llseek = generic_file_llseek,					\
};									\
									\
static struct dim_entry sname##_entry = {				\
	.name = #fname,							\
	.mode = DIM_ENTRY_RW_MASK,					\
	.fops = &sname##_ops,						\
};

int dim_entry_create(struct dim_entry *entry, struct dentry *parent);
void dim_entry_remove(struct dim_entry *entry);
int dim_entry_create_list(struct dim_entry **list,
			  unsigned int len,
			  struct dentry *parent);
void dim_entry_remove_list(struct dim_entry **list, unsigned int len);

#endif

