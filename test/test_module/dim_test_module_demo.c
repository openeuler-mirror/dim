/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 */

#include <linux/module.h>

static int test_mod_init(void)
{
    pr_info("init!\n");
    return 0;
}

static void test_mod_exit(void)
{
    pr_info("exit!\n");
}

module_init(test_mod_init);
module_exit(test_mod_exit);
MODULE_LICENSE("");
