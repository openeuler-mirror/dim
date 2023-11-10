# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

obj-m := dim_test_module_demo.o

KERNEL := $(DESTDIR)/lib/modules/$(shell uname -r)/build
CONFIG_MODULE_SIG=n

PWD := $(shell pwd)

modules :
	$(MAKE) -C $(KERNEL) M=$(PWD) modules

.PHONEY:clean

clean :
	$(MAKE) -C $(KERNEL) SUBDIRS=$(PWD) clean
