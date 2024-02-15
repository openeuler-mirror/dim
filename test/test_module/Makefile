# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

obj-m := dim_test_module_demo.o

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all modules clean

all: modules

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean