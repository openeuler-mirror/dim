# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

obj-m := dim_core.o
obj-m += dim_monitor.o

dim_core-objs += core/dim_core_main.o
dim_core-objs += core/dim_core_fs.o
dim_core-objs += core/dim_core_mem_pool.o
dim_core-objs += core/dim_core_policy.o
dim_core-objs += core/dim_core_static_baseline.o
dim_core-objs += core/dim_core_baseline.o
dim_core-objs += core/dim_core_measure.o
dim_core-objs += core/dim_core_measure_task.o
dim_core-objs += core/dim_core_measure_module.o
dim_core-objs += core/dim_core_measure_kernel.o
dim_core-objs += core/dim_core_measure_common.o
dim_core-objs += core/dim_core_status.o
dim_core-objs += core/dim_core_symbol.o
dim_core-objs += core/dim_core_sig.o
dim_core-objs += common/dim_entry.o
dim_core-objs += common/dim_utils.o
dim_core-objs += common/dim_baseline.o
dim_core-objs += common/dim_hash.o
dim_core-objs += common/dim_measure_log.o
dim_core-objs += common/dim_status.o
dim_core-objs += common/dim_tpm.o
dim_core-objs += common/dim_symbol.o

dim_monitor-objs += monitor/dim_monitor_main.o
dim_monitor-objs += monitor/dim_monitor_fs.o
dim_monitor-objs += monitor/dim_monitor_measure.o
dim_monitor-objs += monitor/dim_monitor_symbol.o
dim_monitor-objs += common/dim_entry.o
dim_monitor-objs += common/dim_hash.o
dim_monitor-objs += common/dim_status.o
dim_monitor-objs += common/dim_utils.o
dim_monitor-objs += common/dim_measure_log.o
dim_monitor-objs += common/dim_baseline.o
dim_monitor-objs += common/dim_tpm.o
dim_monitor-objs += common/dim_symbol.o

ccflags-y := -I$(src)/core
ccflags-y += -I$(src)/monitor
ccflags-y += -I$(src)/common

EXTRA_CFLAGS += -Wall -Werror -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: install test clean

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules KCPPFLAGS="${cflags-y}"

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean

install:
	rmmod -f dim_monitor || :
	rmmod -f dim_core || :
	insmod dim_core.ko
	insmod dim_monitor.ko
