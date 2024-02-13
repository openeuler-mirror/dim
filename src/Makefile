# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

obj-m := dim_core.o
obj-m += dim_monitor.o

dim_core-objs += core/dim_core_main.o
dim_core-objs += core/dim_core_fs.o
dim_core-objs += core/dim_core_mem_pool.o
dim_core-objs += core/dim_core_measure.o
dim_core-objs += core/dim_core_symbol.o
dim_core-objs += core/dim_core_sig.o

dim_core-objs += core/tasks/dim_core_measure_kernel.o
dim_core-objs += core/tasks/dim_core_measure_module.o
dim_core-objs += core/tasks/dim_core_measure_process/dim_vm_hash.o
dim_core-objs += core/tasks/dim_core_measure_process/dim_core_measure_process.o
ifeq ($(DIM_CORE_MEASURE_PROCESS_ELF), y)
dim_core-objs += core/tasks/dim_core_measure_process/dim_core_measure_process_elf.o
ccflags-y += -DDIM_CORE_MEASURE_PROCESS_ELF
else
dim_core-objs += core/tasks/dim_core_measure_process/dim_core_measure_process_vma.o
endif

dim_core-objs += core/policy/dim_core_policy.o
dim_core-objs += core/policy/dim_core_policy_complex.o

dim_core-objs += core/static_baseline/dim_core_static_baseline.o
dim_core-objs += core/static_baseline/dim_core_static_baseline_complex.o

dim_core-objs += common/dim_entry.o
dim_core-objs += common/dim_utils.o
dim_core-objs += common/dim_baseline.o
dim_core-objs += common/dim_hash.o
dim_core-objs += common/dim_measure_log.o
dim_core-objs += common/dim_tpm.o
dim_core-objs += common/dim_symbol.o
dim_core-objs += measure/dim_measure.o
dim_core-objs += measure/dim_measure_baseline.o
dim_core-objs += measure/dim_measure_task.o
dim_core-objs += measure/dim_measure_utils.o
dim_core-objs += measure/dim_measure_status.o

dim_monitor-objs += monitor/dim_monitor_main.o
dim_monitor-objs += monitor/dim_monitor_fs.o
dim_monitor-objs += monitor/dim_monitor_measure.o
dim_monitor-objs += monitor/dim_monitor_symbol.o

dim_monitor-objs += monitor/measure_task/dim_monitor_measure_data.o
dim_monitor-objs += monitor/measure_task/dim_monitor_measure_text.o

dim_monitor-objs += common/dim_entry.o
dim_monitor-objs += common/dim_hash.o
dim_monitor-objs += common/dim_utils.o
dim_monitor-objs += common/dim_measure_log.o
dim_monitor-objs += common/dim_baseline.o
dim_monitor-objs += common/dim_tpm.o
dim_monitor-objs += common/dim_symbol.o
dim_monitor-objs += measure/dim_measure.o
dim_monitor-objs += measure/dim_measure_baseline.o
dim_monitor-objs += measure/dim_measure_task.o
dim_monitor-objs += measure/dim_measure_utils.o
dim_monitor-objs += measure/dim_measure_status.o

ccflags-y := -I$(src)/core
ccflags-y += -I$(src)/core/static_baseline
ccflags-y += -I$(src)/core/tasks
ccflags-y += -I$(src)/core/tasks/dim_core_measure_process
ccflags-y += -I$(src)/core/policy
ccflags-y += -I$(src)/monitor
ccflags-y += -I$(src)/monitor/measure_task
ccflags-y += -I$(src)/common
ccflags-y += -I$(src)/measure

ccflags-y += -Wall -Werror -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all modules modules_install clean

all: modules

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
