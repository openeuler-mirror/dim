# Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.

.PHONY: test clean

test:
	sh test_dim_core.sh
	sh test_dim_monitor.sh

clean:
	rm -f log
	make -C test_module/ clean