# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

.PHONY: test

test:
	sh test_dim_core.sh
	sh test_dim_monitor.sh

clean:
	rm -f log
	make -C test_module/ clean