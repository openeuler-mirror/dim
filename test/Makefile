# Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.

.PHONY: test clean

all: test

test:
	make -C test_interface/ test
	make -C test_function/ test
	make -C test_dfx/ test

clean:
	make -C test_interface/ clean
	make -C test_function/ clean
	make -C test_dfx/ clean