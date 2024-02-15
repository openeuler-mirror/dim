# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

.PHONY: all test clean

all:
	make -C src/

test:
	make -C test/

clean:
	make -C src/ clean
	make -C test/ clean