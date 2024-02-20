# Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.
#!/bin/bash

. ../common.sh

test_pre() {
    remove_dim_modules
    load_dim_core_module
    TEST_RESULT=0
}

test_post() {
    remove_dim_modules
}

check_valid_module_param()
{
    load_dim_monitor_module $1 &> /dev/null
    check_value_zero $? $1
    rmmod dim_monitor &> /dev/null
}

check_invalid_module_param()
{
    load_dim_monitor_module $1 &> /dev/null
    check_value_not_zero $? $1
    rmmod dim_monitor &> /dev/null
}

test_module_param_measure_hash()
{
    check_valid_module_param measure_hash=sha256
    check_valid_module_param measure_hash=sm3
    check_invalid_module_param measure_hash=md5
    check_invalid_module_param measure_hash=abc
}

test_module_param_measure_pcr()
{
    check_valid_module_param measure_pcr=0
    check_valid_module_param measure_pcr=1
    check_valid_module_param measure_pcr=11
    check_valid_module_param measure_pcr=127
    check_invalid_module_param measure_pcr=128
    check_invalid_module_param measure_pcr=-1
    check_invalid_module_param measure_pcr=abc
}

test_module_param_measure_log_capacity()
{
    check_valid_module_param measure_log_capacity=100
    check_valid_module_param measure_log_capacity=10000
    check_valid_module_param measure_log_capacity=4294967295
    check_invalid_module_param measure_log_capacity=99
    check_invalid_module_param measure_log_capacity=0
    check_invalid_module_param measure_log_capacity=4294967296
    check_invalid_module_param measure_log_capacity=abc
}


case_list="
           test_module_param_measure_hash \
           test_module_param_measure_pcr \
           test_module_param_measure_log_capacity \
           "

echo "===== Start testing dim_monitor module parameters ====="

for case in $case_list; do
    test_pre
    $case
    if [ $TEST_RESULT -eq 0 ]; then
        echo "$case PASS"
    else
        echo "$case FAIL"
    fi
done

echo "===== End testing dim_monitor module parameters ====="