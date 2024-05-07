# Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.
#!/bin/bash

. ../common.sh

test_pre() {
    TEST_RESULT=0
}

check_valid_module_param()
{
    remove_dim_modules
    load_dim_core_module $1 &> /dev/null
    check_value_zero $? $1
    remove_dim_modules
}

check_invalid_module_param()
{
    remove_dim_modules
    load_dim_core_module $1 &> /dev/null
    check_value_not_zero $? $1
    remove_dim_modules
}

test_module_param_measure_hash()
{
    check_valid_module_param measure_hash=sha256
    check_invalid_module_param measure_hash=md5
    check_invalid_module_param measure_hash=abc
}

test_module_param_measure_pcr()
{
    check_valid_module_param measure_pcr=0
    check_valid_module_param measure_pcr=1
    check_valid_module_param measure_pcr=11
    check_valid_module_param measure_pcr=127
    check_valid_module_param measure_pcr=128
    check_invalid_module_param measure_pcr=-1
    check_invalid_module_param measure_pcr=abc
}

test_module_param_measure_schedule()
{
    check_valid_module_param measure_schedule=0
    check_valid_module_param measure_schedule=50
    check_valid_module_param measure_schedule=1000
    check_invalid_module_param measure_schedule=-1
    check_invalid_module_param measure_schedule=abc
    check_invalid_module_param measure_schedule=1001
}

test_module_param_measure_interval()
{
    dim_backup_baseline_and_policy
    dim_gen_policy_bprm_path /usr/bin/bash
    dim_gen_baseline_file /usr/bin/bash test.hash
    check_valid_module_param measure_interval=0
    check_valid_module_param measure_interval=1000
    check_valid_module_param measure_interval=525600
    check_invalid_module_param measure_interval=-1
    check_invalid_module_param measure_interval=abc
    # check_invalid_module_param measure_interval=525601
    dim_restore_baseline_and_policy
}

test_module_param_signature()
{
    check_valid_module_param signature=0
    check_valid_module_param signature=1
    check_invalid_module_param signature=abc
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
           test_module_param_measure_schedule \
           test_module_param_measure_interval \
           test_module_param_signature \
           test_module_param_measure_log_capacity \
           "

echo "===== Start testing dim_core module parameters ====="

for case in $case_list; do
    test_pre
    $case
    if [ $TEST_RESULT -eq 0 ]; then
        echo "$case PASS"
    else
        echo "$case FAIL"
    fi
done

echo "===== End testing dim_core module parameters ====="
