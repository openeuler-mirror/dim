# Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.
#!/bin/bash

. ../common.sh

test_pre() {
    dim_backup_baseline_and_policy
    load_dim_modules
}

test_post() {
    remove_dim_modules
    dim_restore_baseline_and_policy
}

test_measure_monitor_normal() {
    dim_gen_baseline_all
    dim_gen_policy_all
    check_dim_core_log_normal
    check_dim_monitor_log_normal
}

test_measure_monitor_tamper() {
    test_measure_monitor_normal
    check_dim_monitor_log_tampered
}

# The following testcases are disabled by default:
#          test_measure_monitor_normal
#          test_measure_monitor_tamper

case_list=""

echo "===== Start testing dim_monitor function ====="

for case in $case_list; do
    test_pre
    $case
    if [ $TEST_RESULT -eq 0 ]; then
        echo "$case PASS"
    else
        echo "$case FAIL"
    fi
    test_post
done

echo "===== End testing dim_monitor function ====="