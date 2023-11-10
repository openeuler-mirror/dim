# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
#!/bin/bash

. ./common.sh

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

# Full measurement. The test is disabled by default.
# case_list="test_measure_monitor_normal \
#            test_measure_monitor_tamper"
case_list=""

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
