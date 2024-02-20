# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
#!/bin/bash

. ../common.sh

test_pre() {
    dim_backup_baseline_and_policy
    load_dim_core_module
    dim_gen_baseline_all
    dim_gen_policy_all
    TEST_RESULT=0
}

test_post() {
    remove_dim_modules
    dim_restore_baseline_and_policy
}

test_rmmod_when_baseline() {
    dim_core_baseline &
    # try to remove module when doing measurement
    for i in {1..1000}; do
        sleep 0.1
        rmmod dim_core &> /dev/null
        if [ $? -eq 0 ]; then
                break
        fi
    done
}

# The following testcases are disabled by default:
#          test_rmmod_when_baseline

case_list=""

echo "===== Start testing dim_core DFX ====="

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

echo "===== End testing dim_core DFX ====="
