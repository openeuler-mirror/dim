# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
#!/bin/bash

. ./common.sh

test_measure_bprm_text_normal() {
    gen_dim_test_demo
    $TEST_DEMO_DIR/dim_test_demo > /dev/null & pid=$!
    # test
    run_dim_core_and_check_log "$(measure_log_static $TEST_DEMO_BPRM)" 1 "$(measure_log_static $TEST_DEMO_BPRM)" 1 $pid
}

test_measure_bprm_text_no_baseline() {
    gen_dim_test_demo
    $TEST_DEMO_DIR/dim_test_demo > /dev/null & pid=$!
    # remove baseline
    rm -f $DIM_BASELINE_DIR_PATH/test.hash
    # test
    run_dim_core_and_check_log "$(measure_log_no_static $TEST_DEMO_BPRM)" 1 "$(measure_log_no_static $TEST_DEMO_BPRM)" 1 $pid
}

test_measure_bprm_text_tamper_1() {
    # prepare
    gen_dim_test_demo
    tamper_dim_test_demo
    $TEST_DEMO_DIR/dim_test_demo > /dev/null & pid=$!
    # test
    run_dim_core_and_check_log "$(measure_log_tampered $TEST_DEMO_BPRM)" 1 "$(measure_log_tampered $TEST_DEMO_BPRM)" 1 $pid
}

test_measure_bprm_text_tamper_2() {
    # prepare
    gen_dim_test_demo
    $TEST_DEMO_DIR/dim_test_demo > /dev/null & pid=$!
    # test baseline
    run_dim_core_and_check_log baseline "$(measure_log_static $TEST_DEMO_BPRM)" 1 $pid
    # tamper dim_test_demo
    tamper_dim_test_demo
    $TEST_DEMO_DIR/dim_test_demo > /dev/null & pid=$!
    # test measure
    run_dim_core_and_check_log measure "$(measure_log_tampered $TEST_DEMO_BPRM)" 2 $pid

    kill $pid
}

test_measure_kernel_normal() {
    dim_gen_policy_kernel
    dim_gen_baseline_kerenl test.hash

    run_dim_core_and_check_log "$(measure_log_static $DIM_KERNEL_NAME "kernel")" 1 "$(measure_log_static $DIM_KERNEL_NAME "kernel")" 1
}

test_measure_module_text_normal() {
    gen_dim_test_mod_demo
    insmod $DIM_TEST_MOD_DEMO
    run_dim_core_and_check_log "$(measure_log_static $DIM_TEST_MOD_DEMO)" 1 "$(measure_log_static $DIM_TEST_MOD_DEMO)" 1
    rmmod $DIM_TEST_MOD_DEMO
}

test_measure_module_text_no_baseline() {
    gen_dim_test_mod_demo
    insmod $DIM_TEST_MOD_DEMO

    # remove baseline
    rm -f $DIM_BASELINE_DIR_PATH/test.hash

    run_dim_core_and_check_log "$(measure_log_no_static $DIM_MOD_NAME "mod_no_static")" 1 "$(measure_log_no_static $DIM_MOD_NAME "mod_no_static")" 1
    rmmod $DIM_TEST_MOD_DEMO
}

test_measure_module_text_tamper() {
    gen_dim_test_mod_demo
    insmod $DIM_TEST_MOD_DEMO

    run_dim_core_and_check_log baseline "$(measure_log_static $DIM_TEST_MOD_DEMO)" 1
    rmmod $DIM_TEST_MOD_DEMO
    tamper_dim_test_mod_demo
    insmod $DIM_TEST_MOD_DEMO
    run_dim_core_and_check_log measure "$(measure_log_tampered $DIM_MOD_NAME "module_tampered")" 2
    rmmod $DIM_TEST_MOD_DEMO
    tamper_dim_test_mod_demo_end
}

test_measure_all_text_normal() {
    dim_gen_baseline_all
    dim_gen_policy_all
    check_dim_core_log_normal
}

test_measure_all_text_normal_sm3() {
    dim_gen_baseline_all 1
    dim_gen_policy_all
    load_dim_modules "measure_hash=sm3"
    check_dim_core_log_normal
}

test_measure_all_text_normal_sign() {
    dim_gen_baseline_all
    dim_gen_policy_all
    dim_gen_cert
    dim_gen_signature
    load_dim_modules "signature=on"
    check_dim_core_log_normal
}

POLICY_INVALID="measure1 obj=BPRM_TEXT path=/opt/dim/demo/dim_test_demo\n\
measure obj1=BPRM_TEXT path=/opt/dim/demo/dim_test_demo\n\
measure obj=BPRM_TEXT1 path=/opt/dim/demo/dim_test_demo\n\
measure obj=BPRM_TEXT name=/opt/dim/demo/dim_test_demo\n\
measure obj=MODULE_TEXT path=$(head -c 4096 < /dev/zero | tr '\0' '\141')\n"

test_invalid_policy() {
    IFS=$'\n'
    for policy in $(echo -e $POLICY_INVALID); do
        echo "$policy" > $DIM_POLICY_PATH
        dim_core_baseline
        dim_core_status
    done &>> $TEST_LOG
}

# Full measurement. The test is disabled by default.
#           test_measure_all_text_normal \
#           test_measure_all_text_normal_sm3 \
#           test_measure_all_text_normal_sign \
case_list="test_measure_bprm_text_normal \
           test_measure_bprm_text_no_baseline \
           test_measure_bprm_text_tamper_1 \
           test_measure_bprm_text_tamper_2 \
           test_measure_module_text_normal \
           test_measure_module_text_no_baseline \
           test_measure_module_text_tamper \
           test_measure_kernel_normal \
           test_invalid_policy"

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

