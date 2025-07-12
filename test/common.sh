# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
#!/bin/bash

TEST_ROOT=/opt/dim
TEST_DEMO_DIR=/opt/dim/demo
TEST_DEMO_BPRM=$TEST_DEMO_DIR/dim_test_demo

TEST_LOG=log
DIM_CORE_PATH=../../src/dim_core.ko
DIM_MONITOR_PATH=../../src/dim_monitor.ko

DIM_BASELINE_DIR_PATH=/etc/dim/digest_list
DIM_POLICY_PATH=/etc/dim/policy

DIM_KERNEL_NAME="/boot/vmlinuz-*.$(arch)"

TEST_MODULE_DIR=test_module
DIM_MOD_NAME=dim_test_module_demo
DIM_TEST_MOD_DEMO=$TEST_MODULE_DIR/dim_test_module_demo.ko

DIM_TEST_MOD_DEMO_C=$TEST_MODULE_DIR/dim_test_module_demo.c
DIM_TEST_MOD_DEMO_TAMPER_C=$TEST_MODULE_DIR/dim_test_module_demo_tamper.c

TEST_RESULT=0

check_value_zero() {
    if [ $1 -ne 0 ]; then
        echo "failed to check value: $1 == 0, context: $2"
        TEST_RESULT=1
        return 1
    fi
}

check_value_not_zero() {
    if [ $1 -eq 0 ]; then
        echo "failed to check value: $1 != 0, context: $2"
        TEST_RESULT=1
        return 1
    fi
}

dim_core_status() {
    cat /sys/kernel/security/dim/runtime_status
}

dim_core_baseline() {
    echo 1 > /sys/kernel/security/dim/baseline_init
}

dim_core_measure() {
    echo 1 > /sys/kernel/security/dim/measure
}

dim_core_measure_log() {
    cat /sys/kernel/security/dim/ascii_runtime_measurements
}

dim_monitor_baseline() {
    echo 1 > /sys/kernel/security/dim/monitor_baseline
}

dim_monitor_measure() {
    echo 1 > /sys/kernel/security/dim/monitor_run
}

dim_monitor_measure_log() {
    cat /sys/kernel/security/dim/monitor_ascii_runtime_measurements
}

remove_dim_modules() {
    # clean loaded modules
    rmmod -f dim_monitor &> /dev/null
    rmmod -f dim_core &> /dev/null
    lsmod | grep -E 'dim_core|dim_monitor' &> /dev/null
    if [ $? -eq 0 ]; then
        echo "fail to remove dim modules!" >> $TEST_LOG
        exit 1
    fi
}

load_dim_modules () {
    remove_dim_modules
    load_dim_core_module $1
    load_dim_monitor_module $2
}

load_dim_core_module () {
    # load dim_core module
    if [ ! $DIM_CORE_PATH ]; then
        modprobe dim_core $1
    else
        insmod $DIM_CORE_PATH $1
    fi

    if [ $? -ne 0 ]; then
        echo "fail to load dim_core!"
        return 1
    fi
}

load_dim_monitor_module () {
    # load dim_monitor module
    if [ ! $DIM_MONITOR_PATH ]; then
        modprobe dim_monitor $1
    else
        insmod $DIM_MONITOR_PATH $1
    fi

    if [ $? -ne 0 ]; then
        echo "fail to load dim_monitor!"
        return 1
    fi
}

dim_backup_baseline_and_policy() {
    if [ -d $DIM_BASELINE_DIR_PATH.bak ]; then
        rm -rf $DIM_BASELINE_DIR_PATH.bak
    fi

    if [ -d $DIM_BASELINE_DIR_PATH ]; then
        mv $DIM_BASELINE_DIR_PATH $DIM_BASELINE_DIR_PATH.bak
    fi

    if [ -f $DIM_POLICY_PATH ]; then
        mv $DIM_POLICY_PATH $DIM_POLICY_PATH.bak
    fi
}

dim_restore_baseline_and_policy() {
    if [ -d $DIM_BASELINE_DIR_PATH.bak ]; then
        rm -rf $DIM_BASELINE_DIR_PATH
        mv $DIM_BASELINE_DIR_PATH.bak $DIM_BASELINE_DIR_PATH
    fi

    if [ -f $DIM_POLICY_PATH.bak ]; then
        mv -f $DIM_POLICY_PATH.bak $DIM_POLICY_PATH
    fi
}

dim_gen_baseline_file() {
    mkdir -p $DIM_BASELINE_DIR_PATH
    if [ -z $2 ]; then
        dim_gen_baseline $1
    else
        dim_gen_baseline $1 -o "$DIM_BASELINE_DIR_PATH/$2"
    fi
}

dim_gen_baseline_dir() {
    mkdir -p $DIM_BASELINE_DIR_PATH
    dim_gen_baseline -r $1 -o $DIM_BASELINE_DIR_PATH/$2
}

dim_gen_baseline_kernel() {
    mkdir -p $DIM_BASELINE_DIR_PATH
    if [ -z $1 ]; then
        dim_gen_baseline -k "$(uname -r)" $DIM_KERNEL_NAME
    else
        dim_gen_baseline -k "$(uname -r)" -o $DIM_BASELINE_DIR_PATH/$1 $DIM_KERNEL_NAME
    fi
}

DIM_BASELINE_DIR_ALL=("/usr/bin" "/usr/sbin" "/usr/lib64" "/usr/libexec" "/usr/lib")

dim_gen_baseline_all() {
    if [ $1 ]; then
        digest_algorithm="-a$1"
    else
        digest_algorithm=""
    fi

    mkdir -p /etc/dim/digest_list
    for baseline_file in "${DIM_BASELINE_DIR_ALL[@]}"; do
        dim_gen_baseline $digest_algorithm -r $baseline_file -o "$DIM_BASELINE_DIR_PATH/${baseline_file##*/}.hash"
    done
    dim_gen_baseline $digest_algorithm -k "$(uname -r)" -o $DIM_BASELINE_DIR_PATH/kernel.hash $DIM_KERNEL_NAME
}


dim_gen_policy_bprm_path() {
    echo "measure obj=BPRM_TEXT path=$1" >> $DIM_POLICY_PATH
}

dim_gen_policy_module_name() {
    echo "measure obj=MODULE_TEXT name=$1" >> $DIM_POLICY_PATH
}

dim_gen_policy_kernel() {
    echo "measure obj=KERNEL_TEXT" >> $DIM_POLICY_PATH
}

dim_gen_policy_all() {
    rm -f $DIM_POLICY_PATH
    cat $DIM_BASELINE_DIR_PATH/* | awk '{print $4}' | while read line; do
        if [[ "$line" == /* ]]; then
            echo "measure obj=BPRM_TEXT path=$line" >> $DIM_POLICY_PATH
            continue
        fi
        if [ "$line" == "$(uname -r)" ]; then
            echo "measure obj=KERNEL_TEXT" >> $DIM_POLICY_PATH
            continue
        fi
        if [ "$line" != "$(uname -r)" ]; then
            echo "measure obj=MODULE_TEXT name=$(basename $line)" >> $DIM_POLICY_PATH
        fi
    done
    sed -i '/dim_core/d' $DIM_POLICY_PATH
    sed -i '/dim_monitor/d' $DIM_POLICY_PATH
}

dim_gen_cert() {
    mkdir -p $TEST_ROOT/cert/
    openssl genrsa -out $TEST_ROOT/cert/dim.key 4096 &>> $TEST_LOG
    openssl req -new -sha256 -key $TEST_ROOT/cert/dim.key -out $TEST_ROOT/cert/dim.csr -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=DIM" &>> $TEST_LOG
    openssl x509 -req -days 3650 -signkey $TEST_ROOT/cert/dim.key -in $TEST_ROOT/cert/dim.csr -out $TEST_ROOT/cert/dim.crt &>> $TEST_LOG
    openssl x509 -in $TEST_ROOT/cert/dim.crt -out $TEST_ROOT/cert/dim.der -outform DER &>> $TEST_LOG
    mkdir -p /etc/keys
    cp $TEST_ROOT/cert/dim.der /etc/keys/x509_dim.der
}

dim_gen_signature() {
    openssl dgst -sha256 -out $DIM_POLICY_PATH.sig -sign $TEST_ROOT/cert/dim.key $DIM_POLICY_PATH
    for file in $(ls $DIM_BASELINE_DIR_PATH | grep .hash); do
        openssl dgst -sha256 -out $DIM_BASELINE_DIR_PATH/$file.sig -sign $TEST_ROOT/cert/dim.key $DIM_BASELINE_DIR_PATH/$file
    done
}

dim_baseline_to_measure_log() {
    name="$(echo "$1" | awk '{print $4}')"
    if [[ $name == $(uname -r)/* ]]; then
        name="$(basename $name)"
    fi

    echo "$(echo "$1" | awk '{print $3}') $name"
}

tamper_dim_test_demo() {
    gcc dim_test_demo_tamper.c -o $TEST_DEMO_DIR/dim_test_demo
}

tamper_dim_test_mod_demo() {
    rm -f $TEST_MODULE_DIR/$DIM_MOD_NAME.o
    mv $DIM_TEST_MOD_DEMO_C $DIM_TEST_MOD_DEMO_C.bak
    mv $DIM_TEST_MOD_DEMO_TAMPER_C $DIM_TEST_MOD_DEMO_C
    cd $TEST_MODULE_DIR
    make > /dev/null
    cd ..
}

tamper_dim_test_mod_demo_end() {
    rm -f $TEST_MODULE_DIR/$DIM_MOD_NAME.o
    mv $DIM_TEST_MOD_DEMO_C $DIM_TEST_MOD_DEMO_TAMPER_C
    mv $DIM_TEST_MOD_DEMO_C.bak $DIM_TEST_MOD_DEMO_C
}

gen_dim_test_demo() {
    gcc dim_test_demo.c -o $TEST_DEMO_BPRM
    dim_gen_baseline_file $TEST_DEMO_BPRM test.hash
    dim_gen_policy_bprm_path $TEST_DEMO_BPRM
}

gen_dim_test_mod_demo() {
    rm -f $TEST_MODULE_DIR/$DIM_MOD_NAME.o
    cd $TEST_MODULE_DIR
    make > /dev/null
    cd ..
    dim_gen_baseline_file $DIM_TEST_MOD_DEMO test.hash
    dim_gen_policy_module_name $DIM_MOD_NAME
}

measure_log_tampered() {
    if [ $2 ]; then
        echo "$1 \[tampered\]"
    else
        baseline="$(dim_gen_baseline_file $1)"
        echo "$(dim_baseline_to_measure_log "$baseline") \[tampered\]"
    fi
}

measure_log_static() {
    if [ $2 ]; then
        baseline="$(dim_gen_baseline_kernel)"
        echo "$(dim_baseline_to_measure_log "$baseline") \[static baseline\]"
    else
        baseline="$(dim_gen_baseline_file $1)"
        echo "$(dim_baseline_to_measure_log "$baseline") \[static baseline\]"
    fi
}

measure_log_no_static() {
    if [ $2 ]; then
        echo "$1 \[no static baseline\]"
    else
        baseline="$(dim_gen_baseline_file $1)"
        echo "$(dim_baseline_to_measure_log "$baseline") \[no static baseline\]"
    fi
}

check_dim_measure_log_match() {
    if [ "$2" == "dim_monitor_measure_log" ]; then
        dim_monitor_measure_log | grep "$1" &> /dev/null
    else
        dim_core_measure_log | grep "$1" &> /dev/null
    fi

    if [ $? -ne 0 ]; then
        echo "check fail:" >> $TEST_LOG
        echo " get measure log: $($2)" >> $TEST_LOG
        echo " want measure log: $1" >> $TEST_LOG
        TEST_RESULT=1
        return 1
    fi

    echo "check ok: measure log has $1" >> $TEST_LOG
}

check_dim_measure_log_length() {
    if [ $($2 | wc -l) -ne $1 ]; then
        echo "check fail: measure log length is not $1" >> $TEST_LOG
        TEST_RESULT=1
        return 1
    fi

    echo "check ok: measure log length is $1" >> $TEST_LOG
}

check_dim_measure_log_not_contain() {
    if [ "$2" == "dim_monitor_measure_log" ]; then
        dim_monitor_measure_log | grep "$1" &> /dev/null
    else
        dim_core_measure_log | grep "$1" &> /dev/null
    fi
    if [ $? -eq 0 ]; then
        echo "check fail"
        TEST_RESULT=1
        return 1
    fi

    echo "check ok: measure log hasn't $1" >> $TEST_LOG
}

check_dim_core_log_normal() {
    dim_core_baseline
    check_dim_measure_log_not_contain "\[no static baseline\]" "dim_core_measure_log"
    check_dim_measure_log_not_contain "\[tampered\]" "dim_core_measure_log"
    dim_core_measure
    check_dim_measure_log_not_contain "\[no static baseline\]" "dim_core_measure_log"
    check_dim_measure_log_not_contain "\[tampered\]" "dim_core_measure_log"
}

check_dim_monitor_log_normal() {
    dim_monitor_baseline
    check_dim_measure_log_length 2 "dim_monitor_measure_log"
    check_dim_measure_log_not_contain "\[tampered\]" "dim_monitor_measure_log"
    dim_monitor_measure
    check_dim_measure_log_length 2 "dim_monitor_measure_log"
    check_dim_measure_log_not_contain "\[tampered\]" "dim_monitor_measure_log"
}

check_dim_monitor_log_tampered() {
    dim_core_baseline
    dim_monitor_measure
    check_dim_measure_log_length 3 "dim_monitor_measure_log"
    check_dim_measure_log_match "dim_core.data \[tampered\]" "dim_monitor_measure_log"
}

run_dim_core_baseline_and_check_log() {
    dim_core_baseline
    check_dim_measure_log_length "$2" "dim_core_measure_log"
    check_dim_measure_log_match "$1" "dim_core_measure_log"
}

run_dim_core_measure_and_check_log() {
    dim_core_measure
    check_dim_measure_log_length "$2" "dim_core_measure_log"
    check_dim_measure_log_match "$1" "dim_core_measure_log"
}

run_dim_core_and_check_log() {
    if [ "$1" = "baseline" ]; then
        run_dim_core_baseline_and_check_log "$2" "$3"
        if [ $4 ]; then
            kill $4
        fi
    elif [ "$1" = "measure" ]; then
        run_dim_core_measure_and_check_log "$2" "$3"
        if [ $4 ]; then
            kill $4
        fi
    else
        run_dim_core_baseline_and_check_log "$1" "$2"
        run_dim_core_measure_and_check_log "$3" "$4"
        if [ $5 ]; then
            kill $5
        fi
    fi
}


