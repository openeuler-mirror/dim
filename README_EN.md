# DIM

## Overview

Dynamic Integrity Measurement (DIM) detects runtime modifications in memory code segments caused by tampering, code injection, or other malicious attacks. By measuring memory code segment data, DIM determines whether runtime code has been altered, allowing it to detect threats and initiate appropriate response measures.

DIM includes two software packages: `dim_tools` and `dim`, which provides the following components:

| Package    | Component           | Description                                                        |
| --------- | ---------------- | ------------------------------------------------------------ |
| dim_tools | dim_gen_baseline | User mode; static baseline generation tool that parses ELF files to generate code segment measurement baselines in a specific format. For details, see <https://gitee.com/openeuler/dim_tools>.
| dim       | dim_core         | Kernel mode; executes core dynamic measurement logic, including policy parsing, static baseline parsing, dynamic baseline establishment, measurement execution, measurement logging, and TPM chip extension operations. |
|           | dim_monitor      | Kernel mode; Executes measurement protection targeted specifically at `dim_core`.                         |

## Installation

### Prerequisites

**Supported OS Versions**: openEuler 23.09 or higher

**Supported Kernel Versions**: openEuler kernel 5.10/6.4

**Note**: Because DIM includes kernel components, all installation and configuration steps must be executed with `root` privileges.

### Installation via openEuler Repositories

Using openEuler 23.09 as an example:

```sh
yum install -y dim_tools dim
```

After installation, the DIM kernel modules do not load by default. You can load and unload them using the following commands:

```sh
modprobe dim_core
modprobe dim_monitor
rmmod dim_monitor
rmmod dim_core
```

**Note**: `dim_monitor` must be loaded after `dim_core` and unloaded before `dim_core`.

### Compilation and Installation from Source

#### Compiling and Installing dim_tools

See <https://gitee.com/openeuler/dim_tools>.

#### Compiling and Installing dim

1. Install development dependencies.

    ```sh
    yum install -y kernel-devel
    ```

    Note: Ensure that the `kernel-devel` version matches your active running kernel version. Verify this by running:

    ```sh
    rpm -qa kernel
    rpm -qa kernel-devel
    ```

2. Clone the source repository.

    ```sh
    git clone https://gitee.com/openeuler/dim.git
    ```

3. Compile the source code.

    ```sh
    cd dim/src/ && make
    ```

4. Load and unload KO files.

    After a successful build, verify that `dim_core.ko` and `dim_monitor.ko` are generated in the `src` directory. Load or unload them using `insmod` and `rmmod`:

    ```sh
    insmod /path/to/dim_core.ko
    insmod /path/to/dim_monitor.ko
    rmmod dim_monitor
    rmmod dim_core
    ```

    **Note**: `dim_monitor` must be loaded after `dim_core` and unloaded before `dim_core`.

## Usage Instructions

### Using dim_core to Measure User-mode Code Segments (Baseline Comparison)

1. Prerequisite

    Ensure `dim_core` is successfully loaded (the following command should return a non-empty result):

    ```bash
    lsmod | grep dim_core
    ```

2. Generate a static baseline for the target binary.

    Using the `bash` process as an example:

    ```sh
    mkdir -p /etc/dim/digest_list
    dim_gen_baseline /usr/bin/bash -o /etc/dim/digest_list/test.hash
    ```

3. Configure the measurement policy.

    Using the `bash` process as an example:

    ```sh
    echo "measure obj=BPRM_TEXT path=/usr/bin/bash" > /etc/dim/policy
    ```

4. Execute the dynamic baseline.

    ```sh
    echo 1 > /sys/kernel/security/dim/baseline_init
    ```

5. Query the measurement logs.

    ```sh
    # cat /sys/kernel/security/dim/ascii_runtime_measurements 
    0 ea5b0e54ae55bc9bd140b4fc679dde6ffcba77b22973dcb17b1e5c3e89531db4 sha256:ad86c3bd36900c33e8ce09ec82266636a4d1f60300f7cb913058fba8ec99aa45 /usr/bin/bash [static baseline]
    ```

    The log entry above indicates that the `bash` process was successfully measured and matches its static baseline.

6. Trigger dynamic measurement.

    After the dynamic baseline is triggered, you can manually trigger dynamic measurements multiple times:

    ```sh
    echo 1 > /sys/kernel/security/dim/measure
    ```

    After the measurement completes, verify the logs via step 5. If the measurement matches the dynamic baseline, the log will not append new entries. If a mismatch/tampering occurs, an anomaly entry will be appended to the log.

### Using dim_core to Measure User-mode Code Segments (Remote Attestation)

1. Load `dim_core`.

    ```sh
    insmod dim_core.ko measure_only=1
    ```

2. Configure the measurement policy.

    Using the `bash` process as an example:

    ```sh
    echo "measure obj=BPRM_TEXT path=/usr/bin/bash" > /etc/dim/policy
    ```

3. Execute measurement.

    After the dynamic baseline is triggered, you can manually trigger dynamic measurements multiple times:

    ```sh
    echo 1 > /sys/kernel/security/dim/measure
    ```

4. Query the measurement logs.

```sh
# cat /sys/kernel/security/dim/ascii_runtime_measurements 
0 ea5b0e54ae55bc9bd140b4fc679dde6ffcba77b22973dcb17b1e5c3e89531db4 ima-ng sha256:ad86c3bd36900c33e8ce09ec82266636a4d1f60300f7cb913058fba8ec99aa45 /usr/bin/bash
```

If the code segment data changes, a new runtime entry will be generated.

### Using dim_monitor to Measure dim_core

1. Prerequisite

    Ensure `dim_monitor` is successfully loaded (the following command should return a non-empty result):

    ```sh
    lsmod | grep dim_monitor
    ```

2. Execute the dynamic baseline.

    ```sh
    echo 1 > /sys/kernel/security/dim/monitor_baseline
    ```

3. Query the measurement logs.

    ```sh
    # cat /sys/kernel/security/dim/monitor_ascii_runtime_measurements 
    0 7115ffe942af2b4f514f0280debed296653ef4a60a524f38f5a6dc1584bda45f sha256:ceefd97cb0ef328b453d19f6ae4d4ce16649bc1b388b3fd4d65af3bc0ba99f22 dim_core.text [dynamic baseline]
    0 a76a61dc2a6965708c7a473dfef402b42e7b6bd77e2a2e0933c0b47d4651b862 sha256:57bbabcbeb505b44c7b982ef9a68238f3837ce1d9f115d246360bf6f64d1198c dim_core.data [dynamic baseline]
    ```

    In the log output, `dim_core.text` contains the measurement of the `dim_core` code segment, and `dim_core.data` tracks the measurement of its critical kernel data structures.

4. Trigger dynamic measurement.

    After the dynamic baseline is triggered, you can manually trigger dynamic measurements multiple times:

    ```sh
    echo 1 > /sys/kernel/security/dim/measure
    ```

    After the measurement completes, verify the logs via step 3. If the measurement matches the dynamic baseline, the log will not append new entries. If a mismatch/tampering occurs, an anomaly entry will be appended to the log.

## Documentation

[DIM User Guide](doc/manual.md)

## Contributing

We warmly welcome new contributors to the project and are glad to provide guidance and onboarding support. Before submitting code, please ensure you have signed the community [CLA](https://clasign.osinfra.cn/sign/6983225bdcbb19710248ccf0).
