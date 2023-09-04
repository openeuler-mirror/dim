# DIM

## 1 概述
DIM（Dynamic Integrity Measurement）动态完整性度量特性能够检测到运行态的篡改和注入等攻击引起的内存代码段变化，通过对内存代码段数据进行度量，确定运行态代码是否被篡改，从而发现攻击行为，并采取应对措施。

DIM包含两个软件包dim_tools和dim，分别提供如下组件：

| 软件包    | 组件             | 说明                                                         |
| --------- | ---------------- | ------------------------------------------------------------ |
| dim_tools | dim_gen_baseline | 用户态组件，静态基线生成工具，通过解析ELF文件生成指定格式的代码段度量基线。详见：https://gitee.com/openeuler/dim_tools |
| dim       | dim_core         | 内核模块，执行核心的动态度量逻辑，包括策略解析、静态基线解析、动态基线建立、度量执行、度量日志记录、TPM芯片扩展操作等。 |
|           | dim_monitor      | 内核模块，执行对dim_core的度量保护。                         |

## 2 安装DIM
### 2.1 前置条件

**OS版本支持**：openEuler 23.09以上版本；

**内核版本支持**：当前支持openEuler kernel 5.10/6.4版本；

**注意**：DIM包含内核组件，相关步骤需要以管理员（root）权限运行。

### 2.2 使用openEuler源进行安装

以openEuler 23.09版本为例：

```
yum install -y dim_tools dim
```

软件包安装完成后，DIM内核组件不会默认加载，可通过如下命令进行加载和卸载：

```
modprobe dim_core
modprobe dim_monitor
rmmod dim_monitor
rmmod dim_core
```

**注意**：dim_monitor必须后于dim_core加载，先于dim_core卸载。

### 2.2 使用源码进行编译安装

#### 2.2.1 编译安装dim_tools软件

详见https://gitee.com/openeuler/dim_tools

#### 2.2.2 编译安装dim软件

**(1) 安装依赖软件包**

```
yum install -y kernel-devel
```

注意：请保证kernel-devel的版本与kernel版本一致，可通过以下命令查询对比：

```
rpm -qa kernel
rpm -qa kernel-devel
```

**(2) 下载源码**

```
git clone https://gitee.com/openeuler/dim.git
```

**(3) 编译源码**

```
cd dim/src/ && make
```

**(3) 安装&&卸载**

编译成功后，检查src目录下生成dim_core.ko和dim_monitor.ko文件，可通过如下命令进行安装和卸载：

```
insmod /path/to/dim_core.ko
insmod /path/to/dim_monitor.ko
rmmod dim_monitor
rmmod dim_core
```

**注意**：dim_monitor必须后于dim_core加载，先于dim_core卸载。

## 4 快速使用指南
### 4.1 使用dim_core组件度量用户态程序代码段

**(1) 前置条件**

dim_core模块加载成功，即执行如下命令返回不为空：

```
lsmod | grep dim_core
```

**(2) 为度量目标进程对应的二进制文件生成静态基线：**

以bash进程为例：

```
mkdir -p /etc/dim/digest_list
dim_gen_baseline /usr/bin/bash -o /etc/dim/digest_list/test.hash
```

**(3) 配置度量策略：**

以度量bash进程为例：

```
echo "measure obj=BPRM_TEXT path=/usr/bin/bash" > /etc/dim/policy
```

**(4) 执行动态基线：**

```
echo 1 > /sys/kernel/security/dim/baseline_init
```

**(5) 查询度量日志：**

```
# cat /sys/kernel/security/dim/ascii_runtime_measurements 
0 ea5b0e54ae55bc9bd140b4fc679dde6ffcba77b22973dcb17b1e5c3e89531db4 sha256:ad86c3bd36900c33e8ce09ec82266636a4d1f60300f7cb913058fba8ec99aa45 /usr/bin/bash [static baseline]
```

如上度量日志说明bash进程被成功度量，且度量结果与静态基线一致。

**(6) 执行动态度量：**

执行动态基线完成后，可通过如下命令多次触发动态度量：

```
echo 1 > /sys/kernel/security/dim/measure
```

度量完成后可通过步骤(6)查询度量日志，如果度量结果和动态基线阶段的度量结果一致，则度量日志不会更新，否则会新增异常度量日志。

### 4.1 使用dim_monitor组件度量dim_core组件

**(1) 前置条件**

dim_monitor模块加载成功，即执行如下命令返回不为空：

```
lsmod | grep dim_monitor
```

**(2) 执行动态基线：**

```
echo 1 > /sys/kernel/security/dim/monitor_baseline_init
```

**(3) 查询度量日志：**

```
# cat /sys/kernel/security/dim/monitor_ascii_runtime_measurements 
0 7115ffe942af2b4f514f0280debed296653ef4a60a524f38f5a6dc1584bda45f sha256:ceefd97cb0ef328b453d19f6ae4d4ce16649bc1b388b3fd4d65af3bc0ba99f22 dim_core.text [dynamic baseline]
0 a76a61dc2a6965708c7a473dfef402b42e7b6bd77e2a2e0933c0b47d4651b862 sha256:57bbabcbeb505b44c7b982ef9a68238f3837ce1d9f115d246360bf6f64d1198c dim_core.data [dynamic baseline]
```

度量日志中dim_core.text为dim_core代码段的度量结果，dim_core.data为dim_core关键数据的度量结果。

**(4) 执行动态度量：**

执行动态基线完成后，可通过如下命令多次触发动态度量：

```
echo 1 > /sys/kernel/security/dim/measure
```

度量完成后可通过步骤(6)查询度量日志，如果度量结果和动态基线阶段的度量结果一致，则度量日志不会更新，否则会新增异常度量日志。

## 5 文档资料

用户指南：[DIM用户指南](doc/manual.md)

## 6 如何贡献

我们非常欢迎新贡献者加入到项目中来，也非常高兴能为新加入贡献者提供指导和帮助。在您贡献代码前，需要先签署[CLA](https://openeuler.org/en/cla.html)。