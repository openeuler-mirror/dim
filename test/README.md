# DIM 测试文档

## 1 前置条件

**OS版本支持**：openEuler 23.09以上版本；

**内核版本支持**：当前支持openEuler kernel 5.10/6.4版本；

**注意**：DIM包含内核组件，相关步骤需要以管理员（root）权限运行。

## 2 使用openEuler源进行安装
```
yum install dim dim_tools make gcc
```

## 3 执行测试用例
```
cd dim/test/
sh test/test_dim_core.sh
sh test/test_monitor_core.sh
```

**注意**：全量度量功能默认关闭，如有需要，请将用例添加到对应的case_list中