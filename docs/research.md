# 研究记录

## 1. 目标与环境

- 目标：Unity IL2CPP 游戏 `dmmdzz.exe`（32 位），BRM 保护。
- 现象：
  - 用户态 `ReadProcessMemory` / `WriteProcessMemory` 失败；
  - `OpenProcess(PROCESS_ALL_ACCESS)` 返回句柄，但 `GrantedAccess` 被剥掉 `PROCESS_VM_READ/WRITE`、`PROCESS_SUSPEND_RESUME`；
  - `DebugActiveProcess` 返回错误 5，`NtDebugActiveProcess` 返回 `0xC0000022`。

## 2. 内核驱动

### 2.1 加载方式

- 驱动编译为 KDU 兼容的 `.sys`（`/GS-`、无 SEH、`DriverEntry` 内用 `IoCreateDriver` 建驱动对象）。
- 用 KDU 的 BYOVD provider 映射，不经过服务/测试签名。
- 设备名 `\Device\WnSvc9F6B`，**不创建符号链接**；用户态通过 `\\.\GLOBALROOT\Device\WnSvc9F6B` 打开。
- 驱动对象创建后调用 `ObMakeTemporaryObject` 摘名，并从 `DriverObject->DriverSection` 摘链。

### 2.2 读写

- `PsLookupProcessByProcessId` 拿 `PEPROCESS`；
- `MmCopyVirtualMemory` 在目标进程上下文复制；
- 读/写按 1MB 分块，单次上限 4MB；
- 代码段写入尝试过 `ZwProtectVirtualMemory`，伪句柄返回 `STATUS_INVALID_PARAMETER`（Win32 87），数据段写入正常。

### 2.3 模块

- 通过 `PsGetProcessPeb` / `PsGetProcessWow64Process` 遍历 PEB 模块链表；
- 返回模块 base/size/path，支持 32/64 位目标。

### 2.4 全权限句柄与 GrantedAccess 修补

`TS_IOCTL_OPEN_PROCESS`：

1. `PsLookupProcessByProcessId`；
2. `ObOpenObjectByPointer(..., PROCESS_ALL_ACCESS, ..., KernelMode, &h)`；
3. 在当前进程句柄表中查找该句柄项；
4. 把 `HANDLE_TABLE_ENTRY.GrantedAccess` 改为 `PROCESS_ALL_ACCESS`；
5. 返回用户态句柄。

实测：

```text
GrantedAccess = 0x1FFFFF
PROCESS_SUSPEND_RESUME / VM_READ / VM_WRITE 全部具备
NtDebugActiveProcess = 0x0
```

## 3. CE 插件

### 3.1 读写代理

- 扫描 CE 主模块可写段，找到 `ReadProcessMemoryActual` / `WriteProcessMemoryActual` 指针；
- 替换为 `TsMemReadProcessMemory` / `TsMemWriteProcessMemory`；
- 后台线程每 500ms 检查一次，防止 CE 初始化/切换模式时重置。

### 3.2 调试代理

- 替换 CE 的 `DebugActiveProcess` / `WaitForDebugEvent` / `ContinueDebugEvent` / `DebugActiveProcessStop` 函数指针；
- `DebugActiveProcess`：
  - 用 `OPEN_PROCESS` 拿全权限句柄；
  - `NtCreateDebugObject` + `NtDebugActiveProcess`；
- `WaitForDebugEvent`：
  - `NtWaitForDebugEvent`；
  - `DbgUiConvertStateChangeStructure` 转成 Win32 `DEBUG_EVENT`；
  - 超时 `STATUS_TIMEOUT (0x102)` 直接返回 FALSE，避免空状态转换失败；
- `ContinueDebugEvent`：`NtDebugContinue`。

### 3.3 实测事件序列

```text
TsDebugActiveProcess <pid>
debug attached <pid>
event code=3 (CREATE_PROCESS)  Continue -> 0
event code=6 (LOAD_DLL)        Continue -> 0
event code=2 (CREATE_THREAD)   Continue -> 0
...
event code=4 (EXIT_THREAD)
event code=5 (EXIT_PROCESS)
```

调试器附加和事件继续都成功，但游戏检测到 `DebugPort` 后自行退出，测试账号随后被封 7 天。

## 4. 游戏行为

- 人机/练习局：本地逻辑，改内存有效。
- 真人局：服务器权威，金币/点券/血量等会被覆盖或对账；本地写入不可靠。
- 调试器附加：BRM 会拒绝/终止，并记录封号。

## 5. DBVM / 反调试尝试

- CE 7.7 设置里的 “DBVM 级调试器” 需要 DBVM hypervisor；
- `dbk64.cepack` 是 **DBK64 驱动**，不是 DBVM；
- 官方 CE 安装包/EFI 分区中没有可用的 Windows DBVM 文件；
- `vmdisk.img` 是 UEFI DBVM 启动盘的一部分，未安装启动项；
- 因此没有取得可用的 DBVM，也没有完成 `DebugPort` 隐藏。

## 6. 已知限制

- KDU provider 受 Windows 驱动黑名单/杀软影响；
- 调试附加会被 `DebugPort` 检测；
- 用户态 CE/插件/Python 特征明显；
- 真人局服务器权威；
- 没有实现 DBVM/EPT 级别的隐藏。
