# TsMem — DMMDZZ 驱动级内存读写研究

> 本地研究/测试记录：自写内核驱动 + 用户态工具 + Cheat Engine 插件。
> 仓库**不包含** KDU、Cheat Engine、游戏文件或任何第三方二进制。

## 背景

目标是一个 Unity IL2CPP 游戏（`dmmdzz.exe`），带 BRM 保护：

- 用户态 `ReadProcessMemory` / `WriteProcessMemory` 被拦截；
- 普通 `OpenProcess` 拿不到 `PROCESS_VM_READ/WRITE`；
- 调试器附加被拒绝（`DebugActiveProcess` → 错误 5）。

本项目验证了一条内核层路径：用自写驱动做读写，用 CE 插件把 CE 的读写/调试 API 代理到驱动。

## 架构

```text
tool.py / Cheat Engine plugin
        │ DeviceIoControl
        ▼
ts_mem_kdu.sys  (KDU-mapped, 无符号链接)
        │ PsLookupProcessByProcessId / MmCopyVirtualMemory
        ▼
target process (dmmdzz.exe)
```

## 功能

驱动 IOCTL：

| IOCTL | 值 | 作用 |
|---|---|---|
| `TS_IOCTL_READ` | `0x00222000` | 读目标进程内存 |
| `TS_IOCTL_WRITE` | `0x00222004` | 写目标进程内存 |
| `TS_IOCTL_MODULE` | `0x00222008` | 按模块名取 base/size/path |
| `TS_IOCTL_INFO` | `0x0022200C` | 驱动信息 |
| `TS_IOCTL_HIDE` | `0x00222010` | 隐藏驱动加载链 |
| `TS_IOCTL_HIDE_DEVICE` | `0x00222014` | `ObMakeTemporaryObject` 摘除设备名 |
| `TS_IOCTL_OPEN_PROCESS` | `0x00222018` | 内核打开全权限进程句柄 + 修补 `GrantedAccess` |

隐蔽处理：

- 设备名随机（当前源码 `WnSvc9F6B`），**不创建符号链接**；
- 驱动对象 `ObMakeTemporaryObject` 摘名，`DriverSection` 摘链；
- 用户态通过 `\\.\GLOBALROOT\Device\WnSvc9F6B` 打开；
- `OPEN_PROCESS` 在内核打开句柄后，直接修补当前进程句柄表项的 `GrantedAccess` 为 `PROCESS_ALL_ACCESS`。

## CE 插件

`ce-plugin/TsMemCEPlugin.c` 做两件事：

1. 扫描 CE 主模块可写段，把 `ReadProcessMemoryActual` / `WriteProcessMemoryActual` 替换为走驱动的实现；
2. 替换 CE 的 `DebugActiveProcess` / `WaitForDebugEvent` / `ContinueDebugEvent` / `DebugActiveProcessStop` 指针，用：
   - `OPEN_PROCESS` 全权限句柄；
   - `NtCreateDebugObject` + `NtDebugActiveProcess`；
   - `NtWaitForDebugEvent` + `DbgUiConvertStateChangeStructure`；
   - `NtDebugContinue`。

详见 [`docs/ce-plugin.md`](docs/ce-plugin.md)。

## 构建

### 驱动

需要 WDK 10.0.26100 + VS 2022 BuildTools：

```bat
cd driver
build_kdu.bat
```

输出 `driver\build\ts_mem_kdu.sys`。

### 用户态工具

`tool/tool.py` 需要 Python 3 + numpy + tkinter：

```bat
python tool\tool.py
```

### CE 插件

```bat
cl /nologo /TC /LD ce-plugin\TsMemCEPlugin.c /Fe:TsMemCEPlugin.dll /link /MACHINE:X64
```

把 DLL 放到 CE 的 `plugins` 目录，或用 `Plugin → Load plugin` 加载。

## 使用

1. 退出杀软（KDU/驱动会被拦）；
2. 用 KDU（第三方，不在本仓库）映射驱动：
   ```bat
   kdu.exe -prv 1 -map driver\build\ts_mem_kdu.sys
   ```
3. 打开 `tool\tool.py`，或启动 CE 并加载插件；
4. 设备路径：`\\.\GLOBALROOT\Device\WnSvc9F6B`。

## 研究结论

- 用户态 `ReadProcessMemory`/`WriteProcessMemory` 被 BRM 拦截；内核 `MmCopyVirtualMemory` 可以读写。
- 人机/练习局：本地数值写入有效；真人局：服务器权威，本地写入会被覆盖/对账。
- 调试附加：
  - 内核打开的全权限句柄 `GrantedAccess = 0x1FFFFF`；
  - `NtDebugActiveProcess` 返回 `0x0`；
  - 初始 `CREATE_PROCESS`/`LOAD_DLL`/`CREATE_THREAD` 事件可以继续；
  - 游戏检测到 `DebugPort` 后自行 `ExitProcess`，测试账号被封 7 天。
- DBVM：
  - CE 7.7 的 `dbk64.cepack` 是 **DBK64 驱动**，不是 DBVM；
  - 官方安装包/EFI 分区里没有可用的 Windows DBVM 文件；
  - 未取得可用的 DBVM hypervisor。
- KDU provider `RTCore64` 在重启后可能被 Windows/杀软拦截（`0xC000017C`）；关闭杀软后重试可加载。

## 限制

- 依赖 KDU/BYOVD provider，受驱动黑名单/杀软影响；
- 没有 DBVM/反调试绕过；调试附加会被 `DebugPort` 检测；
- CE/插件/工具的用户态特征明显，不适合隐蔽使用；
- 真人局金币/点券等为服务器权威，本地修改不可靠。

## 目录

```text
driver/        内核驱动源码、客户端、构建脚本
tool/          Python GUI 工具
ce-plugin/     Cheat Engine 插件源码
docs/          研究记录与插件说明
```

## 免责声明

本项目仅用于本地研究、逆向学习和隔离测试环境；不包含任何第三方二进制，不保证可用性。请勿用于线上游戏或他人设备。
