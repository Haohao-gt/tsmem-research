# CE 插件说明

源码：`ce-plugin/TsMemCEPlugin.c`

## 构建

```bat
cl /nologo /TC /LD ce-plugin\TsMemCEPlugin.c /Fe:TsMemCEPlugin.dll /link /MACHINE:X64
```

把 `TsMemCEPlugin.dll` 放到 Cheat Engine 的 `plugins` 目录，或通过 `Plugin → Load plugin` 加载。

## 行为

1. `CEPlugin_InitializePlugin` 中：
   - 扫描 CE 主模块可写段，替换 `ReadProcessMemoryActual` / `WriteProcessMemoryActual`；
   - 加载 `ntdll` 的 `NtCreateDebugObject` / `NtDebugActiveProcess` / `NtDebugContinue` / `NtRemoveProcessDebug` / `NtWaitForDebugEvent` / `DbgUiConvertStateChangeStructure`；
   - 替换 CE 的 `DebugActiveProcess` / `WaitForDebugEvent` / `ContinueDebugEvent` / `DebugActiveProcessStop` 函数指针。
2. 后台线程每 500ms 重新打补丁，防止 CE 重置。
3. 读写走 `\\.\GLOBALROOT\Device\WnSvc9F6B` 的 IOCTL。

## 依赖

- 驱动已映射，设备 `WnSvc9F6B` 可打开；
- CE 使用 **Windows 调试器** 或兼容接口；DBVM/VEH 接口不走这些指针。

## 限制

- 调试附加虽然能成功，但游戏检测到 `DebugPort` 后会退出；
- CE 7.7 的 `dbk64.cepack` 不是 DBVM，加载 `dbk64.sys` 不解决反调试；
- 插件只做 API 代理，不做反调试隐藏。
