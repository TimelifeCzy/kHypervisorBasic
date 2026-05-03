# kHypervisorBasic

Windows x64 VT-x / HyperPlatform 学习工程，用于研究 VMX、EPT、MSR bitmap、
VM-exit 分发和 nested VMX 基础流程。

Windows x64 VT-x / HyperPlatform research project for VMX, EPT, MSR bitmap,
VM-exit dispatch, and nested VMX basics.

## v1.0

路径 / Path: `kHypervisor/kHypervisor`

v1.0 将 HyperPlatform、VMX/EPT 和 MSR/EPT hook 示例放在同一个驱动里，便于
跟踪原始流程。

## v2.0

路径 / Path: `kHypervisorBasic`

v2.0 目标是做一个更精简的分离基线：

```text
kHypervisorBasic/
  hv/        driver-facing HV interface
  hooks/     separated hook module lifecycle
  vm.*       VMX lifecycle, per-CPU state, VMCS setup
  vmm.*      VM-exit dispatcher
  ept.*      EPT table, MTRR memory type, INVEPT
  vmx.*      nested VMX instruction emulation
```

当前入口流程：

```text
DriverEntry -> HookModuleRegister() -> HvInitialize() -> VmInitialization()
DriverUnload -> HvTerminate() -> module termination -> VmTermination()
```

hook 当前是分离模块骨架：`hooks/hook_module.*` 只注册生命周期，不默认修改
MSR/EPT。后续 MSR hook、EPT hook 应作为 provider 挂到该模块，而不是直接写进
`driver.cpp`、`vm.cpp` 或核心 `ept.cpp`。

## MSR 流程 / MSR Flow

```text
VmpBuildMsrBitmap()
  -> mark required RDMSR/WRMSR VM-exit bits

RDMSR / WRMSR VM-exit
  -> VmmpHandleMsrAccess()
     -> VMCS-backed MSRs use VMCS fields
     -> virtualized VMX MSRs use per-CPU state
     -> other MSRs fall back to real MSR read/write
```

## EPT 流程 / EPT Flow

```text
EptInitialization()
  -> read MTRRs
  -> build EPTP and PML4
  -> create pass-through physical mappings
  -> preallocate page-table pages for VM-exit time

EPT violation VM-exit
  -> VmmpHandleEptViolation()
     -> EptHandleEptViolation()
        -> create missing EPT entry or restore R/W/X access
        -> invalidate EPT translations
```

v2.0 中 EPT hook 应作为 `hv/` 之上的独立模块实现；核心 EPT 层只负责映射、
权限修改、失效刷新和事件分发。

## 编译 / Build

测试环境：Visual Studio 2019 + WDK，x64 Debug/Release。

```powershell
MSBuild kHypervisor\kHypervisor.sln /p:Configuration=Debug /p:Platform=x64 /p:SpectreMitigation=false
MSBuild kHypervisor\kHypervisor.sln /p:Configuration=Release /p:Platform=x64
```
