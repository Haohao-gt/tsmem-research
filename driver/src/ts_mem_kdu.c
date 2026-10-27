/*
 * ts_mem_kdu.c - KDU-mapped variant of TsMem.
 *
 * KDU manual mapping rules:
 *   - DriverEntry receives an unusable DriverObject; create a real one with
 *     IoCreateDriver (resolved dynamically from ntoskrnl).
 *   - SEH tables are NOT registered, so never use __try/__except and never
 *     dereference user-mode pointers directly.
 *   - All copies use MmCopyVirtualMemory (exported by ntoskrnl, no Zw* stub
 *     dependency, no SEH).
 *   - No unload.
 *
 * Protocol: ts_mem_ioctl.h (same as ts_mem_client.exe).
 */

#include <ntifs.h>
#include <ntddk.h>
#include "ts_mem_ioctl.h"

#define TS_DEVICE_NAME  L"\\Device\\WnSvc9F6B"
#define TS_SYMLINK_NAME L"\\??\\WnSvc9F6B"
#define TS_DRIVER_NAME  L"\\Driver\\WnSvc9F6B"

PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);

NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

typedef NTSTATUS (NTAPI *PFN_ZwProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS (NTAPI *PFN_IOCREATEDRIVER)(PUNICODE_STRING, PDRIVER_INITIALIZE);
typedef VOID (NTAPI *PFN_OBMAKETEMPORARY)(PVOID);

static PFN_IOCREATEDRIVER         g_IoCreateDriver = NULL;
static PFN_ZwProtectVirtualMemory  g_ZwProtect = NULL;
static PFN_OBMAKETEMPORARY        g_ObMakeTemporary = NULL;
static PDEVICE_OBJECT             g_Device = NULL;

/* ------------------------------------------------------------------ */
/* 32-bit structures                                                   */
/* ------------------------------------------------------------------ */

typedef struct ts_list32 { ULONG Flink; ULONG Blink; } ts_list32;
typedef struct ts_ustr32 { USHORT Length; USHORT MaximumLength; ULONG Buffer; } ts_ustr32;

typedef struct ts_peb32 {
    UCHAR Reserved[0x0C];
    ULONG Ldr;                       /* 0x0C */
} ts_peb32;

typedef struct ts_ldr_data32 {
    ULONG     Length;                /* 0x00 */
    UCHAR     Initialized;           /* 0x04 */
    UCHAR     pad[3];
    ULONG     SsHandle;              /* 0x08 */
    ts_list32 InLoadOrderModuleList; /* 0x0C */
} ts_ldr_data32;

typedef struct ts_ldr_entry32 {
    ts_list32 InLoadOrderLinks;      /* 0x00 */
    ts_list32 InMemoryOrderLinks;    /* 0x08 */
    ts_list32 InInitOrderLinks;      /* 0x10 */
    ULONG     DllBase;               /* 0x18 */
    ULONG     EntryPoint;            /* 0x1C */
    ULONG     SizeOfImage;           /* 0x20 */
    ts_ustr32 FullDllName;           /* 0x24 */
    ts_ustr32 BaseDllName;           /* 0x2C */
} ts_ldr_entry32;

/* ------------------------------------------------------------------ */
/* 64-bit structures                                                   */
/* ------------------------------------------------------------------ */

typedef struct ts_ldr_data64 {
    ULONG      Length;               /* 0x00 */
    UCHAR      Initialized;          /* 0x04 */
    UCHAR      pad[3];
    PVOID      SsHandle;             /* 0x08 */
    LIST_ENTRY InLoadOrderModuleList;/* 0x10 */
} ts_ldr_data64;

typedef struct ts_ldr_entry64 {
    LIST_ENTRY InLoadOrderLinks;     /* 0x00 */
    LIST_ENTRY InMemoryOrderLinks;   /* 0x10 */
    LIST_ENTRY InInitOrderLinks;     /* 0x20 */
    PVOID      DllBase;              /* 0x30 */
    PVOID      EntryPoint;           /* 0x38 */
    ULONG      SizeOfImage;          /* 0x40 */
    ULONG      pad;                  /* 0x44 */
    UNICODE_STRING FullDllName;      /* 0x48 */
    UNICODE_STRING BaseDllName;      /* 0x58 */
} ts_ldr_entry64;

/* ------------------------------------------------------------------ */
/* Safe copy via MmCopyVirtualMemory (no SEH, no Zw* stubs)            */
/* ------------------------------------------------------------------ */

static BOOLEAN TsSafeCopy(PEPROCESS Process, PVOID dst, PVOID src, SIZE_T size)
{
    SIZE_T done = 0;

    if (size == 0) {
        return TRUE;
    }
    return NT_SUCCESS(MmCopyVirtualMemory(Process, src, PsGetCurrentProcess(),
                                          dst, size, KernelMode, &done)) &&
           done == size;
}

static BOOLEAN TsNameEquals(PEPROCESS Process, PCWSTR Name, PVOID Buffer, USHORT Length)
{
    WCHAR tmp[64];
    USHORT chars = (USHORT)(Length / sizeof(WCHAR));
    UNICODE_STRING a, b;

    if (Buffer == NULL || chars == 0) {
        return FALSE;
    }
    if (chars > 63) {
        chars = 63;
    }
    if (!TsSafeCopy(Process, tmp, Buffer, chars * sizeof(WCHAR))) {
        return FALSE;
    }
    tmp[chars] = 0;
    RtlInitUnicodeString(&a, tmp);
    RtlInitUnicodeString(&b, Name);
    return RtlEqualUnicodeString(&a, &b, TRUE);
}

/* ------------------------------------------------------------------ */
/* Module walkers                                                      */
/* ------------------------------------------------------------------ */

static NTSTATUS TsWalk32(PEPROCESS Process, ULONG Peb32, PCWSTR Name, ts_module_rsp *Rsp)
{
    ts_peb32 peb;
    ts_ldr_data32 ldr;
    ts_ldr_entry32 entry;
    ULONG ldrAddr, head, cur, guard = 0;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!TsSafeCopy(Process, &peb, (PVOID)(ULONG_PTR)Peb32, sizeof(peb))) {
        return STATUS_ACCESS_VIOLATION;
    }
    ldrAddr = peb.Ldr;
    if (ldrAddr == 0) {
        return STATUS_NOT_FOUND;
    }
    if (!TsSafeCopy(Process, &ldr, (PVOID)(ULONG_PTR)ldrAddr, sizeof(ldr))) {
        return STATUS_ACCESS_VIOLATION;
    }

    head = ldrAddr + 0x0C;
    cur = ldr.InLoadOrderModuleList.Flink;
    while (cur != 0 && cur != head && guard++ < 512) {
        if (!TsSafeCopy(Process, &entry, (PVOID)(ULONG_PTR)cur, sizeof(entry))) {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }
        if (TsNameEquals(Process, Name, (PVOID)(ULONG_PTR)entry.BaseDllName.Buffer,
                         entry.BaseDllName.Length)) {
            Rsp->base = entry.DllBase;
            Rsp->size = entry.SizeOfImage;
            if (entry.FullDllName.Buffer && entry.FullDllName.Length) {
                USHORT n = (USHORT)(entry.FullDllName.Length / sizeof(WCHAR));
                if (n > 259) n = 259;
                if (TsSafeCopy(Process, Rsp->path, (PVOID)(ULONG_PTR)entry.FullDllName.Buffer,
                               n * sizeof(WCHAR))) {
                    Rsp->path[n] = 0;
                }
            }
            status = STATUS_SUCCESS;
            break;
        }
        cur = entry.InLoadOrderLinks.Flink;
    }
    return status;
}

static NTSTATUS TsWalk64(PEPROCESS Process, PVOID Peb64, PCWSTR Name, ts_module_rsp *Rsp)
{
    PVOID ldrAddr = NULL;
    ts_ldr_data64 ldr;
    ts_ldr_entry64 entry;
    PVOID head, cur;
    ULONG guard = 0;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Peb64 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!TsSafeCopy(Process, &ldrAddr, (PUCHAR)Peb64 + 0x18, sizeof(ldrAddr))) {
        return STATUS_ACCESS_VIOLATION;
    }
    if (ldrAddr == NULL) {
        return STATUS_NOT_FOUND;
    }
    if (!TsSafeCopy(Process, &ldr, ldrAddr, sizeof(ldr))) {
        return STATUS_ACCESS_VIOLATION;
    }

    head = (PUCHAR)ldrAddr + 0x10;
    cur = ldr.InLoadOrderModuleList.Flink;
    while (cur != NULL && cur != head && guard++ < 512) {
        if (!TsSafeCopy(Process, &entry, cur, sizeof(entry))) {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }
        if (TsNameEquals(Process, Name, entry.BaseDllName.Buffer, entry.BaseDllName.Length)) {
            Rsp->base = (ts_u64)(ULONG_PTR)entry.DllBase;
            Rsp->size = entry.SizeOfImage;
            if (entry.FullDllName.Buffer && entry.FullDllName.Length) {
                USHORT n = (USHORT)(entry.FullDllName.Length / sizeof(WCHAR));
                if (n > 259) n = 259;
                if (TsSafeCopy(Process, Rsp->path, entry.FullDllName.Buffer, n * sizeof(WCHAR))) {
                    Rsp->path[n] = 0;
                }
            }
            status = STATUS_SUCCESS;
            break;
        }
        cur = entry.InLoadOrderLinks.Flink;
    }
    return status;
}

static NTSTATUS TsLookupModule(PEPROCESS Process, PCWSTR Name, ts_module_rsp *Rsp)
{
    PVOID wow;

    RtlZeroMemory(Rsp, sizeof(*Rsp));
    wow = PsGetProcessWow64Process(Process);
    if (wow != NULL) {
        return TsWalk32(Process, (ULONG)(ULONG_PTR)wow, Name, Rsp);
    }
    return TsWalk64(Process, PsGetProcessPeb(Process), Name, Rsp);
}

/* ------------------------------------------------------------------ */
/* Read / write                                                        */
/* ------------------------------------------------------------------ */

static NTSTATUS TsCopy(PEPROCESS Process, PVOID Target, PVOID Local, ULONG Size, BOOLEAN Write)
{
    SIZE_T done = 0;
    NTSTATUS status;

    if (Write) {
        status = MmCopyVirtualMemory(PsGetCurrentProcess(), Local, Process, Target,
                                     Size, KernelMode, &done);
    } else {
        status = MmCopyVirtualMemory(Process, Target, PsGetCurrentProcess(), Local,
                                     Size, KernelMode, &done);
    }
    if (NT_SUCCESS(status) && done != Size) {
        status = STATUS_PARTIAL_COPY;
    }
    return status;
}

static NTSTATUS TsCopyProtected(PEPROCESS Process, PVOID Target, PVOID Local, ULONG Size)
{
    KAPC_STATE apc;
    PVOID base = Target;
    SIZE_T region = Size;
    ULONG oldProtect = 0;
    NTSTATUS status;
    SIZE_T done = 0;

    if (g_ZwProtect == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    KeStackAttachProcess(Process, &apc);

    status = g_ZwProtect((HANDLE)-1, &base, &region,
                         PAGE_EXECUTE_READWRITE, &oldProtect);
    if (NT_SUCCESS(status)) {
        status = MmCopyVirtualMemory(PsGetCurrentProcess(), Local, Process, Target,
                                     Size, KernelMode, &done);
        if (NT_SUCCESS(status) && done != Size) {
            status = STATUS_PARTIAL_COPY;
        }
        base = Target;
        region = Size;
        g_ZwProtect((HANDLE)-1, &base, &region, oldProtect, &oldProtect);
    }

    KeUnstackDetachProcess(&apc);
    return status;
}

static NTSTATUS TsReadWrite(ULONG Pid, ts_u64 Addr, PVOID Local, ULONG Size, ULONG Flags, BOOLEAN Write)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);

    if (Size == 0 || Size > 0x400000) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = TsCopy(process, (PVOID)(ULONG_PTR)Addr, Local, Size, Write);
    if (!NT_SUCCESS(status) && Write) {
        status = TsCopyProtected(process, (PVOID)(ULONG_PTR)Addr, Local, Size);
    }
    ObDereferenceObject(process);
    return status;
}

/* ------------------------------------------------------------------ */
/* IRP handlers                                                        */
/* ------------------------------------------------------------------ */

static NTSTATUS TsCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

BOOLEAN NTAPI MmIsAddressValid(PVOID VirtualAddress);

typedef struct _TS_HANDLE_ENTRY {
    PVOID Object;
    ULONG GrantedAccess;
    ULONG Pad;
} TS_HANDLE_ENTRY, *PTS_HANDLE_ENTRY;

static PVOID TsFindHandleTable(void)
{
    PEPROCESS process = PsGetCurrentProcess();
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    ULONG off;

    for (off = 0; off < 0x1000; off += sizeof(PVOID)) {
        PVOID p = *(PVOID*)((PUCHAR)process + off);
        ULONG64 tableCode;
        ULONG level;
        ULONG_PTR base;

        if (p == NULL || !MmIsAddressValid(p)) continue;
        if (!MmIsAddressValid((PUCHAR)p + 0x30)) continue;
        if (*(ULONG*)((PUCHAR)p + 0x28) != pid) continue;
        tableCode = *(ULONG64*)((PUCHAR)p + 0x8);
        level = (ULONG)(tableCode & 3);
        if (level > 2) continue;
        base = (ULONG_PTR)(tableCode & ~3ULL);
        if (base == 0 || !MmIsAddressValid((PVOID)base)) continue;
        return p;
    }
    return NULL;
}

static PTS_HANDLE_ENTRY TsLookupEntry(PVOID table, HANDLE handle)
{
    ULONG64 tableCode = *(ULONG64*)((PUCHAR)table + 0x8);
    ULONG index = (ULONG)((ULONG_PTR)handle >> 2);
    ULONG level = (ULONG)(tableCode & 3);
    ULONG_PTR base = (ULONG_PTR)(tableCode & ~3ULL);
    ULONG_PTR page;

    if (level == 0) {
        PTS_HANDLE_ENTRY e = &((PTS_HANDLE_ENTRY)base)[index & 0xFF];
        return MmIsAddressValid(e) ? e : NULL;
    }
    if (level == 1) {
        if (!MmIsAddressValid((PVOID)(base + sizeof(PVOID) * (index >> 8)))) return NULL;
        page = ((ULONG_PTR*)base)[index >> 8];
        if (page == 0 || !MmIsAddressValid((PVOID)page)) return NULL;
        {
            PTS_HANDLE_ENTRY e = &((PTS_HANDLE_ENTRY)page)[index & 0xFF];
            return MmIsAddressValid(e) ? e : NULL;
        }
    }
    if (level == 2) {
        ULONG_PTR mid;
        if (!MmIsAddressValid((PVOID)(base + sizeof(PVOID) * (index >> 16)))) return NULL;
        mid = ((ULONG_PTR*)base)[index >> 16];
        if (mid == 0 || !MmIsAddressValid((PVOID)mid)) return NULL;
        if (!MmIsAddressValid((PVOID)(mid + sizeof(PVOID) * ((index >> 8) & 0xFF)))) return NULL;
        page = ((ULONG_PTR*)mid)[(index >> 8) & 0xFF];
        if (page == 0 || !MmIsAddressValid((PVOID)page)) return NULL;
        {
            PTS_HANDLE_ENTRY e = &((PTS_HANDLE_ENTRY)page)[index & 0xFF];
            return MmIsAddressValid(e) ? e : NULL;
        }
    }
    return NULL;
}

static NTSTATUS TsDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case TS_IOCTL_READ:
    case TS_IOCTL_WRITE:
    {
        ts_mem_req *req = (ts_mem_req *)buffer;
        ULONG pid, size, flags;
        ts_u64 addr;

        if (req == NULL || inLen < sizeof(ts_mem_req)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        pid = req->pid;
        size = req->size;
        addr = req->addr;
        flags = req->flags;

        if (code == TS_IOCTL_READ) {
            if (outLen < size) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = TsReadWrite(pid, addr, buffer, size, flags, FALSE);
            if (NT_SUCCESS(status)) {
                info = size;
            }
        } else {
            if (inLen < sizeof(ts_mem_req) + size) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = TsReadWrite(pid, addr, (PUCHAR)buffer + sizeof(ts_mem_req),
                                 size, flags, TRUE);
            if (NT_SUCCESS(status)) {
                info = 0;
            }
        }
        break;
    }
    case TS_IOCTL_MODULE:
    {
        ts_module_req *req = (ts_module_req *)buffer;
        ts_module_rsp *rsp = (ts_module_rsp *)buffer;
        PEPROCESS process = NULL;
        WCHAR moduleName[64];

        if (req == NULL || inLen < sizeof(ts_module_req) || outLen < sizeof(ts_module_rsp)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        RtlCopyMemory(moduleName, req->name, sizeof(moduleName));
        moduleName[63] = 0;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->pid, &process);
        if (!NT_SUCCESS(status)) {
            break;
        }
        status = TsLookupModule(process, moduleName, rsp);
        ObDereferenceObject(process);
        if (NT_SUCCESS(status)) {
            info = sizeof(ts_module_rsp);
        }
        break;
    }
    case TS_IOCTL_INFO:
    {
        ts_info_rsp *rsp = (ts_info_rsp *)buffer;
        if (rsp == NULL || outLen < sizeof(ts_info_rsp)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        rsp->version = TS_PROTOCOL_VERSION;
        rsp->hidden = 0;
        rsp->driver_base = 0;
        rsp->build_id = 0x20260101;
        status = STATUS_SUCCESS;
        info = sizeof(ts_info_rsp);
        break;
    }
    case TS_IOCTL_HIDE:
        status = STATUS_SUCCESS;
        break;
    case TS_IOCTL_HIDE_DEVICE:
        if (g_ObMakeTemporary != NULL && g_Device != NULL) {
            g_ObMakeTemporary(g_Device);
        }
        status = STATUS_SUCCESS;
        break;
    case TS_IOCTL_OPEN_PROCESS:
    {
        ULONG pid;
        PEPROCESS process = NULL;
        HANDLE hUser = NULL;
        PVOID table;
        PTS_HANDLE_ENTRY entry;

        if (buffer == NULL || inLen < sizeof(ULONG) || outLen < sizeof(ULONG64)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        pid = *(ULONG*)buffer;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) {
            break;
        }
        status = ObOpenObjectByPointer(process, 0, NULL, PROCESS_ALL_ACCESS,
                                       *PsProcessType, KernelMode, &hUser);
        ObDereferenceObject(process);
        if (!NT_SUCCESS(status)) {
            break;
        }

        table = TsFindHandleTable();
        if (table != NULL) {
            entry = TsLookupEntry(table, hUser);
            if (entry != NULL) {
                entry->GrantedAccess = PROCESS_ALL_ACCESS;
            }
        }

        *(ULONG64*)buffer = (ULONG64)(ULONG_PTR)hUser;
        info = sizeof(ULONG64);
        break;
    }
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

static NTSTATUS TsInit(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING devName, procName;
    NTSTATUS status;

    RtlInitUnicodeString(&procName, L"ZwProtectVirtualMemory");
    g_ZwProtect = (PFN_ZwProtectVirtualMemory)MmGetSystemRoutineAddress(&procName);
    RtlInitUnicodeString(&procName, L"ObMakeTemporaryObject");
    g_ObMakeTemporary = (PFN_OBMAKETEMPORARY)MmGetSystemRoutineAddress(&procName);

    RtlInitUnicodeString(&devName, TS_DEVICE_NAME);

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &g_Device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = TsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TsDeviceControl;
    DriverObject->DriverUnload = NULL; /* KDU cannot unload */

    g_Device->Flags |= DO_BUFFERED_IO;
    g_Device->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Hide the driver object name and its load-order entry. */
    if (g_ObMakeTemporary != NULL) {
        g_ObMakeTemporary(DriverObject);
    }
    if (DriverObject->DriverSection != NULL) {
        PLIST_ENTRY entry = (PLIST_ENTRY)DriverObject->DriverSection;
        RemoveEntryList(entry);
        InitializeListHead(entry);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS TsRealEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    return TsInit(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING procName, drvName;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&procName, L"IoCreateDriver");
    g_IoCreateDriver = (PFN_IOCREATEDRIVER)MmGetSystemRoutineAddress(&procName);
    if (g_IoCreateDriver == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlInitUnicodeString(&drvName, TS_DRIVER_NAME);
    return g_IoCreateDriver(&drvName, TsRealEntry);
}
