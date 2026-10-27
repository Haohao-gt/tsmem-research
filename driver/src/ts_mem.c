/*
 * TsMem.sys - kernel memory read/write for a protected 32-bit game process.
 *
 * Why this exists: the game ships BRM-DRIVER207 (BrmsDriver.sys), which blocks
 * NtReadVirtualMemory / NtWriteVirtualMemory / NtAllocateVirtualMemory against
 * the game process even for an elevated caller (STATUS_ACCESS_DENIED).  The
 * driver below never touches those syscalls: it resolves EPROCESS directly and
 * copies through MmCopyVirtualMemory, or attaches to the target address space
 * and copies with RtlCopyMemory.
 *
 * Protocol: see ts_mem_ioctl.h.
 */

#include <ntifs.h>
#include <ntddk.h>
#include "ts_mem_ioctl.h"

#define TS_DEVICE_NAME   L"\\Device\\TsMem"
#define TS_SYMLINK_NAME  L"\\??\\TsMem"
#define TS_TAG           'meMT'

/* Undocumented but exported since Vista. */
PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);

/* Exported by ntoskrnl but no longer declared in the public WDK headers. */
NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize);

static PDEVICE_OBJECT g_DeviceObject = NULL;
static BOOLEAN        g_Hidden = FALSE;

/* ------------------------------------------------------------------ */
/* 32-bit target structures (WOW64 game on x64 kernel)                 */
/* ------------------------------------------------------------------ */

typedef struct ts_list32 {
    ts_u32 Flink;
    ts_u32 Blink;
} ts_list32;

typedef struct ts_ustr32 {
    unsigned short Length;
    unsigned short MaximumLength;
    ts_u32         Buffer;
} ts_ustr32;

typedef struct ts_ldr32 {
    ts_list32 InLoadOrderLinks;      /* 0x00 */
    ts_list32 InMemoryOrderLinks;    /* 0x08 */
    ts_list32 InInitOrderLinks;      /* 0x10 */
    ts_u32    DllBase;               /* 0x18 */
    ts_u32    EntryPoint;            /* 0x1C */
    ts_u32    SizeOfImage;           /* 0x20 */
    ts_ustr32 FullDllName;           /* 0x24 */
    ts_ustr32 BaseDllName;           /* 0x2C */
} ts_ldr32;

typedef struct ts_ldr_data32 {
    ts_u32    Length;                       /* 0x00 */
    unsigned char Initialized;              /* 0x04 */
    unsigned char pad[3];
    ts_u32    SsHandle;                     /* 0x08 */
    ts_list32 InLoadOrderModuleList;        /* 0x0C */
} ts_ldr_data32;

/* PEB32 offsets */
#define TS_PEB32_LDR 0x0C

/* ------------------------------------------------------------------ */
/* 64-bit target structures (for completeness / tests)                 */
/* ------------------------------------------------------------------ */

typedef struct ts_ldr64 {
    LIST_ENTRY InLoadOrderLinks;     /* 0x00 */
    LIST_ENTRY InMemoryOrderLinks;   /* 0x10 */
    LIST_ENTRY InInitOrderLinks;     /* 0x20 */
    PVOID      DllBase;              /* 0x30 */
    PVOID      EntryPoint;           /* 0x38 */
    ULONG      SizeOfImage;          /* 0x40 */
    ULONG      pad;                  /* 0x44 */
    UNICODE_STRING FullDllName;      /* 0x48 */
    UNICODE_STRING BaseDllName;      /* 0x58 */
} ts_ldr64;

typedef struct ts_ldr_data64 {
    ULONG      Length;               /* 0x00 */
    BOOLEAN    Initialized;          /* 0x04 */
    PVOID      SsHandle;             /* 0x08 */
    LIST_ENTRY InLoadOrderModuleList;/* 0x10 */
} ts_ldr_data64;

#define TS_PEB64_LDR 0x18

/* ------------------------------------------------------------------ */
/* Copy primitives                                                     */
/* ------------------------------------------------------------------ */

static NTSTATUS TsCopyViaAttach(PEPROCESS Process, PVOID Target, PVOID Local, ULONG Size, BOOLEAN Write)
{
    KAPC_STATE apc;
    NTSTATUS status = STATUS_SUCCESS;

    KeStackAttachProcess(Process, &apc);
    __try {
        if (Write) {
            RtlCopyMemory(Target, Local, Size);
        } else {
            RtlCopyMemory(Local, Target, Size);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    return status;
}

static NTSTATUS TsCopyMm(PEPROCESS Process, PVOID Target, PVOID Local, ULONG Size, BOOLEAN Write)
{
    SIZE_T copied = 0;
    if (Write) {
        return MmCopyVirtualMemory(PsGetCurrentProcess(), Local, Process, Target, Size, KernelMode, &copied);
    }
    return MmCopyVirtualMemory(Process, Target, PsGetCurrentProcess(), Local, Size, KernelMode, &copied);
}

static NTSTATUS TsReadWrite(ULONG Pid, ts_u64 Addr, PVOID Local, ULONG Size, ULONG Flags, BOOLEAN Write)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (Size == 0 || Size > 0x400000) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Addr == 0 || Addr > 0xFFFFFFFFull) {
        /* game is 32-bit; reject obvious garbage but allow low addresses */
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (Flags & TS_FLAG_ATTACH) {
        status = TsCopyViaAttach(process, (PVOID)(ULONG_PTR)Addr, Local, Size, Write);
    } else {
        status = TsCopyMm(process, (PVOID)(ULONG_PTR)Addr, Local, Size, Write);
    }

    if (!NT_SUCCESS(status) && (Flags & TS_FLAG_FORCE)) {
        if (Flags & TS_FLAG_ATTACH) {
            status = TsCopyMm(process, (PVOID)(ULONG_PTR)Addr, Local, Size, Write);
        } else {
            status = TsCopyViaAttach(process, (PVOID)(ULONG_PTR)Addr, Local, Size, Write);
        }
    }

    ObDereferenceObject(process);
    return status;
}

/* ------------------------------------------------------------------ */
/* Module lookup                                                       */
/* ------------------------------------------------------------------ */

static BOOLEAN TsNameEquals(PCWSTR Local, const unsigned short *Buffer, unsigned short Length)
{
    WCHAR tmp[64];
    USHORT chars = Length / sizeof(WCHAR);
    UNICODE_STRING a, b;

    if (Buffer == NULL || chars == 0) {
        return FALSE;
    }
    if (chars > 63) {
        chars = 63;
    }
    RtlCopyMemory(tmp, Buffer, chars * sizeof(WCHAR));
    tmp[chars] = 0;

    RtlInitUnicodeString(&a, tmp);
    RtlInitUnicodeString(&b, Local);
    return RtlEqualUnicodeString(&a, &b, TRUE);
}

static NTSTATUS TsWalk32(PEPROCESS Process, PVOID Peb32, PCWSTR Name, ts_module_rsp *Rsp)
{
    KAPC_STATE apc;
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG_PTR peb = (ULONG_PTR)Peb32;

    if (peb == 0 || peb > 0xFFFFFFFFull) {
        return STATUS_INVALID_PARAMETER;
    }

    KeStackAttachProcess(Process, &apc);
    __try {
        ts_u32 ldr = *(ts_u32 *)(peb + TS_PEB32_LDR);
        ts_u32 head, cur;
        ts_ldr32 *entry;
        ULONG guard = 0;

        if (ldr == 0) {
            status = STATUS_NOT_FOUND;
        } else {
            head = ldr + 0x0C;
            cur = *(ts_u32 *)(ULONG_PTR)head;
            while (cur != 0 && cur != head && guard++ < 512) {
                entry = (ts_ldr32 *)(ULONG_PTR)cur;
                if (TsNameEquals(Name, (const unsigned short *)(ULONG_PTR)entry->BaseDllName.Buffer,
                                 entry->BaseDllName.Length)) {
                    Rsp->base = entry->DllBase;
                    Rsp->size = entry->SizeOfImage;
                    if (entry->FullDllName.Buffer && entry->FullDllName.Length) {
                        USHORT n = entry->FullDllName.Length / sizeof(WCHAR);
                        if (n > 259) n = 259;
                        RtlCopyMemory(Rsp->path, (PVOID)(ULONG_PTR)entry->FullDllName.Buffer, n * sizeof(WCHAR));
                        Rsp->path[n] = 0;
                    }
                    status = STATUS_SUCCESS;
                    break;
                }
                cur = entry->InLoadOrderLinks.Flink;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    return status;
}

static NTSTATUS TsWalk64(PEPROCESS Process, PVOID Peb64, PCWSTR Name, ts_module_rsp *Rsp)
{
    KAPC_STATE apc;
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG guard = 0;

    if (Peb64 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeStackAttachProcess(Process, &apc);
    __try {
        ts_ldr_data64 *ldr = *(ts_ldr_data64 **)((PUCHAR)Peb64 + TS_PEB64_LDR);
        LIST_ENTRY *head, *cur;
        ts_ldr64 *entry;

        if (ldr == NULL) {
            status = STATUS_NOT_FOUND;
        } else {
            head = &ldr->InLoadOrderModuleList;
            cur = head->Flink;
            while (cur != NULL && cur != head && guard++ < 512) {
                entry = (ts_ldr64 *)cur;
                if (TsNameEquals(Name, entry->BaseDllName.Buffer, entry->BaseDllName.Length)) {
                    Rsp->base = (ts_u64)(ULONG_PTR)entry->DllBase;
                    Rsp->size = entry->SizeOfImage;
                    if (entry->FullDllName.Buffer && entry->FullDllName.Length) {
                        USHORT n = entry->FullDllName.Length / sizeof(WCHAR);
                        if (n > 259) n = 259;
                        RtlCopyMemory(Rsp->path, entry->FullDllName.Buffer, n * sizeof(WCHAR));
                        Rsp->path[n] = 0;
                    }
                    status = STATUS_SUCCESS;
                    break;
                }
                cur = cur->Flink;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    return status;
}

static NTSTATUS TsLookupModule(PEPROCESS Process, PCWSTR Name, ts_module_rsp *Rsp)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PVOID wow;
    PVOID peb;

    RtlZeroMemory(Rsp, sizeof(*Rsp));
    wow = PsGetProcessWow64Process(Process);
    peb = PsGetProcessPeb(Process);

    if (wow != NULL) {
        /*
         * Depending on the Windows build, PsGetProcessPeb may return the
         * 64-bit PEB and PsGetProcessWow64Process may return either the
         * 32-bit PEB directly or a WOW64_PROCESS wrapper.  Try all shapes.
         */
        PVOID candidates[2];
        int count = 0;
        int i;

        /*
         * Never dereference a candidate here: PsGetProcessWow64Process may
         * return a user-mode PEB address.  TsWalk32 validates the address
         * range, attaches to the target and guards the reads with SEH.
         */
        candidates[count++] = peb;
        candidates[count++] = wow;

        for (i = 0; i < count; i++) {
            if (candidates[i] == NULL) {
                continue;
            }
            status = TsWalk32(Process, candidates[i], Name, Rsp);
            if (NT_SUCCESS(status)) {
                return status;
            }
        }
        return status;
    }

    return TsWalk64(Process, peb, Name, Rsp);
}

/* ------------------------------------------------------------------ */
/* Hide driver from PsLoadedModuleList                                 */
/* ------------------------------------------------------------------ */

static VOID TsHideDriver(PDRIVER_OBJECT DriverObject)
{
    PLIST_ENTRY entry;

    if (g_Hidden || DriverObject->DriverSection == NULL) {
        return;
    }
    entry = (PLIST_ENTRY)DriverObject->DriverSection; /* KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks */
    RemoveEntryList(entry);
    InitializeListHead(entry);
    g_Hidden = TRUE;
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
        ULONG pid;
        ULONG size;
        ULONG flags;
        ts_u64 addr;

        if (req == NULL || inLen < sizeof(ts_mem_req)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        /* Save the request before the read overwrites the system buffer. */
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
        rsp->hidden = g_Hidden ? 1 : 0;
        rsp->driver_base = (ts_u64)(ULONG_PTR)DeviceObject->DriverObject->DriverStart;
        rsp->build_id = 0x20260101;
        status = STATUS_SUCCESS;
        info = sizeof(ts_info_rsp);
        break;
    }
    case TS_IOCTL_HIDE:
        TsHideDriver(DeviceObject->DriverObject);
        status = STATUS_SUCCESS;
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID TsUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink;

    RtlInitUnicodeString(&symlink, TS_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName, TS_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, TS_SYMLINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = TsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TsDeviceControl;
    DriverObject->DriverUnload = TsUnload;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
