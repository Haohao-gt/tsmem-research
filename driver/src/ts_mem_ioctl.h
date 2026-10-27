#pragma once
/*
 * ts_mem_ioctl.h - shared protocol between TsMem.sys and ts_mem_client.exe
 * Plain C, no Windows headers required.
 */

typedef unsigned int        ts_u32;
typedef unsigned long long  ts_u64;
typedef wchar_t             ts_wchar;

/* CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x800+n, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0) */
#define TS_IOCTL_READ    0x00222000u
#define TS_IOCTL_WRITE   0x00222004u
#define TS_IOCTL_MODULE  0x00222008u
#define TS_IOCTL_INFO    0x0022200Cu
#define TS_IOCTL_HIDE    0x00222010u
#define TS_IOCTL_HIDE_DEVICE 0x00222014u
#define TS_IOCTL_OPEN_PROCESS 0x00222018u

#define TS_PROTOCOL_VERSION 1u

/* flags for ts_mem_req.flags */
#define TS_FLAG_ATTACH   1u   /* use KeStackAttachProcess + RtlCopyMemory instead of MmCopyVirtualMemory */
#define TS_FLAG_FORCE    2u   /* try the other method if the first one fails */

#pragma pack(push, 8)

typedef struct ts_mem_req {
    ts_u32 pid;
    ts_u32 size;
    ts_u64 addr;
    ts_u32 flags;
    ts_u32 reserved;
} ts_mem_req;

typedef struct ts_module_req {
    ts_u32   pid;
    ts_u32   reserved;
    ts_wchar name[64];
} ts_module_req;

typedef struct ts_module_rsp {
    ts_u64   base;
    ts_u32   size;
    ts_u32   reserved;
    ts_wchar path[260];
} ts_module_rsp;

typedef struct ts_info_rsp {
    ts_u32 version;
    ts_u32 hidden;
    ts_u64 driver_base;
    ts_u64 build_id;
} ts_info_rsp;

#pragma pack(pop)
