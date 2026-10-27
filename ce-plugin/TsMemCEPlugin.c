// TsMemCEPlugin.c - Cheat Engine plugin (C build, matches cepluginsdk.h)
// Routes CE's ReadProcessMemory/WriteProcessMemory through the TsMem driver.

#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

static void Log(const char* fmt, ...) {
    FILE* f = fopen("C:\\ProgramData\\tsmem_ce.log", "a");
    va_list ap;
    if (!f) return;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

#define CESDK_VERSION 6

typedef struct _PluginVersion {
    unsigned int version;
    char* pluginname;
} PluginVersion, *PPluginVersion;

typedef struct _ExportedFunctions {
    int sizeofExportedFunctions;
    /* remaining fields are not used by this plugin */
} ExportedFunctions, *PExportedFunctions;

#pragma pack(push, 8)
typedef struct {
    uint32_t pid;
    uint32_t size;
    uint64_t addr;
    uint32_t flags;
    uint32_t reserved;
} TS_MEM_REQ;
#pragma pack(pop)

static const wchar_t* kDevicePath = L"\\\\.\\GLOBALROOT\\Device\\WnSvc9F6B";
static HANDLE g_dev = INVALID_HANDLE_VALUE;

typedef BOOL (WINAPI *RPM_T)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *WPM_T)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

static RPM_T g_realRPM = NULL;
static WPM_T g_realWPM = NULL;
static uintptr_t* g_pRPM = NULL;
static uintptr_t* g_pWPM = NULL;
static uintptr_t g_origRPM = 0;
static uintptr_t g_origWPM = 0;
static uintptr_t* g_pWait = NULL;
static uintptr_t* g_pCont = NULL;
static uintptr_t* g_pDbg = NULL;
static uintptr_t* g_pStop = NULL;

static HANDLE OpenDev(void) {
    if (g_dev == INVALID_HANDLE_VALUE || g_dev == NULL) {
        g_dev = CreateFileW(kDevicePath, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, 0, NULL);
    }
    return g_dev;
}

/* ---- debugger proxy ---- */

typedef struct _TS_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} TS_CLIENT_ID;

typedef struct _TS_OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} TS_OBJECT_ATTRIBUTES;

typedef struct _TS_DBGUI_STATE {
    ULONG64 opaque[64];
} TS_DBGUI_STATE;

typedef LONG (NTAPI *PFN_NT_CREATE_DEBUG_OBJECT)(PHANDLE, DWORD, TS_OBJECT_ATTRIBUTES*, ULONG);
typedef LONG (NTAPI *PFN_NT_DEBUG_ACTIVE_PROCESS)(HANDLE, HANDLE);
typedef LONG (NTAPI *PFN_NT_DEBUG_CONTINUE)(HANDLE, TS_CLIENT_ID*, LONG);
typedef LONG (NTAPI *PFN_NT_REMOVE_PROCESS_DEBUG)(HANDLE, HANDLE);
typedef LONG (NTAPI *PFN_NT_WAIT_FOR_DEBUG_EVENT)(HANDLE, BOOLEAN, LARGE_INTEGER*, TS_DBGUI_STATE*);
typedef LONG (NTAPI *PFN_DBGUI_CONVERT)(TS_DBGUI_STATE*, LPDEBUG_EVENT);

static PFN_NT_CREATE_DEBUG_OBJECT pNtCreateDebugObject = NULL;
static PFN_NT_DEBUG_ACTIVE_PROCESS pNtDebugActiveProcess = NULL;
static PFN_NT_DEBUG_CONTINUE pNtDebugContinue = NULL;
static PFN_NT_REMOVE_PROCESS_DEBUG pNtRemoveProcessDebug = NULL;
static PFN_NT_WAIT_FOR_DEBUG_EVENT pNtWaitForDebugEvent = NULL;
static PFN_DBGUI_CONVERT pDbgUiConvert = NULL;

static HANDLE g_dbgObj = NULL;
static HANDLE g_dbgProc = NULL;
static DWORD g_dbgPid = 0;

static BOOL WINAPI TsDebugActiveProcessStop(DWORD pid);

static void LoadDebugApis(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    pNtCreateDebugObject = (PFN_NT_CREATE_DEBUG_OBJECT)GetProcAddress(ntdll, "NtCreateDebugObject");
    pNtDebugActiveProcess = (PFN_NT_DEBUG_ACTIVE_PROCESS)GetProcAddress(ntdll, "NtDebugActiveProcess");
    pNtDebugContinue = (PFN_NT_DEBUG_CONTINUE)GetProcAddress(ntdll, "NtDebugContinue");
    pNtRemoveProcessDebug = (PFN_NT_REMOVE_PROCESS_DEBUG)GetProcAddress(ntdll, "NtRemoveProcessDebug");
    pNtWaitForDebugEvent = (PFN_NT_WAIT_FOR_DEBUG_EVENT)GetProcAddress(ntdll, "NtWaitForDebugEvent");
    pDbgUiConvert = (PFN_DBGUI_CONVERT)GetProcAddress(ntdll, "DbgUiConvertStateChangeStructure");
    Log("debug apis create=%p active=%p wait=%p convert=%p", pNtCreateDebugObject,
        pNtDebugActiveProcess, pNtWaitForDebugEvent, pDbgUiConvert);
}

static HANDLE OpenFullProcess(DWORD pid) {
    HANDLE dev = OpenDev();
    ULONG in = pid;
    ULONG64 out = 0;
    DWORD bytes = 0;
    if (dev == INVALID_HANDLE_VALUE) return NULL;
    if (!DeviceIoControl(dev, 0x00222018, &in, sizeof(in), &out, sizeof(out), &bytes, NULL)) {
        Log("OPEN_PROCESS ioctl failed %lu", GetLastError());
        return NULL;
    }
    return (HANDLE)(ULONG_PTR)out;
}

static BOOL WINAPI TsDebugActiveProcess(DWORD pid) {
    TS_OBJECT_ATTRIBUTES oa;
    LONG st;
    Log("TsDebugActiveProcess %lu", pid);
    if (!pNtCreateDebugObject || !pNtDebugActiveProcess) return FALSE;
    if (g_dbgObj) TsDebugActiveProcessStop(g_dbgPid);

    g_dbgProc = OpenFullProcess(pid);
    if (!g_dbgProc) return FALSE;

    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    st = pNtCreateDebugObject(&g_dbgObj, 0x1F000F, &oa, 0);
    if (st < 0) {
        Log("NtCreateDebugObject %08X", st);
        return FALSE;
    }
    st = pNtDebugActiveProcess(g_dbgProc, g_dbgObj);
    if (st < 0) {
        Log("NtDebugActiveProcess %08X", st);
        return FALSE;
    }
    g_dbgPid = pid;
    Log("debug attached %lu", pid);
    return TRUE;
}

static BOOL WINAPI TsWaitForDebugEvent(LPDEBUG_EVENT ev, DWORD ms) {
    TS_DBGUI_STATE state;
    LARGE_INTEGER timeout;
    LARGE_INTEGER* pt = NULL;
    LONG st;
    if (!g_dbgObj || !pNtWaitForDebugEvent || !pDbgUiConvert) return FALSE;
    memset(&state, 0, sizeof(state));
    if (ms != INFINITE) {
        timeout.QuadPart = -(LONGLONG)ms * 10000;
        pt = &timeout;
    }
    st = pNtWaitForDebugEvent(g_dbgObj, FALSE, pt, &state);
    if (st == 0x102) return FALSE; /* STATUS_TIMEOUT */
    if (st < 0) {
        Log("NtWaitForDebugEvent %08X", st);
        return FALSE;
    }
    {
        ULONG newState = *(ULONG*)&state;
        if (newState == 0) return FALSE; /* DbgIdle */
        Log("NtWait state=%lu st=%08X", newState, st);
    }
    memset(ev, 0, sizeof(DEBUG_EVENT));
    st = pDbgUiConvert(&state, ev);
    if (st < 0) {
        Log("DbgUiConvert state=%lu %08X", *(ULONG*)&state, st);
        return FALSE;
    }
    Log("event code=%lu pid=%lu tid=%lu state=%lu", ev->dwDebugEventCode,
        ev->dwProcessId, ev->dwThreadId, *(ULONG*)&state);
    return TRUE;
}

static BOOL WINAPI TsContinueDebugEvent(DWORD pid, DWORD tid, DWORD status) {
    TS_CLIENT_ID cid;
    LONG st;
    if (!g_dbgObj || !pNtDebugContinue) return FALSE;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;
    st = pNtDebugContinue(g_dbgObj, &cid, (LONG)status);
    Log("Continue pid=%lu tid=%lu status=%08X -> %08X", pid, tid, status, st);
    return st >= 0;
}

static BOOL WINAPI TsDebugActiveProcessStop(DWORD pid) {
    if (g_dbgObj && g_dbgProc && pNtRemoveProcessDebug) {
        pNtRemoveProcessDebug(g_dbgProc, g_dbgObj);
    }
    if (g_dbgObj) CloseHandle(g_dbgObj);
    if (g_dbgProc) CloseHandle(g_dbgProc);
    g_dbgObj = NULL;
    g_dbgProc = NULL;
    g_dbgPid = 0;
    return TRUE;
}

BOOL WINAPI TsMemReadProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,
                                   LPVOID lpBuffer, SIZE_T nSize,
                                   SIZE_T* lpNumberOfBytesRead) {
    HANDLE dev;
    DWORD pid;
    SIZE_T total;
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
    if (nSize == 0) return TRUE;

    dev = OpenDev();
    pid = GetProcessId(hProcess);
    if (dev == INVALID_HANDLE_VALUE || pid == 0) {
        if (g_realRPM) return g_realRPM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        return FALSE;
    }

    total = 0;
    while (total < nSize) {
        SIZE_T remain = nSize - total;
        DWORD chunk = (DWORD)(remain > 0x100000 ? 0x100000 : remain);
        TS_MEM_REQ req;
        DWORD bytes = 0;
        req.pid = pid;
        req.size = chunk;
        req.addr = (uint64_t)((uintptr_t)lpBaseAddress + total);
        req.flags = 0;
        req.reserved = 0;
        if (!DeviceIoControl(dev, 0x00222000, &req, sizeof(req),
                             (BYTE*)lpBuffer + total, chunk, &bytes, NULL)) {
            break;
        }
        if (bytes == 0) break;
        total += bytes;
    }
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = total;
    return total == nSize;
}

BOOL WINAPI TsMemWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,
                                    LPCVOID lpBuffer, SIZE_T nSize,
                                    SIZE_T* lpNumberOfBytesWritten) {
    HANDLE dev;
    DWORD pid;
    SIZE_T total;
    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0;
    if (nSize == 0) return TRUE;

    dev = OpenDev();
    pid = GetProcessId(hProcess);
    if (dev == INVALID_HANDLE_VALUE || pid == 0) {
        if (g_realWPM) return g_realWPM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        return FALSE;
    }

    total = 0;
    while (total < nSize) {
        SIZE_T remain = nSize - total;
        DWORD chunk = (DWORD)(remain > 0x100000 ? 0x100000 : remain);
        BYTE* in;
        TS_MEM_REQ* req;
        DWORD bytes = 0;
        in = (BYTE*)malloc(sizeof(TS_MEM_REQ) + chunk);
        if (!in) break;
        req = (TS_MEM_REQ*)in;
        req->pid = pid;
        req->size = chunk;
        req->addr = (uint64_t)((uintptr_t)lpBaseAddress + total);
        req->flags = 0;
        req->reserved = 0;
        memcpy(in + sizeof(TS_MEM_REQ), (const BYTE*)lpBuffer + total, chunk);
        if (!DeviceIoControl(dev, 0x00222004, in, (DWORD)(sizeof(TS_MEM_REQ) + chunk),
                             NULL, 0, &bytes, NULL)) {
            free(in);
            break;
        }
        free(in);
        total += chunk;
    }
    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = total;
    return total == nSize;
}

static int PatchValue(uintptr_t value, uintptr_t replacement, const char* name, uintptr_t** out) {
    HMODULE ce = GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS* nt;
    IMAGE_SECTION_HEADER* sec;
    int i;
    if (!ce || !value) return 0;
    dos = (IMAGE_DOS_HEADER*)ce;
    nt = (IMAGE_NT_HEADERS*)((BYTE*)ce + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        BYTE* start;
        SIZE_T size;
        SIZE_T off;
        if (!(sec->Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        start = (BYTE*)ce + sec->VirtualAddress;
        size = sec->Misc.VirtualSize;
        for (off = 0; off + 8 <= size; off += 8) {
            uintptr_t* p = (uintptr_t*)(start + off);
            if (p[0] == value) {
                DWORD old = 0;
                if (!VirtualProtect(p, 8, PAGE_READWRITE, &old)) continue;
                p[0] = replacement;
                VirtualProtect(p, 8, old, &old);
                if (out) *out = p;
                Log("patched %s at %p", name, p);
                return 1;
            }
        }
    }
    Log("patch %s not found", name);
    return 0;
}

static int PatchPair(uintptr_t rpm, uintptr_t wpm) {
    HMODULE ce = GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS* nt;
    IMAGE_SECTION_HEADER* sec;
    int i;
    if (!ce) return 0;
    dos = (IMAGE_DOS_HEADER*)ce;
    nt = (IMAGE_NT_HEADERS*)((BYTE*)ce + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        BYTE* start;
        SIZE_T size;
        SIZE_T off;
        if (!(sec->Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        start = (BYTE*)ce + sec->VirtualAddress;
        size = sec->Misc.VirtualSize;
        for (off = 0; off + 16 <= size; off += 8) {
            uintptr_t* p = (uintptr_t*)(start + off);
            if (p[0] == rpm && p[1] == wpm) {
                DWORD old = 0;
                if (!VirtualProtect(p, 16, PAGE_READWRITE, &old)) continue;
                g_pRPM = &p[0];
                g_pWPM = &p[1];
                g_origRPM = p[0];
                g_origWPM = p[1];
                g_realRPM = (RPM_T)p[0];
                g_realWPM = (WPM_T)p[1];
                p[0] = (uintptr_t)&TsMemReadProcessMemory;
                p[1] = (uintptr_t)&TsMemWriteProcessMemory;
                VirtualProtect(p, 16, old, &old);
                return 1;
            }
        }
    }
    return 0;
}

static int PatchIndividual(uintptr_t rpm, uintptr_t wpm) {
    HMODULE ce = GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS* nt;
    IMAGE_SECTION_HEADER* sec;
    int i;
    int gotR = 0;
    int gotW = 0;
    if (!ce) return 0;
    dos = (IMAGE_DOS_HEADER*)ce;
    nt = (IMAGE_NT_HEADERS*)((BYTE*)ce + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        BYTE* start;
        SIZE_T size;
        SIZE_T off;
        if (!(sec->Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        start = (BYTE*)ce + sec->VirtualAddress;
        size = sec->Misc.VirtualSize;
        for (off = 0; off + 8 <= size; off += 8) {
            uintptr_t* p = (uintptr_t*)(start + off);
            if (!gotR && p[0] == rpm) {
                DWORD old = 0;
                if (VirtualProtect(p, 8, PAGE_READWRITE, &old)) {
                    g_pRPM = p;
                    g_origRPM = p[0];
                    g_realRPM = (RPM_T)p[0];
                    p[0] = (uintptr_t)&TsMemReadProcessMemory;
                    VirtualProtect(p, 8, old, &old);
                    gotR = 1;
                }
            } else if (!gotW && p[0] == wpm) {
                DWORD old = 0;
                if (VirtualProtect(p, 8, PAGE_READWRITE, &old)) {
                    g_pWPM = p;
                    g_origWPM = p[0];
                    g_realWPM = (WPM_T)p[0];
                    p[0] = (uintptr_t)&TsMemWriteProcessMemory;
                    VirtualProtect(p, 8, old, &old);
                    gotW = 1;
                }
            }
        }
    }
    return gotR || gotW;
}

static DWORD WINAPI RepatchThread(LPVOID param) {
    (void)param;
    for (;;) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        uintptr_t rpm = (uintptr_t)GetProcAddress(k32, "ReadProcessMemory");
        uintptr_t wpm = (uintptr_t)GetProcAddress(k32, "WriteProcessMemory");
        if (g_pRPM && *g_pRPM == rpm) {
            DWORD old = 0;
            if (VirtualProtect(g_pRPM, 8, PAGE_READWRITE, &old)) {
                *g_pRPM = (uintptr_t)&TsMemReadProcessMemory;
                VirtualProtect(g_pRPM, 8, old, &old);
                Log("repatch RPM");
            }
        }
        if (g_pWPM && *g_pWPM == wpm) {
            DWORD old = 0;
            if (VirtualProtect(g_pWPM, 8, PAGE_READWRITE, &old)) {
                *g_pWPM = (uintptr_t)&TsMemWriteProcessMemory;
                VirtualProtect(g_pWPM, 8, old, &old);
                Log("repatch WPM");
            }
        }
        {
            uintptr_t waitAddr = (uintptr_t)GetProcAddress(k32, "WaitForDebugEvent");
            uintptr_t contAddr = (uintptr_t)GetProcAddress(k32, "ContinueDebugEvent");
            uintptr_t dbgAddr = (uintptr_t)GetProcAddress(k32, "DebugActiveProcess");
            uintptr_t stopAddr = (uintptr_t)GetProcAddress(k32, "DebugActiveProcessStop");
            DWORD old = 0;
            if (g_pWait && *g_pWait == waitAddr && VirtualProtect(g_pWait, 8, PAGE_READWRITE, &old)) {
                *g_pWait = (uintptr_t)&TsWaitForDebugEvent;
                VirtualProtect(g_pWait, 8, old, &old);
                Log("repatch WaitForDebugEvent");
            }
            if (g_pCont && *g_pCont == contAddr && VirtualProtect(g_pCont, 8, PAGE_READWRITE, &old)) {
                *g_pCont = (uintptr_t)&TsContinueDebugEvent;
                VirtualProtect(g_pCont, 8, old, &old);
                Log("repatch ContinueDebugEvent");
            }
            if (g_pDbg && *g_pDbg == dbgAddr && VirtualProtect(g_pDbg, 8, PAGE_READWRITE, &old)) {
                *g_pDbg = (uintptr_t)&TsDebugActiveProcess;
                VirtualProtect(g_pDbg, 8, old, &old);
                Log("repatch DebugActiveProcess");
            }
            if (g_pStop && *g_pStop == stopAddr && VirtualProtect(g_pStop, 8, PAGE_READWRITE, &old)) {
                *g_pStop = (uintptr_t)&TsDebugActiveProcessStop;
                VirtualProtect(g_pStop, 8, old, &old);
                Log("repatch DebugActiveProcessStop");
            }
        }
        Sleep(500);
    }
    return 0;
}

static void Restore(void) {
    if (g_pRPM) {
        DWORD old = 0;
        if (VirtualProtect(g_pRPM, 8, PAGE_READWRITE, &old)) {
            *g_pRPM = g_origRPM;
            VirtualProtect(g_pRPM, 8, old, &old);
        }
    }
    if (g_pWPM) {
        DWORD old = 0;
        if (VirtualProtect(g_pWPM, 8, PAGE_READWRITE, &old)) {
            *g_pWPM = g_origWPM;
            VirtualProtect(g_pWPM, 8, old, &old);
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) Log("DllMain attach");
    if (reason == DLL_PROCESS_DETACH) Log("DllMain detach");
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion) {
    Log("GetVersion size=%d", sizeofpluginversion);
    if (!pv) return FALSE;
    pv->version = CESDK_VERSION;
    pv->pluginname = (char*)"TsMem";
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid) {
    HMODULE k32;
    uintptr_t rpm;
    uintptr_t wpm;
    Log("Initialize ef=%p size=%d", ef, ef ? ef->sizeofExportedFunctions : -1);
    if (!ef || ef->sizeofExportedFunctions <= 0) return FALSE;

    k32 = GetModuleHandleW(L"kernel32.dll");
    rpm = (uintptr_t)GetProcAddress(k32, "ReadProcessMemory");
    wpm = (uintptr_t)GetProcAddress(k32, "WriteProcessMemory");
    if (!rpm || !wpm) return FALSE;

    {
        int pair = PatchPair(rpm, wpm);
        int ind = 0;
        if (!pair) ind = PatchIndividual(rpm, wpm);
        Log("Patch pair=%d individual=%d rpm=%p wpm=%p pRPM=%p pWPM=%p", pair, ind, (void*)rpm, (void*)wpm, (void*)g_pRPM, (void*)g_pWPM);
    }
    LoadDebugApis();
    {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        PatchValue((uintptr_t)GetProcAddress(k32, "WaitForDebugEvent"),
                   (uintptr_t)&TsWaitForDebugEvent, "WaitForDebugEvent", &g_pWait);
        PatchValue((uintptr_t)GetProcAddress(k32, "ContinueDebugEvent"),
                   (uintptr_t)&TsContinueDebugEvent, "ContinueDebugEvent", &g_pCont);
        PatchValue((uintptr_t)GetProcAddress(k32, "DebugActiveProcess"),
                   (uintptr_t)&TsDebugActiveProcess, "DebugActiveProcess", &g_pDbg);
        PatchValue((uintptr_t)GetProcAddress(k32, "DebugActiveProcessStop"),
                   (uintptr_t)&TsDebugActiveProcessStop, "DebugActiveProcessStop", &g_pStop);
    }
    {
        static int started = 0;
        if (!started) {
            started = 1;
            CreateThread(NULL, 0, RepatchThread, NULL, 0, NULL);
        }
    }
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall CEPlugin_DisablePlugin(void) {
    Restore();
    if (g_dev != INVALID_HANDLE_VALUE) {
        CloseHandle(g_dev);
        g_dev = INVALID_HANDLE_VALUE;
    }
    return TRUE;
}
