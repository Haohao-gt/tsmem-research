// ts_mem_client.exe - user-mode client for TsMem.sys
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include "ts_mem_ioctl.h"

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static std::wstring DevicePath() {
    wchar_t buf[260];
    DWORD n = GetEnvironmentVariableW(L"TS_DEV", buf, 260);
    if (n > 0 && n < 260) {
        return std::wstring(buf, n);
    }
    return L"\\\\.\\TsMem";
}

static bool OpenDevice() {
    std::wstring path = DevicePath();
    g_dev = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        std::printf("[!] open %ls failed, err=%lu\n", path.c_str(), GetLastError());
        return false;
    }
    return true;
}

static DWORD FindPid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool ResolvePid(const wchar_t* arg, DWORD& pid) {
    wchar_t* end = nullptr;
    unsigned long v = wcstoul(arg, &end, 0);
    if (end && *end == 0 && v != 0) { pid = (DWORD)v; return true; }
    pid = FindPid(arg);
    if (pid == 0) std::printf("[!] process not found: %ls\n", arg);
    return pid != 0;
}

static bool DevRead(DWORD pid, ULONGLONG addr, void* buf, DWORD size, DWORD flags) {
    std::vector<unsigned char> in(sizeof(ts_mem_req) + size);
    auto* req = (ts_mem_req*)in.data();
    req->pid = pid; req->addr = addr; req->size = size; req->flags = flags;
    DWORD ret = 0;
    if (!DeviceIoControl(g_dev, TS_IOCTL_READ, in.data(), sizeof(ts_mem_req), buf, size, &ret, nullptr)) {
        return false;
    }
    return ret == size;
}

static bool DevWrite(DWORD pid, ULONGLONG addr, const void* buf, DWORD size, DWORD flags) {
    std::vector<unsigned char> in(sizeof(ts_mem_req) + size);
    auto* req = (ts_mem_req*)in.data();
    req->pid = pid; req->addr = addr; req->size = size; req->flags = flags;
    memcpy(in.data() + sizeof(ts_mem_req), buf, size);
    DWORD ret = 0;
    return DeviceIoControl(g_dev, TS_IOCTL_WRITE, in.data(), (DWORD)in.size(), nullptr, 0, &ret, nullptr) != 0;
}

static bool DevModule(DWORD pid, const wchar_t* name, ts_module_rsp& rsp) {
    ts_module_req req{};
    req.pid = pid;
    wcsncpy_s(req.name, name, _TRUNCATE);
    DWORD ret = 0;
    return DeviceIoControl(g_dev, TS_IOCTL_MODULE, &req, sizeof(req), &rsp, sizeof(rsp), &ret, nullptr) != 0;
}

static void HexDump(const unsigned char* p, DWORD n, ULONGLONG base) {
    for (DWORD i = 0; i < n; i += 16) {
        std::printf("%08llX  ", base + i);
        for (DWORD j = 0; j < 16; j++) {
            if (i + j < n) std::printf("%02X ", p[i + j]); else std::printf("   ");
            if (j == 7) std::printf(" ");
        }
        std::printf(" |");
        for (DWORD j = 0; j < 16 && i + j < n; j++) {
            unsigned char c = p[i + j];
            std::printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        std::printf("|\n");
    }
}

static int ParseHexBytes(const wchar_t* s, std::vector<unsigned char>& out) {
    std::wstring t(s);
    for (auto& c : t) if (c == L',' || c == L'-' || c == L' ') c = L' ';
    wchar_t* ctx = nullptr;
    for (wchar_t* tok = wcstok_s(t.data(), L" ", &ctx); tok; tok = wcstok_s(nullptr, L" ", &ctx)) {
        wchar_t* end = nullptr;
        unsigned long v = wcstoul(tok, &end, 16);
        if (end == tok || v > 0xFF) return -1;
        out.push_back((unsigned char)v);
    }
    return (int)out.size();
}

static void Usage() {
    std::printf(
        "ts_mem_client - TsMem.sys control\n"
        "  ts_mem_client info\n"
        "  ts_mem_client testself [--attach]\n"
        "  ts_mem_client hide\n"
        "  ts_mem_client pid <name>\n"
        "  ts_mem_client read  <pid|name> <hexaddr> <size> [--attach] [--force]\n"
        "  ts_mem_client write <pid|name> <hexaddr> <hex bytes...> [--attach] [--force]\n"
        "  ts_mem_client module <pid|name> <module>\n"
        "  ts_mem_client test  <pid|name>\n");
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { Usage(); return 1; }

    std::wstring cmd = argv[1];
    if (cmd == L"pid") {
        if (argc < 3) { Usage(); return 1; }
        DWORD pid = FindPid(argv[2]);
        std::printf("%lu\n", pid);
        return pid ? 0 : 2;
    }
    if (cmd == L"testself") {
        if (!OpenDevice()) return 3;
        HMODULE base = GetModuleHandleW(nullptr);
        unsigned char buf[64];
        DWORD flags = (argc > 2 && wcscmp(argv[2], L"--attach") == 0) ? TS_FLAG_ATTACH : 0;
        if (DevRead(GetCurrentProcessId(), (ULONGLONG)(ULONG_PTR)base, buf, sizeof(buf), flags)) {
            std::printf("[+] self read OK base=%p MZ=%02X%02X\n", (void*)base, buf[0], buf[1]);
            HexDump(buf, 32, (ULONGLONG)(ULONG_PTR)base);
            return 0;
        }
        std::printf("[!] self read failed err=%lu\n", GetLastError());
        return 4;
    }
    if (cmd == L"info" || cmd == L"hide" || cmd == L"test") {
        if (!OpenDevice()) return 3;
        if (cmd == L"info") {
            ts_info_rsp rsp{};
            DWORD ret = 0;
            if (!DeviceIoControl(g_dev, TS_IOCTL_INFO, nullptr, 0, &rsp, sizeof(rsp), &ret, nullptr)) {
                std::printf("[!] info failed err=%lu\n", GetLastError()); return 4;
            }
            std::printf("version=%u hidden=%u base=%016llX build=%016llX\n",
                        rsp.version, rsp.hidden, (unsigned long long)rsp.driver_base, (unsigned long long)rsp.build_id);
            return 0;
        }
        if (cmd == L"hide") {
            DWORD ret = 0;
            if (!DeviceIoControl(g_dev, TS_IOCTL_HIDE, nullptr, 0, nullptr, 0, &ret, nullptr)) {
                std::printf("[!] hide failed err=%lu\n", GetLastError()); return 4;
            }
            std::printf("[+] hidden\n");
            return 0;
        }
        // test
        if (argc < 3) { Usage(); return 1; }
        DWORD pid = 0;
        if (!ResolvePid(argv[2], pid)) return 2;
        unsigned char buf[64];
        if (DevRead(pid, 0x400000, buf, sizeof(buf), TS_FLAG_FORCE)) {
            std::printf("[+] read 0x400000 OK, MZ=%02X%02X\n", buf[0], buf[1]);
            HexDump(buf, 32, 0x400000);
        } else {
            std::printf("[!] read 0x400000 failed err=%lu\n", GetLastError());
        }
        ts_module_rsp rsp{};
        if (DevModule(pid, L"dmmdzz.exe", rsp)) {
            std::printf("[+] dmmdzz.exe base=%016llX size=%X path=%ls\n",
                        (unsigned long long)rsp.base, rsp.size, rsp.path);
            unsigned char hdr[16];
            if (DevRead(pid, rsp.base, hdr, sizeof(hdr), TS_FLAG_FORCE)) {
                std::printf("    header: %02X %02X %02X %02X ...\n", hdr[0], hdr[1], hdr[2], hdr[3]);
            }
        } else {
            std::printf("[!] module dmmdzz.exe failed err=%lu\n", GetLastError());
        }
        return 0;
    }

    if (argc < 4) { Usage(); return 1; }
    DWORD pid = 0;
    if (!ResolvePid(argv[2], pid)) return 2;

    if (cmd == L"module") {
        if (argc < 4) { Usage(); return 1; }
        if (!OpenDevice()) return 3;
        ts_module_rsp rsp{};
        if (!DevModule(pid, argv[3], rsp)) {
            std::printf("[!] module failed err=%lu\n", GetLastError()); return 4;
        }
        std::printf("base=%016llX size=%X\npath=%ls\n",
                    (unsigned long long)rsp.base, rsp.size, rsp.path);
        return 0;
    }

    wchar_t* end = nullptr;
    ULONGLONG addr = wcstoull(argv[3], &end, 16);
    if (end == argv[3]) { std::printf("[!] bad address\n"); return 1; }

    DWORD flags = 0;
    for (int i = 4; i < argc; i++) {
        if (wcscmp(argv[i], L"--attach") == 0) flags |= TS_FLAG_ATTACH;
        if (wcscmp(argv[i], L"--force") == 0) flags |= TS_FLAG_FORCE;
    }

    if (!OpenDevice()) return 3;

    if (cmd == L"read") {
        if (argc < 5) { Usage(); return 1; }
        DWORD size = (DWORD)wcstoul(argv[4], nullptr, 0);
        if (size == 0 || size > 0x100000) { std::printf("[!] bad size\n"); return 1; }
        std::vector<unsigned char> buf(size);
        if (!DevRead(pid, addr, buf.data(), size, flags)) {
            std::printf("[!] read failed err=%lu\n", GetLastError()); return 4;
        }
        HexDump(buf.data(), size, addr);
        return 0;
    }

    if (cmd == L"write") {
        std::vector<unsigned char> bytes;
        for (int i = 4; i < argc; i++) {
            if (wcscmp(argv[i], L"--attach") == 0 || wcscmp(argv[i], L"--force") == 0) continue;
            if (ParseHexBytes(argv[i], bytes) < 0) { std::printf("[!] bad hex\n"); return 1; }
        }
        if (bytes.empty()) { std::printf("[!] no bytes\n"); return 1; }
        if (!DevWrite(pid, addr, bytes.data(), (DWORD)bytes.size(), flags)) {
            std::printf("[!] write failed err=%lu\n", GetLastError()); return 4;
        }
        std::printf("[+] wrote %zu bytes at %016llX\n", bytes.size(), (unsigned long long)addr);
        return 0;
    }

    Usage();
    return 1;
}
