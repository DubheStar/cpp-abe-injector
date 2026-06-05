# Chrome ABE 解密工具

## 项目简介

本项目是 Chrome **App-Bound Encryption (ABE)** 解密技术的研究实现，仅供安全研究和教育目的使用。

Chrome 127 引入了 ABE 机制，将 Cookie 加密密钥委托给系统级服务（`elevation_service.exe`，即 Google Update 的一部分）进行加密/解密。本项目演示了如何通过进程注入技术，在拥有足够权限的前提下完成密钥解密。

> **免责声明**：本项目仅供授权的安全研究、渗透测试和教育目的使用。在未经授权的系统上使用本工具可能违反法律。作者不对任何滥用行为承担责任。

---

## 技术原理概述

### App-Bound Encryption (ABE)

Chrome 将 Cookie 加密密钥存储在 `%LOCALAPPDATA%\Google\Chrome\User Data\Local State` 中，JSON 字段 `os_crypt.app_bound_encrypted_key` 包含一个 Base64 编码的密文。该密文由 `elevation_service.exe`（以 SYSTEM 权限运行）加密，只有通过 `IElevator` COM 接口才能解密。

### 解密流程

```
注入器 (injector.exe)
  │
  ├── 1. 读取 Local State → 获取 app_bound_encrypted_key (Base64)
  ├── 2. 找到 Chrome 主进程 PID（父进程不是 chrome 的那个）
  ├── 3. 创建命名管道（NULL DACL）
  ├── 4. Hell's Gate 直接系统调用注入 payload_dll.dll
  │       Stage 1: shellcode → LoadLibraryW(payload_dll.dll)
  │       Stage 2: NtCreateThreadEx → PayloadEntry(管道名+密文)
  │
  └── 5. 从管道读取解密结果

Payload DLL (payload_dll.cpp，运行在 Chrome 进程中)
  │
  ├── 1. CoInitializeEx(COINIT_MULTITHREADED)  // Chrome 是 MTA
  ├── 2. CoCreateInstance(IElevator)
  ├── 3. CoSetProxyBlanket(EOAC_DYNAMIC_CLOAKING)  // 使用 Chrome 身份
  ├── 4. IElevator::DecryptData(密文) → 明文密钥
  └── 5. 通过命名管道返回明文
```

### 核心技术

| 技术 | 用途 |
|------|------|
| **Hell's Gate** | 直接系统调用，绕过 EDR 对 ntdll 的 hook |
| **NtCreateThreadEx** | 比 CreateRemoteThread 更底层，更难被拦截 |
| **两阶段注入** | shellcode → LoadLibraryW → PayloadEntry，避免手写 PE loader |
| **NULL DACL 管道** | 保证跨完整性级别通信不被 Windows 权限拒绝 |
| **共享内存读 hModule** | GetExitCodeThread 只有 32 位，无法读取 x64 高地址 |
| **EOAC_DYNAMIC_CLOAKING** | COM 代理使用 Chrome 进程令牌，通过服务端身份验证 |
| **NtQuerySystemInformation(64)** | 枚举全系统 64 位句柄（SystemExtendedHandleInformation） |
| **NtDuplicateObject** | 跨进程句柄复制，借用已建立的 IElevator ALPC 连接 |

---

## 环境要求

- **操作系统**：Windows 10/11（x64）
- **Chrome 版本**：127+ （ABE 引入版本）
- **权限**：管理员权限（`PROCESS_ALL_ACCESS` 需要 SeDebugPrivilege）
- **编译工具**：Visual Studio 2019/2022（含 MSVC C++ 工具链）
- **Chrome 状态**：运行中（需要 Chrome 进程存在）

---

## 编译

### 一键编译（推荐）

```powershell
# 以管理员权限打开 PowerShell
cd D:\ClaudeCode-Home\JoyAI\projects\cpp-abe-injector

# 编译全部版本
.\build.ps1

# 仅编译 separated 版本
.\build.ps1 -Separated

# 仅编译 combined 版本
.\build.ps1 -Combined
```

### 手动编译

```powershell
# Separated 版本
cd separated
.\build.ps1

# Combined 版本
cd combined
.\build.ps1
```

---

## 使用方法

### Separated 版本

需要两个文件：`injector.exe` 和 `payload_dll.dll`，必须在同一目录。

```powershell
# 以管理员权限运行
cd separated\bin

# 使用默认路径（payload_dll.dll 在当前目录）
.\injector.exe

# 或指定 DLL 路径
.\injector.exe "C:\path\to\payload_dll.dll"
```

### Combined 版本（单文件）

```powershell
cd combined\bin

# 正常解密模式
.\all_in_one.exe

# 提取内嵌的 DLL 到当前目录
.\all_in_one.exe --extract

# 提取到指定路径
.\all_in_one.exe --extract "C:\output\payload.dll"
```

---

## 项目结构

```
cpp-abe-injector/
├── README.md               本文件
├── .gitignore
├── build.ps1               根目录构建脚本（编译全部版本）
│
├── separated/              分离版本（injector + DLL 分开）
│   ├── injector.cpp        注入器（Hell's Gate + 两阶段注入）
│   ├── payload_dll.cpp     Payload DLL（IElevator COM 解密）
│   ├── build.ps1
│   └── bin/                (编译输出)
│       ├── injector.exe
│       └── payload_dll.dll
│
└── combined/               合并版本（单 EXE，DLL 内嵌）
    ├── all_in_one.cpp      单文件版（含 --extract 模式）
    ├── build.ps1           (自动生成 generated_dll_bytes.h)
    └── bin/                (编译输出)
        └── all_in_one.exe
```

---

## 常见问题

**Q: 运行时提示"未找到 chrome.exe"**
A: 确保 Chrome 正在运行，且以相同或更低完整性级别运行。

**Q: 注入成功但管道超时**
A: 可能是 Chrome 版本过新（127+）导致 IElevator 验证更严格。尝试检查 `elevation_service.exe` 是否正在运行：`tasklist | findstr elevation`。

**Q: CoSetProxyBlanket 失败**
A: 这不是致命错误，工具会继续尝试。若最终解密失败，说明当前 Chrome 版本启用了更严格的调用者验证。

**Q: 编译报错"找不到 ntdll.h"**
A: 确保安装了 Windows SDK（10.0.19041.0 或更高版本）。在 Visual Studio Installer 中勾选"Windows 10 SDK"。

---

## 参考资料

- [Chrome App-Bound Encryption 源码](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/os_crypt/)
- [Hell's Gate 原始论文](https://github.com/am0nsec/HellsGate)
- [NtCreateThreadEx 文档（非官方）](https://ntdoc.m417z.com/ntcreatethreadex)
- [SystemExtendedHandleInformation 结构体](https://ntdoc.m417z.com/system_handle_table_entry_info_ex)

---

## 免责声明

本工具仅用于：
1. 理解 Chrome ABE 机制的工作原理（安全研究）
2. 测试您自己设备上的安全防护能力（授权测试）
3. 教学演示（CTF、安全课程）

**禁止**用于任何未经授权的访问、数据窃取或恶意活动。使用者须自行承担法律责任。
