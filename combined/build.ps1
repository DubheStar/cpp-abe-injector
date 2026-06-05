# combined/build.ps1
# 编译 all_in_one.exe（内嵌 payload DLL 字节）
#
# 构建流程：
#   1. 定位并初始化 MSVC x64 工具链
#   2. 先编译 payload_dll.dll（来自 separated/）
#   3. 读取 DLL 字节，生成 C 头文件 generated_dll_bytes.h
#   4. 编译 all_in_one.cpp（引用上述头文件）

param(
    [switch]$SkipPayloadBuild,  # 跳过重新编译 payload DLL（使用已有 DLL）
    [string]$ExistingDllPath    # 指定已有 DLL 路径（配合 -SkipPayloadBuild 使用）
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── 定位 MSVC ────────────────────────────────────────────────────────────────
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "未找到 vswhere.exe，请安装 Visual Studio 2019/2022"
}

$vsPath = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vsPath) { Write-Error "未找到 MSVC 工具链" }

$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir   = Split-Path -Parent $scriptDir
$binDir    = Join-Path $scriptDir "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

# ── Step 1：编译 payload_dll.dll ──────────────────────────────────────────────
$payloadDllPath = $null

if ($SkipPayloadBuild -and $ExistingDllPath) {
    # 使用用户指定的已有 DLL
    if (-not (Test-Path $ExistingDllPath)) {
        Write-Error "指定的 DLL 不存在: $ExistingDllPath"
    }
    $payloadDllPath = $ExistingDllPath
    Write-Host "[*] 使用已有 DLL: $payloadDllPath" -ForegroundColor Cyan
} else {
    # 从 separated/payload_dll.cpp 编译
    Write-Host "[*] 编译 payload_dll.dll..." -ForegroundColor Yellow
    $payloadSrc = Join-Path $rootDir "separated\payload_dll.cpp"
    $payloadDllPath = Join-Path $binDir "payload_dll.dll"

    $compileCmd = @"
call "$vcvars" > nul 2>&1
cl.exe /nologo /W3 /O2 /MT /EHsc /std:c++17 /LD "$payloadSrc" /Fe:"$payloadDllPath" /link /DLL /SUBSYSTEM:WINDOWS /EXPORT:PayloadEntry
"@
    $result = cmd /c $compileCmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host $result -ForegroundColor Red
        Write-Error "payload_dll.dll 编译失败"
    }
    Write-Host "[+] payload_dll.dll 编译成功" -ForegroundColor Green
}

# ── Step 2：将 DLL 转换为 C 头文件 ────────────────────────────────────────────
#
# 原理：读取 DLL 的所有字节，生成如下格式的 C 头文件：
#
#   #pragma once
#   #define PAYLOAD_DLL_BYTES_INCLUDED
#   static const unsigned char g_PayloadDllBytes[] = {
#       0x4D, 0x5A, 0x90, 0x00, ...
#   };
#   static const size_t g_PayloadDllSize = sizeof(g_PayloadDllBytes);
#
# 生成的头文件由 all_in_one.cpp 的 #include "generated_dll_bytes.h" 引用

Write-Host "[*] 生成 DLL 字节数组头文件..." -ForegroundColor Yellow

$dllBytes = [System.IO.File]::ReadAllBytes($payloadDllPath)
$dllSize  = $dllBytes.Length
Write-Host "[*] DLL 大小: $dllSize 字节"

$headerPath = Join-Path $scriptDir "generated_dll_bytes.h"

# 构建 C 数组字符串（每行 16 字节，格式化输出）
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("// 自动生成文件 —— 请勿手动编辑")
[void]$sb.AppendLine("// 由 combined/build.ps1 从 payload_dll.dll 自动生成")
[void]$sb.AppendLine("// 源文件: $payloadDllPath")
[void]$sb.AppendLine("// 生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$sb.AppendLine("#pragma once")
[void]$sb.AppendLine("#define PAYLOAD_DLL_BYTES_INCLUDED")
[void]$sb.AppendLine("static const unsigned char g_PayloadDllBytes[] = {")

$lineBytes = @()
for ($i = 0; $i -lt $dllBytes.Length; $i++) {
    $lineBytes += ("0x{0:X2}" -f $dllBytes[$i])
    if ($lineBytes.Count -eq 16 -or $i -eq ($dllBytes.Length - 1)) {
        $comma = if ($i -eq ($dllBytes.Length - 1)) { "" } else { "," }
        [void]$sb.AppendLine("    $($lineBytes -join ', ')$comma")
        $lineBytes = @()
    }
}

[void]$sb.AppendLine("};")
[void]$sb.AppendLine("static const size_t g_PayloadDllSize = sizeof(g_PayloadDllBytes);")

[System.IO.File]::WriteAllText($headerPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
Write-Host "[+] 头文件生成完成: $headerPath" -ForegroundColor Green

# ── Step 3：编译 all_in_one.exe ───────────────────────────────────────────────
Write-Host "[*] 编译 all_in_one.exe..." -ForegroundColor Yellow

$allInOneSrc = Join-Path $scriptDir "all_in_one.cpp"
$allInOneOut = Join-Path $binDir "all_in_one.exe"

# 添加 /I 指令让编译器能找到 generated_dll_bytes.h
$compileCmd2 = @"
call "$vcvars" > nul 2>&1
cl.exe /nologo /W3 /O2 /MT /EHsc /std:c++17 /I"$scriptDir" "$allInOneSrc" /Fe:"$allInOneOut" /link /SUBSYSTEM:CONSOLE
"@
$result2 = cmd /c $compileCmd2 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host $result2 -ForegroundColor Red
    Write-Error "all_in_one.exe 编译失败"
}
Write-Host "[+] all_in_one.exe 编译成功" -ForegroundColor Green

# ── 输出摘要 ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== 构建完成 ===" -ForegroundColor Green
Write-Host "  输出目录:    $binDir"
Write-Host "  all_in_one:  $allInOneOut"
Write-Host "  DLL 来源:    $payloadDllPath  ($dllSize 字节内嵌)"
Write-Host ""
Write-Host "使用方法（以管理员权限运行）："
Write-Host "  .\bin\all_in_one.exe              # 执行完整 ABE 解密"
Write-Host "  .\bin\all_in_one.exe --extract    # 提取内嵌 DLL 到当前目录"
