# separated/build.ps1
# 分别编译 injector.exe 和 payload_dll.dll

# ── 定位 MSVC 编译器 ─────────────────────────────────────────────────────────
# 通过 vswhere 自动查找 Visual Studio 安装路径，免去手动配置
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "未找到 vswhere.exe，请安装 Visual Studio 2019 或更高版本"
    exit 1
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    Write-Error "未找到 MSVC 工具链"
    exit 1
}

# 初始化 x64 编译环境
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    Write-Error "未找到 vcvars64.bat: $vcvars"
    exit 1
}

# 创建输出目录
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir = Join-Path $scriptDir "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

Write-Host "[*] 编译环境: $vcvars" -ForegroundColor Cyan

# ── 编译函数 ─────────────────────────────────────────────────────────────────
function Invoke-VsCompile {
    param(
        [string]$Source,
        [string]$Output,
        [string]$ExtraFlags = ""
    )
    $srcName = Split-Path -Leaf $Source
    Write-Host "[*] 编译: $srcName -> $Output" -ForegroundColor Yellow

    $cmd = @"
call "$vcvars" > nul 2>&1
cl.exe /nologo /W3 /WX- /O2 /MT /EHsc /std:c++17 $ExtraFlags "$Source" /Fe:"$Output" /link /SUBSYSTEM:CONSOLE
"@
    $result = cmd /c $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host $result -ForegroundColor Red
        Write-Error "编译失败: $srcName"
        return $false
    }
    Write-Host "[+] 编译成功: $Output" -ForegroundColor Green
    return $true
}

function Invoke-VsCompileDll {
    param(
        [string]$Source,
        [string]$Output
    )
    $srcName = Split-Path -Leaf $Source
    Write-Host "[*] 编译 DLL: $srcName -> $Output" -ForegroundColor Yellow

    $cmd = @"
call "$vcvars" > nul 2>&1
cl.exe /nologo /W3 /WX- /O2 /MT /EHsc /std:c++17 /LD "$Source" /Fe:"$Output" /link /DLL /SUBSYSTEM:WINDOWS /EXPORT:PayloadEntry
"@
    $result = cmd /c $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host $result -ForegroundColor Red
        Write-Error "编译 DLL 失败: $srcName"
        return $false
    }
    Write-Host "[+] DLL 编译成功: $Output" -ForegroundColor Green
    return $true
}

# ── 编译 payload_dll.dll ─────────────────────────────────────────────────────
$payloadSrc = Join-Path $scriptDir "payload_dll.cpp"
$payloadOut = Join-Path $binDir "payload_dll.dll"
$ok1 = Invoke-VsCompileDll -Source $payloadSrc -Output $payloadOut

# ── 编译 injector.exe ────────────────────────────────────────────────────────
$injectorSrc = Join-Path $scriptDir "injector.cpp"
$injectorOut = Join-Path $binDir "injector.exe"
$ok2 = Invoke-VsCompile -Source $injectorSrc -Output $injectorOut

# ── 总结 ─────────────────────────────────────────────────────────────────────
if ($ok1 -and $ok2) {
    Write-Host ""
    Write-Host "=== 编译完成 ===" -ForegroundColor Green
    Write-Host "  payload_dll.dll: $payloadOut"
    Write-Host "  injector.exe:    $injectorOut"
    Write-Host ""
    Write-Host "使用方法（管理员权限）："
    Write-Host "  cd $binDir"
    Write-Host "  .\injector.exe [payload_dll.dll 的完整路径]"
} else {
    Write-Error "部分文件编译失败，请检查上方错误信息"
    exit 1
}
