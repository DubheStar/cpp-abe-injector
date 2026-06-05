# build.ps1（根目录）
# 编译 separated 和 combined 两个版本
#
# 用法：
#   .\build.ps1            # 编译全部
#   .\build.ps1 -Separated # 仅编译 separated 版本
#   .\build.ps1 -Combined  # 仅编译 combined 版本

param(
    [switch]$Separated,
    [switch]$Combined
)

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildAll = (-not $Separated -and -not $Combined)

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Chrome ABE 解密工具 - 构建脚本"       -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

if ($buildAll -or $Separated) {
    Write-Host "─── 编译 separated 版本 ────────────────" -ForegroundColor Magenta
    & "$rootDir\separated\build.ps1"
    if ($LASTEXITCODE -ne 0) { Write-Error "separated 构建失败" }
    Write-Host ""
}

if ($buildAll -or $Combined) {
    Write-Host "─── 编译 combined 版本 ─────────────────" -ForegroundColor Magenta
    & "$rootDir\combined\build.ps1"
    if ($LASTEXITCODE -ne 0) { Write-Error "combined 构建失败" }
    Write-Host ""
}

Write-Host "======================================"  -ForegroundColor Green
Write-Host "  全部构建完成！"                         -ForegroundColor Green
Write-Host "======================================"  -ForegroundColor Green
Write-Host ""
Write-Host "输出文件位置："
if ($buildAll -or $Separated) {
    Write-Host "  separated/bin/injector.exe"
    Write-Host "  separated/bin/payload_dll.dll"
}
if ($buildAll -or $Combined) {
    Write-Host "  combined/bin/all_in_one.exe"
}
