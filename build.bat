@echo off
chcp 65001 >nul

REM SUMURAI 构建脚本 (Windows版本)
echo 🔪 构建 SUMURAI CTF工具...

REM 检查Go是否安装
go version >nul 2>&1
if errorlevel 1 (
    echo ❌ 错误: 未找到Go编译器，请先安装Go
    pause
    exit /b 1
)

REM 设置Go模块
echo 📦 初始化Go模块...
go mod init sumurai

REM 清理之前的构建
echo 🧹 清理之前的构建...
if exist sumurai.exe del sumurai.exe
if exist results rmdir /s /q results

REM 构建程序
echo 🔨 编译程序...
go build -o sumurai.exe main.go

REM 检查构建是否成功
if exist sumurai.exe (
    echo ✅ 构建成功! 生成文件: sumurai.exe
    echo 🎯 使用方法:
    echo    sumurai.exe ^<目标文件^>
    echo    sumurai.exe ^<URL^>
    echo    sumurai.exe flag.txt
    echo    sumurai.exe https://example.com
) else (
    echo ❌ 构建失败!
    pause
    exit /b 1
)

echo 🚀 SUMURAI 已准备就绪!
pause 