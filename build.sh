#!/bin/bash

# SUMURAI 构建脚本
echo "🔪 构建 SUMURAI CTF工具..."

# 检查Go是否安装
if ! command -v go &> /dev/null; then
    echo "❌ 错误: 未找到Go编译器，请先安装Go"
    exit 1
fi

# 设置Go模块
echo "📦 初始化Go模块..."
go mod init sumurai

# 清理之前的构建
echo "🧹 清理之前的构建..."
rm -f *.exe
rm -rf results/

# 构建程序
echo "🔨 编译程序..."
go build -o solve.exe main.go

# 检查构建是否成功
if [ -f "solve.exe" ]; then
    echo "✅ 构建成功! 生成文件: solve.exe"
    ./solve.exe test.txt
else
    echo "❌ 构建失败!"
    exit 1
fi

echo "🚀 SUMURAI 已准备就绪!" 