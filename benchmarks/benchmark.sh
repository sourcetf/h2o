#!/bin/bash

# 基准测试脚本：对比 proxy-core 与 h2o
# 使用 wrk 测试 HTTP/1.1 性能，使用 h2load 测试 HTTP/2 / HTTP/3 性能

set -e

PROXY_URL="http://127.0.0.1:8080/"
H2O_URL="http://127.0.0.1:8081/"
HTTPS_PROXY_URL="https://127.0.0.1:8443/"
HTTPS_H2O_URL="https://127.0.0.1:8444/"

CONNECTIONS=500
THREADS=8
DURATION="30s"

echo "=========================================="
echo "          基准测试：并发与延迟            "
echo "=========================================="

# 检查工具是否安装
if ! command -v wrk &> /dev/null; then
    echo "错误: 未找到 wrk，请先安装 (apt install wrk)"
    exit 1
fi

if ! command -v h2load &> /dev/null; then
    echo "警告: 未找到 h2load，将跳过 HTTP/2 和 HTTP/3 测试 (apt install nghttp2-client)"
fi

echo "------------------------------------------"
echo "1. HTTP/1.1 基准测试 (wrk)"
echo "------------------------------------------"
echo "测试 proxy-core (HTTP/1.1):"
wrk -t$THREADS -c$CONNECTIONS -d$DURATION $PROXY_URL

echo ""
echo "测试 h2o (HTTP/1.1):"
wrk -t$THREADS -c$CONNECTIONS -d$DURATION $H2O_URL

if command -v h2load &> /dev/null; then
    echo "------------------------------------------"
    echo "2. HTTP/2 基准测试 (h2load)"
    echo "------------------------------------------"
    echo "测试 proxy-core (HTTP/2):"
    h2load -n 100000 -c $CONNECTIONS -m 100 $HTTPS_PROXY_URL

    echo ""
    echo "测试 h2o (HTTP/2):"
    h2load -n 100000 -c $CONNECTIONS -m 100 $HTTPS_H2O_URL
    
    echo "------------------------------------------"
    echo "3. HTTP/3 基准测试 (h2load over QUIC)"
    echo "------------------------------------------"
    echo "注意: 需要支持 HTTP/3 的 h2load"
    # h2load --npn-list=h3 -n 100000 -c $CONNECTIONS -m 100 https://127.0.0.1:8443/
fi

echo "=========================================="
echo "             测试完成                     "
echo "=========================================="
