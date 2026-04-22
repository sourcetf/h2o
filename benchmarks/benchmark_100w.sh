#!/bin/bash
set -e

# 为了支持 100w 并发，必须首先提升系统的文件描述符限制
ulimit -n 1048576 || echo "无法提升文件描述符，可能权限不足，尽力而为"

PROXY_URL="https://127.0.0.1:8080/"
H2O_URL="https://127.0.0.1:8081/"

# 100万请求的并发测试参数设计
# -c 10000 个 TCP 连接
# -m 100 每连接最大 100 个并发 HTTP/2 Streams
# -n 1000000 意味着测试共发出 1,000,000 次请求
CONNECTIONS=10000
STREAMS=100
REQUESTS=1000000

echo "=========================================="
echo "   极限基准测试：100w 请求 (HTTP/2)       "
echo "=========================================="
echo "测试 proxy-core (HTTP/2 with P-384):"
h2load -n $REQUESTS -c $CONNECTIONS -m $STREAMS $PROXY_URL

echo ""
echo "测试 h2o (HTTP/2 with P-384):"
h2load -n $REQUESTS -c $CONNECTIONS -m $STREAMS $H2O_URL
