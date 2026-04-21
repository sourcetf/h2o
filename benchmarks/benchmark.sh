#!/bin/bash
set -e

PROXY_URL="http://127.0.0.1:8080/"
H2O_URL="http://127.0.0.1:8085/"
HTTPS_PROXY_URL="https://127.0.0.1:8080/"
HTTPS_H2O_URL="https://127.0.0.1:8445/"

CONNECTIONS=500
THREADS=4
DURATION="10s"

echo "=========================================="
echo "    基准测试：并发与延迟 (强制短连接)     "
echo "=========================================="

echo "------------------------------------------"
echo "1. HTTP/1.1 短连接基准测试 (wrk)"
echo "------------------------------------------"
echo "测试 proxy-core (HTTP/1.1 over TLS):"
wrk -t$THREADS -c$CONNECTIONS -d$DURATION -H "Connection: close" $HTTPS_PROXY_URL

echo ""
echo "测试 h2o (HTTP/1.1 over TLS):"
wrk -t$THREADS -c$CONNECTIONS -d$DURATION -H "Connection: close" $HTTPS_H2O_URL

echo "=========================================="
echo "             测试完成                     "
echo "=========================================="
