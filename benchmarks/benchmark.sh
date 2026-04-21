#!/bin/bash
set -e

PROXY_URL="http://127.0.0.1:8080/"
H2O_URL="http://127.0.0.1:8085/"

CONNECTIONS=50
THREADS=4
DURATION="5s"

echo "=========================================="
echo "          基准测试：并发与延迟            "
echo "=========================================="

echo "------------------------------------------"
echo "1. HTTP/1.1 基准测试 (wrk)"
echo "------------------------------------------"
echo "测试 proxy-core (HTTP/1.1):"
wrk -t$THREADS -c$CONNECTIONS -d$DURATION -H "Host: localhost" $PROXY_URL

echo ""
echo "测试 h2o (HTTP/1.1):"
wrk -t$THREADS -c$CONNECTIONS -d$DURATION -H "Host: localhost" $H2O_URL

echo "=========================================="
echo "             测试完成                     "
echo "=========================================="
