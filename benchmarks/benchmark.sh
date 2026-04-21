#!/bin/bash
set -e

PROXY_URL="https://127.0.0.1:8080/"
H2O_URL="https://127.0.0.1:8081/"

CONNECTIONS=500
THREADS=4
DURATION="10s"

echo "=========================================="
echo "    基准测试：并发与吞吐量 (HTTP/1.1)     "
echo "=========================================="

echo "测试 proxy-core (HTTP/1.1 over TLS with P-384):"
wrk -t$THREADS -c$CONNECTIONS -d$DURATION $PROXY_URL

echo ""
echo "测试 h2o (HTTP/1.1 over TLS with P-384):"
wrk -t$THREADS -c$CONNECTIONS -d$DURATION $H2O_URL

if command -v h2load &> /dev/null; then
    echo "=========================================="
    echo "    基准测试：并发与吞吐量 (HTTP/2)       "
    echo "=========================================="
    echo "测试 proxy-core (HTTP/2 with P-384):"
    h2load -n 50000 -c $CONNECTIONS -m 100 $PROXY_URL

    echo ""
    echo "测试 h2o (HTTP/2 with P-384):"
    h2load -n 50000 -c $CONNECTIONS -m 100 $H2O_URL
fi

echo "=========================================="
echo "    基准测试：并发与吞吐量 (HTTP/3)       "
echo "=========================================="
echo "HTTP/3 压测使用 h3bench 测试 proxy-core (8443):"
/workspace/h3bench/target/release/h3bench 8443 || echo "h3bench failed"

echo ""
echo "HTTP/3 压测使用 h3bench 测试 h2o (8444):"
/workspace/h3bench/target/release/h3bench 8444 || echo "h3bench failed"

echo "=========================================="
echo "             测试完成                     "
echo "=========================================="
