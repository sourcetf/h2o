#!/bin/bash
set -e

echo "Starting Feature Validation for proxy-core..."

echo "1. Checking HTTP/HTTPS Proxy (HTTP/1.1)..."
HTTP_RES=$(curl --http1.1 -s -k -H "Host: localhost" https://localhost:8080/)
if [[ "$HTTP_RES" == *"HTTP OK"* ]]; then
    echo "  [OK] HTTP/HTTPS Proxy is working"
else
    echo "  [FAIL] HTTP/HTTPS Proxy"
    exit 1
fi

echo "2. Checking TCP Proxy (pure passthrough)..."
TCP_RES=$(echo "test" | nc -q 1 127.0.0.1 8081)
if [[ "$TCP_RES" == *"TCP OK"* ]]; then
    echo "  [OK] TCP Proxy is working"
else
    echo "  [FAIL] TCP Proxy"
    exit 1
fi

echo "3. Checking UDP Proxy (pure passthrough)..."
UDP_RES=$(echo "test" | nc -u -w1 127.0.0.1 8082)
if [[ "$UDP_RES" == *"UDP OK"* ]]; then
    echo "  [OK] UDP Proxy is working"
else
    echo "  [FAIL] UDP Proxy"
    exit 1
fi

echo "4. Checking HTTP/3 (QUIC) Port Binding..."
if ss -lntu | grep -q ":8443"; then
    echo "  [OK] HTTP/3 QUIC port 8443 is listening"
else
    echo "  [FAIL] HTTP/3 QUIC port not found"
    exit 1
fi

echo ""
echo "All features verified successfully!"
