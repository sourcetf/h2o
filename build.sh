#!/bin/bash
set -e
echo "Starting compilation of proxy-core in release mode..."
cd /workspace/proxy-core
cargo build --release
echo "Compilation successful. Binary is located at /workspace/proxy-core/target/release/proxy-core"
