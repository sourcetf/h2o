# Audit and Benchmark Spec

## Why
为了确保 `proxy-core` 代理软件的安全性和稳定性，需要对代码进行全面的审查，排查潜在的 bug、panic、空指针和内存溢出等漏洞。同时，为了验证其在实际应用中的性能表现，需要使用 `p384-sha384` 证书与 `h2o` 服务器进行对比测试，涵盖 HTTP/1.1 到 HTTP/3 协议的资源占用、吞吐量和并发能力。

## What Changes
- 全面审查和修复 `proxy-core` 的 Rust 代码，消除可能引发 panic、空指针解引用和内存溢出的隐患。
- 生成基于 P-384 曲线和 SHA-384 签名的测试证书。
- 配置并运行针对 `proxy-core` 和 `h2o` 的基准测试，覆盖 HTTP/1.1, HTTP/2, HTTP/3 协议。
- 收集并对比内存/CPU 占用、吞吐量和并发指标。

## Impact
- Affected specs: 性能测试能力、代码安全基线
- Affected code: `proxy-core` 源码、测试脚本目录（`benchmarks/`）

## ADDED Requirements
### Requirement: 安全审查
系统 SHALL 提供健壮的代码实现，不会在极端输入或边界条件下发生 panic、空指针异常或内存溢出。

#### Scenario: 极端流量或异常输入
- **WHEN** 代理服务器收到非法的 HTTP 请求、错误的 TLS 握手包或超出长度限制的数据
- **THEN** 系统应妥善处理错误并返回合理的响应，或者安全地断开连接，而不会导致进程崩溃或资源泄漏。

### Requirement: 基准测试 (P-384 证书)
系统 SHALL 能够在 P-384 椭圆曲线证书的加密强度下，与 `h2o` 代理进行公平的 HTTP/1.1、HTTP/2 和 HTTP/3 性能对比。

#### Scenario: 性能压测
- **WHEN** 使用高并发测试工具发起请求
- **THEN** 测试脚本将输出 `proxy-core` 和 `h2o` 的吞吐量 (Requests/sec)、延迟 (Latency) 以及资源占用 (CPU/Memory)。