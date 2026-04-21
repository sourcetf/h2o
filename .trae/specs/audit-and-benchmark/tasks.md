# Tasks
- [x] Task 1: 代码安全审查与加固
  - [x] SubTask 1.1: 审查 `proxy-core` 中的错误处理逻辑，将所有可能触发 panic 的 `unwrap()`、`expect()` 替换为安全的错误处理模式。
  - [x] SubTask 1.2: 检查缓冲区、数组访问和数据解析，确保没有越界访问和溢出漏洞。
  - [x] SubTask 1.3: 确认 Rust 安全机制未被不当的 `unsafe` 块破坏（排查空指针等漏洞）。
- [x] Task 2: 准备 P-384 (p384-sha384) 测试证书
  - [x] SubTask 2.1: 使用 OpenSSL 生成 P-384 椭圆曲线证书和私钥。
  - [x] SubTask 2.2: 配置 `proxy-core` 和 `h2o` 均使用该新证书进行 TLS 握手。
- [x] Task 3: 执行性能与资源基准测试
  - [x] SubTask 3.1: 编写/更新基准测试脚本，分别针对 `proxy-core` 和 `h2o` 进行 HTTP/1.1、HTTP/2、HTTP/3 压测。
  - [x] SubTask 3.2: 记录高并发下的吞吐量（QPS）和延迟。
  - [x] SubTask 3.3: 收集高并发压测期间的资源占用情况（CPU 和内存）。

# Task Dependencies
- [Task 3] depends on [Task 1, Task 2]