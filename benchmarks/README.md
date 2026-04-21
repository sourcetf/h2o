# Performance Optimization & Benchmarking

本目录包含了针对 `proxy-core` (Rust Reverse Proxy) 的性能基准测试与极限负载测试脚本，主要用于评估其与 [h2o](https://h2o.examp1e.net/) 的并发数、延迟及吞吐量表现。

## 优化记录 (SubTask 5.1)

为了最大化代理的吞吐能力和降低延迟，我们在代码库中进行了如下的性能优化和并发调优：

1. **HTTP Client 复用与全局化**：
   - 优化前，每个 HTTP 反向代理请求都会新建一个 `Client`，造成大量开销。
   - 优化后，利用 `std::sync::OnceLock` 全局缓存并复用 HTTP `Client` 实例，充分利用底层的连接池机制，显著降低连接建立开销。
2. **全局分配器替换 (jemalloc/mimalloc)**：
   - 引入了 `mimalloc` 作为全局内存分配器。由于异步 Rust 存在大量的细粒度内存分配与释放，`mimalloc` 在多线程环境下的极低碎片率与高性能可以大幅度降低 GC 和内存碎片带来的延迟。
3. **Tokio 调度器调优**：
   - 默认采用 `#[tokio::main]` 多线程调度器（`flavor = "multi_thread"`），在 Release 模式下自动分配与 CPU 核心数相同的 Worker Threads，并优化 I/O 与 Timer 处理。
4. **无锁设计**：
   - 核心代理路径（`handle_http_request`）避免了任何全局 `Mutex` / `RwLock` 锁的使用。共享的配置对象 `Config` 通过 `Arc` 引用计数共享，实现了真正意义上的无锁处理和高并发伸缩。

## 测试准备

要运行这些基准测试，你需要先安装以下工具：

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install wrk apache2-utils nghttp2-client
```

## 测试脚本说明

### 1. `benchmark.sh` (基准测试)

执行与 `h2o` 的对比测试。

- **HTTP/1.1** 测试：使用 `wrk` 工具生成高并发请求。
- **HTTP/2** 测试：使用 `h2load` 工具，对并发复用和流数量进行压力测试。
- **HTTP/3 (QUIC)** 测试：需要带有 NPN/ALPN h3 支持的 `h2load` 版本。

运行方法：
```bash
chmod +x benchmark.sh
./benchmark.sh
```

### 2. `loadtest.sh` (极限负载测试)

主要验证 `proxy-core` 在极端高并发环境下的稳定性和错误率：

- **突发大流量**：通过 `wrk` 模拟超过 5000 甚至更高的短时突发连接。
- **长连接保活 (Keep-Alive)**：通过 `ab -k` 发送海量请求，测试连接复用能力。
- **新建连接压力**：通过关闭 Keep-Alive（纯 `ab`）测试 Tokio `Accept` 性能及内核的 SYN backlog 处理能力。

运行方法：
```bash
chmod +x loadtest.sh
./loadtest.sh
```

## 预期表现

得益于 `tokio` 异步运行时的无栈协程模型、`hyper` 高性能 HTTP 实现，以及 `mimalloc` 的无锁内存分配，`proxy-core` 的预期表现应如下：

- **并发连接数**：轻松处理数以万计的并发连接，无内存溢出 (OOM) 风险。
- **延迟 (Latency)**：得益于客户端连接池和零拷贝设计，长连接情况下的 P99 延迟应在毫秒级别。
- **错误率**：在高压极限负载下，能够保持极低的连接失败率。
