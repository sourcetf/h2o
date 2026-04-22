# Tasks
- [ ] Task 1: 修复协议嗅探 (Peek) 的慢速攻击漏洞
  - [ ] SubTask 1.1: 在 `main.rs` 中用于区分 HTTP/1.1 和 TLS/QUIC 的 `stream.peek(&mut buf).await` 逻辑外层，包裹 `tokio::time::timeout(Duration::from_secs(3), ...)`。
  - [ ] SubTask 1.2: 如果嗅探操作超时（`Err(_)`），则判定为非法或恶意连接，直接断开（`return` 放弃该 stream）。
- [ ] Task 2: 防御域前置攻击 (Domain Fronting) 与 HTTP Host 校验
  - [ ] SubTask 2.1: 在 `middleware_handler` 接收到客户端请求后，除了执行原有的 Hop-by-hop 清理外，提取当前配置的 `sni_name`。
  - [ ] SubTask 2.2: 检查请求头 `Host` 或 HTTP/2 的 `:authority`，如果与 `sni_name` 不符，将其强制改写为 `sni_name`，或直接返回 HTTP 421 Misdirected Request 以中断攻击。
- [ ] Task 3: 配置加载安全与消除运行时崩溃 (Panics)
  - [ ] SubTask 3.1: 将 `middleware_handler` 内部或配置解析处类似 `HeaderValue::from_str(v).unwrap()` 和 `HeaderName::from_bytes(k.as_bytes()).unwrap()` 的硬性断言改为使用 `if let Ok(...)` 进行模式匹配，并丢弃不合法的值或返回安全日志。
- [ ] Task 4: 添加 Hyper Server 前端连接超时限制
  - [ ] SubTask 4.1: 在 `hyper` 的 `http1::Builder::new()` 和 `http2::Builder::new()` 中，配置 `keep_alive_timeout`、`header_read_timeout` 和相关的空闲超时控制（如 `max_keep_alive_retries` 等），彻底防御 Slowloris 和空闲连接堆积。

# Task Dependencies
无特殊依赖。所有的修复均可在现有代码结构上直接进行。