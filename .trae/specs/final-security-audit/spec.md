# Final Security Audit Spec

## Why
在前面的漏洞排查与功能修复（包括 DoS 限制、Hop-by-hop 头清洗、SSRF 防御、全局超时设置）之后，我们结合 `brainstorming` 和 `security-best-practices` 对系统的核心逻辑进行了最后一轮“黑盒/白盒”安全审计，确保所有的功能实现完整且没有安全死角。
审计发现，在代理处理客户端连接和域名路由时，仍存在以下高危隐患，且部分配置加载存在崩溃风险。

## What Changes
- **修复 TCP Peek 慢速攻击 (Slowloris on Peek)**: 在实现 80/443 端口复用（协议嗅探）时，使用了 `stream.peek()`。如果恶意客户端建立 TCP 连接但不发送任何数据，该 `peek` 操作将永久挂起，从而耗尽服务器的文件描述符 (FD)。必须为嗅探操作添加严格的超时（例如 3 秒）。
- **防御域前置与 SNI-Host 不匹配 (Domain Fronting Mitigation)**: 尽管在 TLS 握手阶段启用了 SNI 校验，但代理并没有校验 HTTP 层的 `Host` 头是否与握手时的 SNI 匹配。攻击者可以通过 TLS 传递合法的 SNI，但在 HTTP 报文中发送 `Host: internal.admin.com` 来绕过安全策略。代理 MUST 强制校验或重写 HTTP Host。
- **修复前端连接资源耗尽 (Frontend Timeout)**: 虽然已经为 `reqwest::Client` (后端请求) 配置了超时，但对于接收客户端 HTTP/1.1 和 HTTP/2 的 `hyper` server builder，缺乏全局读写超时和并发连接数限制（Max Connections），依然容易被慢速攻击拖垮。
- **消除运行时崩溃 (Runtime Panic)**: 在启动或热加载时，如果 `config.toml` 中配置了不符合规范的 HTTP Header（如包含换行符 `\r\n`），`HeaderValue::from_str(v).unwrap()` 会直接导致整个代理进程崩溃。需要改为安全处理（跳过非法头或优雅退出）。

## Impact
- Affected specs: 代理底层连接协议嗅探、请求头转发安全、服务稳定性。
- Affected code: `proxy-core/src/main.rs` (连接分发逻辑、Hyper Server Builder、配置加载解析)

## ADDED Requirements
### Requirement: 严格的 SNI 与 HTTP 身份一致性
代理服务器 SHALL 强制要求加密通道的 SNI 与应用层协议的 Host / :authority 保持一致，或直接使用配置的 `sni-name` 覆盖请求目标，彻底阻断域前置攻击。

#### Scenario: 攻击者利用 Domain Fronting
- **WHEN** 客户端通过合法的 SNI `security.source.tf` 建立 TLS，却发送 `Host: evil.internal.com`
- **THEN** 代理检测到不一致，直接拒绝该请求（返回 HTTP 421 Misdirected Request 或 403 Forbidden），或者强制重写为安全的后端目标。

## MODIFIED Requirements
### Requirement: 安全的协议嗅探
在进行端口复用的协议嗅探（Peek）时，系统 MUST 设定一个短暂的超时阈值（如 3s）。如果在此期间未读取到任何字节，代理应主动断开 TCP 连接，防止恶意占线。