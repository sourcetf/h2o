# Advanced Proxy Features Spec

## Why
当前代理需要提升其通用性和安全性，包括支持更多协议（如 SCTP 和旧版 HTTP/3、ESNI 等），提升压缩性能（brotli 和 gzip），并强化 HTTP 头部的安全与客户端 IP 透传。此外，还需完善工程构建和配置文件的自动化生成（ECH配置及 DNS 记录生成）。

## What Changes
- **协议支持**: 增加 SCTP 代理转发、ESNI 的旧草案支持、h3-29 草案支持。
- **功能特性**:
  - 增加可选的 brotli (`br`) 和 `gzip` 压缩，支持基于特定大小和扩展名过滤。
  - 代理所有类型的连接（HTTP, TCP, UDP, WSS, SCTP）至本地 8080 端口。
  - **BREAKING**: 关闭 0-RTT 以防止重放攻击并保证安全。
- **HTTP/Header 处理**:
  - 增加 XSS 保护头。
  - 使用自定义请求头 `X-Real-IP-75fe608c` 传递真实客户端 IP 到 8080 端口。
- **安全与配置自动化**:
  - 如果 TOML 中包含 ECH 字段，则自动生成 ECH 配置文件及 `dns.zone` 记录（一致时不重新生成）。
  - 在 TOML 中强制限制：TLS 1.3 只支持 `ECDHE-ECDSA-AES256-GCM-SHA384`，TLS 1.2 只支持 `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`。
  - 将证书与私钥路径固定为 `/web/cert/cert.pem` 和 `/web/cert/cert.key`。
- **工程化**: 编写一键编译脚本 `build.sh`。

## Impact
- Affected specs: 代理转发模块、配置解析模块、TLS握手模块、HTTP 中间件。
- Affected code:
  - `proxy-core` 中的配置读取与 TLS 设置。
  - 请求转发和协议监听模块。
  - 新增 `build.sh` 文件。

## ADDED Requirements
### Requirement: 编译自动化与配置更新
系统 SHALL 提供一个脚本能够一键编译整个项目。系统 SHALL 解析配置文件并自动同步生成 ECH 的部署配置文件和 DNS 记录。

#### Scenario: 自动生成 ECH 记录
- **WHEN** 配置文件中配置了 ECH 属性且和已有记录不一致时
- **THEN** 系统覆盖旧的 `dns.zone` 和 ech 配置文件。

## MODIFIED Requirements
### Requirement: TLS 握手及证书限制
系统 MUST 将加载证书路径指向 `/web/cert/`，并严格限制允许的加密套件为特定值，且强制关闭 0-RTT。

### Requirement: 代理转发与 HTTP 头部
系统 MUST 代理 TCP/UDP/HTTP/WSS/SCTP 所有流量到本地 8080，且对于 HTTP 流量 MUST 附带 XSS 保护及 `X-Real-IP-75fe608c` 头，并支持条件触发的 gzip/br 压缩。
