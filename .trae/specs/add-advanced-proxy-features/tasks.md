# Tasks
- [x] Task 1: 工程化与证书配置
  - [x] SubTask 1.1: 编写 `build.sh` 编译脚本，一键编译 `proxy-core` 项目。
  - [x] SubTask 1.2: 修改 `proxy-core` 的证书加载逻辑，固定从 `/web/cert/cert.pem` 和 `/web/cert/cert.key` 读取。
- [x] Task 2: 配置文件增强 (ECH、TLS套件与关闭 0-RTT)
  - [x] SubTask 2.1: 在 TOML 中支持 ECH 相关配置的解析（`public-name`, `cipher-suite`, `max-name-length`, `advertise` 等）。
  - [x] SubTask 2.2: 编写逻辑在应用启动时，若检测到 TOML 中 ECH 变化，则自动生成或覆盖 `dns.zone` 和 `ech` 配置文件。
  - [x] SubTask 2.3: 限制 TLS 1.3 只支持 `TLS13_AES_256_GCM_SHA384`（对应的配置字符串为 `ECDHE-ECDSA-AES256-GCM-SHA384`），TLS 1.2 只支持 `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`。
  - [x] SubTask 2.4: 在传输层或 TLS 握手层关闭 0-RTT 支持。
- [x] Task 3: HTTP 中间件与头部处理
  - [x] SubTask 3.1: 增加可选的 `br` (Brotli) 和 `gzip` 压缩中间件，支持根据文件大小和扩展名判断是否压缩。
  - [x] SubTask 3.2: 为所有 HTTP 响应附加 XSS 保护相关的头部 (`X-XSS-Protection: 1; mode=block`)。
  - [x] SubTask 3.3: 为代理请求添加 `X-Real-IP-75fe608c` 头部，传递客户端真实 IP。
- [x] Task 4: 协议与转发支持
  - [x] SubTask 4.1: 实现将所有流量（HTTP, TCP, UDP, WSS, SCTP）代理转发到本地 `8080` 端口的功能。
  - [x] SubTask 4.2: 在 `quinn` 或底层配置中加入 `h3-29` 和 `ESNI`（旧 draft）的向后兼容配置支持。
  - [x] SubTask 4.3: 引入 SCTP 相关的转发逻辑或依赖支持。

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 2]
- [Task 4] depends on [Task 3]
