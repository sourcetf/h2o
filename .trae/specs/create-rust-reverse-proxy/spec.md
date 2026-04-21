# Rust Reverse Proxy Spec

## Why
用户需要一个极致轻量、高性能且安全的 Rust 反向代理工具，在性能和并发上期望超越 h2o。同时需要支持前沿的网络和加密协议（如 HTTP/3, ECH, PQC, QMux 等）以及多层级的反向代理能力（WSS, TCP, UDP）。

## What Changes
- 创建一个全新的 Rust 语言编写的反向代理项目
- 集成 `rustls` 和 `aws-lc-rs`（静态编译）作为核心加密库
- 支持 HTTP/1.0 到 HTTP/3 (QUIC) 的解析和代理，允许用户自由配置
- 支持 HTTPS、WSS、TCP、UDP 等多协议的反向代理（四层透传时不处理 SSL）
- 引入前沿 TLS 特性：ECH（可手工开启）、RSA+ECC 双证书、自定义加密套件、PSK、PQC（后量子密码学）/ 混合算法
- 引入前沿 QUIC/HTTP3 特性：QUIC path migration, multipath (draft 05), HTTP/3 over QMux (draft-ietf-quic-qmux-01)
- 提供高级 TLS 配置：OCSP 装订、NPN/ALPN 协议选择（包含各种 IEEE 草案）、自定义 EC 椭圆曲线及服务器偏好优先设置
- 提供用户自定义 HTTP header 的功能
- 核心架构设计注重极致性能、高并发、低内存占用及稳定性

## Impact
- Affected specs: 核心网络层、TLS层、HTTP路由与反向代理层
- Affected code: 全新项目，涉及 `Cargo.toml`, `src/main.rs`, `src/config.rs`, `src/proxy/`, `src/tls/`, `src/quic/` 等

## ADDED Requirements
### Requirement: 核心代理功能
The system SHALL provide TCP, UDP, WSS 和 HTTP/1.0-HTTP/3 的反向代理能力。对于 TCP/UDP/WSS 在配置为纯透传时不需要处理 SSL。

#### Scenario: 代理 HTTP/3 请求
- **WHEN** 客户端发送 HTTP/3 请求
- **THEN** 代理服务器解析并将其安全地路由到后端服务，且支持 QUIC multipath 和 path migration。

### Requirement: 高级 TLS 与加密支持
The system SHALL provide 基于 `rustls` + `aws-lc-rs` 的加密，支持 ECH（手工开启）、RSA+ECC 双证书、PQC/混合算法、PSK、自定义加密套件、OCSP装订、自定义 EC 曲线及服务器端偏好优先。

#### Scenario: TLS 握手
- **WHEN** 客户端发起带有 ECH 和 PQC 算法的 Client Hello
- **THEN** 服务器根据配置的偏好优先选择 PQC 混合算法，解密 ECH，并完成安全的 TLS 握手。

### Requirement: 性能与并发
The system SHALL 提供超越 h2o 的高并发和低延迟处理能力，保持极低的资源占用。

#### Scenario: 高并发连接
- **WHEN** 面临海量并发连接
- **THEN** 系统稳定运行，不报错，且 CPU 和内存占用优于 h2o。