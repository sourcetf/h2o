# Rust 高性能反向代理工具 Spec

## Why
用户需要一个极致注重性能和并发的反向代理工具，要求超越 h2o。该工具需支持最新的加密和网络协议（包括 HTTP/3, QUIC, PQC 等），并提供高度的配置自由度，满足高性能、轻量、低占用、安全、稳定不易报错的需求。

## What Changes
- 初始化 Rust 项目结构，搭建核心异步网络架构。
- 集成并静态编译 BoringSSL 作为底层加密库。
- 实现对 HTTP/1.0 至 HTTP/3 (QUIC) 的支持，允许用户自由配置。
- 支持高级加密特性：ECH、RSA+ECC 双证书、自定义加密套件、PSK 套件、PQC/混合算法。
- 支持网络层高级特性：QUIC path migration, multipath (draft 05), HTTP/3 over QMux (draft-ietf-quic-qmux-01)。
- 实现反向代理核心逻辑，支持 HTTP 代理及 WSS、TCP、UDP 等协议代理（支持直接透传或非 SSL 处理模式）。
- 支持 NPN/ALPN（包含各种 IEEE 草案）、OCSP 装订、自定义 HTTP Header 等附加功能。
- 支持可配置的 EC 椭圆曲线和服务器偏好优先级配置。

## Impact
- Affected specs: 全新项目，建立网络接入层与代理路由层。
- Affected code: 项目整体初始化，主要涉及网络监听、TLS 握手处理、QUIC/HTTP3 协议栈及代理转发模块。

## ADDED Requirements
### Requirement: 核心代理与协议支持
系统必须能够处理 HTTP/1.0、HTTP/1.1、HTTP/2 以及 HTTP/3 (QUIC) 流量，并能够代理 WSS、TCP 和 UDP 协议。
#### Scenario: Success case
- **WHEN** 客户端通过 HTTP/3 发起请求
- **THEN** 代理服务器能够建立 QUIC 连接并将其路由至后端，同时支持 QMux 以及 path migration/multipath。

### Requirement: 现代加密支持 (基于 BoringSSL)
系统必须静态编译 BoringSSL，并支持 ECH、RSA+ECC 双证书、PQC（后量子加密）混合算法、OCSP 装订及自定义 EC 曲线。
#### Scenario: Success case
- **WHEN** 客户端发送启用了 ECH 的握手请求
- **THEN** 服务器能够正确解密并使用配置的 PQC 混合算法偏好完成安全握手。
