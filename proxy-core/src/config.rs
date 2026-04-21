use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub quic: QuicConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    /// Certificates and their corresponding keys.
    /// Can contain multiple pairs (e.g. RSA and ECC).
    pub certs: Vec<CertKeyConfig>,
    /// ECH (Encrypted Client Hello) configuration.
    pub ech: Option<EchConfig>,
    /// Custom cipher suites (e.g. TLS13_AES_256_GCM_SHA384).
    pub cipher_suites: Option<Vec<String>>,
    /// Custom EC curves (e.g. secp256r1, x25519).
    pub ec_curves: Option<Vec<String>>,
    /// Enable PQC/Hybrid algorithms (e.g. x25519_kyber768).
    pub pqc_hybrid: Option<bool>,
    /// Path to the OCSP response file or `true` to enable dynamic fetching.
    pub ocsp_stapling: Option<bool>,
    /// ALPN protocols to negotiate (e.g. h3, h2, http/1.1).
    pub alpn_protocols: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CertKeyConfig {
    pub cert_path: String,
    pub key_path: String,
    /// Path to OCSP response file for this certificate
    pub ocsp_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EchConfig {
    pub config_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RouteConfig {
    pub domain: String,
    pub upstream: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct QuicConfig {
    pub enable: bool,
    pub port: Option<u16>,
    pub multipath: bool, // Support for QUIC multipath (draft 05)
    pub qmux: bool,      // Support HTTP/3 over QMux (draft-ietf-quic-qmux-01)
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ProxyConfig {
    #[serde(default)]
    pub tcp: Vec<TcpProxyConfig>,
    #[serde(default)]
    pub udp: Vec<UdpProxyConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TcpProxyConfig {
    pub listen_port: u16,
    pub upstream: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UdpProxyConfig {
    pub listen_port: u16,
    pub upstream: String,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file at {:?}", path.as_ref()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config file as TOML")?;
        Ok(config)
    }
}
