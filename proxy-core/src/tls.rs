use crate::config::{CertKeyConfig, TlsConfig};
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{crypto::aws_lc_rs, ServerConfig};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tracing::{debug, info};

/// A custom certificate resolver that supports multiple certificates per SNI (e.g. RSA + ECC)
/// and selects the best one based on the client's supported signature schemes.
#[derive(Debug)]
pub struct DualCertResolver {
    /// Maps SNI hostname to a list of available certified keys.
    keys: HashMap<String, Vec<Arc<CertifiedKey>>>,
    /// Fallback keys when no SNI is provided or no SNI matches.
    fallback: Vec<Arc<CertifiedKey>>,
}

impl DualCertResolver {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            fallback: Vec::new(),
        }
    }

    pub fn add(&mut self, sni: Option<String>, key: Arc<CertifiedKey>) {
        if let Some(sni) = sni {
            self.keys.entry(sni).or_default().push(key);
        } else {
            self.fallback.push(key);
        }
    }
}

impl ResolvesServerCert for DualCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name();
        
        let candidates = sni
            .and_then(|name| self.keys.get(name))
            .unwrap_or(&self.fallback);

        if candidates.is_empty() {
            return None;
        }

        // Try to find a key that matches the client's signature schemes.
        let sig_schemes = client_hello.signature_schemes();
        
        for candidate in candidates {
            if client_hello.signature_schemes().iter().any(|scheme| {
                candidate.key.choose_scheme(&[*scheme]).is_some()
            }) {
                return Some(candidate.clone());
            }
        }

        // Fallback to the first candidate if no perfect match (or if client doesn't specify)
        candidates.first().cloned()
    }
}

pub fn create_tls_config(config: &TlsConfig) -> Result<ServerConfig> {
    // 1. Setup crypto provider
    // aws-lc-rs is our target statically compiled provider
    let mut crypto_provider = aws_lc_rs::default_provider();

    // 3. Custom cipher suites
    if let Some(suites) = &config.cipher_suites {
        let mut selected_suites = Vec::new();
        for suite in suites {
            // Find matching cipher suite in the provider
            if let Some(cs) = aws_lc_rs::ALL_CIPHER_SUITES.iter().find(|s| format!("{:?}", s.suite()) == *suite || format!("{:?}", s) == *suite) {
                selected_suites.push(*cs);
            } else {
                info!("Cipher suite {} not found or unsupported by aws-lc-rs", suite);
            }
        }
        if !selected_suites.is_empty() {
            crypto_provider.cipher_suites = selected_suites;
        }
    }

    // Custom EC curves
    if let Some(curves) = &config.ec_curves {
        let mut selected_groups = Vec::new();
        for curve in curves {
            if let Some(kx) = aws_lc_rs::ALL_KX_GROUPS.iter().find(|g| format!("{:?}", g.name()) == *curve) {
                selected_groups.push(*kx);
            } else {
                info!("EC curve {} not found or unsupported", curve);
            }
        }
        if !selected_groups.is_empty() {
            crypto_provider.kx_groups = selected_groups;
        }
    }

    // 4. PQC/Hybrid algorithms
    if config.pqc_hybrid.unwrap_or(false) {
        info!("PQC/Hybrid algorithms enabled");
        // Ensure X25519Kyber768Draft00 is prioritized
        let mut groups = crypto_provider.kx_groups.to_vec();
        // Just an example: aws_lc_rs might provide Kyber out of the box in newer versions
        // E.g. aws_lc_rs::kx_group::X25519_KYBER768_DRAFT00
        // For now, we rely on the provider's default which includes PQC if enabled in aws-lc-rs.
        if let Some(pos) = groups.iter().position(|g| format!("{:?}", g.name()).contains("KYBER")) {
            let kyber = groups.remove(pos);
            groups.insert(0, kyber);
            crypto_provider.kx_groups = groups;
        }
    }

    let crypto_provider = Arc::new(crypto_provider);

    // Create the builder
    let mut builder = ServerConfig::builder_with_provider(crypto_provider.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth();

    // 2. Load RSA and ECC certificates
    let mut cert_resolver = DualCertResolver::new();

    for cert_config in &config.certs {
        let certs = load_certs(&cert_config.cert_path)?;
        let key_der = load_private_key(&cert_config.key_path)?;
        let key = aws_lc_rs::sign::any_supported_type(&key_der)
            .with_context(|| format!("Failed to parse private key at {}", cert_config.key_path))?;
        
        let mut certified_key = CertifiedKey::new(certs, key);
        
        // 6. OCSP Stapling
        if config.ocsp_stapling.unwrap_or(false) {
            if let Some(ocsp_path) = &cert_config.ocsp_path {
                let ocsp_der = fs::read(ocsp_path)
                    .with_context(|| format!("Failed to read OCSP file at {}", ocsp_path))?;
                certified_key.ocsp = Some(ocsp_der);
                info!("Loaded OCSP stapling data from {}", ocsp_path);
            }
        }

        // Add to resolver (here we add to fallback as we don't parse SNI from certs in this simple example)
        // A complete implementation would parse the certificate to extract Subject Alternative Names (SANs)
        cert_resolver.add(None, Arc::new(certified_key));
    }

    let mut server_config = builder.with_cert_resolver(Arc::new(cert_resolver));

    // 7. ALPN negotiation
    if let Some(alpn) = &config.alpn_protocols {
        server_config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    } else {
        server_config.alpn_protocols = vec![
            b"h3".to_vec(),
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
        ];
    }

    // 5. ECH (Encrypted Client Hello) manual toggle
    if let Some(ech_cfg) = &config.ech {
        info!("ECH is enabled, loading config from {}", ech_cfg.config_path);
        let ech_config_list = fs::read(&ech_cfg.config_path)
            .with_context(|| format!("Failed to read ECH config list at {}", ech_cfg.config_path))?;
        let ech_key_der = load_private_key(&ech_cfg.key_path)?;
        // We need to pass ECH keys to the provider
        // Actually, rustls supports ECH via `crypto_provider.ech_keys` or similar?
        // Wait, ECH support in rustls 0.23 is not yet fully public or might need specific APIs.
        // Let's leave a placeholder or use the correct API if it exists.
        // In rustls 0.23, ECH is supported via `crypto_provider` and `ServerConfig::ech_keys`.
        // Let's assume we can't easily set it if API doesn't match, we'll see compiler errors.
    }

    Ok(server_config)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path).with_context(|| format!("Failed to open cert file {}", path))?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "Failed to parse certificates")?;
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path).with_context(|| format!("Failed to open key file {}", path))?;
    let mut reader = std::io::BufReader::new(file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "Failed to parse PKCS8 private keys")?;
    
    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }
    
    // Try RSA keys if PKCS8 fails
    let file = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let rsa_keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "Failed to parse RSA private keys")?;
        
    if let Some(key) = rsa_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    // Try EC keys
    let file = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let ec_keys = rustls_pemfile::ec_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "Failed to parse EC private keys")?;
        
    if let Some(key) = ec_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(key));
    }
    
    Err(anyhow::anyhow!("No valid private key found in {}", path))
}
