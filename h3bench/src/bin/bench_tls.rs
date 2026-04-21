use anyhow::Result;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use std::time::Instant;

#[derive(Debug)]
struct SkipServerVerification;
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

async fn run_bench(name: &str, kx_name: &str) -> Result<()> {
    let mut crypto_provider = rustls::crypto::aws_lc_rs::default_provider();
    
    // Force specific Key Exchange group
    if let Some(pos) = crypto_provider.kx_groups.iter().position(|g| format!("{:?}", g.name()) == kx_name) {
        let selected_kx = crypto_provider.kx_groups[pos];
        crypto_provider.kx_groups = vec![selected_kx];
    } else {
        println!("Available KX Groups:");
        for g in &crypto_provider.kx_groups {
            println!("  - {:?}", g.name());
        }
        panic!("KX group {} not found", kx_name);
    }

    // Force AES256-GCM
    if let Some(pos) = crypto_provider.cipher_suites.iter().position(|cs| format!("{:?}", cs.suite()).contains("AES_256_GCM_SHA384")) {
        let selected_cs = crypto_provider.cipher_suites[pos];
        crypto_provider.cipher_suites = vec![selected_cs];
    } else {
        panic!("Cipher suite TLS13_AES_256_GCM_SHA384 not found");
    }

    let mut tls_config = ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    tls_config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

    let connector = TlsConnector::from(Arc::new(tls_config));
    let domain = rustls::pki_types::ServerName::try_from("localhost")?;

    println!("Starting TLS Handshake Benchmark: {}", name);
    let start = Instant::now();
    let num_conns = 2000;
    let concurrency = 50;

    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = vec![];

    for _ in 0..num_conns {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let connector = connector.clone();
        let domain = domain.clone();
        
        handles.push(tokio::spawn(async move {
            let stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();
            let _tls_stream = connector.connect(domain, stream).await.unwrap();
            drop(permit);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let elapsed = start.elapsed();
    let cps = (num_conns as f64) / elapsed.as_secs_f64();
    println!("=========================================");
    println!("Results for {}", name);
    println!("  Total Connections: {}", num_conns);
    println!("  Time Elapsed:      {:.2?}", elapsed);
    println!("  Handshakes/sec:    {:.2} conn/s", cps);
    println!("=========================================\n");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // warmup
    let _ = run_bench("Warmup", "secp256r1").await;
    
    // P-384
    run_bench("P-384 + AES-256-GCM", "secp384r1").await?;
    
    // PQC ML-KEM-768
    run_bench("PQC (X25519MLKEM768) + AES-256-GCM", "X25519MLKEM768").await?;
    
    Ok(())
}