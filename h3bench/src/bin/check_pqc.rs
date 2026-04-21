use anyhow::Result;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut roots = rustls::RootCertStore::empty();
    
    // WARNING: Insecure for local testing
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
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    let mut crypto_provider = rustls::crypto::aws_lc_rs::default_provider();
    
    // Force PQC ML-KEM to be the ONLY supported key exchange
    if let Some(pos) = crypto_provider.kx_groups.iter().position(|g| format!("{:?}", g.name()) == "X25519MLKEM768") {
        let kyber = crypto_provider.kx_groups[pos];
        crypto_provider.kx_groups = vec![kyber];
    } else {
        panic!("PQC not supported by the client provider");
    }

    let mut tls_config = ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        
    tls_config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

    let connector = TlsConnector::from(Arc::new(tls_config));
    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    let domain = rustls::pki_types::ServerName::try_from("localhost")?;
    
    println!("Connecting with Forced PQC (X25519MLKEM768)...");
    let mut tls_stream = connector.connect(domain, stream).await?;
    
    let negotiated_kx = tls_stream.get_ref().1.negotiated_key_exchange_group();
    println!("Successfully connected! Negotiated Key Exchange: {:?}", negotiated_kx);

    Ok(())
}