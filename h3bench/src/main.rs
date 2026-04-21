use anyhow::Result;
use quinn::{ClientConfig, Endpoint};
use std::sync::Arc;
use tokio::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(
        rustls_native_certs::load_native_certs().expect("could not load platform certs"),
    );

    // Accept invalid certs for local testing
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

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
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }
    
    tls_config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap()
    )));

    let addr = "127.0.0.1:8443".parse().unwrap();
    
    println!("Connecting to {} over HTTP/3...", addr);
    let conn = endpoint.connect(addr, "localhost")?.await?;
    let mut h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    println!("Starting HTTP/3 benchmark...");
    let start = Instant::now();
    let num_requests = 5000;
    
    let mut futures = vec![];
    let semaphore = Arc::new(tokio::sync::Semaphore::new(100));
    for _ in 0..num_requests {
        let mut sender = send_request.clone();
        let req = http::Request::builder()
            .method("GET")
            .uri("https://localhost:8443/")
            .body(())
            .unwrap();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
            
        futures.push(tokio::spawn(async move {
            let mut stream = sender.send_request(req).await.unwrap();
            stream.finish().await.unwrap();
            let _resp = stream.recv_response().await.unwrap();
            // Read body
            while let Some(_) = stream.recv_data().await.unwrap() {}
            drop(permit);
        }));
    }

    for f in futures {
        f.await.unwrap();
    }

    let elapsed = start.elapsed();
    let qps = (num_requests as f64) / elapsed.as_secs_f64();
    println!("Finished in {:?}", elapsed);
    println!("Requests per second: {:.2}", qps);

    Ok(())
}