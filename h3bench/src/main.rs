use anyhow::Result;
use quinn::{ClientConfig, Endpoint};
use std::sync::Arc;
use tokio::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    let mut roots = rustls::RootCertStore::empty();
    
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
            ]
        }
    }

    let mut crypto_provider = rustls::crypto::ring::default_provider();
    
    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    tls_config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap()
    )));

    let port = std::env::args().nth(1).unwrap_or_else(|| "8443".to_string());
    let addr = format!("127.0.0.1:{}", port).parse().unwrap();
    let uri = format!("https://localhost:{}/", port);
    
    println!("Connecting to {} over HTTP/3...", addr);
    let conn = endpoint.connect(addr, "localhost")?.await?;
    let mut h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

    tokio::spawn(async move {
        let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        eprintln!("h3 driver finished: {:?}", e);
    });

    println!("Starting HTTP/3 benchmark...");
    let start = Instant::now();
    let num_requests = 10000;
    
    let mut futures = vec![];
    let semaphore = Arc::new(tokio::sync::Semaphore::new(100));
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    
    for _ in 0..num_requests {
        let mut sender = send_request.clone();
        let req = http::Request::builder()
            .method("GET")
            .uri(uri.clone())
            .body(())
            .unwrap();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let latencies = latencies.clone();
            
        futures.push(tokio::spawn(async move {
            let req_start = Instant::now();
            let mut stream = match sender.send_request(req).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("send_request err: {:?}", e);
                    return;
                }
            };
            if let Err(e) = stream.finish().await {
                return;
            }
            let _resp = match stream.recv_response().await {
                Ok(r) => r,
                Err(e) => {
                    return;
                }
            };
            // Read body
            while let Ok(Some(_)) = stream.recv_data().await {}
            latencies.lock().await.push(req_start.elapsed().as_micros());
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
    
    let mut lats = latencies.lock().await.clone();
    lats.sort_unstable();
    if !lats.is_empty() {
        let sum: u128 = lats.iter().sum();
        let mean = (sum as f64) / (lats.len() as f64) / 1000.0;
        println!("Mean latency: {:.2} ms", mean);
    }

    Ok(())
}