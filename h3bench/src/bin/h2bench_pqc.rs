use anyhow::Result;
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
        }
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <url> <pqc_only>", args[0]);
        std::process::exit(1);
    }
    
    let force_pqc = args[2] == "true";

    let url_str = &args[1];
    let uri: hyper::Uri = url_str.parse()?;
    let host = uri.host().unwrap();
    let port = uri.port_u16().unwrap_or(443);
    let addr = format!("{}:{}", host, port);

    let mut crypto_provider = rustls::crypto::aws_lc_rs::default_provider();
    
    if force_pqc {
        if let Some(pos) = crypto_provider.kx_groups.iter().position(|g| format!("{:?}", g.name()) == "X25519MLKEM768") {
            let kyber = crypto_provider.kx_groups[pos];
            crypto_provider.kx_groups = vec![kyber];
        } else {
            panic!("PQC not supported by the client provider");
        }
    } else {
        // Just use X25519 to test h2o (since OpenSSL 3.0 doesn't support MLKEM)
        if let Some(pos) = crypto_provider.kx_groups.iter().position(|g| format!("{:?}", g.name()) == "X25519") {
            let x25519 = crypto_provider.kx_groups[pos];
            crypto_provider.kx_groups = vec![x25519];
        }
    }
    
    // Force AES_256_GCM_SHA384
    if let Some(pos) = crypto_provider.cipher_suites.iter().position(|s| format!("{:?}", s.suite()) == "TLS13_AES_256_GCM_SHA384") {
        let aes256 = crypto_provider.cipher_suites[pos];
        crypto_provider.cipher_suites = vec![aes256];
    }

    let mut tls_config = ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    tls_config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

    let connector = TlsConnector::from(Arc::new(tls_config));
    let domain = rustls::pki_types::ServerName::try_from(host.to_string())?;
    
    let num_requests = 100000;
    let concurrency = 50;
    
    println!("Starting HTTP/2 Benchmark over {} (PQC: {})", url_str, force_pqc);
    let start = Instant::now();
    
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut futures = vec![];
    
    // In order to benchmark HTTP/2 properly, we establish the connections upfront
    let mut connections = vec![];
    for _ in 0..concurrency {
        let stream = TcpStream::connect(&addr).await?;
        let tls_stream = connector.connect(domain.clone(), stream).await?;
        
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .handshake(TokioIo::new(tls_stream))
            .await?;
            
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                // Ignore connection close errors at the end
            }
        });
        
        connections.push(sender);
    }
    
    let connect_elapsed = start.elapsed();
    println!("Connected {} connections in {:?}", concurrency, connect_elapsed);
    
    let bench_start = Instant::now();

    for i in 0..num_requests {
        let mut sender = connections[i % concurrency].clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let url_clone = url_str.to_string();
        
        futures.push(tokio::spawn(async move {
            let req = Request::builder()
                .method("GET")
                .uri(&url_clone)
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap();
                
            let res = sender.send_request(req).await.unwrap();
            use http_body_util::BodyExt;
            let _ = res.into_body().collect().await.unwrap();
            drop(permit);
        }));
    }

    for f in futures {
        f.await.unwrap();
    }

    let elapsed = bench_start.elapsed();
    let qps = (num_requests as f64) / elapsed.as_secs_f64();
    println!("Finished in {:?}", elapsed);
    println!("Requests per second: {:.2}", qps);

    Ok(())
}