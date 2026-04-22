use std::sync::Arc;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ];
    let provider_arc = Arc::new(provider);
    
    let mut certfile = BufReader::new(File::open("/web/cert/cert.pem").unwrap());
    let certs = rustls_pemfile::certs(&mut certfile).collect::<Result<Vec<_>, _>>().unwrap();
    
    let mut keyfile = BufReader::new(File::open("/web/cert/cert.key").unwrap());
    let key: rustls::pki_types::PrivateKeyDer = rustls_pemfile::pkcs8_private_keys(&mut keyfile).next().unwrap().unwrap().into();
    
    let res = rustls::ServerConfig::builder_with_provider(provider_arc.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key);
    
    println!("Res: {:?}", res.is_ok());
    let quic_config = res.unwrap();
    let q = quinn::crypto::rustls::QuicServerConfig::try_from(quic_config);
    println!("q: {:?}", q.is_ok());
    if let Err(e) = q {
        println!("Error: {:?}", e);
    }
}
