use std::sync::Arc;
fn main() {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ];
    let provider_arc = Arc::new(provider);
    
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open("/web/cert/cert.pem").unwrap())).collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(std::fs::File::open("/web/cert/cert.key").unwrap())).next().unwrap().unwrap().into();
    
    let res = rustls::ServerConfig::builder_with_provider(provider_arc.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key);
    
    println!("Res: {:?}", res.err());
}
