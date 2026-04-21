use anyhow::{Context, Result};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpListener;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use hyper_util::server::conn::auto;
use hyper::service::service_fn;
use hyper::{Request, Response, body::Bytes};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use std::convert::Infallible;
use tokio_rustls::TlsAcceptor;

async fn handle_req(_: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("HTTP OK"))))
}

fn load_certs(filename: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = File::open(filename).context("cannot open cert file")?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("cannot parse certs")?;
    Ok(certs)
}

fn load_private_key(filename: &str) -> Result<PrivateKeyDer<'static>> {
    let keyfile = File::open(filename).context("cannot open private key file")?;
    let mut reader = BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("cannot parse pkcs8 private key")?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(key.into());
    }
    anyhow::bail!("no pkcs8 private key found");
}

async fn handle_h3_connection(conn: quinn::Connection) -> Result<()> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;
    loop {
        match h3_conn.accept().await {
            Ok(Some(mut req_resolver)) => {
                tokio::spawn(async move {
                    match req_resolver.resolve_request().await {
                        Ok((_req, mut stream)) => {
                            let resp = match http::Response::builder()
                                .status(200)
                                .body(()) {
                                    Ok(r) => r,
                                    Err(_) => return,
                                };
                            if let Err(e) = stream.send_response(resp).await {
                                eprintln!("h3 send response err: {}", e);
                                return;
                            }
                            if let Err(e) = stream.send_data(Bytes::from("HTTP OK")).await {
                                eprintln!("h3 send data err: {}", e);
                                return;
                            }
                            if let Err(e) = stream.finish().await {
                                eprintln!("h3 finish err: {}", e);
                            }
                        }
                        Err(e) => eprintln!("h3 resolve err: {}", e),
                    }
                });
            }
            Ok(None) => break,
            Err(err) => {
                eprintln!("Error accepting request: {}", err);
                break;
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    let certs = load_certs("/workspace/certs/p384.crt")?;
    let key = load_private_key("/workspace/certs/p384.key")?;
    
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key.clone_key())?;
        
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    
    // Start QUIC/H3
    let mut quic_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    quic_config.alpn_protocols = vec![b"h3".to_vec()];
    
    let server_config = quinn::crypto::rustls::QuicServerConfig::try_from(quic_config)?;
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(server_config)),
        "0.0.0.0:8443".parse()?,
    )?;
    
    tokio::spawn(async move {
        println!("proxy-core QUIC listening on 8443");
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = handle_h3_connection(conn).await {
                            eprintln!("h3 err: {}", e);
                        }
                    }
                    Err(e) => eprintln!("quic accept err: {}", e),
                }
            });
        }
    });

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("proxy-core HTTP/HTTPS listening on 8080");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("accept error: {}", e);
                continue;
            }
        };
        let tls_acceptor = tls_acceptor.clone();
        
        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    let builder = auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                    if let Err(err) = builder
                        .serve_connection(io, service_fn(handle_req))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                }
                Err(e) => eprintln!("tls error: {}", e),
            }
        });
    }
}
