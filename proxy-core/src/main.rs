use anyhow::{Context, Result};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpListener;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, Response, body::Bytes};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use std::convert::Infallible;
use tokio_rustls::TlsAcceptor;
use socket2::{Socket, Domain, Type, Protocol};
use std::net::SocketAddr;

async fn handle_req(_: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from_static(b"HTTP OK"))))
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
    let mut join_set = tokio::task::JoinSet::new();
    
    loop {
        match h3_conn.accept().await {
            Ok(Some(mut req_resolver)) => {
                join_set.spawn_local(async move {
                    match req_resolver.resolve_request().await {
                        Ok((_req, mut stream)) => {
                            let resp = match http::Response::builder()
                                .status(200)
                                .body(()) {
                                    Ok(r) => r,
                                    Err(_) => return,
                                };
                            if let Err(_) = stream.send_response(resp).await { return; }
                            if let Err(_) = stream.send_data(Bytes::from_static(b"HTTP OK")).await { return; }
                            if let Err(_) = stream.finish().await { return; }
                        }
                        Err(_) => {}
                    }
                });
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    
    while let Some(_) = join_set.join_next().await {}
    
    Ok(())
}

fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    let certs = load_certs("/workspace/certs/p384.crt")?;
    let key = load_private_key("/workspace/certs/p384.key")?;
    
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    println!("Spawning {} worker threads", cores);
    
    let mut handles = vec![];
    let core_ids = core_affinity::get_core_ids().unwrap();

    for i in 0..cores {
        let certs = certs.clone();
        let key = key.clone_key();
        let core_id = core_ids[i % core_ids.len()];
        
        handles.push(std::thread::spawn(move || {
            core_affinity::set_for_current(core_id);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                // HTTPS Configuration
                let mut server_config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs.clone(), key.clone_key()).unwrap();
                server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

                // QUIC/H3 Configuration
                let mut quic_config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key).unwrap();
                quic_config.alpn_protocols = vec![b"h3".to_vec()];
                let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(quic_config).unwrap();
                
                let mut quic_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
                let mut transport_config = quinn::TransportConfig::default();
                // Extreme QUIC Tuning
                transport_config.max_concurrent_bidi_streams(10_000u32.into());
                transport_config.receive_window((1024 * 1024 * 10u32).into());
                transport_config.stream_receive_window((1024 * 1024 * 10u32).into());
                transport_config.datagram_receive_buffer_size(Some(1024 * 1024 * 10));
                quic_cfg.transport_config(Arc::new(transport_config));
                
                // QUIC Socket with SO_REUSEPORT and SO_BUSY_POLL
                let addr_quic: SocketAddr = "0.0.0.0:8443".parse().unwrap();
                let domain = if addr_quic.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
                let quic_socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).unwrap();
                quic_socket.set_reuse_address(true).unwrap();
                #[cfg(target_os = "linux")]
                {
                    quic_socket.set_reuse_port(true).unwrap();
                    unsafe {
                        let val: libc::c_int = 50; // 50 microseconds busy poll
                        libc::setsockopt(
                            std::os::unix::io::AsRawFd::as_raw_fd(&quic_socket),
                            libc::SOL_SOCKET,
                            libc::SO_BUSY_POLL,
                            &val as *const libc::c_int as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        );
                    }
                }
                quic_socket.bind(&addr_quic.into()).unwrap();
                let std_udp_socket: std::net::UdpSocket = quic_socket.into();
                std_udp_socket.set_nonblocking(true).unwrap();
                
                let endpoint = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(quic_cfg),
                    std_udp_socket,
                    Arc::new(quinn::TokioRuntime),
                ).unwrap();

                // Start QUIC/H3 listener
                tokio::task::spawn_local(async move {
                    if i == 0 {
                        println!("proxy-core QUIC listening on 8443");
                    }
                    while let Some(incoming) = endpoint.accept().await {
                        tokio::task::spawn_local(async move {
                            if let Ok(conn) = incoming.await {
                                let _ = handle_h3_connection(conn).await;
                            }
                        });
                    }
                });

                // HTTPS Socket with SO_REUSEPORT and SO_BUSY_POLL
                let addr_https: SocketAddr = "0.0.0.0:8080".parse().unwrap();
                let domain = if addr_https.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
                let https_socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).unwrap();
                https_socket.set_reuse_address(true).unwrap();
                #[cfg(target_os = "linux")]
                {
                    https_socket.set_reuse_port(true).unwrap();
                    unsafe {
                        let val: libc::c_int = 1;
                        libc::setsockopt(
                            std::os::unix::io::AsRawFd::as_raw_fd(&https_socket),
                            libc::IPPROTO_TCP,
                            libc::TCP_DEFER_ACCEPT,
                            &val as *const libc::c_int as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        );
                        let poll_val: libc::c_int = 50; // 50 microseconds busy poll
                        libc::setsockopt(
                            std::os::unix::io::AsRawFd::as_raw_fd(&https_socket),
                            libc::SOL_SOCKET,
                            libc::SO_BUSY_POLL,
                            &poll_val as *const libc::c_int as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        );
                    }
                }
                https_socket.bind(&addr_https.into()).unwrap();
                https_socket.listen(1024).unwrap();
                
                let std_tcp_listener: std::net::TcpListener = https_socket.into();
                std_tcp_listener.set_nonblocking(true).unwrap();
                let listener = TcpListener::from_std(std_tcp_listener).unwrap();

                if i == 0 {
                    println!("proxy-core HTTP/HTTPS listening on 8080");
                }

                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(res) => res,
                        Err(_) => continue,
                    };
                    
                    let _ = stream.set_nodelay(true); // Optimization: TCP_NODELAY
                    
                    #[cfg(target_os = "linux")]
                    unsafe {
                        let val: libc::c_int = 1;
                        libc::setsockopt(
                            std::os::unix::io::AsRawFd::as_raw_fd(&stream),
                            libc::IPPROTO_TCP,
                            libc::TCP_QUICKACK,
                            &val as *const libc::c_int as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        );
                    }
                    
                    let tls_acceptor = tls_acceptor.clone();
                    
                    tokio::task::spawn_local(async move {
                        if let Ok(tls_stream) = tls_acceptor.accept(stream).await {
                            let alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                            let io = TokioIo::new(tls_stream);
                            
                            if alpn.as_deref() == Some(b"h2") {
                                let mut builder = http2::Builder::new(hyper_util::rt::TokioExecutor::new());
                                builder.max_concurrent_streams(1_000_000);
                                builder.initial_stream_window_size(1024 * 1024 * 10);
                                builder.initial_connection_window_size(1024 * 1024 * 10);
                                let _ = builder.serve_connection(io, service_fn(handle_req)).await;
                            } else {
                                let builder = http1::Builder::new();
                                let _ = builder.serve_connection(io, service_fn(handle_req)).await;
                            }
                        }
                    });
                }
            });
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    Ok(())
}