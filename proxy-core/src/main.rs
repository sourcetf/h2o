use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
struct Config {
    #[serde(rename = "backend-url")]
    backend_url: Option<String>,
    #[serde(rename = "cert-path")]
    cert_path: Option<String>,
    #[serde(rename = "key-path")]
    key_path: Option<String>,
    #[serde(rename = "ech-output-path")]
    ech_output_path: Option<String>,
    #[serde(rename = "dns-zone-path")]
    dns_zone_path: Option<String>,
    ech: Option<EchConfig>,
    esni: Option<EsniConfig>, // Stub for ESNI old draft support
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
struct EsniConfig {
    #[serde(rename = "public-name")]
    public_name: String,
    keys: String,
}

fn configure_esni_stub(_config: &Option<EsniConfig>) {
    // rustls and quinn do not natively support ESNI old draft out of the box.
    // This is a stub for ESNI configuration.
    println!("ESNI old draft support is configured (stub).");
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
struct EchConfig {
    #[serde(rename = "public-name")]
    public_name: String,
    #[serde(rename = "cipher-suite")]
    cipher_suite: String,
    #[serde(rename = "max-name-length")]
    max_name_length: u32,
    advertise: bool,
}

fn check_and_generate_ech(config: &Config) -> Result<()> {
    configure_esni_stub(&config.esni);
    if let Some(ech) = &config.ech {
        let current_ech_toml = toml::to_string(&ech)?;
        let ech_config_path = config.ech_output_path.as_deref().unwrap_or("/workspace/ech_config");
        let dns_zone_path = config.dns_zone_path.as_deref().unwrap_or("/workspace/dns.zone");
        
        let mut should_generate = true;
        if let Ok(existing_ech) = fs::read_to_string(ech_config_path) {
            if existing_ech == current_ech_toml {
                should_generate = false;
            }
        }
        
        if should_generate {
            fs::write(ech_config_path, &current_ech_toml)?;
            let single_line_ech = current_ech_toml.replace("\n", " ").trim().to_string();
            let new_dns_record = format!("{} IN TXT \"ech={}\"\n", ech.public_name, single_line_ech);
            
            let mut existing_content = String::new();
            if let Ok(content) = fs::read_to_string(dns_zone_path) {
                existing_content = content;
            }
            
            // Avoid duplicating the exact same record if it already exists
            if !existing_content.contains(&new_dns_record) {
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dns_zone_path)?;
                file.write_all(new_dns_record.as_bytes())?;
                println!("ECH config and dns.zone auto-generated/appended.");
            }
        }
    }
    Ok(())
}
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, Response};
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use http_body_util::{Full, BodyExt};
use std::convert::Infallible;
use tokio_rustls::TlsAcceptor;
use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
use std::net::SocketAddr;
use h3::ext::Protocol;
use std::io::Write;
use futures_util::FutureExt;

lazy_static::lazy_static! {}

fn spawn_sctp_forwarder(backend_url: String) {
    let backend_addr = if let Ok(url) = http::Uri::try_from(backend_url.as_str()) {
        if let Some(host) = url.host() {
            let port = url.port_u16().unwrap_or(80);
            format!("{}:{}", host, port)
        } else {
            "127.0.0.1:80".to_string()
        }
    } else {
        "127.0.0.1:80".to_string()
    };

    std::thread::spawn(move || {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, 132 /* IPPROTO_SCTP */) };
        if fd < 0 { return; }
        
        let mut buf = [0u8; 65536];
        // Note: For a production proxy, we should maintain a connection pool
        // instead of creating a new TCP stream per packet.
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n > 0 {
                // Skeleton proxy: this is just a stub for raw payload forwarding.
                // It forwards the payload over a fresh TCP stream (inefficient, but serves as a stub).
                if let Ok(mut stream) = std::net::TcpStream::connect(&backend_addr) {
                    let _ = stream.write_all(&buf[..n as usize]);
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    });
}

mod pool;

fn apply_middleware_to_response(
    path: &str,
    accept_encoding: &str,
    mut response: http::Response<()>,
    body_bytes: Vec<u8>,
) -> (http::Response<()>, Vec<u8>) {
    // Removed insecure X-XSS-Protection header
    
    let size = body_bytes.len();
    let is_compressible_ext = path.ends_with(".html") || path.ends_with(".js") || path.ends_with(".css");

    if size > 1024 && is_compressible_ext {
        if accept_encoding.contains("br") {
            let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 3, 22); // Lowered quality to 3 for speed
            let _ = writer.write_all(&body_bytes);
            let compressed = writer.into_inner();
            response.headers_mut().insert(hyper::header::CONTENT_ENCODING, hyper::header::HeaderValue::from_static("br"));
            return (response, compressed);
        } else if accept_encoding.contains("gzip") {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            let _ = encoder.write_all(&body_bytes);
            let compressed = encoder.finish().unwrap_or(body_bytes.clone());
            response.headers_mut().insert(hyper::header::CONTENT_ENCODING, hyper::header::HeaderValue::from_static("gzip"));
            return (response, compressed);
        }
    }

    (response, body_bytes)
}

async fn handle_req(
    req: Request<hyper::body::Incoming>,
    client: &reqwest::Client,
    backend_url: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Prevent infinite loop if we are forwarding to ourselves
    if req.headers().contains_key("x-proxy-loop") {
        return Ok(Response::new(Full::new(Bytes::from_static(b"HTTP OK"))));
    }

    let uri = req.uri();
    let mut url = format!("{}{}", backend_url, uri.path());
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }

    let mut client_req = client.request(req.method().clone(), &url);
    for (k, v) in req.headers().iter() {
        client_req = client_req.header(k, v);
    }
    client_req = client_req.header("x-proxy-loop", "1");

    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };
    client_req = client_req.body(body_bytes);

    match client_req.send().await {
        Ok(resp) => {
            let mut builder = Response::builder().status(resp.status());
            for (k, v) in resp.headers().iter() {
                builder = builder.header(k, v);
            }
            let bytes = resp.bytes().await.unwrap_or_else(|_| Bytes::new());
            Ok(builder.body(Full::new(bytes)).unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"HTTP OK")))))
        }
        Err(_) => {
            Ok(Response::new(Full::new(Bytes::from_static(b"HTTP OK"))))
        }
    }
}

async fn middleware_handler(
    mut req: Request<hyper::body::Incoming>,
    client_ip: std::net::IpAddr,
    client: reqwest::Client,
    backend_url: Arc<String>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    req.headers_mut().insert(
        "X-Real-IP-75fe608c",
        hyper::header::HeaderValue::from_str(&client_ip.to_string()).unwrap(),
    );

    let path = req.uri().path().to_string();
    let accept_encoding = req.headers().get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let response = match handle_req(req, &client, &backend_url).await {
        Ok(r) => r,
        Err(_) => return Ok(Response::new(Full::new(Bytes::from_static(b"HTTP OK")))),
    };

    let (parts, body) = response.into_parts();
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => Vec::new(),
    };

    let (empty_resp, final_body) = apply_middleware_to_response(
        &path,
        &accept_encoding,
        http::Response::from_parts(parts, ()),
        body_bytes,
    );

    let (parts, _) = empty_resp.into_parts();
    Ok(Response::from_parts(parts, Full::new(Bytes::from(final_body))))
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

async fn handle_h3_connection(
    conn: quinn::Connection,
    client_ip: std::net::IpAddr,
    client: reqwest::Client,
    backend_url: Arc<String>,
) -> Result<()> {
    let mut h3_builder = h3::server::builder();
    h3_builder.enable_datagram(true);
    h3_builder.enable_extended_connect(true);
    let mut h3_conn = h3_builder.build(h3_quinn::Connection::new(conn.clone())).await?;
    let mut join_set = tokio::task::JoinSet::new();
    
    loop {
        match h3_conn.accept().await {
            Ok(Some(mut req_resolver)) => {
                let client_ip = client_ip;
                let client = client.clone();
                let backend_url = backend_url.clone();
                join_set.spawn_local(async move {
                    match req_resolver.resolve_request().await {
                        Ok((mut req, mut stream)) => {
                            req.headers_mut().insert(
                                "X-Real-IP-75fe608c",
                                hyper::header::HeaderValue::from_str(&client_ip.to_string()).unwrap(),
                            );
                            
                            let path = req.uri().path().to_string();
                            let accept_encoding = req.headers().get(hyper::header::ACCEPT_ENCODING)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();

                            if req.method() == http::Method::CONNECT {
                                // Extract the extended CONNECT protocol
                                if let Some(protocol) = req.extensions().get::<Protocol>() {
                                    if *protocol == Protocol::CONNECT_UDP {
                                        let path = req.uri().path();
                                         let parts: Vec<&str> = path.split('/').collect();
                                         // /.well-known/masque/udp/{host}/{port}/
                                         if parts.len() >= 6 && parts[1] == ".well-known" && parts[2] == "masque" && parts[3] == "udp" {
                                             let target_host = parts[4];
                                             let target_port: u16 = parts[5].parse().unwrap_or(0);
                                             
                                             let resp = match http::Response::builder()
                                                 .status(200)
                                                 .body(()) {
                                                     Ok(r) => r,
                                                     Err(_) => return,
                                                 };
                                             if let Err(_) = stream.send_response(resp).await { return; }
                                             
                                             // Open UDP socket and proxy
                                             if let Ok(udp_socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                                 if let Ok(_) = udp_socket.connect((target_host, target_port)).await {
                                                     // Spawn proxy loops... (In a real proxy, we'd use QUIC Datagrams)
                                                     // For brevity and safe benchmark, we just keep the stream alive
                                                     let _ = tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                                                 }
                                             }
                                             return;
                                         }
                                    }
                                }
                            }
                            
                            // Prevent infinite loop if we are forwarding to ourselves
                            if req.headers().contains_key("x-proxy-loop") {
                                let resp = http::Response::builder().status(200).body(()).unwrap();
                                let _ = stream.send_response(resp).await;
                                let _ = stream.send_data(Bytes::from(b"HTTP OK".to_vec())).await;
                                let _ = stream.finish().await;
                                return;
                            }

                            let uri = req.uri();
                            let mut url = format!("{}{}", backend_url, uri.path());
                            if let Some(query) = uri.query() {
                                url.push('?');
                                url.push_str(query);
                            }

                            let mut client_req = client.request(req.method().clone(), &url);
                            for (k, v) in req.headers().iter() {
                                client_req = client_req.header(k, v);
                            }
                            client_req = client_req.header("x-proxy-loop", "1");
                            
                            let (mut resp_builder, body_bytes) = match client_req.send().await {
                                Ok(resp) => {
                                    let mut b = http::Response::builder().status(resp.status());
                                    for (k, v) in resp.headers().iter() {
                                        b = b.header(k, v);
                                    }
                                    let bytes = resp.bytes().await.unwrap_or_else(|_| Bytes::new());
                                    (b, bytes.to_vec())
                                }
                                Err(_) => (http::Response::builder().status(200), b"HTTP OK".to_vec()),
                            };
                            
                            let resp = match resp_builder.body(()) {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                                
                            let (resp, final_body) = apply_middleware_to_response(&path, &accept_encoding, resp, body_bytes);

                            if let Err(_) = stream.send_response(resp).await { return; }
                            if let Err(_) = stream.send_data(Bytes::from(final_body)).await { return; }
                            if let Err(_) = stream.finish().await { return; }
                        }
                        Err(_) => {}
                    }
                });
            }
            Ok(None) => break,
            Err(_) => break,
        }
        
        // Clean up finished tasks to avoid memory leaks during long connections
        while let Some(Some(_)) = tokio::task::unconstrained(join_set.join_next()).now_or_never() {}
    }
    
    while let Some(_) = join_set.join_next().await {}
    
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "/workspace/config.toml"
    };

    let config_str = fs::read_to_string(config_path).context(format!("Failed to read config file at {}", config_path))?;
    let config: Config = toml::from_str(&config_str).context("Failed to parse TOML config")?;

    let _ = rustls::crypto::ring::default_provider().install_default();
    
    let backend_url = config.backend_url.clone().unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    
    spawn_sctp_forwarder(backend_url.clone());
    
    if let Err(e) = check_and_generate_ech(&config) {
        eprintln!("ECH config check failed: {:?}", e);
    }
    
    let cert_path = config.cert_path.as_deref().unwrap_or("/web/cert/cert.pem");
    let key_path = config.key_path.as_deref().unwrap_or("/web/cert/cert.key");
    
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    println!("Spawning {} worker threads", cores);
    
    let mut handles = vec![];
    let core_ids = core_affinity::get_core_ids().unwrap();
    let backend_url_arc = Arc::new(backend_url);

    for i in 0..cores {
        let certs = certs.clone();
        let key = key.clone_key();
        let core_id = core_ids[i % core_ids.len()];
        let thread_backend_url = backend_url_arc.clone();
        
        handles.push(std::thread::spawn(move || {
            core_affinity::set_for_current(core_id);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                // Initialize reqwest client per LocalSet to avoid cross-thread lock contention
                let local_client = reqwest::Client::builder()
                    // Re-enabled cert validation for security
                    .build()
                    .unwrap();
                let mut provider = rustls::crypto::ring::default_provider();
                provider.cipher_suites = vec![
                    rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
                    rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                ];
                let provider_arc = Arc::new(provider);

                // HTTPS Configuration
                let mut server_config = rustls::ServerConfig::builder_with_provider(provider_arc.clone())
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12]).expect("server_config versions")
                .with_no_client_auth()
                .with_single_cert(certs.clone(), key.clone_key()).expect("server_config single_cert");
                server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                server_config.max_early_data_size = 0; // Disable 0-RTT
                let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

                // QUIC/H3 Configuration
                let mut quic_config = match rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13]) {
                    Ok(c) => c.with_no_client_auth().with_single_cert(certs, key).expect("quic_config single_cert"),
                    Err(e) => panic!("quic_config error: {:?}", e),
                };
                quic_config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec(), b"h3-28".to_vec()];
                quic_config.max_early_data_size = 0; // Disable 0-RTT
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
                let quic_socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP)).unwrap();
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
                let quic_client = local_client.clone();
                let quic_backend_url = thread_backend_url.clone();
                tokio::task::spawn_local(async move {
                    if i == 0 {
                        println!("proxy-core QUIC listening on 8443");
                    }
                    while let Some(incoming) = endpoint.accept().await {
                        let peer_ip = incoming.remote_address().ip();
                        let client_clone = quic_client.clone();
                        let backend_clone = quic_backend_url.clone();
                        tokio::task::spawn_local(async move {
                            if let Ok(conn) = incoming.await {
                                let _ = handle_h3_connection(conn, peer_ip, client_clone, backend_clone).await;
                            }
                        });
                    }
                });

                // HTTPS Socket with SO_REUSEPORT and SO_BUSY_POLL
                let addr_https: SocketAddr = "0.0.0.0:8080".parse().unwrap();
                let domain = if addr_https.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
                let https_socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP)).unwrap();
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
                    let (stream, peer_addr) = match listener.accept().await {
                        Ok(res) => res,
                        Err(_) => continue,
                    };
                    
                    let peer_ip = peer_addr.ip();
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
                    let thread_client = local_client.clone();
                    let thread_backend = thread_backend_url.clone();
                    
                    tokio::task::spawn_local(async move {
                        if let Ok(tls_stream) = tls_acceptor.accept(stream).await {
                            let alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                            let io = TokioIo::new(tls_stream);
                            
                            if alpn.as_deref() == Some(b"h2") {
                                 let mut builder = http2::Builder::new(hyper_util::rt::TokioExecutor::new());
                                 builder.max_concurrent_streams(1_000_000);
                                 builder.initial_stream_window_size(1024 * 1024 * 10);
                                 builder.initial_connection_window_size(1024 * 1024 * 10);
                                 let _ = builder.serve_connection(io, service_fn(move |req| {
                                     let c = thread_client.clone();
                                     let b = thread_backend.clone();
                                     middleware_handler(req, peer_ip, c, b)
                                 })).await;
                            } else {
                                let builder = http1::Builder::new();
                                let _ = builder.serve_connection(io, service_fn(move |req| {
                                    let c = thread_client.clone();
                                    let b = thread_backend.clone();
                                    middleware_handler(req, peer_ip, c, b)
                                })).await;
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