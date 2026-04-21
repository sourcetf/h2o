use crate::config::Config;
use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, error};
use hyper_util::server::conn::auto;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsAcceptor;
use socket2::{Socket, Domain, Type, Protocol};
use std::net::SocketAddr;

use crate::proxy::{handle_http_request};
use crate::tls::create_tls_config;

pub struct Server {
    config: Arc<Config>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let config_clone = Arc::clone(&self.config);

        // Start TCP proxies
        for tcp_cfg in &self.config.proxy.tcp {
            let upstream = tcp_cfg.upstream.clone();
            let port = tcp_cfg.listen_port;
            
            // Need a SO_REUSEPORT socket for TCP proxy too if running in thread-per-core
            tokio::spawn(async move {
                let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
                let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
                let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).unwrap();
                
                socket.set_reuse_address(true).unwrap();
                #[cfg(target_os = "linux")]
                socket.set_reuse_port(true).unwrap();
                
                let addr_sockaddr = addr.into();
                socket.bind(&addr_sockaddr).unwrap();
                socket.listen(1024).unwrap();
                
                let std_listener: std::net::TcpListener = socket.into();
                std_listener.set_nonblocking(true).unwrap();
                let listener = TcpListener::from_std(std_listener).unwrap();

                loop {
                    match listener.accept().await {
                        Ok((mut stream, _)) => {
                            let upstream_clone = upstream.clone();
                            tokio::spawn(async move {
                                if let Ok(mut backend) = tokio::net::TcpStream::connect(upstream_clone).await {
                                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut backend).await;
                                }
                            });
                        }
                        Err(e) => error!("TCP proxy accept error: {}", e),
                    }
                }
            });
        }

        // Start UDP proxies
        for udp_cfg in &self.config.proxy.udp {
            let upstream = udp_cfg.upstream.clone();
            let port = udp_cfg.listen_port;
            tokio::spawn(async move {
                let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
                let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
                let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).unwrap();
                
                socket.set_reuse_address(true).unwrap();
                #[cfg(target_os = "linux")]
                socket.set_reuse_port(true).unwrap();
                
                let addr_sockaddr = addr.into();
                socket.bind(&addr_sockaddr).unwrap();
                
                let std_socket: std::net::UdpSocket = socket.into();
                std_socket.set_nonblocking(true).unwrap();
                let listener = tokio::net::UdpSocket::from_std(std_socket).unwrap();

                let mut buf = vec![0u8; 65535];
                loop {
                    if let Ok((len, peer)) = listener.recv_from(&mut buf).await {
                        let data = buf[..len].to_vec();
                        let upstream_clone = upstream.clone();
                        tokio::spawn(async move {
                            if let Ok(backend) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let _ = backend.send_to(&data, upstream_clone).await;
                            }
                        });
                    }
                }
            });
        }

        // Setup TLS Acceptor if configured
        let tls_acceptor = if let Some(tls_cfg) = &self.config.server.tls {
            match create_tls_config(tls_cfg) {
                Ok(server_config) => {
                    info!("TLS is enabled");
                    Some(TlsAcceptor::from(Arc::new(server_config)))
                }
                Err(e) => {
                    error!("Failed to create TLS config: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Start main HTTP/HTTPS proxy
        let port = self.config.server.port;
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

        // Use socket2 to create a SO_REUSEPORT socket
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        
        socket.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        {
            socket.set_reuse_port(true)?;
            // Optional: TCP_DEFER_ACCEPT to delay wakeups until data arrives
            // set_tcp_defer_accept is not available directly in socket2, using setsockopt
            unsafe {
                let val: libc::c_int = 1;
                libc::setsockopt(
                    std::os::unix::io::AsRawFd::as_raw_fd(&socket),
                    libc::IPPROTO_TCP,
                    libc::TCP_DEFER_ACCEPT,
                    &val as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
        
        let addr_sockaddr = addr.into();
        socket.bind(&addr_sockaddr)?;
        socket.listen(1024)?; // High backlog for high concurrency
        
        let std_listener: std::net::TcpListener = socket.into();
        std_listener.set_nonblocking(true)?;
        
        let listener = TcpListener::from_std(std_listener)?;

        info!("HTTP/HTTPS Server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let cfg = Arc::clone(&config_clone);
                    let acceptor = tls_acceptor.clone();
                    
                    // Spawn a new task for each connection
                    tokio::spawn(async move {
                        let _ = stream.set_nodelay(true);
                        
                        if let Some(acceptor) = acceptor {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let io = TokioIo::new(tls_stream);
                                    let builder = auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                                    if let Err(err) = builder
                                        .serve_connection(
                                            io,
                                            service_fn(move |req| {
                                                let cfg = Arc::clone(&cfg);
                                                handle_http_request(req.map(|b| http_body_util::BodyExt::boxed(b)), cfg)
                                            }),
                                        )
                                        .await
                                    {
                                        error!("Error serving TLS connection from {}: {:?}", peer_addr, err);
                                    }
                                }
                                Err(e) => {
                                    error!("TLS handshake failed with {}: {}", peer_addr, e);
                                }
                            }
                        } else {
                            let io = TokioIo::new(stream);
                            let builder = auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                            if let Err(err) = builder
                                .serve_connection(
                                    io,
                                    service_fn(move |req| {
                                        let cfg = Arc::clone(&cfg);
                                        handle_http_request(req.map(|b| http_body_util::BodyExt::boxed(b)), cfg)
                                    }),
                                )
                                .await
                            {
                                error!("Error serving connection from {}: {:?}", peer_addr, err);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}
