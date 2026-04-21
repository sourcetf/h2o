use crate::config::Config;
use anyhow::Result;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, error};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsAcceptor;

use crate::proxy::{handle_http_request, run_tcp_proxy, run_udp_proxy};
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
            tokio::spawn(async move {
                if let Err(e) = run_tcp_proxy(port, upstream).await {
                    error!("TCP proxy failed: {}", e);
                }
            });
        }

        // Start UDP proxies
        for udp_cfg in &self.config.proxy.udp {
            let upstream = udp_cfg.upstream.clone();
            let port = udp_cfg.listen_port;
            tokio::spawn(async move {
                if let Err(e) = run_udp_proxy(port, upstream).await {
                    error!("UDP proxy failed: {}", e);
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
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;

        info!("HTTP/HTTPS Server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let cfg = Arc::clone(&config_clone);
                    let acceptor = tls_acceptor.clone();
                    
                    // Spawn a new task for each connection
                    tokio::spawn(async move {
                        if let Some(acceptor) = acceptor {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let io = TokioIo::new(tls_stream);
                                    if let Err(err) = http1::Builder::new()
                                        .serve_connection(
                                            io,
                                            service_fn(move |req| {
                                                let cfg = Arc::clone(&cfg);
                                                handle_http_request(req, cfg)
                                            }),
                                        )
                                        .with_upgrades()
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
                            if let Err(err) = http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(move |req| {
                                        let cfg = Arc::clone(&cfg);
                                        handle_http_request(req, cfg)
                                    }),
                                )
                                .with_upgrades()
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
